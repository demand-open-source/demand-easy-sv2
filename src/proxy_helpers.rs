use codec_sv2::{HandshakeRole, Initiator, Responder};
pub use const_sv2;
use demand_sv2_connection::noise_connection_tokio::Connection;
use key_utils::{Error as KeyUtilsError, Secp256k1PublicKey, Secp256k1SecretKey};
pub use roles_logic_sv2;
pub use roles_logic_sv2::parsers::PoolMessages;
use tokio::{
    net::TcpStream,
    select,
    sync::mpsc::{channel, Receiver, Sender},
};

use crate::message_channel::MessageChannel;
use crate::Frame_;
use crate::Remote;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProxyError {
    DownstreamClosed,
    UpstreamClosed,
}

pub struct Proxy {
    from_client: Receiver<Frame_>,
    to_client: Sender<Frame_>,
    from_server: Receiver<Frame_>,
    to_server: Sender<Frame_>,
    handlers: Vec<MessageChannel>,
}

impl Proxy {
    pub async fn start(self) -> Result<(), ProxyError> {
        let mut client_handlers = vec![];
        let mut server_handlers = vec![];
        for handler in self.handlers {
            match handler.expect_from {
                Remote::Client => client_handlers.push(handler),
                Remote::Server => server_handlers.push(handler),
            }
        }
        select! {
            r = Self::recv_from_down_send_to_up(self.from_client, self.to_server, client_handlers) => r,
            r = Self::recv_from_up_send_to_down(self.from_server, self.to_client, server_handlers) => r,
        }
    }

    async fn recv_from_down_send_to_up(
        mut recv: Receiver<Frame_>,
        send: Sender<Frame_>,
        mut handlers: Vec<MessageChannel>,
    ) -> Result<(), ProxyError> {
        while let Some(mut frame) = recv.recv().await {
            let mut send_original_frame_upstream = true;
            for handler in handlers.iter_mut() {
                if let Some(frame) = handler.on_message(&mut frame).await {
                    send_original_frame_upstream = false;
                    if send.send(frame).await.is_err() {
                        return Err(ProxyError::UpstreamClosed);
                    };
                }
            }
            if send_original_frame_upstream && send.send(frame).await.is_err() {
                return Err(ProxyError::UpstreamClosed);
            };
        }
        Err(ProxyError::DownstreamClosed)
    }

    async fn recv_from_up_send_to_down(
        mut recv: Receiver<Frame_>,
        send: Sender<Frame_>,
        mut handlers: Vec<MessageChannel>,
    ) -> Result<(), ProxyError> {
        while let Some(mut frame) = recv.recv().await {
            let mut send_original_frame_upstream = true;
            for handler in handlers.iter_mut() {
                if let Some(frame) = handler.on_message(&mut frame).await {
                    send_original_frame_upstream = false;
                    if send.send(frame).await.is_err() {
                        return Err(ProxyError::DownstreamClosed);
                    };
                }
            }
            if send_original_frame_upstream && send.send(frame).await.is_err() {
                return Err(ProxyError::DownstreamClosed);
            };
        }
        Err(ProxyError::UpstreamClosed)
    }
}

pub struct ProxyBuilder {
    from_client: Option<Receiver<Frame_>>,
    to_client: Option<Sender<Frame_>>,
    from_server: Option<Receiver<Frame_>>,
    to_server: Option<Sender<Frame_>>,
    cert_validity: u64,
    proxy_pub_key: Secp256k1PublicKey,
    proxy_sec_key: Secp256k1SecretKey,
    server_auth_key: Option<Secp256k1PublicKey>,
    handlers: Vec<MessageChannel>,
}

#[derive(Debug)]
pub enum ProxyBuilderError {
    KeyError(KeyUtilsError),
    ImpossibleToCompleteHandShakeWithDownstream,
    ImpossibleToCompleteHandShakeWithUpstream,
    IncompleteBuilder,
}

impl ProxyBuilder {
    pub fn new() -> Self {
        Self {
            from_client: None,
            to_client: None,
            from_server: None,
            to_server: None,
            cert_validity: 10000,
            proxy_pub_key: "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
                .to_string()
                .parse()
                .expect("Invalid default pub key"),
            proxy_sec_key: "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
                .to_string()
                .parse()
                .expect("Invalid default sec key"),
            server_auth_key: None,
            handlers: vec![],
        }
    }
    pub async fn try_add_client(
        &mut self,
        stream: TcpStream,
    ) -> Result<&mut Self, ProxyBuilderError> {
        let auth_pub_k_as_bytes = self.proxy_pub_key.into_bytes();
        let auth_prv_k_as_bytes = self.proxy_sec_key.into_bytes();
        let responder = Responder::from_authority_kp(
            &auth_pub_k_as_bytes,
            &auth_prv_k_as_bytes,
            std::time::Duration::from_secs(self.cert_validity),
        )
        .expect("invalid key pair");

        if let Ok((receiver_from_client, send_to_client, _, _)) =
            Connection::new::<'static, PoolMessages<'static>>(
                stream,
                HandshakeRole::Responder(responder),
            )
            .await
        {
            self.from_client = Some(receiver_from_client);
            self.to_client = Some(send_to_client);
            Ok(self)
        } else {
            Err(ProxyBuilderError::ImpossibleToCompleteHandShakeWithDownstream)
        }
    }
    pub async fn try_add_server(
        &mut self,
        stream: TcpStream,
    ) -> Result<&mut Self, ProxyBuilderError> {
        let initiator = match self.server_auth_key {
            Some(key) => Initiator::from_raw_k(key.into_bytes())
                .expect("Pub key is already checked for validity"),
            None => Initiator::without_pk().expect("This fn call can not fail"),
        };

        if let Ok((receiver_from_client, send_to_client, _, _)) =
            Connection::new::<'static, PoolMessages<'static>>(
                stream,
                HandshakeRole::Initiator(initiator),
            )
            .await
        {
            self.from_server = Some(receiver_from_client);
            self.to_server = Some(send_to_client);
            Ok(self)
        } else {
            Err(ProxyBuilderError::ImpossibleToCompleteHandShakeWithUpstream)
        }
    }
    pub fn override_cert_validity(&mut self, cert_validity: u64) -> &mut Self {
        self.cert_validity = cert_validity;
        self
    }
    pub fn override_proxy_pub_key(
        &mut self,
        pub_key: String,
    ) -> Result<&mut Self, ProxyBuilderError> {
        self.proxy_pub_key = pub_key.parse()?;
        Ok(self)
    }
    pub fn override_proxy_sec_key(
        &mut self,
        sec_key: String,
    ) -> Result<&mut Self, ProxyBuilderError> {
        self.proxy_sec_key = sec_key.parse()?;
        Ok(self)
    }
    pub fn with_server_auth_key(
        &mut self,
        auth_key: String,
    ) -> Result<&mut Self, ProxyBuilderError> {
        let auth_pub_k: Secp256k1PublicKey = auth_key.parse()?;
        self.server_auth_key = Some(auth_pub_k);
        Ok(self)
    }
    pub fn add_handler(
        &mut self,
        expect_from: Remote,
        message_type: u8,
    ) -> Receiver<PoolMessages<'static>> {
        let (s, r) = channel(3);
        let channel = MessageChannel {
            message_type,
            expect_from,
            receiver: None,
            sender: s,
        };
        self.handlers.push(channel);
        r
    }
    pub fn add_handler_with_sender(
        &mut self,
        expect_from: Remote,
        message_type: u8,
    ) -> (
        Receiver<PoolMessages<'static>>,
        Sender<PoolMessages<'static>>,
    ) {
        let (s, r) = channel(3);
        let (s1, r1) = channel(3);
        let channel = MessageChannel {
            message_type,
            expect_from,
            receiver: Some(r1),
            sender: s,
        };
        self.handlers.push(channel);
        (r, s1)
    }
    pub fn try_build(self) -> Result<Proxy, ProxyBuilderError> {
        if let (Some(from_client), Some(to_client), Some(from_server), Some(to_server)) = (
            self.from_client,
            self.to_client,
            self.from_server,
            self.to_server,
        ) {
            Ok(Proxy {
                from_client,
                to_client,
                from_server,
                to_server,
                handlers: self.handlers,
            })
        } else {
            Err(ProxyBuilderError::IncompleteBuilder)
        }
    }
}
impl From<KeyUtilsError> for ProxyBuilderError {
    fn from(value: KeyUtilsError) -> Self {
        Self::KeyError(value)
    }
}
