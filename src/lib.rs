pub use roles_logic_sv2;
pub use roles_logic_sv2::parsers::PoolMessages;
pub use const_sv2;
use codec_sv2::{
    framing_sv2::framing2::EitherFrame, Frame, HandshakeRole, Initiator, Responder,
    StandardEitherFrame, StandardSv2Frame,
};
use demand_sv2_connection::noise_connection_tokio::Connection;
use key_utils::{Error as KeyUtilsError, Secp256k1PublicKey, Secp256k1SecretKey};
use tokio::{
    net::TcpStream,
    select,
    sync::mpsc::{Receiver, Sender,channel},
};
#[cfg(feature = "with_serde")]
mod into_static_serde;
#[cfg(feature = "with_serde")]
use into_static_serde::into_static;
#[cfg(not(feature = "with_serde"))]
mod into_static;
#[cfg(not(feature = "with_serde"))]
use into_static::into_static;

pub type Frame_ = StandardEitherFrame<PoolMessages<'static>>;
pub type StdFrame = StandardSv2Frame<PoolMessages<'static>>;

#[derive(Clone,Copy,Debug,PartialEq)]
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

pub type MessageType = u8;

#[derive(PartialEq)]
pub enum Remote {
    Client,
    Server,
}

struct MessageChannel {
    message_type: MessageType,
    expect_from: Remote,
    receiver: Option<Receiver<PoolMessages<'static>>>,
    sender: Sender<PoolMessages<'static>>,
}

impl MessageChannel {
    async fn on_message(&mut self, frame: &mut Frame_) -> Option<Frame_> {
        let (mt, message) = self.message_from_frame(frame);
        if mt == self.message_type {
            if self.sender.send(message).await.is_err() {
                eprintln!("Impossible to send message to message handler, for: {mt}");
                std::process::exit(1);
            };
            if let Some(receiver) = &mut self.receiver {
                if let Some(message) = receiver.recv().await {
                    let frame: StdFrame = message
                        .try_into()
                        .expect("A message can always be converted in a frame");
                    Some(frame.into())
                } else {
                    eprintln!("Impossible to receive message from message handler, for: {mt}");
                    std::process::exit(1);
                }
            } else {
                None
            }
        } else {
            None
        }
    }
    fn message_from_frame(&self, frame: &mut Frame_) -> (u8, PoolMessages<'static>) {
        let expect_from = &self.expect_from;
        match frame {
            EitherFrame::Sv2(frame) => {
                if let Some(header) = frame.get_header() {
                    let mt = header.msg_type();
                    let mut payload = frame.payload().to_vec();
                    let maybe_message: Result<PoolMessages<'_>, _> =
                        (mt, payload.as_mut_slice()).try_into();
                    if let Ok(message) = maybe_message {
                        (mt, into_static(message))
                    } else {
                        eprintln!("Received frame with invalid payload or message type: {frame:?}, from: {expect_from}");
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("Received frame with invalid header: {frame:?}, from: {expect_from}");
                    std::process::exit(1);
                }
            }
            EitherFrame::HandShake(f) => {
                eprintln!("Received unexpected handshake frame: {f:?}, from: {expect_from}");
                std::process::exit(1);
            }
        }
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
    pub async fn try_add_client(&mut self, stream: TcpStream) -> Result<&mut Self, ProxyBuilderError> {
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
    pub async fn try_add_server(&mut self, stream: TcpStream) -> Result<&mut Self, ProxyBuilderError> {
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
            Err(ProxyBuilderError::ImpossibleToCompleteHandShakeWithDownstream)
        }
    }
    pub fn override_cert_validity(&mut self, cert_validity: u64) -> &mut Self {
        self.cert_validity = cert_validity;
        self
    }
    pub fn override_proxy_pub_key(&mut self, pub_key: String) -> Result<&mut Self, ProxyBuilderError> {
        self.proxy_pub_key = pub_key.parse()?;
        Ok(self)
    }
    pub fn override_proxy_sec_key(&mut self, sec_key: String) -> Result<&mut Self, ProxyBuilderError> {
        self.proxy_sec_key = sec_key.parse()?;
        Ok(self)
    }
    pub fn with_server_auth_key(&mut self, auth_key: String) -> Result<&mut Self, ProxyBuilderError> {
        let auth_pub_k: Secp256k1PublicKey = auth_key.parse()?;
        self.server_auth_key = Some(auth_pub_k);
        Ok(self)
    }
    pub fn add_handler(&mut self, expect_from: Remote, message_type: u8) -> Receiver<PoolMessages<'static>> {
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
    pub fn add_handler_with_sender(&mut self, expect_from: Remote, message_type: u8) -> (Receiver<PoolMessages<'static>>, Sender<PoolMessages<'static>>) {
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


impl std::fmt::Display for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client => write!(f, "client"),
            Self::Server => write!(f, "server"),
        }
    }
}

impl From<KeyUtilsError> for ProxyBuilderError {
    fn from(value: KeyUtilsError) -> Self {
        Self::KeyError(value)
    }
}

