use codec_sv2::{HandshakeRole, Responder};
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
use crate::StdFrame;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ServerError {
    MessagesToSendSenderDropped,
    DownstreamClosed,
    DownstreamClosedDuringSetupSv2Connection,
    ImpossibleSetupSv2ConnectionWithUpstream,
}

pub struct Server {
    from_client: Receiver<Frame_>,
    to_client: Sender<Frame_>,
    handlers: Vec<MessageChannel>,
    messages_to_send: Option<Receiver<PoolMessages<'static>>>,
}
impl Server {
    pub async fn start(self) -> Result<(), ServerError> {
        let mut client_handlers = vec![];
        let mut server_handlers = vec![];
        for handler in self.handlers {
            match handler.expect_from {
                Remote::Client => client_handlers.push(handler),
                Remote::Server => server_handlers.push(handler),
            }
        }
        if let Some(messages_to_send) = self.messages_to_send {
            select! {
                r = Self::send_to_down(messages_to_send, self.to_client.clone()) => r,
                r = Self::recv_from_down(self.from_client, self.to_client, server_handlers) => r,
            }
        } else {
            Self::recv_from_down(self.from_client, self.to_client, server_handlers).await
        }
    }

    async fn send_to_down(
        mut recv: Receiver<PoolMessages<'static>>,
        send: Sender<Frame_>,
    ) -> Result<(), ServerError> {
        while let Some(message) = recv.recv().await {
            let frame: StdFrame = message
                .try_into()
                .expect("A message can always be converted in a frame");
            if send.send(frame.into()).await.is_err() {
                return Err(ServerError::DownstreamClosed);
            }
        }
        Err(ServerError::MessagesToSendSenderDropped)
    }

    async fn recv_from_down(
        mut recv: Receiver<Frame_>,
        send: Sender<Frame_>,
        mut handlers: Vec<MessageChannel>,
    ) -> Result<(), ServerError> {
        while let Some(mut frame) = recv.recv().await {
            for handler in handlers.iter_mut() {
                if let Some(frame) = handler.on_message(&mut frame).await {
                    if send.send(frame).await.is_err() {
                        return Err(ServerError::DownstreamClosed);
                    };
                }
            }
        }
        Err(ServerError::DownstreamClosed)
    }
}

pub struct ServerBuilder {
    from_client: Option<Receiver<Frame_>>,
    to_client: Option<Sender<Frame_>>,
    server_sec_key: Secp256k1SecretKey,
    server_pub_key: Secp256k1PublicKey,
    handlers: Vec<MessageChannel>,
    messages_to_send: Option<Receiver<PoolMessages<'static>>>,
    cert_validity: u64,
}

#[derive(Debug)]
pub enum ServerBuilderError {
    KeyError(KeyUtilsError),
    IncompleteBuilder,
    ImpossibleToCompleteHandShakeWithDownstream,
    TryToAddProtocolAfterAddingSetupConnection,
    TryToAddSetupConnectionAfterAddingProtocol,
    CanNotHaveMoreThan1Client,
}
impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            from_client: None,
            to_client: None,
            cert_validity: 10000,
            server_pub_key: "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
                .to_string()
                .parse()
                .expect("Invalid default pub key"),
            server_sec_key: "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
                .to_string()
                .parse()
                .expect("Invalid default sec key"),
            handlers: vec![],
            messages_to_send: None,
        }
    }
    pub fn try_with_client(
        &mut self,
        from_client: Receiver<Frame_>,
        to_client: Sender<Frame_>,
    ) -> Result<&mut Self, ServerBuilderError> {
        if self.from_client.is_none() && self.to_client.is_none() {
            self.from_client = Some(from_client);
            self.to_client = Some(to_client);
            Ok(self)
        } else {
            Err(ServerBuilderError::CanNotHaveMoreThan1Client)
        }
    }
    pub async fn try_add_client(
        &mut self,
        stream: TcpStream,
    ) -> Result<&mut Self, ServerBuilderError> {
        if self.from_client.is_none() && self.to_client.is_none() {
            let auth_pub_k_as_bytes = self.server_pub_key.into_bytes();
            let auth_prv_k_as_bytes = self.server_sec_key.into_bytes();
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
                Err(ServerBuilderError::ImpossibleToCompleteHandShakeWithDownstream)
            }
        } else {
            Err(ServerBuilderError::CanNotHaveMoreThan1Client)
        }
    }

    pub fn add_handler(&mut self, message_type: u8) -> Receiver<PoolMessages<'static>> {
        let (s, r) = channel(3);
        let channel = MessageChannel {
            message_type,
            expect_from: Remote::Server,
            receiver: None,
            sender: s,
        };
        self.handlers.push(channel);
        r
    }
    pub fn add_handler_with_sender(
        &mut self,
        message_type: u8,
    ) -> (
        Receiver<PoolMessages<'static>>,
        Sender<PoolMessages<'static>>,
    ) {
        let (s, r) = channel(3);
        let (s1, r1) = channel(3);
        let channel = MessageChannel {
            message_type,
            expect_from: Remote::Server,
            receiver: Some(r1),
            sender: s,
        };
        self.handlers.push(channel);
        (r, s1)
    }
    pub fn add_message_sender(&mut self) -> Sender<PoolMessages<'static>> {
        let (s, r) = channel(3);
        self.messages_to_send = Some(r);
        s
    }
    pub fn try_build(self) -> Result<Server, ServerBuilderError> {
        if let (Some(from_client), Some(to_client)) = (self.from_client, self.to_client) {
            Ok(Server {
                from_client,
                to_client,
                handlers: self.handlers,
                messages_to_send: self.messages_to_send,
            })
        } else {
            Err(ServerBuilderError::IncompleteBuilder)
        }
    }
}

impl From<KeyUtilsError> for ServerBuilderError {
    fn from(value: KeyUtilsError) -> Self {
        Self::KeyError(value)
    }
}
