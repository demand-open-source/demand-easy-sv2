use codec_sv2::{HandshakeRole, Initiator};
pub use const_sv2;
use demand_sv2_connection::noise_connection_tokio::Connection;
use key_utils::{Error as KeyUtilsError, Secp256k1PublicKey};
pub use roles_logic_sv2;
pub use roles_logic_sv2::parsers::PoolMessages;
use roles_logic_sv2::{
    common_messages_sv2::{Protocol, SetupConnection},
    parsers::CommonMessages,
};
use tokio::{
    net::TcpStream,
    select,
    sync::mpsc::{channel, Receiver, Sender},
};

use crate::Frame_;
use crate::Remote;
use crate::StdFrame;
use crate::{into_static, message_channel::MessageChannel};

pub struct Client {
    from_server: Receiver<Frame_>,
    to_server: Sender<Frame_>,
    handlers: Vec<MessageChannel>,
    messages_to_send: Option<Receiver<PoolMessages<'static>>>,
    setup_connection_message: Option<PoolMessages<'static>>,
    protocol: Protocol,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClientError {
    MessagesToSendSenderDropped,
    UpstreamClosed,
    UpstreamClosedDuringSetupSv2Connection,
    ImpossibleSetupSv2ConnectionWithUpstream,
}

impl Client {
    pub async fn start(mut self) -> Result<(), ClientError> {
        let mut client_handlers = vec![];
        let mut server_handlers = vec![];
        self.setup_connection().await?;
        for handler in self.handlers {
            match handler.expect_from {
                Remote::Client => client_handlers.push(handler),
                Remote::Server => server_handlers.push(handler),
            }
        }
        if let Some(messages_to_send) = self.messages_to_send {
            select! {
                r = Self::send_to_up(messages_to_send, self.to_server.clone()) => r,
                r = Self::recv_from_up(self.from_server, self.to_server, server_handlers) => r,
            }
        } else {
            Self::recv_from_up(self.from_server, self.to_server, server_handlers).await
        }
    }

    async fn setup_connection(&mut self) -> Result<(), ClientError> {
        let recv = &mut self.from_server;
        let send = &self.to_server;
        let setup_connection = self.setup_connection_message.clone();
        let protocol = self.protocol;
        let setup_connection = match setup_connection {
            Some(m) => m,
            None => PoolMessages::Common(CommonMessages::SetupConnection(SetupConnection {
                protocol,
                min_version: 2,
                max_version: 2,
                flags: u32::MAX,
                endpoint_host: "".to_string().try_into().unwrap(),
                endpoint_port: 0,
                vendor: "DEMAND".to_string().try_into().unwrap(),
                hardware_version: "".to_string().try_into().unwrap(),
                firmware: "".to_string().try_into().unwrap(),
                device_id: "".to_string().try_into().unwrap(),
            })),
        };
        let frame: StdFrame = setup_connection
            .try_into()
            .expect("A message can always be converted in a frame");
        if send.send(frame.into()).await.is_err() {
            Err(ClientError::UpstreamClosedDuringSetupSv2Connection)
        } else {
            if let Some(_) = recv.recv().await {
                // TODO handle setup connection error here
                println!("Connection setup with upstream");
                Ok(())
            } else {
                Err(ClientError::ImpossibleSetupSv2ConnectionWithUpstream)
            }
        }
    }

    async fn send_to_up(
        mut recv: Receiver<PoolMessages<'static>>,
        send: Sender<Frame_>,
    ) -> Result<(), ClientError> {
        while let Some(message) = recv.recv().await {
            let frame: StdFrame = message
                .try_into()
                .expect("A message can always be converted in a frame");
            if send.send(frame.into()).await.is_err() {
                return Err(ClientError::UpstreamClosed);
            }
        }
        Err(ClientError::MessagesToSendSenderDropped)
    }

    async fn recv_from_up(
        mut recv: Receiver<Frame_>,
        send: Sender<Frame_>,
        mut handlers: Vec<MessageChannel>,
    ) -> Result<(), ClientError> {
        while let Some(mut frame) = recv.recv().await {
            for handler in handlers.iter_mut() {
                if let Some(frame) = handler.on_message(&mut frame).await {
                    if send.send(frame).await.is_err() {
                        return Err(ClientError::UpstreamClosed);
                    };
                }
            }
        }
        Err(ClientError::UpstreamClosed)
    }
}

pub struct ClientBuilder {
    from_server: Option<Receiver<Frame_>>,
    to_server: Option<Sender<Frame_>>,
    server_auth_key: Option<Secp256k1PublicKey>,
    handlers: Vec<MessageChannel>,
    messages_to_send: Option<Receiver<PoolMessages<'static>>>,
    setup_connection_message: Option<PoolMessages<'static>>,
    protocol: Option<Protocol>,
}

#[derive(Debug)]
pub enum ClientBuilderError {
    KeyError(KeyUtilsError),
    IncompleteBuilder,
    ImpossibleToCompleteHandShakeWithUpstream,
    TryToAddProtocolAfterAddingSetupConnection,
    TryToAddSetupConnectionAfterAddingProtocol,
}

// TODO a way for the caller to add a channel where it can receive the SetupConnection.Success or
// Error message.
// Something like with_custom_setup_connection_handler() ?
impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            from_server: None,
            to_server: None,
            server_auth_key: None,
            handlers: vec![],
            messages_to_send: None,
            setup_connection_message: None,
            protocol: None,
        }
    }
    pub async fn try_add_server(
        &mut self,
        stream: TcpStream,
    ) -> Result<&mut Self, ClientBuilderError> {
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
            Err(ClientBuilderError::ImpossibleToCompleteHandShakeWithUpstream)
        }
    }
    pub fn with_protocol(&mut self, protocol: Protocol) -> Result<&mut Self, ClientBuilderError> {
        if self.setup_connection_message.is_some() {
            eprintln!("You can select a protocol or add a setup connection message not both");
            return Err(ClientBuilderError::TryToAddProtocolAfterAddingSetupConnection);
        }
        self.protocol = Some(protocol);
        Ok(self)
    }
    pub fn with_server_auth_key(
        &mut self,
        auth_key: String,
    ) -> Result<&mut Self, ClientBuilderError> {
        let auth_pub_k: Secp256k1PublicKey = auth_key.parse()?;
        self.server_auth_key = Some(auth_pub_k);
        Ok(self)
    }

    pub fn with_custom_setup_connection(
        &mut self,
        setup_connection: SetupConnection,
    ) -> Result<&mut Self, ClientBuilderError> {
        if self.protocol.is_some() {
            eprintln!("You can select a protocol or add a setup connection message not both");
            return Err(ClientBuilderError::TryToAddSetupConnectionAfterAddingProtocol);
        }
        self.setup_connection_message = Some(into_static(PoolMessages::Common(
            CommonMessages::SetupConnection(setup_connection),
        )));
        Ok(self)
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
    fn get_protocol(&self) -> Result<Protocol, ClientBuilderError> {
        match (self.protocol, &self.setup_connection_message) {
            (Some(protocol), None) => Ok(protocol),
            (
                None,
                Some(PoolMessages::Common(CommonMessages::SetupConnection(setup_connection))),
            ) => Ok(setup_connection.protocol),
            (None, None) => Err(ClientBuilderError::IncompleteBuilder),
            _ => unreachable!(),
        }
    }
    pub fn try_build(self) -> Result<Client, ClientBuilderError> {
        let protocol = self.get_protocol()?;
        if let (Some(from_server), Some(to_server)) = (self.from_server, self.to_server) {
            Ok(Client {
                from_server,
                to_server,
                handlers: self.handlers,
                messages_to_send: self.messages_to_send,
                setup_connection_message: self.setup_connection_message,
                protocol,
            })
        } else {
            Err(ClientBuilderError::IncompleteBuilder)
        }
    }
}

impl From<KeyUtilsError> for ClientBuilderError {
    fn from(value: KeyUtilsError) -> Self {
        Self::KeyError(value)
    }
}
