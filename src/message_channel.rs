use crate::into_static;
use codec_sv2::framing_sv2::framing::Frame as EitherFrame;
pub use roles_logic_sv2;
pub use roles_logic_sv2::parsers::PoolMessages;
use roles_logic_sv2::parsers::TemplateDistribution;
use tokio::sync::mpsc::{Receiver, Sender};

pub type MessageType = u8;
use crate::Frame_;
use crate::StdFrame;

#[derive(PartialEq)]
pub enum Remote {
    Client,
    Server,
}

pub struct MessageChannel {
    pub message_type: MessageType,
    pub expect_from: Remote,
    pub receiver: Option<Receiver<PoolMessages<'static>>>,
    pub sender: Sender<PoolMessages<'static>>,
}

impl MessageChannel {
    pub async fn on_message(&mut self, frame: &mut Frame_) -> Option<Frame_> {
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
                    let mut payload2 = payload.clone();
                    // TODO TODO TODO we need todo this orrible thing cause
                    // that https://github.com/stratum-mining/stratum/issues/936
                    // as soon as fixed remove it
                    let maybe_message: Result<PoolMessages<'_>, _> =
                        (mt, payload.as_mut_slice()).try_into();
                    let maybe_message2: Result<TemplateDistribution<'_>, _> =
                        (mt, payload2.as_mut_slice()).try_into();
                    match (maybe_message, maybe_message2) {
                        (Ok(message), _) => (mt, into_static(message)),
                        (_, Ok(message)) => {
                            (mt, into_static(PoolMessages::TemplateDistribution(message)))
                        }
                        _ => {
                            eprintln!("Received frame with invalid payload or message type: {frame:?}, from: {expect_from}");
                            std::process::exit(1);
                        }
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
impl std::fmt::Display for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client => write!(f, "client"),
            Self::Server => write!(f, "server"),
        }
    }
}
