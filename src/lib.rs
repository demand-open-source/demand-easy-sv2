use codec_sv2::{StandardEitherFrame, StandardSv2Frame};
pub use const_sv2;
pub use roles_logic_sv2;
pub use roles_logic_sv2::parsers::PoolMessages;

#[cfg(feature = "with_serde")]
mod into_static_serde;
#[cfg(feature = "with_serde")]
pub(crate) use into_static_serde::into_static;
#[cfg(not(feature = "with_serde"))]
mod into_static;
#[cfg(not(feature = "with_serde"))]
pub(crate) use into_static::into_static;

mod message_channel;
pub use message_channel::Remote;

pub mod client_helpers;
pub mod proxy_helpers;
pub use client_helpers::*;
pub use proxy_helpers::*;

pub type Frame_ = StandardEitherFrame<PoolMessages<'static>>;
pub type StdFrame = StandardSv2Frame<PoolMessages<'static>>;
