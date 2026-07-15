//! Concrete [`CollaborativeMessageSet`](crate::CollaborativeMessageSet) adapters for common dependencies.

#[cfg(feature = "reqwest")]
mod directory;
#[cfg(feature = "reqwest")]
mod request_sender;
#[cfg(feature = "reqwest")]
pub use directory::{DirectoryMailbox, DirectoryMailboxError};
#[cfg(feature = "reqwest")]
pub use request_sender::ReqwestSender;
