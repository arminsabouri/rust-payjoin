//! Concrete [`CollaborativeMessageSet`](crate::CollaborativeMessageSet) adapters for common dependencies.

#[cfg(feature = "reqwest")]
mod directory;
#[cfg(feature = "reqwest")]
pub use directory::{DirectoryMailbox, DirectoryMailboxError};
