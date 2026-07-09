//! Driver loops for payjoin session state machines.
//!
//! The `payjoin` crate exposes pure, loop-free protocol state machines: they
//! take plaintext messages read from a shared mailbox, return state-transition
//! objects to persist, and tell you the next message to write. This crate
//! provides the *drivers* that run those state machines against real
//! dependencies.
//!
//! Dependencies are thin traits so the drivers stay composable and portable:
//!
//! - [`CollaborativeMessageSet`] is an append-only broadcast channel (mirroring
//!   `payjoin`'s trait of the same shape). Its implementation owns all
//!   transport and crypto — OHTTP, HPKE, directory addressing — so none of that
//!   lives in the state machine. Use the bundled [`adapters::DirectoryMailbox`]
//!   (feature `reqwest`) or supply your own.
//! - Persistence uses [`payjoin::persist::SessionPersister`] directly; any
//!   persister (including [`payjoin::persist::InMemoryPersister`]) works.
//!
//! The traits carry no `Send` bound, so the drivers run on single-threaded
//! executors (WASM) as well as multithreaded ones.

pub mod adapters;
pub mod broadcaster;
mod error;
mod mailbox;
pub mod participant;
pub mod schedule;
pub mod signer;

pub use broadcaster::Broadcaster;
pub use error::DriverError;
pub use mailbox::CollaborativeMessageSet;
pub use schedule::Schedule;
pub use signer::Signer;
