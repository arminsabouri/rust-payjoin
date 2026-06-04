//! Multiparty session registry: many disjoint event logs, keyed by an opaque handle.
//!
//! Each multiparty role (initiator, responder, session creator, …) persists to its own
//! [`crate::persist::SessionPersister`]. A [`MultipartySessionRegistry`] tracks which logs
//! are still open and resolves a handle to the corresponding persister.

use core::fmt;
use std::error;

use crate::multiparty::session::MultipartySessionEvent;
use crate::persist::{InMemoryPersister, SessionPersister};

/// Index of many multiparty session persisters.
pub trait MultipartySessionRegistry {
    /// Registry-level errors (not per-log storage errors).
    type Error: error::Error + Send + Sync + 'static;
    /// Concrete persister type returned for a handle.
    type Persister: SessionPersister<SessionEvent = MultipartySessionEvent>;

    /// Handles for session logs that are not closed.
    fn list_open(&self) -> Result<Vec<&Self::Persister>, Self::Error>;
}

/// Errors from [`InMemoryMultipartyRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// No session is registered under this handle.
    NotFound(SessionId),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "multiparty session not found: {:?}", id),
        }
    }
}

impl error::Error for RegistryError {}

/// Opaque identifier for one persisted multiparty session log.
///
/// The registry assigns handles; the library does not embed protocol semantics in the id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

/// In-memory registry for tests and prototyping.
///
/// Use [`InMemoryMultipartyRegistry::create_session`] to register a new empty log, then pass
/// the returned [`SessionId`] into transition `.save(&registry.persister(&id)?)` flows.
// TODO: move this to test-utils
#[derive(Default)]
pub struct InMemoryMultipartyRegistry {
    sessions: Vec<InMemoryPersister<MultipartySessionEvent>>,
}

impl InMemoryMultipartyRegistry {
    pub fn new() -> Self { Self::default() }

    /// Register a new open session and return its handle.
    pub fn create_session(&mut self) -> InMemoryPersister<MultipartySessionEvent> {
        let persister = InMemoryPersister::default();
        self.sessions.push(persister.clone());
        persister
    }
}

impl MultipartySessionRegistry for InMemoryMultipartyRegistry {
    type Error = RegistryError;
    type Persister = InMemoryPersister<MultipartySessionEvent>;

    fn list_open(&self) -> Result<Vec<&Self::Persister>, Self::Error> {
        Ok(self
            .sessions
            .iter()
            .filter(|persister| !persister.inner.read().unwrap().is_closed)
            .collect())
    }
}
