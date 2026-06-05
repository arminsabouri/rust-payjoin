//! Multiparty session registry for a coordinator wallet (initiator / session creator).
//!
//! Each protocol session has its own [`crate::persist::SessionPersister`] event log (one log per
//! initiator bootstrap, per responder bootstrap, per creator distribution, …). Only the
//! coordinator needs a [`MultipartySessionRegistry`]: it registers handles for every log it
//! orchestrates (including responders' logs in tests and integrated apps) and uses
//! [`crate::multiparty::collect_open_sessions_awaiting_parameters`] to find participants ready
//! for session parameters.

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

    /// Create new session
    /// TODO: do we want to link the previous session wiht the new one?
    /// TODO: does not need to be mut. Use interior mutability for the inmemory registry.
    fn new_session(&mut self) -> Result<Self::Persister, Self::Error>;
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
    fn create_session(&mut self) -> InMemoryPersister<MultipartySessionEvent> {
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

    fn new_session(&mut self) -> Result<Self::Persister, Self::Error> { Ok(self.create_session()) }
}
