use std::error::Error as StdError;
use std::fmt;

use payjoin::error::ReplayError;
use payjoin::multiparty::{MultipartySession, MultipartySessionEvent};

/// Error from a participant driver.
#[derive(Debug)]
pub enum DriverError {
    /// Replaying the event log failed.
    Replay(ReplayError<MultipartySession, MultipartySessionEvent>),
    /// The shared mailbox failed to read or write.
    Mailbox(Box<dyn StdError + Send + Sync>),
    /// The action schedule's timer/clock failed.
    Schedule(Box<dyn StdError + Send + Sync>),
    /// The signer failed to sign the accumulated PSBT.
    Sign(Box<dyn StdError + Send + Sync>),
    /// The broadcaster failed to relay the finalized transaction.
    Broadcast(Box<dyn StdError + Send + Sync>),
    /// Persisting a state transition failed, or the protocol reached a fatal state.
    Persist(String),
    /// The replayed session was not in a state this driver can advance.
    UnexpectedState,
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replay(e) => write!(f, "replay error: {e}"),
            Self::Mailbox(e) => write!(f, "mailbox error: {e}"),
            Self::Schedule(e) => write!(f, "schedule error: {e}"),
            Self::Sign(e) => write!(f, "signer error: {e}"),
            Self::Broadcast(e) => write!(f, "broadcaster error: {e}"),
            Self::Persist(e) => write!(f, "persistence error: {e}"),
            Self::UnexpectedState =>
                write!(f, "session is not in a state the participant driver can advance"),
        }
    }
}

impl StdError for DriverError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Replay(e) => Some(e),
            Self::Mailbox(e) | Self::Schedule(e) | Self::Sign(e) | Self::Broadcast(e) =>
                Some(e.as_ref()),
            Self::Persist(_) | Self::UnexpectedState => None,
        }
    }
}

impl From<ReplayError<MultipartySession, MultipartySessionEvent>> for DriverError {
    fn from(e: ReplayError<MultipartySession, MultipartySessionEvent>) -> Self { Self::Replay(e) }
}
