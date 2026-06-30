use core::fmt;
use std::error;

use crate::hpke::HpkeError;
use crate::ohttp::{DirectoryResponseError, OhttpEncapsulationError};

/// Error that may occur during a multiparty session-creator typestate change.
#[derive(Debug)]
pub struct SessionCreatorSessionError(pub(super) InternalSessionCreatorSessionError);

impl From<InternalSessionCreatorSessionError> for SessionCreatorSessionError {
    fn from(value: InternalSessionCreatorSessionError) -> Self { SessionCreatorSessionError(value) }
}

#[derive(Debug)]
pub(crate) enum InternalSessionCreatorSessionError {
    ParseUrl(crate::into_url::Error),
    OhttpEncapsulation(OhttpEncapsulationError),
    Hpke(HpkeError),
    DirectoryResponse(DirectoryResponseError),
    UnknownParticipant,
    AlreadyDelivered,
}

impl From<crate::into_url::Error> for SessionCreatorSessionError {
    fn from(value: crate::into_url::Error) -> Self {
        SessionCreatorSessionError(InternalSessionCreatorSessionError::ParseUrl(value))
    }
}

impl From<OhttpEncapsulationError> for SessionCreatorSessionError {
    fn from(value: OhttpEncapsulationError) -> Self {
        SessionCreatorSessionError(InternalSessionCreatorSessionError::OhttpEncapsulation(value))
    }
}

impl fmt::Display for SessionCreatorSessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalSessionCreatorSessionError::*;

        match &self.0 {
            ParseUrl(e) => write!(f, "URL parsing failed: {e}"),
            OhttpEncapsulation(e) => write!(f, "OHTTP encapsulation error: {e}"),
            Hpke(e) => write!(f, "HPKE encryption failed: {e}"),
            DirectoryResponse(e) => write!(f, "directory response error: {e}"),
            UnknownParticipant => write!(f, "unknown session participant"),
            AlreadyDelivered => write!(f, "session parameters already delivered to participant"),
        }
    }
}

impl error::Error for SessionCreatorSessionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use InternalSessionCreatorSessionError::*;

        match &self.0 {
            ParseUrl(e) => Some(e),
            OhttpEncapsulation(e) => Some(e),
            Hpke(e) => Some(e),
            DirectoryResponse(e) => Some(e),
            UnknownParticipant | AlreadyDelivered => None,
        }
    }
}
