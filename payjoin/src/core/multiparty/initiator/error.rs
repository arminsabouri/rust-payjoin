use core::fmt;
use std::error;

use crate::hpke::HpkeError;
use crate::ohttp::{DirectoryResponseError, OhttpEncapsulationError};

/// Errors from multiparty initiator operations (request creation and typestate transitions).
#[derive(Debug)]
#[non_exhaustive]
pub enum InitiatorError {
    ParseUrl(crate::into_url::Error),
    OhttpEncapsulation(OhttpEncapsulationError),
    Hpke(HpkeError),
    DirectoryResponse(DirectoryResponseError),
}

/// Alias for typestate transition APIs ([`crate::persist::MaybeFatalTransitionWithNoResults`]).
pub type InitiatorSessionError = InitiatorError;

impl From<crate::into_url::Error> for InitiatorError {
    fn from(value: crate::into_url::Error) -> Self { Self::ParseUrl(value) }
}

impl From<OhttpEncapsulationError> for InitiatorError {
    fn from(value: OhttpEncapsulationError) -> Self { Self::OhttpEncapsulation(value) }
}

impl From<HpkeError> for InitiatorError {
    fn from(value: HpkeError) -> Self { Self::Hpke(value) }
}

impl From<DirectoryResponseError> for InitiatorError {
    fn from(value: DirectoryResponseError) -> Self { Self::DirectoryResponse(value) }
}

impl fmt::Display for InitiatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseUrl(e) => write!(f, "URL parsing failed: {e}"),
            Self::OhttpEncapsulation(e) => write!(f, "OHTTP encapsulation error: {e}"),
            Self::Hpke(e) => write!(f, "HPKE decryption failed: {e}"),
            Self::DirectoryResponse(e) => write!(f, "directory response error: {e}"),
        }
    }
}

impl error::Error for InitiatorError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::ParseUrl(e) => Some(e),
            Self::OhttpEncapsulation(e) => Some(e),
            Self::Hpke(e) => Some(e),
            Self::DirectoryResponse(e) => Some(e),
        }
    }
}
