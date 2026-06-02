use core::fmt;
use std::error;

use crate::hpke::HpkeError;
use crate::ohttp::{DirectoryResponseError, OhttpEncapsulationError};

/// Errors from multiparty responder operations (request creation and typestate transitions).
#[derive(Debug)]
#[non_exhaustive]
pub enum ResponderError {
    ParseUrl(crate::into_url::Error),
    OhttpEncapsulation(OhttpEncapsulationError),
    Hpke(HpkeError),
    DirectoryResponse(DirectoryResponseError),
    Expired,
    NotV2,
}

/// Alias for typestate transition APIs ([`crate::persist::MaybeFatalTransition`]).
pub type ResponderSessionError = ResponderError;

impl From<crate::into_url::Error> for ResponderError {
    fn from(value: crate::into_url::Error) -> Self { Self::ParseUrl(value) }
}

impl From<OhttpEncapsulationError> for ResponderError {
    fn from(value: OhttpEncapsulationError) -> Self { Self::OhttpEncapsulation(value) }
}

impl From<HpkeError> for ResponderError {
    fn from(value: HpkeError) -> Self { Self::Hpke(value) }
}

impl From<DirectoryResponseError> for ResponderError {
    fn from(value: DirectoryResponseError) -> Self { Self::DirectoryResponse(value) }
}

impl fmt::Display for ResponderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseUrl(e) => write!(f, "URL parsing failed: {e}"),
            Self::OhttpEncapsulation(e) => write!(f, "OHTTP encapsulation error: {e}"),
            Self::Hpke(e) => write!(f, "HPKE encryption failed: {e}"),
            Self::DirectoryResponse(e) => write!(f, "directory response error: {e}"),
            Self::Expired => write!(f, "Payjoin URI expired"),
            Self::NotV2 => write!(f, "multiparty responder requires a v2 pj parameter"),
        }
    }
}

impl error::Error for ResponderError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::ParseUrl(e) => Some(e),
            Self::OhttpEncapsulation(e) => Some(e),
            Self::Hpke(e) => Some(e),
            Self::DirectoryResponse(e) => Some(e),
            Self::Expired | Self::NotV2 => None,
        }
    }
}
