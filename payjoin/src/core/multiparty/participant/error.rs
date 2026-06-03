use core::fmt;
use std::error;

use crate::hpke::HpkeError;
use crate::multiparty::SessionParametersError;
use crate::ohttp::{DirectoryResponseError, OhttpEncapsulationError};

/// Errors from shared multiparty participant operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParticipantError {
    ParseUrl(crate::into_url::Error),
    OhttpEncapsulation(OhttpEncapsulationError),
    Hpke(HpkeError),
    DirectoryResponse(DirectoryResponseError),
    SessionParameters(SessionParametersError),
}

/// Alias for typestate transition APIs ([`crate::persist::MaybeFatalTransitionWithNoResults`]).
pub type ParticipantSessionError = ParticipantError;

impl From<crate::into_url::Error> for ParticipantError {
    fn from(value: crate::into_url::Error) -> Self { Self::ParseUrl(value) }
}

impl From<OhttpEncapsulationError> for ParticipantError {
    fn from(value: OhttpEncapsulationError) -> Self { Self::OhttpEncapsulation(value) }
}

impl From<HpkeError> for ParticipantError {
    fn from(value: HpkeError) -> Self { Self::Hpke(value) }
}

impl From<DirectoryResponseError> for ParticipantError {
    fn from(value: DirectoryResponseError) -> Self { Self::DirectoryResponse(value) }
}

impl From<SessionParametersError> for ParticipantError {
    fn from(value: SessionParametersError) -> Self { Self::SessionParameters(value) }
}

impl fmt::Display for ParticipantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseUrl(e) => write!(f, "URL parsing failed: {e}"),
            Self::OhttpEncapsulation(e) => write!(f, "OHTTP encapsulation error: {e}"),
            Self::Hpke(e) => write!(f, "HPKE encryption failed: {e}"),
            Self::DirectoryResponse(e) => write!(f, "directory response error: {e}"),
            Self::SessionParameters(e) => write!(f, "session parameters error: {e}"),
        }
    }
}

impl error::Error for ParticipantError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::ParseUrl(e) => Some(e),
            Self::OhttpEncapsulation(e) => Some(e),
            Self::Hpke(e) => Some(e),
            Self::DirectoryResponse(e) => Some(e),
            Self::SessionParameters(e) => Some(e),
        }
    }
}
