//! Multiparty session parameters broadcast by the session creator.
//!
//! See [honest protocol session parameters](https://github.com/payjoin/multiparty-protocol-docs/blob/main/honest.md#session-parameters).
//! Participants verify the final transaction against these values before signing.
//!
//! Wire format (version 0):
//! - magic `mpp0` (4 bytes)
//! - version `0` (1 byte)
//! - `tx_version` (i32 LE)
//! - `lock_time` (u32 LE, Bitcoin locktime consensus encoding)
//! - `min_fee_rate_sat_per_vb` (u64 LE)
//! - `input_sequence` (u32 LE)
//! - `allowed_input_types` (u8 length, then u8 discriminants)
//! - `session_expiry`: `0` = absent, `1` + u32 LE unix time = present (`T_session`)
//! - `session_secret` (32 bytes): shared Payjoin Directory mailbox namespace for all
//!   participants (`linked_mailbox`: `H("v0-PayjoinDirectoryEntry" || secret || i)`)

use std::fmt;

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{FeeRate, Sequence};
use hpke::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Length of [`SessionParameters::session_secret`] in bytes (256 bits).
pub const SESSION_SECRET_LEN: usize = 32;

const MAGIC: &[u8; 4] = b"mpp0";
const VERSION: u8 = 0;
const MAX_ALLOWED_INPUT_TYPES: usize = 5;

/// Script categories permitted for inputs in the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum InputScriptType {
    P2pkh = 0,
    P2sh = 1,
    P2wpkh = 2,
    P2wsh = 3,
    P2tr = 4,
}

impl InputScriptType {
    fn from_discriminant(byte: u8) -> Result<Self, SessionParametersError> {
        Ok(match byte {
            0 => Self::P2pkh,
            1 => Self::P2sh,
            2 => Self::P2wpkh,
            3 => Self::P2wsh,
            4 => Self::P2tr,
            _ => return Err(SessionParametersError::UnknownInputType(byte)),
        })
    }

    fn discriminant(self) -> u8 {
        match self {
            Self::P2pkh => 0,
            Self::P2sh => 1,
            Self::P2wpkh => 2,
            Self::P2wsh => 3,
            Self::P2tr => 4,
        }
    }
}

/// Parameters fixed by the session creator before the multiparty session opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionParameters {
    /// Global `nVersion` for the collaborative transaction.
    tx_version: Version,
    /// Global `nLockTime` (block height or unix time).
    lock_time: LockTime,
    /// Minimum feerate each participant must meet for their contributed weight (sat/vB).
    min_feerate: FeeRate,
    /// Required `nSequence` on contributed inputs.
    input_sequence: Sequence,
    /// Allowed input script categories.
    allowed_input_types: Vec<InputScriptType>,
    /// Optional session expiration (`T_session`), as a UNIX timestamp.
    session_expiry: Option<u32>,
    /// Shared secret for the collaborative directory mailbox chain (CSPRNG, 32 bytes).
    session_secret: [u8; SESSION_SECRET_LEN],
}

/// Draw a new session secret suitable for [`SessionParameters::session_secret`].
pub fn generate_session_secret() -> [u8; SESSION_SECRET_LEN] {
    let mut secret = [0u8; SESSION_SECRET_LEN];
    OsRng.fill_bytes(&mut secret);
    secret
}

impl SessionParameters {
    pub fn new(
        tx_version: Version,
        lock_time: LockTime,
        min_feerate: FeeRate,
        input_sequence: Sequence,
        allowed_input_types: Vec<InputScriptType>,
        session_expiry: Option<u32>,
    ) -> Self {
        Self {
            tx_version,
            lock_time,
            min_feerate,
            input_sequence,
            allowed_input_types,
            session_expiry,
            session_secret: generate_session_secret(),
        }
    }
    /// Serialize to the version-0 wire encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            4 + 1 + 4 + 4 + 8 + 4 + 1 + self.allowed_input_types.len() + 5 + SESSION_SECRET_LEN,
        );
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.tx_version.0.to_le_bytes());
        out.extend_from_slice(&self.lock_time.to_consensus_u32().to_le_bytes());
        out.extend_from_slice(&self.min_feerate.to_sat_per_vb_floor().to_le_bytes());
        out.extend_from_slice(&self.input_sequence.to_consensus_u32().to_le_bytes());
        let len = u8::try_from(self.allowed_input_types.len())
            .expect("allowed_input_types length checked at construction");
        out.push(len);
        for ty in &self.allowed_input_types {
            out.push(ty.discriminant());
        }
        match self.session_expiry {
            None => out.push(0),
            Some(expiry) => {
                out.push(1);
                out.extend_from_slice(&expiry.to_le_bytes());
            }
        }
        out.extend_from_slice(&self.session_secret);
        out
    }

    /// Deserialize from the version-0 wire encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SessionParametersError> {
        let mut cursor = bytes;
        let header = take_fixed::<4>(&mut cursor)?;
        if header != *MAGIC {
            return Err(SessionParametersError::InvalidMagic);
        }
        let version = take_u8(&mut cursor)?;
        if version != VERSION {
            return Err(SessionParametersError::UnsupportedVersion(version));
        }

        let tx_version = Version(i32::from_le_bytes(take_fixed(&mut cursor)?));
        let lock_time = LockTime::from_consensus(u32::from_le_bytes(take_fixed(&mut cursor)?));
        let min_feerate_sat_per_vb = u64::from_le_bytes(take_fixed(&mut cursor)?);
        if min_feerate_sat_per_vb == 0 {
            return Err(SessionParametersError::InvalidFeeRate);
        }
        let min_feerate = FeeRate::from_sat_per_vb(min_feerate_sat_per_vb)
            .ok_or(SessionParametersError::InvalidFeeRate)?;
        let input_sequence = Sequence::from_consensus(u32::from_le_bytes(take_fixed(&mut cursor)?));

        let count = take_u8(&mut cursor)? as usize;
        if count == 0 {
            return Err(SessionParametersError::EmptyAllowedInputTypes);
        }
        if count > MAX_ALLOWED_INPUT_TYPES {
            return Err(SessionParametersError::TooManyAllowedInputTypes(count));
        }
        let mut allowed_input_types = Vec::with_capacity(count);
        for _ in 0..count {
            allowed_input_types.push(InputScriptType::from_discriminant(take_u8(&mut cursor)?)?);
        }
        ensure_unique_input_types(&allowed_input_types)?;

        let session_expiry = match take_u8(&mut cursor)? {
            0 => None,
            1 => Some(u32::from_le_bytes(take_fixed(&mut cursor)?)),
            flag => return Err(SessionParametersError::InvalidSessionExpiryFlag(flag)),
        };

        let session_secret = take_fixed::<SESSION_SECRET_LEN>(&mut cursor)?;
        if session_secret == [0u8; SESSION_SECRET_LEN] {
            return Err(SessionParametersError::InvalidSessionSecret);
        }

        if !cursor.is_empty() {
            return Err(SessionParametersError::TrailingBytes(cursor.len()));
        }

        Ok(Self {
            tx_version,
            lock_time,
            min_feerate,
            input_sequence,
            allowed_input_types,
            session_expiry,
            session_secret,
        })
    }

    /// Deserialize session parameters from a message-A plaintext body (zero-padded to
    /// [`crate::hpke::PADDED_PLAINTEXT_A_LENGTH`]).
    pub fn from_message_a_body(bytes: &[u8]) -> Result<Self, SessionParametersError> {
        match Self::from_bytes(bytes) {
            Ok(params) => Ok(params),
            Err(SessionParametersError::TrailingBytes(trailing)) => {
                let encoded_len = bytes
                    .len()
                    .checked_sub(trailing)
                    .ok_or(SessionParametersError::TrailingBytes(trailing))?;
                if bytes[encoded_len..].iter().all(|byte| *byte == 0) {
                    Self::from_bytes(&bytes[..encoded_len])
                } else {
                    Err(SessionParametersError::TrailingBytes(trailing))
                }
            }
            Err(err) => Err(err),
        }
    }
}

fn ensure_unique_input_types(types: &[InputScriptType]) -> Result<(), SessionParametersError> {
    for (i, a) in types.iter().enumerate() {
        if types[i + 1..].contains(a) {
            return Err(SessionParametersError::DuplicateInputType(*a));
        }
    }
    Ok(())
}

fn take_u8(cursor: &mut &[u8]) -> Result<u8, SessionParametersError> {
    if cursor.is_empty() {
        return Err(SessionParametersError::Truncated);
    }
    let byte = cursor[0];
    *cursor = &cursor[1..];
    Ok(byte)
}

fn take_fixed<const N: usize>(cursor: &mut &[u8]) -> Result<[u8; N], SessionParametersError> {
    if cursor.len() < N {
        return Err(SessionParametersError::Truncated);
    }
    let (head, tail) = cursor.split_at(N);
    *cursor = tail;
    head.try_into().map_err(|_| SessionParametersError::Truncated)
}

/// Errors when parsing session parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionParametersError {
    InvalidMagic,
    UnsupportedVersion(u8),
    Truncated,
    TrailingBytes(usize),
    InvalidFeeRate,
    EmptyAllowedInputTypes,
    TooManyAllowedInputTypes(usize),
    UnknownInputType(u8),
    DuplicateInputType(InputScriptType),
    InvalidSessionExpiryFlag(u8),
    InvalidSessionSecret,
}

impl fmt::Display for SessionParametersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid session parameters magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported session parameters version {v}"),
            Self::Truncated => write!(f, "truncated session parameters"),
            Self::TrailingBytes(n) => write!(f, "trailing bytes ({n})"),
            Self::InvalidFeeRate => write!(f, "invalid minimum feerate"),
            Self::EmptyAllowedInputTypes => write!(f, "allowed input types must not be empty"),
            Self::TooManyAllowedInputTypes(n) => write!(f, "too many allowed input types ({n})"),
            Self::UnknownInputType(b) => write!(f, "unknown input script type {b}"),
            Self::DuplicateInputType(t) => write!(f, "duplicate allowed input type {t:?}"),
            Self::InvalidSessionExpiryFlag(b) => write!(f, "invalid session expiry flag {b}"),
            Self::InvalidSessionSecret =>
                write!(f, "session secret must be 32 non-zero random bytes"),
        }
    }
}

impl std::error::Error for SessionParametersError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_session_secret() -> [u8; SESSION_SECRET_LEN] { [0x42u8; SESSION_SECRET_LEN] }

    fn sample_params() -> SessionParameters {
        SessionParameters {
            tx_version: Version::TWO,
            lock_time: LockTime::from_height(850_000).expect("valid height locktime"),
            min_feerate: FeeRate::from_sat_per_vb(2).expect("valid feerate"),
            input_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            allowed_input_types: vec![InputScriptType::P2wpkh, InputScriptType::P2tr],
            session_expiry: Some(1_800_000_000),
            session_secret: sample_session_secret(),
        }
    }

    #[test]
    fn round_trip_with_session_expiry() {
        let params = sample_params();
        let bytes = params.to_bytes();
        let parsed = SessionParameters::from_bytes(&bytes).expect("deserialize");
        assert_eq!(parsed, params);
    }

    #[test]
    fn round_trip_without_session_expiry() {
        let mut params = sample_params();
        params.session_expiry = None;
        let parsed = SessionParameters::from_bytes(&params.to_bytes()).expect("deserialize");
        assert_eq!(parsed, params);
    }

    #[test]
    fn round_trip_lock_time_seconds() {
        let params = SessionParameters {
            lock_time: LockTime::from_time(1_700_000_000).expect("valid time locktime"),
            ..sample_params()
        };
        assert_eq!(SessionParameters::from_bytes(&params.to_bytes()).expect("deserialize"), params);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut bytes = sample_params().to_bytes();
        bytes[0] ^= 1;
        assert_eq!(
            SessionParameters::from_bytes(&bytes),
            Err(SessionParametersError::InvalidMagic)
        );
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = sample_params().to_bytes();
        bytes[4] = 99;
        assert_eq!(
            SessionParameters::from_bytes(&bytes),
            Err(SessionParametersError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn rejects_empty_allowed_input_types() {
        let mut bytes = sample_params().to_bytes();
        bytes[25] = 0;
        assert_eq!(
            SessionParameters::from_bytes(&bytes),
            Err(SessionParametersError::EmptyAllowedInputTypes)
        );
    }

    #[test]
    fn rejects_duplicate_allowed_input_types() {
        let params = SessionParameters {
            allowed_input_types: vec![InputScriptType::P2wpkh, InputScriptType::P2wpkh],
            ..sample_params()
        };
        assert_eq!(
            SessionParameters::from_bytes(&params.to_bytes()),
            Err(SessionParametersError::DuplicateInputType(InputScriptType::P2wpkh))
        );
    }

    #[test]
    fn rejects_unknown_input_type() {
        let mut bytes = sample_params().to_bytes();
        // first allowed type discriminant
        bytes[26] = 255;
        assert_eq!(
            SessionParameters::from_bytes(&bytes),
            Err(SessionParametersError::UnknownInputType(255))
        );
    }

    #[test]
    fn rejects_all_zero_session_secret() {
        let mut params = sample_params();
        params.session_secret = [0u8; SESSION_SECRET_LEN];
        assert_eq!(
            SessionParameters::from_bytes(&params.to_bytes()),
            Err(SessionParametersError::InvalidSessionSecret)
        );
    }

    #[test]
    fn generate_session_secret_is_non_zero() {
        let secret = generate_session_secret();
        assert_ne!(secret, [0u8; SESSION_SECRET_LEN]);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample_params().to_bytes();
        bytes.push(0);
        assert_eq!(
            SessionParameters::from_bytes(&bytes),
            Err(SessionParametersError::TrailingBytes(1))
        );
    }

    #[test]
    fn rejects_invalid_feerate() {
        let mut bytes = sample_params().to_bytes();
        // zero sat/vb is invalid for FeeRate::from_sat_per_vb
        bytes[13..21].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            SessionParameters::from_bytes(&bytes),
            Err(SessionParametersError::InvalidFeeRate)
        );
    }

    #[test]
    fn wire_layout_is_stable() {
        let params = SessionParameters {
            tx_version: Version::TWO,
            lock_time: LockTime::ZERO,
            min_feerate: FeeRate::from_sat_per_vb(1).expect("valid feerate"),
            input_sequence: Sequence(0xffff_ffff),
            allowed_input_types: vec![InputScriptType::P2pkh],
            session_expiry: None,
            session_secret: sample_session_secret(),
        };
        let bytes = params.to_bytes();
        assert_eq!(&bytes[..5], b"mpp0\x00");
        assert_eq!(bytes[5..9], 2i32.to_le_bytes());
        assert_eq!(bytes[9..13], LockTime::ZERO.to_consensus_u32().to_le_bytes());
        assert_eq!(bytes[13..21], 1u64.to_le_bytes());
        assert_eq!(bytes[21..25], Sequence(0xffff_ffff).to_consensus_u32().to_le_bytes());
        assert_eq!(bytes[25..27], [1u8, InputScriptType::P2pkh.discriminant()]);
        assert_eq!(bytes[27], 0);
        assert_eq!(bytes[28..28 + SESSION_SECRET_LEN], sample_session_secret());
    }

    #[test]
    fn feerate_round_trip_preserves_floor_sat_per_vb() {
        let rate = FeeRate::from_sat_per_vb(3).expect("valid feerate");
        let params = SessionParameters { min_feerate: rate, ..sample_params() };
        let parsed = SessionParameters::from_bytes(&params.to_bytes()).expect("deserialize");
        assert_eq!(parsed.min_feerate.to_sat_per_vb_floor(), rate.to_sat_per_vb_floor());
    }
}
