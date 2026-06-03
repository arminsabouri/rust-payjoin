//! BIP-321 Payjoin URIs for multiparty initiators
//!
//! Multiparty initiators have no on-chain payment target. [BIP-321] allows an empty
//! `bitcoin:` path when other payment instructions are present. We use
//! [`bitcoin_uri_composer`] for parsing; serialization includes `pj` and `mppj`
//! because `Bip321::build` in v0.1.0 does not emit custom extras.
//!
//! [BIP-321]: https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki

use std::borrow::Cow;
use std::fmt;

use bitcoin::Network;
use bitcoin_uri_composer::{Bip321, Bip321Errors, Bip321ExtraHandle};
use percent_encoding_rfc3986::{utf8_percent_encode, NON_ALPHANUMERIC};

use crate::uri::{PjParam, PjParseError};

/// A multiparty Payjoin URI with no `bitcoin:` address (BIP-321).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartyPjUri {
    pj_param: PjParam,
    uri: String,
}

impl MultipartyPjUri {
    pub fn as_str(&self) -> &str { &self.uri }

    pub fn pj_param(&self) -> &PjParam { &self.pj_param }

    /// Parse a BIP-321 URI containing `pj` and `mppj=1`.
    pub fn parse(s: &str) -> Result<Self, MultipartyUriError> {
        let parsed =
            Bip321::<PayjoinBip321Extras>::parse_url(s).map_err(MultipartyUriError::composer)?;
        if parsed.address.is_some() {
            return Err(MultipartyUriError::UnexpectedAddress);
        }
        let extras = parsed.extras.ok_or(MultipartyUriError::MissingPj)?;
        if extras.bad_mppj {
            return Err(MultipartyUriError::BadMppj);
        }
        if !extras.mppj {
            return Err(MultipartyUriError::MissingMppj);
        }
        let pj = extras.pj.ok_or(MultipartyUriError::MissingPj)?;
        let pj_param = PjParam::parse(&pj).map_err(MultipartyUriError::Pj)?;
        Ok(Self { pj_param, uri: s.to_string() })
    }

    /// Re-parse and run BIP-321 network checks (no-op when address is absent).
    pub fn into_network_checked(self, network: Network) -> Result<Self, MultipartyUriError> {
        let parsed = Bip321::<PayjoinBip321Extras>::parse_url(&self.uri)
            .map_err(MultipartyUriError::composer)?;
        parsed.into_checked(network).map_err(MultipartyUriError::composer)?;
        Ok(self)
    }
}

impl fmt::Display for MultipartyPjUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.uri) }
}

/// Build a BIP-321 multiparty Payjoin URI (`bitcoin:?pj=…&mppj=1`).
pub fn build_multiparty_pj_uri(pj_param: &PjParam) -> MultipartyPjUri {
    let pj = pj_param.to_string();
    let encoded = utf8_percent_encode(pj.as_str(), NON_ALPHANUMERIC).to_string();
    let uri = format!("bitcoin:?pj={encoded}&mppj=1");
    MultipartyPjUri { pj_param: pj_param.clone(), uri }
}

#[derive(Debug, Clone, Default)]
struct PayjoinBip321Extras {
    pj: Option<String>,
    mppj: bool,
    bad_mppj: bool,
}

impl<'a> Bip321ExtraHandle<'a> for PayjoinBip321Extras {
    fn handle_param(
        &mut self,
        key: &'a str,
        values: Vec<Cow<'a, str>>,
    ) -> Result<(), Bip321Errors<'a>> {
        match key {
            "pj" => {
                if self.pj.is_some() || values.len() > 1 {
                    return Err(Bip321Errors::DuplicateParam("pj"));
                }
                if let Some(val) = values.into_iter().next() {
                    self.pj = Some(val.into_owned());
                }
                Ok(())
            }
            "mppj" => {
                if self.mppj || self.bad_mppj || values.len() > 1 {
                    return Err(Bip321Errors::DuplicateParam("mppj"));
                }
                match values.first().map(|v| v.as_ref()) {
                    Some("1") => self.mppj = true,
                    Some(_) => self.bad_mppj = true,
                    None => {}
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn is_empty(&self) -> bool { self.pj.is_none() && !self.mppj && !self.bad_mppj }

    fn is_supported_key(&self, key: &str) -> bool { matches!(key, "pj" | "mppj") }
}

/// Errors when parsing or building multiparty BIP-321 Payjoin URIs.
#[derive(Debug)]
pub enum MultipartyUriError {
    Composer(&'static str),
    UnexpectedAddress,
    MissingPj,
    MissingMppj,
    BadMppj,
    Pj(PjParseError),
}

impl MultipartyUriError {
    fn composer(e: Bip321Errors<'_>) -> Self {
        Self::Composer(match e {
            Bip321Errors::DuplicateParam(_) => "duplicate query parameter",
            Bip321Errors::IncorrectSchema => "incorrect bitcoin: URI scheme",
            Bip321Errors::InvalidAddress(_) => "invalid address",
            Bip321Errors::InvalidAmount => "invalid amount",
            Bip321Errors::NoOnePaymentWasFound => "URI has no payment instructions",
            Bip321Errors::InvalidEncoding => "invalid percent-encoding",
            Bip321Errors::InvalidRequiredPayment => "unsupported required parameter",
        })
    }
}

impl fmt::Display for MultipartyUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Composer(msg) => write!(f, "BIP-321 URI error: {msg}"),
            Self::UnexpectedAddress => {
                write!(f, "multiparty URI must not include a bitcoin address")
            }
            Self::MissingPj => write!(f, "missing pj parameter"),
            Self::MissingMppj => write!(f, "missing mppj=1 parameter"),
            Self::BadMppj => write!(f, "mppj must be 1"),
            Self::Pj(e) => write!(f, "invalid pj parameter: {e}"),
        }
    }
}

impl std::error::Error for MultipartyUriError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pj(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use payjoin_test_utils::EXAMPLE_URL;

    use super::*;
    use crate::hpke::HpkeKeyPair;
    use crate::multiparty::test_helpers::test_ohttp_keys;
    use crate::time::Time;
    use crate::uri::v2::PjParam as V2PjParam;
    use crate::Url;

    fn sample_v2_pj_param() -> PjParam {
        let directory = Url::from_str(EXAMPLE_URL).expect("valid directory URL");
        let expiration =
            Time::from_now(std::time::Duration::from_secs(60 * 60 * 24)).expect("valid expiration");
        PjParam::V2(V2PjParam::new(
            directory,
            crate::uri::ShortId([0xab; 8]),
            expiration,
            test_ohttp_keys(),
            HpkeKeyPair::gen_keypair().1,
        ))
    }

    #[test]
    fn build_and_parse_addressless_uri() {
        let pj_param = sample_v2_pj_param();
        let built = build_multiparty_pj_uri(&pj_param);
        assert!(built.as_str().starts_with("bitcoin:?"));
        assert!(!built.as_str().contains("tb1"));
        assert!(built.as_str().contains("mppj=1"));

        let parsed = MultipartyPjUri::parse(built.as_str()).expect("round-trip parse");
        assert_eq!(
            parsed.pj_param().endpoint().to_ascii_lowercase(),
            built.pj_param().endpoint().to_ascii_lowercase(),
        );
    }

    #[test]
    fn rejects_uri_with_address() {
        let built = build_multiparty_pj_uri(&sample_v2_pj_param());
        let with_addr = built.as_str().replacen(
            "bitcoin:?",
            "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4?",
            1,
        );
        assert!(matches!(
            MultipartyPjUri::parse(&with_addr),
            Err(MultipartyUriError::UnexpectedAddress)
        ));
    }

    #[test]
    fn rejects_missing_mppj() {
        let built = build_multiparty_pj_uri(&sample_v2_pj_param());
        let without_mppj = built.as_str().replace("&mppj=1", "");
        assert!(matches!(
            MultipartyPjUri::parse(&without_mppj),
            Err(MultipartyUriError::MissingMppj)
        ));
    }

    #[test]
    fn rejects_bad_mppj() {
        let err = MultipartyPjUri::parse("bitcoin:?pj=https://example.com/pj&mppj=0").unwrap_err();
        assert!(matches!(err, MultipartyUriError::BadMppj));
    }
}
