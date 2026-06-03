//! Shared helpers for multiparty unit tests.

use http::StatusCode;
pub use payjoin_test_utils::EncapsulatedDirectoryMessage;
use payjoin_test_utils::{
    simulate_directory_response as simulate_directory_response_for_config, test_ohttp_key_config,
};

use crate::OhttpKeys;

/// OHTTP keys for multiparty unit tests.
pub fn test_ohttp_keys() -> OhttpKeys { OhttpKeys(test_ohttp_key_config()) }

/// Decapsulate a directory OHTTP request and return an encapsulated response.
#[allow(unused)]
pub fn simulate_directory_response(
    ohttp_keys: &OhttpKeys,
    encapsulated_req: &EncapsulatedDirectoryMessage,
    status: StatusCode,
    response_body: &[u8],
) -> Vec<u8> {
    simulate_directory_response_for_config(&ohttp_keys.0, encapsulated_req, status, response_body)
}
