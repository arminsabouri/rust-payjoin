//! Helpers for unit tests that simulate Payjoin Directory OHTTP round-trips locally.

use http::StatusCode;
use ohttp::KeyConfig;
use payjoin::directory::ENCAPSULATED_MESSAGE_BYTES;

/// OHTTP relay URL used in multiparty unit tests (not contacted; only parsed into requests).
pub const OHTTP_RELAY: &str = "http://127.0.0.1:8080";

/// Fixed-size OHTTP request/response body for the Payjoin Directory.
pub type EncapsulatedDirectoryMessage = [u8; ENCAPSULATED_MESSAGE_BYTES];

const BHTTP_RES_BYTES: usize = ENCAPSULATED_MESSAGE_BYTES - (32 + 16);

/// OHTTP key config matching [`crate::KEM`] and [`crate::SYMMETRIC`].
pub fn test_ohttp_key_config() -> KeyConfig {
    KeyConfig::new(crate::KEY_ID, crate::KEM, Vec::from(crate::SYMMETRIC))
        .expect("valid OHTTP key config")
}

/// Decapsulate a directory OHTTP request, build a BHTTP response, and re-encapsulate it.
pub fn simulate_directory_response(
    key_config: &KeyConfig,
    encapsulated_req: &EncapsulatedDirectoryMessage,
    status: StatusCode,
    response_body: &[u8],
) -> Vec<u8> {
    let server = ohttp::Server::new(key_config.clone()).expect("OHTTP server");
    let (_bhttp_req, server_ctx) =
        server.decapsulate(encapsulated_req).expect("directory should decapsulate request");

    let mut bhttp_res = bhttp::Message::response(
        bhttp::StatusCode::try_from(status.as_u16()).expect("valid status"),
    );
    if !response_body.is_empty() {
        bhttp_res.write_content(response_body);
    }
    let mut bhttp_bytes = Vec::new();
    bhttp_res
        .write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes)
        .expect("bhttp encoding should succeed");
    bhttp_bytes.resize(BHTTP_RES_BYTES, 0);
    server_ctx.encapsulate(&bhttp_bytes).expect("directory should encapsulate response")
}
