//! A [`RequestSender`] backed by `reqwest`.

use payjoin::Request;
use reqwest::Client;

use crate::request_sender::RequestSender;

/// Performs the raw HTTP round-trip for a pre-encapsulated [`Request`].
///
/// This is the single HTTP send path in the crate; [`DirectoryMailbox`](super::DirectoryMailbox)
/// routes its posts through it as well.
#[derive(Clone)]
pub struct ReqwestSender {
    client: Client,
}

impl ReqwestSender {
    /// Wrap a `reqwest` client.
    pub fn new(client: Client) -> Self { Self { client } }
}

impl RequestSender for ReqwestSender {
    type Error = reqwest::Error;

    async fn send(&self, request: Request) -> Result<Vec<u8>, Self::Error> {
        let response = self
            .client
            .post(request.url)
            .header("Content-Type", request.content_type)
            .body(request.body)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.bytes().await?.to_vec())
    }
}
