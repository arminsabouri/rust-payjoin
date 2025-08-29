use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::{Method, Request};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use nostr::event::{Event, EventBuilder, Kind, Tag};
use nostr::filter::{Filter, SingleLetterTag};
use nostr::key::Keys;
use nostr::message::{ClientMessage, SubscriptionId};
use nostr::util::{hex, JsonUtil};

use super::Error;

struct NostrClient {}

impl NostrClient {
    async fn send_event(event: Event) -> Result<(), NostrBackendError> {
        let http = HttpConnector::new();
        let client: Client<HttpConnector, String> =
            Client::builder(TokioExecutor::new()).build(http);
        let client_message = ClientMessage::Event(Cow::Borrowed(&event)).as_json();
        let req = Request::builder()
            .method(Method::POST)
            .uri("http://127.0.0.1:8080/rest")
            .body(client_message)
            .unwrap();

        let resp = client.request(req).await.unwrap();
        println!("RESPONSE STATUS: {}", resp.status());
        Ok(())
    }

    async fn fetch_event(filter: Filter) -> Result<Option<Event>, NostrBackendError> {
        let http = HttpConnector::new();
        let client: Client<HttpConnector, String> =
            Client::builder(TokioExecutor::new()).build(http);
        let subscription_id = SubscriptionId::generate();
        let client_message = ClientMessage::Req {
            subscription_id: Cow::Borrowed(&subscription_id),
            filter: Cow::Borrowed(&filter),
        }
        .as_json();

        // Construct GET request with body (non-standard but Hyper allows it)
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://127.0.0.1:8080/rest")
            .header("Content-Type", "application/json")
            .body(client_message)
            .unwrap();

        let resp = client.request(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        // Parse newline-delimited JSON events
        let s = String::from_utf8(body_bytes.to_vec()).unwrap();

        let mut events = s
            .split('\n')
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| Event::from_json(line).ok());

        Ok(events.next())
    }
}

#[derive(Clone)]
pub struct Db {
    key: nostr::key::Keys,
    timeout: Duration,
}

impl Db {
    pub async fn new() -> Self { Self { key: Keys::generate(), timeout: Duration::from_secs(5) } }

    async fn push_v2_nostr_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
        data: Vec<u8>,
    ) -> Result<(), NostrBackendError> {
        let hex_data = hex::encode(data);
        let tag = Tag::parse(vec!["h".to_string(), mailbox_id.to_string()]).unwrap();
        let event = EventBuilder::new(Kind::TextNote, hex_data)
            .tag(tag)
            .build(self.key.public_key())
            .sign(&self.key.clone())
            .await
            .map_err(NostrBackendError::EventError)?;
        NostrClient::send_event(event).await?;

        Ok(())
    }

    async fn read_v2_nostr_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
    ) -> Result<Vec<u8>, Error<NostrBackendError>> {
        // TODO: only assuming one event per h tag for now
        let filter = Filter::new()
            .kind(Kind::TextNote)
            .custom_tag(SingleLetterTag::from_str("h").unwrap(), mailbox_id.to_string());

        let fut = async {
            loop {
                let event = NostrClient::fetch_event(filter.clone()).await?;
                if let Some(event) = event {
                    return Ok::<_, NostrBackendError>(event.clone());
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        };

        let event = match tokio::time::timeout(self.timeout, fut).await {
            Ok(event) => Ok(event),
            Err(elapsed) => Err(super::Error::Timeout(elapsed)),
        }?
        .expect("sender should not be dropped");

        println!("EVENT: {:?}", event);
        let data = hex::decode(event.content.as_str()).map_err(NostrBackendError::HexError)?;

        Ok(data)
    }
}

impl super::Db for Db {
    type OperationalError = NostrBackendError;

    async fn post_v2_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
        data: Vec<u8>,
    ) -> Result<Option<()>, Error<Self::OperationalError>> {
        self.push_v2_nostr_payload(mailbox_id, data).await?;
        Ok(Some(()))
    }

    async fn wait_for_v2_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
    ) -> Result<Arc<Vec<u8>>, Error<Self::OperationalError>> {
        let resp = Arc::new(self.read_v2_nostr_payload(mailbox_id).await?);
        Ok(resp)
    }

    async fn post_v1_response(
        &self,
        _mailbox_id: &payjoin::directory::ShortId,
        _data: Vec<u8>,
    ) -> Result<(), Error<Self::OperationalError>> {
        println!("POST_V1_RESPONSE");
        unimplemented!()
    }

    async fn post_v1_request_and_wait_for_response(
        &self,
        _mailbox_id: &payjoin::directory::ShortId,
        _data: Vec<u8>,
    ) -> Result<Arc<Vec<u8>>, Error<Self::OperationalError>> {
        println!("POST_V1_REQUEST_AND_WAIT_FOR_RESPONSE");
        unimplemented!()
    }
}

#[derive(Debug)]
pub enum NostrBackendError {
    EventError(nostr::event::Error),
    HexError(nostr::util::hex::Error),
    ClientError(hyper::Error),
}

impl crate::db::SendableError for NostrBackendError {}

impl std::error::Error for NostrBackendError {}

impl std::fmt::Display for NostrBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use NostrBackendError::*;
        match self {
            EventError(e) => write!(f, "Event error: {e}"),
            ClientError(e) => write!(f, "Client error: {e}"),
            HexError(e) => write!(f, "Hex error: {e}"),
        }
    }
}
