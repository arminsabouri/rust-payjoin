use std::borrow::Cow;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::{Method, Request};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use nostr::event::{Event, EventBuilder, Kind, Tag, UnsignedEvent};
use nostr::filter::{Filter, SingleLetterTag};
use nostr::hashes::{sha256, Hash};
use nostr::key::Keys;
use nostr::message::{ClientMessage, SubscriptionId};
use nostr::nips::nip59::extract_rumor;
use nostr::types::Timestamp;
use nostr::util::{hex, JsonUtil};
use payjoin::directory::ShortId;

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
    // TODO: the exact same key cannot be used for all giftwraps,
    key: nostr::key::Keys,
    timeout: Duration,
}

impl Db {
    fn derive_key_pair(&self, short_id: &ShortId) -> nostr::SecretKey{
        // TODO No domain separation for now
        // TODO: use bip32 hardened derivations / keyed-hash'd derivation
        let mut hasher = sha256::Hash::engine();
        hasher.write(short_id.as_slice()).unwrap();
        hasher.write(self.key.secret_key().as_secret_bytes()).unwrap();
        let sks = sha256::Hash::from_engine(hasher).as_byte_array().to_vec();
        let sk = nostr::SecretKey::from_slice(&sks).unwrap();

        sk
    }

    pub async fn new() -> Self { Self { key: Keys::generate(), timeout: Duration::from_secs(5) } }

    async fn push_v2_nostr_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
        data: Vec<u8>,
    ) -> Result<(), NostrBackendError> {
        let hex_data = hex::encode(data);
        let tag = Tag::parse(vec!["h".to_string(), mailbox_id.to_string()]).unwrap();
        let inner_note = UnsignedEvent::new(
            self.key.public_key(),
            Timestamp::now(),
            Kind::TextNote,
            vec![],
            hex_data,
        );

        let dervied_sk= self.derive_key_pair(mailbox_id);
        let signer = nostr::key::Keys::new(dervied_sk);
        let gift_wrap =
            EventBuilder::gift_wrap(&signer, &signer.public_key(), inner_note, vec![tag])
                .await
                // TODO: handle error
                .unwrap();

        NostrClient::send_event(gift_wrap).await?;

        Ok(())
    }

    async fn read_v2_nostr_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
    ) -> Result<Vec<u8>, Error<NostrBackendError>> {
        // TODO: only assuming one event per h tag for now
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
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

        println!("GIFT WRAP EVENT: {:?}", event);
        // Unwrap the gift
        let dervied_sk= self.derive_key_pair(mailbox_id);
        let signer = nostr::key::Keys::new(dervied_sk);
        let inner_note = extract_rumor(&signer, &event).await.unwrap().rumor;

        println!("EVENT: {:?}", inner_note);
        let data = hex::decode(inner_note.content.as_str()).map_err(NostrBackendError::HexError)?;

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
