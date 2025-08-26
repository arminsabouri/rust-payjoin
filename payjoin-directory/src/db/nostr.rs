use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use nostr::event::{Event, EventBuilder, Kind, Tag};
use nostr::filter::{Filter, SingleLetterTag};
use nostr::key::Keys;
use nostr::util::hex;
use nostr_sdk::Client;

use super::Error;

struct NostrClient {}

impl NostrClient {
    async fn connect() -> Result<Client, NostrBackendError> {
        let client = Client::new(Keys::generate());
        // TODO: hard coded for now, should be configurable
        let relay_url = format!("ws://127.0.0.1:8080");
        client.add_relay(relay_url).await.map_err(NostrBackendError::ClientError)?;
        client.connect().await;
        Ok(client)
    }

    async fn send_event(event: Event) -> Result<(), NostrBackendError> {
        let client = Self::connect().await?;
        client.send_event(&event).await.map_err(NostrBackendError::ClientError)?;
        client.disconnect().await;
        Ok(())
    }

    async fn fetch_event(filter: Filter) -> Result<Option<Event>, NostrBackendError> {
        let client = Self::connect().await?;
        let events = client
            .fetch_events(filter, Duration::from_secs(5))
            .await
            .map_err(NostrBackendError::ClientError)?;

        let event = events.first().cloned();
        client.disconnect().await;
        Ok(event)
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
    ClientError(nostr_sdk::client::Error),
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
