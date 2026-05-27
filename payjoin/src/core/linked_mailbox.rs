//! Append-only broadcast channel over Payjoin Directory mailboxes.
//!
//! Multiple peers sharing a secret can write concurrently. Concurrent writers
//! converge on distinct slots because the directory returns 409 on an occupied
//! mailbox; the writer then advances to the next slot and retries.

use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::hashes::{sha256, Hash, HashEngine};
use futures::{stream, Stream};

use crate::directory::{ShortId, ENCAPSULATED_MESSAGE_BYTES};
use crate::ohttp::{ohttp_decapsulate, ohttp_encapsulate};
use crate::OhttpKeys;

fn generate_short_id(shared_secret: &[u8], index: u64) -> ShortId {
    let mut engine = sha256::Hash::engine();
    engine.input(b"v0-PayjoinDirectoryEntry");
    engine.input(shared_secret);
    engine.input(index.to_le_bytes().as_slice());
    sha256::Hash::from_engine(engine).into()
}

type MailboxError = Box<dyn std::error::Error + Send + Sync>;

async fn raw_write(
    client: &reqwest::Client,
    gateway_url: &str,
    directory_url: &str,
    ohttp_keys: &OhttpKeys,
    short_id: ShortId,
    message: &[u8],
) -> Result<http::StatusCode, MailboxError> {
    let target = format!("{directory_url}/{short_id}");
    let (req, ohttp_ctx) = ohttp_encapsulate(ohttp_keys, "POST", &target, Some(message))
        .map_err(|e| std::io::Error::other(format!("OHTTP encapsulation error: {e}")))?;
    let body = client
        .post(gateway_url)
        .header("Content-Type", "message/ohttp-req")
        .body(req.to_vec())
        .send()
        .await?
        .bytes()
        .await?;
    let body_arr: &[u8; ENCAPSULATED_MESSAGE_BYTES] = body
        .as_ref()
        .try_into()
        .map_err(|_| std::io::Error::other("unexpected relay response size"))?;
    let res = ohttp_decapsulate(ohttp_ctx, body_arr)
        .map_err(|e| std::io::Error::other(format!("OHTTP decapsulation error: {e}")))?;
    Ok(res.status())
}

async fn raw_read(
    client: &reqwest::Client,
    gateway_url: &str,
    directory_url: &str,
    ohttp_keys: &OhttpKeys,
    short_id: ShortId,
) -> Result<Option<Vec<u8>>, MailboxError> {
    let target = format!("{directory_url}/{short_id}");
    let (req, ohttp_ctx) = ohttp_encapsulate(ohttp_keys, "GET", &target, None)
        .map_err(|e| std::io::Error::other(format!("OHTTP encapsulation error: {e}")))?;
    let body = client
        .post(gateway_url)
        .header("Content-Type", "message/ohttp-req")
        .body(req.to_vec())
        .send()
        .await?
        .bytes()
        .await?;
    let body_arr: &[u8; ENCAPSULATED_MESSAGE_BYTES] = body
        .as_ref()
        .try_into()
        .map_err(|_| std::io::Error::other("unexpected relay response size"))?;
    let res = ohttp_decapsulate(ohttp_ctx, body_arr)
        .map_err(|e| std::io::Error::other(format!("OHTTP decapsulation error: {e}")))?;
    match res.status() {
        http::StatusCode::OK => Ok(Some(res.into_body())),
        http::StatusCode::ACCEPTED => Ok(None),
        s => Err(std::io::Error::other(format!("unexpected directory status: {s}")).into()),
    }
}

/// Append-only broadcast channel shared by multiple participants.
///
/// Each participant is initialized with the same shared secret.
#[allow(async_fn_in_trait)]
pub trait CollaborativeMessageSet {
    type Message;
    type Error;

    type Messages<'a>: Stream<Item = Result<Self::Message, Self::Error>> + Send + 'a
    where
        Self: 'a;

    /// Append one complete message.
    async fn write(&self, message: Self::Message) -> Result<(), Self::Error>;

    /// Read all messages from the beginning in server-determined order.
    fn read(&self) -> Self::Messages<'_>;
}

/// [`CollaborativeMessageSet`] over a chain of Payjoin Directory mailboxes.
///
/// `short_id(i) = H("v0-PayjoinDirectoryEntry" || shared_secret || i)`.
/// `write` walks forward on 409 so concurrent writers converge on distinct
/// slots. `read` polls each slot in order and stops when the directory's
/// wait timeout elapses without a payload.
pub struct DirectoryLinkedMailbox {
    client: reqwest::Client,
    /// Full relay gateway URL, e.g. `http://relay/{directory_url}`.
    gateway_url: String,
    /// Base URL of the directory, e.g. `https://payjo.in`.
    directory_url: String,
    ohttp_keys: OhttpKeys,
    shared_secret: [u8; 32],
    next_write_index: AtomicU64,
}

impl DirectoryLinkedMailbox {
    pub fn new(
        client: reqwest::Client,
        gateway_url: String,
        directory_url: String,
        ohttp_keys: OhttpKeys,
        shared_secret: [u8; 32],
    ) -> Self {
        Self {
            client,
            gateway_url,
            directory_url,
            ohttp_keys,
            shared_secret,
            next_write_index: AtomicU64::new(0),
        }
    }
}

impl CollaborativeMessageSet for DirectoryLinkedMailbox {
    type Message = Vec<u8>;
    type Error = MailboxError;
    type Messages<'a> =
        std::pin::Pin<Box<dyn Stream<Item = Result<Vec<u8>, MailboxError>> + Send + 'a>>;

    async fn write(&self, message: Vec<u8>) -> Result<(), Self::Error> {
        let mut i = self.next_write_index.load(Ordering::Relaxed);
        loop {
            let short_id = generate_short_id(&self.shared_secret, i);
            match raw_write(
                &self.client,
                &self.gateway_url,
                &self.directory_url,
                &self.ohttp_keys,
                short_id,
                &message,
            )
            .await?
            {
                http::StatusCode::OK => {
                    self.next_write_index.fetch_max(i + 1, Ordering::Relaxed);
                    return Ok(());
                }
                http::StatusCode::CONFLICT => i += 1,
                s =>
                    return Err(
                        std::io::Error::other(format!("unexpected write status: {s}")).into()
                    ),
            }
        }
    }

    fn read(&self) -> Self::Messages<'_> {
        let secret = self.shared_secret;
        let client = self.client.clone();
        let gateway_url = self.gateway_url.clone();
        let directory_url = self.directory_url.clone();
        let ohttp_keys = self.ohttp_keys.clone();
        Box::pin(stream::try_unfold(0u64, move |i| {
            let client = client.clone();
            let gateway_url = gateway_url.clone();
            let directory_url = directory_url.clone();
            let ohttp_keys = ohttp_keys.clone();
            async move {
                let short_id = generate_short_id(&secret, i);
                match raw_read(&client, &gateway_url, &directory_url, &ohttp_keys, short_id).await?
                {
                    Some(payload) => Ok(Some((payload, i + 1))),
                    None => Ok(None),
                }
            }
        }))
    }
}
