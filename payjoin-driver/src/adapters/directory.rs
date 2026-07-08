use std::cell::Cell;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::Stream;
use payjoin::append_mailbox::{
    append_request, process_append_response, process_read_response, read_request, MailboxError,
};
use payjoin::multiparty::{parse_mailbox_psbt_fragment, Psbt, SessionParameters};
use payjoin::{HpkeKeyPair, IntoUrl, IntoUrlError, OhttpKeys, Request, Url};
use reqwest::Client;

use crate::mailbox::CollaborativeMessageSet;

/// Session keys needed to reach one shared mailbox on the Payjoin Directory.
#[derive(Debug, Clone)]
struct SharedMailboxCoordinates {
    directory: Url,
    ohttp_keys: OhttpKeys,
    shared_keypair: HpkeKeyPair,
}

/// A [`CollaborativeMessageSet`] over a Payjoin Directory mailbox, backed by `reqwest`.
///
/// This adapter owns everything the state machine does not: OHTTP encapsulation,
/// HPKE sealing/decryption, directory addressing, and HTTP.
#[derive(Clone)]
pub struct DirectoryMailbox {
    client: Client,
    ohttp_relay: Url,
    coords: SharedMailboxCoordinates,
    /// Parsed PSBT fragments already read and persisted for this session.
    fragments_read: Arc<Cell<usize>>,
}

/// Long-poll stream over one [`DirectoryMailbox`].
pub struct DirectoryMailboxMessages {
    mailbox: DirectoryMailbox,
    in_flight: Option<Pin<Box<dyn Future<Output = Result<Vec<Psbt>, DirectoryMailboxError>>>>>,
}

impl DirectoryMailbox {
    /// Build a mailbox for one session and an OHTTP relay.
    ///
    /// `fragments_read` is how many directory PSBT fragments were already read
    /// and persisted before this driver run (typically
    /// [`Participant::directory_psbt_fragment_count`](payjoin::multiparty::Participant::directory_psbt_fragment_count)
    /// replayed from the event log).
    pub fn new(
        client: Client,
        ohttp_relay: impl IntoUrl,
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
        session_parameters: &SessionParameters,
        fragments_read: usize,
    ) -> Result<Self, DirectoryMailboxError> {
        Ok(Self {
            client,
            ohttp_relay: ohttp_relay.into_url()?,
            coords: SharedMailboxCoordinates {
                directory: directory.into_url()?,
                ohttp_keys,
                shared_keypair: session_parameters.session_shared_keypair(),
            },
            fragments_read: Arc::new(Cell::new(fragments_read)),
        })
    }

    async fn post(&self, request: Request) -> Result<Vec<u8>, DirectoryMailboxError> {
        let response = self
            .client
            .post(request.url)
            .header("Content-Type", request.content_type)
            .body(request.body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(DirectoryMailboxError::Http(
                response.error_for_status().expect_err("non-success status"),
            ));
        }
        Ok(response.bytes().await?.to_vec())
    }

    /// Long-poll the directory for PSBT fragments past the persisted cursor.
    async fn fetch_fragments(&self) -> Result<Vec<Psbt>, DirectoryMailboxError> {
        let skip = self.fragments_read.get();
        let (request, ohttp_ctx) = read_request(
            &self.coords.ohttp_keys,
            &self.coords.directory,
            self.ohttp_relay.as_str(),
            &self.coords.shared_keypair.public_key().short_id(),
            skip,
        )?;
        let body = self.post(request).await?;
        let frames = process_read_response(&body, ohttp_ctx, &self.coords.shared_keypair)?;
        let fragments: Vec<Psbt> =
            frames.iter().filter_map(|frame| parse_mailbox_psbt_fragment(frame).ok()).collect();
        self.fragments_read.set(skip + fragments.len());
        Ok(fragments)
    }
}

impl Stream for DirectoryMailboxMessages {
    type Item = Result<Vec<Psbt>, DirectoryMailboxError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.in_flight.is_none() {
            let mailbox = self.mailbox.clone();
            self.in_flight = Some(Box::pin(async move { mailbox.fetch_fragments().await }));
        }

        match self.in_flight.as_mut().expect("just initialized").as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.in_flight = None;
                Poll::Ready(Some(result))
            }
        }
    }
}

impl CollaborativeMessageSet for DirectoryMailbox {
    type Message = Psbt;
    type Error = DirectoryMailboxError;
    type Messages<'a> = Pin<Box<DirectoryMailboxMessages>>;

    async fn write(&self, message: Psbt) -> Result<(), Self::Error> {
        let (request, ohttp_ctx) = append_request(
            &self.coords.ohttp_keys,
            &self.coords.directory,
            self.ohttp_relay.as_str(),
            &message.serialize(),
            self.coords.shared_keypair.public_key(),
        )?;
        let body = self.post(request).await?;
        process_append_response(&body, ohttp_ctx)?;
        Ok(())
    }

    fn read(&self) -> Self::Messages<'_> {
        Box::pin(DirectoryMailboxMessages { mailbox: self.clone(), in_flight: None })
    }
}

/// Transport/crypto failure from [`DirectoryMailbox`].
#[derive(Debug)]
pub enum DirectoryMailboxError {
    /// OHTTP encapsulation, HPKE, or directory-response decoding failed.
    Mailbox(MailboxError),
    /// The OHTTP relay argument was not a valid URL.
    Relay(IntoUrlError),
    /// The HTTP request itself failed.
    Http(reqwest::Error),
}

impl fmt::Display for DirectoryMailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mailbox(e) => write!(f, "mailbox error: {e}"),
            Self::Relay(e) => write!(f, "invalid OHTTP relay URL: {e}"),
            Self::Http(e) => write!(f, "HTTP error: {e}"),
        }
    }
}

impl StdError for DirectoryMailboxError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Mailbox(e) => Some(e),
            Self::Relay(e) => Some(e),
            Self::Http(e) => Some(e),
        }
    }
}

impl From<MailboxError> for DirectoryMailboxError {
    fn from(e: MailboxError) -> Self { Self::Mailbox(e) }
}
impl From<IntoUrlError> for DirectoryMailboxError {
    fn from(e: IntoUrlError) -> Self { Self::Relay(e) }
}
impl From<reqwest::Error> for DirectoryMailboxError {
    fn from(e: reqwest::Error) -> Self { Self::Http(e) }
}
