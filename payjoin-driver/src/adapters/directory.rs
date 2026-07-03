use std::error::Error as StdError;
use std::fmt;
use std::pin::Pin;

use futures::{stream, Stream, TryStreamExt};
use payjoin::append_mailbox::{
    append_request, process_append_response, process_read_response, read_request, MailboxError,
};
use payjoin::multiparty::{parse_mailbox_psbt_fragment, Psbt, SharedMailboxCoordinates};
use payjoin::{IntoUrl, IntoUrlError, Request, Url};
use reqwest::Client;

use crate::mailbox::CollaborativeMessageSet;

/// A [`CollaborativeMessageSet`] over a Payjoin Directory mailbox, backed by `reqwest`.
///
/// This adapter owns everything the state machine does not: OHTTP encapsulation,
/// HPKE sealing/decryption, directory addressing, and HTTP. It is built from the
/// session keys the participant hands out via
/// [`Participant::shared_mailbox_coordinates`](payjoin::multiparty::Participant).
#[derive(Clone)]
pub struct DirectoryMailbox {
    client: Client,
    ohttp_relay: Url,
    coords: SharedMailboxCoordinates,
}

impl DirectoryMailbox {
    /// Build a mailbox for one session from its coordinates and an OHTTP relay.
    pub fn new(
        client: Client,
        ohttp_relay: impl IntoUrl,
        coords: SharedMailboxCoordinates,
    ) -> Result<Self, DirectoryMailboxError> {
        Ok(Self { client, ohttp_relay: ohttp_relay.into_url()?, coords })
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
}

impl CollaborativeMessageSet for DirectoryMailbox {
    type Message = Psbt;
    type Error = DirectoryMailboxError;
    type Messages<'a> = Pin<Box<dyn Stream<Item = Result<Psbt, DirectoryMailboxError>> + 'a>>;

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
        // Clone into the stream so it is self-contained (the directory returns
        // the whole append-only mailbox in one GET; we decrypt, parse, and yield
        // each valid fragment — invalid frames are dropped here, not by the
        // state machine).
        let this = self.clone();
        let fetch = async move {
            let (request, ohttp_ctx) = read_request(
                &this.coords.ohttp_keys,
                &this.coords.directory,
                this.ohttp_relay.as_str(),
                &this.coords.mailbox_id,
            )?;
            let body = this.post(request).await?;
            let frames = process_read_response(&body, ohttp_ctx, &this.coords.shared_keypair)?;
            let fragments: Vec<Psbt> =
                frames.iter().filter_map(|frame| parse_mailbox_psbt_fragment(frame).ok()).collect();
            Ok::<Vec<Psbt>, DirectoryMailboxError>(fragments)
        };
        Box::pin(
            stream::once(fetch)
                .map_ok(|fragments| stream::iter(fragments.into_iter().map(Ok)))
                .try_flatten(),
        )
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
