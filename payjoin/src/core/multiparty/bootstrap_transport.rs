//! Byte-level transport for the multiparty bootstrap mailboxes.
//!
//! Bootstrap runs *before* a shared session secret exists, so its messages can't
//! ride the shared plan mailbox. Each message is a [message A] sealed to one
//! recipient's per-participant mailbox, with the sender's own reply key carried
//! inside the ciphertext (so the recipient learns it). Two rhythms cover every
//! bootstrap stage: **poll** a mailbox for the first message sealed to you, and
//! **post** a message sealed from you to a recipient.
//!
//! A stage supplies its exact mailbox target and keys as a [`PollIo`]/[`PostIo`];
//! this module performs the OHTTP encapsulation and HPKE sealing/opening. A driver
//! adapter owns only the HTTP round-trip. Keeping the *exact* target URL in the
//! descriptor (rather than recomputing a mailbox id) preserves each stage's
//! addressing precisely — the stages derive mailbox ids in slightly different ways
//! (`sha256(compressed_pubkey)` vs. the URI's advertised endpoint).
//!
//! [message A]: crate::hpke::encrypt_message_a

pub use crate::append_mailbox::MailboxError;
use crate::hpke::{decrypt_message_a, encrypt_message_a, HpkeKeyPair, HpkePublicKey};
use crate::ohttp::{full_relay_url, ohttp_encapsulate, process_get_res, process_post_res};
use crate::{IntoUrl, OhttpKeys, Request, Url};

/// Everything the transport needs to poll one mailbox and open the first message
/// sealed to this participant.
#[derive(Debug, Clone)]
pub struct PollIo {
    /// OHTTP keys for the participant's Payjoin Directory.
    pub ohttp_keys: OhttpKeys,
    /// Directory origin, used to build the OHTTP relay URL.
    pub directory: Url,
    /// The exact mailbox endpoint to GET.
    pub target: Url,
    /// Keypair whose secret opens the inbound message A.
    pub decrypt_key: HpkeKeyPair,
}

/// Everything the transport needs to seal a message from this participant to a
/// recipient's mailbox and post it.
#[derive(Debug, Clone)]
pub struct PostIo {
    /// OHTTP keys for the Payjoin Directory.
    pub ohttp_keys: OhttpKeys,
    /// Directory origin, used to build the OHTTP relay URL.
    pub directory: Url,
    /// The exact recipient mailbox endpoint to POST to.
    pub target: Url,
    /// Recipient the message is HPKE-sealed to.
    pub recipient: HpkePublicKey,
    /// This participant's keypair; its public key is carried inside the ciphertext
    /// as the reply key.
    pub sender: HpkeKeyPair,
    /// Plaintext payload (empty for a bare reply-key exchange).
    pub payload: Vec<u8>,
}

/// Build the OHTTP-encapsulated GET that polls `io`'s mailbox.
pub fn poll_request(
    io: &PollIo,
    ohttp_relay: impl IntoUrl,
) -> Result<(Request, ohttp::ClientResponse), MailboxError> {
    let (body, ctx) = ohttp_encapsulate(&io.ohttp_keys.0, "GET", io.target.as_str(), None)?;
    let relay = full_relay_url(ohttp_relay, &io.directory).map_err(MailboxError::from)?;
    Ok((Request::new_v2(&relay, &body), ctx))
}

/// Open the first message A from a poll response with `decrypt_key`.
///
/// Returns the `(payload, sender_reply_key)` pair, or `None` when the directory
/// has nothing yet (HTTP 202 ACCEPTED).
pub fn process_poll_response(
    body: &[u8],
    ctx: ohttp::ClientResponse,
    decrypt_key: &HpkeKeyPair,
) -> Result<Option<(Vec<u8>, HpkePublicKey)>, MailboxError> {
    let Some(message_a) = process_get_res(body, ctx)? else {
        return Ok(None);
    };
    let (payload, sender) = decrypt_message_a(&message_a, decrypt_key.secret_key())?;
    Ok(Some((payload, sender)))
}

/// Build the OHTTP-encapsulated POST that seals `io`'s payload to its recipient.
pub fn post_request(
    io: &PostIo,
    ohttp_relay: impl IntoUrl,
) -> Result<(Request, ohttp::ClientResponse), MailboxError> {
    let message_a = encrypt_message_a(io.payload.clone(), io.sender.public_key(), &io.recipient)?;
    let (body, ctx) =
        ohttp_encapsulate(&io.ohttp_keys.0, "POST", io.target.as_str(), Some(&message_a))?;
    let relay = full_relay_url(ohttp_relay, &io.directory).map_err(MailboxError::from)?;
    Ok((Request::new_v2(&relay, &body), ctx))
}

/// Confirm the directory acknowledged a [`post_request`].
pub fn process_post_ack(body: &[u8], ctx: ohttp::ClientResponse) -> Result<(), MailboxError> {
    process_post_res(body, ctx).map_err(MailboxError::from)
}
