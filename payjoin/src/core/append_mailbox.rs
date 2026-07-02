//! Client helpers for append-only Payjoin Directory mailboxes.
//!
//! A mailbox is addressed by a [`ShortId`] and holds a sequence of fixed-size
//! HPKE-encrypted frames. [`append_request`] encrypts a message and builds the
//! request to append it; [`read_request`] reads the whole mailbox and
//! [`process_read_response`] decrypts the frames addressed to the reader. The
//! caller supplies the [`ShortId`] and the HPKE keys, and sends each returned
//! [`Request`] with its own HTTP client.

use crate::directory::{ShortId, PADDED_MESSAGE_BYTES};
use crate::hpke::{decrypt_message_a, encrypt_message_a, HpkeError};
use crate::ohttp::{
    ohttp_encapsulate, process_get_res, process_post_res, DirectoryResponseError,
    OhttpEncapsulationError,
};
use crate::{
    HpkeKeyPair, HpkePublicKey, IntoUrl, IntoUrlError, OhttpKeys, Request, Url, UrlParseError,
};

/// Pairs a mailbox request with the state needed to read its response.
///
/// Hold it between sending a [`Request`] and processing the response; it is
/// consumed when the response is processed.
pub struct MailboxCtx(ohttp::ClientResponse);

/// Build the request that encrypts `message` and appends it to `mailbox`.
///
/// `message` is HPKE-sealed to `receiver_key` into one [`PADDED_MESSAGE_BYTES`]
/// frame; `reply_key` is the sender's public key, carried inside the ciphertext
/// so the recipient can reply. Returns the [`Request`] to send and the
/// [`MailboxCtx`] to process its response with.
pub fn append_request(
    ohttp_keys: &OhttpKeys,
    directory: &Url,
    ohttp_relay: impl IntoUrl,
    mailbox: &ShortId,
    message: &[u8],
    reply_key: &HpkePublicKey,
    receiver_key: &HpkePublicKey,
) -> Result<(Request, MailboxCtx), MailboxError> {
    let frame = encrypt_message_a(message.to_vec(), reply_key, receiver_key)?;
    let target = mailbox_endpoint(directory, mailbox);
    let (body, ctx) = ohttp_encapsulate(&ohttp_keys.0, "POST", target.as_str(), Some(&frame))?;
    let request = Request::new_v2(&relay_url(ohttp_relay, directory)?, &body);
    Ok((request, MailboxCtx(ctx)))
}

/// Process the response to an [`append_request`].
pub fn process_append_response(res: &[u8], ctx: MailboxCtx) -> Result<(), MailboxError> {
    process_post_res(res, ctx.0).map_err(MailboxError::from)
}

/// Build the request that reads the entire `mailbox`.
pub fn read_request(
    ohttp_keys: &OhttpKeys,
    directory: &Url,
    ohttp_relay: impl IntoUrl,
    mailbox: &ShortId,
) -> Result<(Request, MailboxCtx), MailboxError> {
    let target = mailbox_endpoint(directory, mailbox);
    let (body, ctx) = ohttp_encapsulate(&ohttp_keys.0, "GET", target.as_str(), None)?;
    let request = Request::new_v2(&relay_url(ohttp_relay, directory)?, &body);
    Ok((request, MailboxCtx(ctx)))
}

/// A mailbox frame decrypted by the reader.
pub struct DecryptedMessage {
    /// The plaintext message.
    pub plaintext: Vec<u8>,
    /// The sender's reply public key, carried in the frame, to reply to them.
    pub reply_key: HpkePublicKey,
}

/// Process the response to a [`read_request`] into the messages addressed to the
/// reader.
///
/// Each frame is HPKE-sealed to one recipient, so the whole mailbox is read and
/// every frame is decrypted with `receiver_keypair`; frames sealed to other
/// recipients don't open and are skipped. Returns an empty `Vec` if the mailbox
/// has no messages yet.
pub fn process_read_response(
    res: &[u8],
    ctx: MailboxCtx,
    receiver_keypair: &HpkeKeyPair,
) -> Result<Vec<DecryptedMessage>, MailboxError> {
    let frames = match process_get_res(res, ctx.0)? {
        Some(blob) => split_frames(&blob)?,
        None => return Ok(Vec::new()),
    };
    Ok(decrypt_frames(&frames, receiver_keypair))
}

/// Decrypt the frames addressed to `receiver_keypair`, skipping the rest.
fn decrypt_frames(frames: &[Vec<u8>], receiver_keypair: &HpkeKeyPair) -> Vec<DecryptedMessage> {
    frames
        .iter()
        .filter_map(|frame| decrypt_message_a(frame, receiver_keypair.secret_key()).ok())
        .map(|(plaintext, reply_key)| DecryptedMessage { plaintext, reply_key })
        .collect()
}

/// Split a concatenated mailbox payload into its fixed-size frames.
///
/// Every frame is [`PADDED_MESSAGE_BYTES`]; a payload that isn't a whole number
/// of frames is rejected as truncated rather than yielding a partial frame.
pub fn split_frames(blob: &[u8]) -> Result<Vec<Vec<u8>>, MailboxError> {
    if blob.len() % PADDED_MESSAGE_BYTES != 0 {
        return Err(MailboxError::PartialFrame { len: blob.len() });
    }
    Ok(blob.chunks(PADDED_MESSAGE_BYTES).map(<[u8]>::to_vec).collect())
}

fn mailbox_endpoint(directory: &Url, mailbox: &ShortId) -> Url {
    let mut url = directory.clone();
    url.path_segments_mut()
        .expect("Payjoin Directory URL cannot be a base")
        .push(&mailbox.to_string());
    url
}

/// Relay URL that reveals only the directory's scheme and authority to the relay.
fn relay_url(ohttp_relay: impl IntoUrl, directory: &Url) -> Result<Url, MailboxError> {
    let relay_base = ohttp_relay.into_url()?;
    let directory_base = directory.join("/")?;
    Ok(relay_base.join(&format!("/{directory_base}"))?)
}

/// Error from building or processing a mailbox request.
#[derive(Debug)]
pub enum MailboxError {
    /// Failed to OHTTP-encapsulate the request.
    Encapsulation(OhttpEncapsulationError),
    /// The directory returned an unexpected or undecodable response.
    Response(DirectoryResponseError),
    /// Failed to parse the directory or relay URL.
    ParseUrl(UrlParseError),
    /// Failed to interpret the OHTTP relay argument as a URL.
    IntoUrl(IntoUrlError),
    /// Failed to HPKE-seal a message into a frame.
    Hpke(HpkeError),
    /// The mailbox payload was not a whole number of frames.
    PartialFrame { len: usize },
}

impl From<OhttpEncapsulationError> for MailboxError {
    fn from(e: OhttpEncapsulationError) -> Self { Self::Encapsulation(e) }
}
impl From<HpkeError> for MailboxError {
    fn from(e: HpkeError) -> Self { Self::Hpke(e) }
}
impl From<DirectoryResponseError> for MailboxError {
    fn from(e: DirectoryResponseError) -> Self { Self::Response(e) }
}
impl From<UrlParseError> for MailboxError {
    fn from(e: UrlParseError) -> Self { Self::ParseUrl(e) }
}
impl From<IntoUrlError> for MailboxError {
    fn from(e: IntoUrlError) -> Self { Self::IntoUrl(e) }
}

impl std::fmt::Display for MailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use MailboxError::*;
        match self {
            Encapsulation(e) => write!(f, "OHTTP encapsulation error: {e}"),
            Response(e) => write!(f, "directory response error: {e}"),
            ParseUrl(e) => write!(f, "URL parse error: {e}"),
            IntoUrl(e) => write!(f, "invalid relay URL: {e}"),
            Hpke(e) => write!(f, "HPKE error: {e}"),
            PartialFrame { len } =>
                write!(f, "mailbox payload of {len} bytes is not a whole number of frames"),
        }
    }
}

impl std::error::Error for MailboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use MailboxError::*;
        match self {
            Encapsulation(e) => Some(e),
            Response(e) => Some(e),
            ParseUrl(e) => Some(e),
            IntoUrl(e) => Some(e),
            Hpke(e) => Some(e),
            PartialFrame { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_frames_splits_on_frame_boundaries() {
        let blob = vec![0u8; PADDED_MESSAGE_BYTES * 3];
        let frames = split_frames(&blob).expect("whole frames");
        assert_eq!(frames.len(), 3);
        assert!(frames.iter().all(|f| f.len() == PADDED_MESSAGE_BYTES));
    }

    #[test]
    fn split_frames_empty_is_no_frames() {
        assert!(split_frames(&[]).expect("empty is valid").is_empty());
    }

    #[test]
    fn split_frames_rejects_partial() {
        assert!(matches!(
            split_frames(&[0u8; PADDED_MESSAGE_BYTES + 1]),
            Err(MailboxError::PartialFrame { len }) if len == PADDED_MESSAGE_BYTES + 1
        ));
    }

    #[test]
    fn mailbox_endpoint_appends_short_id() {
        let directory = Url::parse("https://payjo.in").expect("valid url");
        let mailbox = ShortId([0u8; 8]);
        let endpoint = mailbox_endpoint(&directory, &mailbox);
        assert!(endpoint.as_str().ends_with(&mailbox.to_string()));
    }

    #[test]
    fn decrypt_frames_keeps_only_messages_for_the_reader() {
        let alice = HpkeKeyPair::gen_keypair();
        let bob = HpkeKeyPair::gen_keypair();
        let sender = HpkeKeyPair::gen_keypair();

        // Two frames sealed to alice, one to bob — as append_request builds them.
        let frames = vec![
            encrypt_message_a(b"for alice 1".to_vec(), sender.public_key(), alice.public_key())
                .unwrap(),
            encrypt_message_a(b"for bob".to_vec(), sender.public_key(), bob.public_key()).unwrap(),
            encrypt_message_a(b"for alice 2".to_vec(), sender.public_key(), alice.public_key())
                .unwrap(),
        ];

        // Alice reads only the two frames sealed to her, in order.
        let alice_msgs = decrypt_frames(&frames, &alice);
        let plaintexts: Vec<&[u8]> = alice_msgs.iter().map(|m| m.plaintext.as_slice()).collect();
        assert_eq!(plaintexts, vec![&b"for alice 1"[..], &b"for alice 2"[..]]);
        assert!(alice_msgs.iter().all(|m| m.reply_key == *sender.public_key()));

        // Bob reads only his one frame; a stranger reads none.
        assert_eq!(decrypt_frames(&frames, &bob).len(), 1);
        assert!(decrypt_frames(&frames, &HpkeKeyPair::gen_keypair()).is_empty());
    }
}
