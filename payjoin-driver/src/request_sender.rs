//! Minimal HTTP transport for driving typestates that still own their crypto.
//!
//! The bootstrap typestates ([`ParticipantAwaitingSessionParameters`], the
//! [`SessionCreator`]) build a fully-encapsulated [`Request`](payjoin::Request)
//! themselves and expect the raw response bytes back to decrypt. Unlike
//! [`CollaborativeMessageSet`](crate::CollaborativeMessageSet), this adapter owns
//! *no* crypto — it only performs the HTTP round-trip. Like the other driver
//! dependencies it carries no `Send` bound, so it runs on single-threaded
//! executors too.
//!
//! [`ParticipantAwaitingSessionParameters`]: payjoin::multiparty::ParticipantAwaitingSessionParameters
//! [`SessionCreator`]: payjoin::multiparty::SessionCreator

/// Sends a pre-built [`Request`](payjoin::Request) and returns the response body.
#[allow(async_fn_in_trait)]
pub trait RequestSender {
    /// Transport failure from the underlying implementation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// POST `request` and return the raw response body on success.
    async fn send(&self, request: payjoin::Request) -> Result<Vec<u8>, Self::Error>;
}
