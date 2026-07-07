//! The participant network task: a dumb reader of the shared mailbox.
//!
//! It has no state machine and no persister. It reads the mailbox (the adapter
//! decrypts *and parses* frames into [`Psbt`] fragments) past the actor's
//! persisted count, so it only ever forwards fragments the actor has not yet
//! seen. To know that boundary it asks the actor over a per-batch oneshot: the
//! actor replies with the number of fragments now persisted, which the
//! network task uses as the cursor for the next read.
//!
//! The read blocks server-side (a long poll) until a fragment past the cursor
//! exists, so the loop is naturally paced without a client-side timer and
//! stays portable (FFI, WASM). It stops when the actor drops the channel
//! (plan complete) or a read fails.

use futures::channel::mpsc::UnboundedSender;
use futures::channel::oneshot;
use futures::TryStreamExt;
use payjoin::multiparty::Psbt;

use crate::error::DriverError;
use crate::mailbox::CollaborativeMessageSet;

/// A batch of new fragments the network task hands to the actor, with a reply
/// channel for the actor's authoritative persisted-fragment count.
pub struct FragmentBatch {
    /// Parsed fragments past the count the actor last reported persisted.
    pub fragments: Vec<Psbt>,
    /// The actor replies here with the number of fragments now persisted.
    pub ack: oneshot::Sender<usize>,
}

/// Read the shared mailbox in a loop, forwarding newly seen fragments to the
/// actor and syncing the persisted count over a per-batch oneshot.
///
/// Pure I/O: no persister, no protocol state beyond the running persisted count.
pub async fn run_network_task<M>(
    mailbox: &M,
    batches: UnboundedSender<FragmentBatch>,
) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
{
    // Sync the persisted count first (an empty batch), so a resumed session does
    // not re-forward fragments already in the log.
    let Some(mut persisted) = send_batch(&batches, Vec::new()).await else {
        return Ok(());
    };

    loop {
        if batches.is_closed() {
            return Ok(());
        }
        // TODO: is there an issue here where malformed fragments are getting re-read again? Should test for this.
        // The adapter (and the directory behind it) already skips to
        // `persisted`, long-polling server-side if nothing new has landed
        // yet, so every fragment returned here is new.
        let new: Vec<Psbt> = mailbox
            .read(persisted)
            .try_collect()
            .await
            .map_err(|e| DriverError::Mailbox(Box::new(e)))?;

        match send_batch(&batches, new).await {
            Some(count) => persisted = count,
            // Actor is gone (plan complete or aborted); nothing left to forward.
            None => return Ok(()),
        }
    }
}

/// Send a batch and await the actor's persisted-count reply. Returns `None` if
/// the actor has gone away.
async fn send_batch(
    batches: &UnboundedSender<FragmentBatch>,
    fragments: Vec<Psbt>,
) -> Option<usize> {
    let (ack, ack_rx) = oneshot::channel();
    if batches.unbounded_send(FragmentBatch { fragments, ack }).is_err() {
        return None;
    }
    ack_rx.await.ok()
}
