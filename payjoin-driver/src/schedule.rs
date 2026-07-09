use futures::Stream;
use payjoin::multiparty::Plan;

/// A time source that paces a participant plan's outbound actions.
///
/// The plan assigns each action a `send_at` offset (a Poisson arrival schedule).
/// This trait turns those relative offsets into a stream of "the next action is
/// due" signals, so the driver posts actions on a jittered cadence rather than
/// as fast as it can read the mailbox.
///
/// The implementation owns all clock and timer access — `now()` and the sleep
/// primitive — so the driver (and the `payjoin` state machine) stay time-free
/// and runtime-agnostic. On `wasm32` back it with `gloo-timers`/`web_time`; on a
/// tokio runtime with `tokio::time`.
#[allow(async_fn_in_trait)]
pub trait Schedule {
    /// Timer/clock failure from the underlying implementation.
    type Error: std::error::Error + Send + Sync + 'static;
    /// The stream returned by [`due_actions`](Self::due_actions).
    type DueActions<'a>: Stream<Item = Result<usize, Self::Error>> + Unpin + 'a
    where
        Self: 'a;

    /// Stream of plan indices that have become due to broadcast.
    ///
    /// Yields indices `from_cursor..plan.len()` in order, each once its `send_at`
    /// offset — measured relative to `from_cursor`, so a resumed plan waits only
    /// the remaining gaps — has elapsed since the stream was created. While the
    /// next action is not yet due the stream returns
    /// [`futures::task::Poll::Pending`] so other driver work can run. The stream
    /// completes (`None`) once every action from `from_cursor` onward is due.
    ///
    /// The yielded index is a timing signal only; the state machine remains the
    /// authority on *which* fragment to post (via `next_action_fragment`).
    ///
    /// The driver polls this stream under a `select` alongside mailbox reads, so
    /// the pending `poll_next` is repeatedly dropped and re-created. An
    /// implementation must therefore key its wake-up on an absolute deadline
    /// (anchor + offset) recomputed against `now()` each poll, not on a relative
    /// sleep started inside `poll_next` — otherwise the timer would restart every
    /// time a read completes first.
    fn due_actions(&self, plan: &Plan, from_cursor: usize) -> Self::DueActions<'_>;
}
