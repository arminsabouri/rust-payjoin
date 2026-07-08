use futures::Stream;

/// An append-only broadcast channel shared by session participants.
#[allow(async_fn_in_trait)]
pub trait CollaborativeMessageSet {
    /// A message written to / read from the mailbox (e.g. a serialized fragment).
    type Message;
    /// Transport/crypto failure from the underlying implementation.
    type Error: std::error::Error + Send + Sync + 'static;
    /// The stream returned by [`read`](Self::read).
    type Messages<'a>: Stream<Item = Result<Vec<Self::Message>, Self::Error>> + Unpin + 'a
    where
        Self: 'a;

    /// Append one complete message.
    async fn write(&self, message: Self::Message) -> Result<(), Self::Error>;

    /// Stream of read rounds over the mailbox.
    ///
    /// Each item is every message returned by one long-poll. An empty vector
    /// means nothing new yet; the driver should keep going and poll again. While
    /// a round is in flight the stream returns
    /// [`futures::task::Poll::Pending`], so other work can run between polls.
    fn read(&self) -> Self::Messages<'_>;
}
