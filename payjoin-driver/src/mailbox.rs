use futures::Stream;

/// An append-only broadcast channel shared by session participants.
#[allow(async_fn_in_trait)]
pub trait CollaborativeMessageSet {
    /// A message written to / read from the mailbox (e.g. a serialized fragment).
    type Message;
    /// Transport/crypto failure from the underlying implementation.
    type Error: std::error::Error + Send + Sync + 'static;
    /// The stream returned by [`read`](Self::read).
    type Messages<'a>: Stream<Item = Result<Self::Message, Self::Error>> + 'a
    where
        Self: 'a;

    /// Append one complete message.
    async fn write(&self, message: Self::Message) -> Result<(), Self::Error>;

    /// Read all messages from the beginning in server-determined order.
    fn read(&self) -> Self::Messages<'_>;
}
