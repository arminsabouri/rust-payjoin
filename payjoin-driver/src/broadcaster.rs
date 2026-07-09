/// Broadcasts the finalized collaborative transaction to the bitcoin network.
///
/// Once every participant's witness is in, the accumulated PSBT finalizes and the
/// driver extracts the network transaction
/// ([`final_tx`](payjoin::multiparty::PlanPsbtAccumulator::final_tx)) and hands it
/// to this dependency. The implementation owns all network I/O — a bitcoind
/// `sendrawtransaction`, a p2p connection, an Electrum server — so none of it
/// lives in the driver or the state machine. Like
/// [`Signer`](crate::Signer) it carries no `Send` bound, so it runs on
/// single-threaded executors too.
#[allow(async_fn_in_trait)]
pub trait Broadcaster {
    /// Network or node failure from the underlying implementation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Broadcast the finalized collaborative transaction. Broadcasting is
    /// idempotent — re-broadcasting an already-relayed transaction is a no-op — so
    /// the driver may call this again on resume without harm.
    async fn broadcast(&self, tx: payjoin::bitcoin::Transaction) -> Result<(), Self::Error>;
}
