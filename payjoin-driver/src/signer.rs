use payjoin::multiparty::Psbt;

/// Signs the accumulated collaborative PSBT on the participant's behalf.
///
/// Once registration balances to zero the driver hands the sorted, ready-to-sign
/// PSBT to this dependency and folds the returned, signed PSBT back into the
/// state machine as witness-broadcast actions. The implementation owns all key
/// material and signing I/O — an in-process key, a hardware wallet, a `bitcoind`
/// `walletprocesspsbt` call — so none of it lives in the driver or the state
/// machine. Like [`CollaborativeMessageSet`](crate::CollaborativeMessageSet) it
/// carries no `Send` bound, so it runs on single-threaded executors too.
#[allow(async_fn_in_trait)]
pub trait Signer {
    /// Key-management or signing failure from the underlying implementation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Sign every input this participant owns in `psbt`, returning the PSBT with
    /// those inputs finalized (each carrying its `final_script_witness`).
    async fn sign(&self, psbt: Psbt) -> Result<Psbt, Self::Error>;
}
