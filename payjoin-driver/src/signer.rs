use payjoin::multiparty::{Plan, Psbt};

/// The participant's wallet: builds its contribution plan and signs the result.
///
/// This dependency owns everything wallet-shaped that the state machine must not:
/// coin selection, output policy, and all key material and signing I/O — an
/// in-process key, a hardware wallet, a `bitcoind` `walletprocesspsbt` call.
///
/// - [`plan`](Self::plan) builds this participant's [`Plan`] — its inputs to
///   register and outputs to fund (assemble one with
///   [`Plan::from_registration`](payjoin::multiparty::Plan::from_registration)).
///   The driver hands it straight to the waiting state machine, so plan
///   construction stays out of the typestate.
/// - [`sign`](Self::sign) finalizes this participant's inputs once registration
///   balances to zero.
///
/// Like [`CollaborativeMessageSet`](crate::CollaborativeMessageSet) it carries no
/// `Send` bound, so it runs on single-threaded executors too.
#[allow(async_fn_in_trait)]
pub trait Signer {
    /// Key-management, coin-selection, or signing failure from the implementation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Build this participant's contribution [`Plan`].
    async fn plan(&self) -> Result<Plan, Self::Error>;

    /// Sign every input this participant owns in `psbt`, returning the PSBT with
    /// those inputs finalized (each carrying its `final_script_witness`).
    async fn sign(&self, psbt: Psbt) -> Result<Psbt, Self::Error>;
}
