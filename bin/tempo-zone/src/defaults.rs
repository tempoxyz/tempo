use reth_node_core::args::DefaultTxPoolValues;

/// Match Tempo's per-account pool capacity so independent expiring-nonce
/// transactions from one Zone account are not constrained by Reth's default.
const MAX_ACCOUNT_SLOTS: usize = 150_000;

pub(crate) fn init_defaults() {
    DefaultTxPoolValues::default()
        .with_max_account_slots(MAX_ACCOUNT_SLOTS)
        .try_init()
        .expect("failed to initialize transaction pool defaults");
}
