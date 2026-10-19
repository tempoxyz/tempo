use alloy_primitives::U256;
use reth_node_core::args::{DefaultRpcServerArgs, DefaultTxPoolValues, GasPriceOracleArgs};

/// Match Tempo's per-account pool capacity so independent expiring-nonce
/// transactions from one Zone account are not constrained by Reth's default.
const MAX_ACCOUNT_SLOTS: usize = 150_000;

pub(crate) fn init_defaults() {
    DefaultTxPoolValues::default()
        .with_max_account_slots(MAX_ACCOUNT_SLOTS)
        .try_init()
        .expect("failed to initialize transaction pool defaults");

    DefaultRpcServerArgs::default()
        .with_gas_price_oracle(GasPriceOracleArgs {
            // Match Tempo's gas oracle defaults so zero-tip transactions are sampled.
            ignore_price: 0,
            default_suggested_fee: Some(U256::ZERO),
            ..Default::default()
        })
        .try_init()
        .expect("failed to initialize RPC defaults");
}
