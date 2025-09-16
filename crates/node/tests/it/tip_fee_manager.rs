use alloy::{
    primitives::U256,
    providers::ProviderBuilder,
    signers::local::{MnemonicBuilder, coins_bip39::English},
    sol_types::SolEvent,
};
use alloy_primitives::Address;
use std::env;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        tip_fee_manager::amm::{MIN_LIQUIDITY, PoolKey, sqrt},
        types::{IFeeManager, ITIP20, ITIPFeeAMM},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn test_set_user_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    todo!();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_set_validator_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    todo!();
    Ok(())
}
