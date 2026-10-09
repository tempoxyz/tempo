//! Tests for per-transaction gas limit caps across hardforks ([TIP-1000]/[TIP-1010]).
//!
//! TIP-1010 sets the per-tx gas limit cap to 30M (`TEMPO_T1_TX_GAS_LIMIT_CAP`).
//!
//! [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
//! [TIP-1010]: <https://docs.tempo.xyz/protocol/tips/tip-1010>

use alloy::{primitives::Address, providers::Provider};
use alloy_eips::eip7825::MAX_TX_GAS_LIMIT_OSAKA;
use alloy_primitives::Bytes;
use eyre::WrapErr;
use reth_e2e_test_utils::wallet::Wallet;
use tempo_chainspec::{hardfork::TempoHardfork, spec::TEMPO_T1_TX_GAS_LIMIT_CAP};

use crate::utils::{TestNodeBuilder, make_genesis_at, t1_account};

/// Helper to build and encode a signed EIP-1559 transaction of the first test account with a
/// specific gas limit.
async fn build_tx(chain_id: u64, gas_limit: u64) -> Bytes {
    t1_account(&Wallet::default().with_chain_id(chain_id), 0)
        .tx()
        .to(Address::ZERO)
        .gas_limit(gas_limit)
        .await
}

/// Post-T1A: tx at the Osaka limit (16M) should be accepted by the pool and
/// included in a block.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1a_tx_at_osaka_limit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let provider = setup.node.rpc_provider();
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(chain_id, MAX_TX_GAS_LIMIT_OSAKA).await;
    setup
        .node
        .mine([raw_tx])
        .await
        .wrap_err("tx at 16M should be included in block")?;

    Ok(())
}

/// Post-T1A: tx between the Osaka limit (16M) and Tempo's T1A cap (30M) should
/// be accepted by the pool and included in a block.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1a_tx_above_osaka_below_tempo_cap() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let provider = setup.node.rpc_provider();
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(chain_id, 20_000_000).await;
    setup
        .node
        .mine([raw_tx])
        .await
        .wrap_err("tx at 20M should be included in block (TIP-1010 cap is 30M)")?;

    Ok(())
}

/// Post-T1A: tx at exactly the Tempo T1A cap (30M) should be accepted by the
/// pool and included in a block.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1a_tx_at_tempo_cap() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let provider = setup.node.rpc_provider();
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(chain_id, TEMPO_T1_TX_GAS_LIMIT_CAP).await;
    setup
        .node
        .mine([raw_tx])
        .await
        .wrap_err("tx at Tempo's 30M cap should be included in block")?;

    Ok(())
}

/// Post-T1A: tx exceeding Tempo's 30M cap should be rejected by the pool.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1a_tx_exceeding_tempo_cap() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .with_genesis(make_genesis_at(TempoHardfork::T10))
        .build_with_node_access()
        .await?;
    let provider = setup.node.rpc_provider();
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(chain_id, TEMPO_T1_TX_GAS_LIMIT_CAP + 1).await;
    let result = provider.send_raw_transaction(&raw_tx).await;
    assert!(
        result.is_err(),
        "tx with gas_limit > 30M should be rejected post-T1A"
    );

    Ok(())
}
