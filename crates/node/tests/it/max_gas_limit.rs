//! Tests for per-transaction gas limit caps across hardforks (TIP-1000/1010).
//!
//! Pre-T1A: EIP-7825 Osaka limit (16,777,216 gas).
//! Post-T1A (TIP-1010): per-tx gas limit cap is 30M (`TEMPO_T1_TX_GAS_LIMIT_CAP`).

use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_eips::{eip2718::Encodable2718, eip7825::MAX_TX_GAS_LIMIT_OSAKA};
use alloy_network::TxSignerSync;
use alloy_primitives::Bytes;
use reth_primitives_traits::transaction::TxHashRef;
use tempo_chainspec::spec::{TEMPO_T1_BASE_FEE, TEMPO_T1_TX_GAS_LIMIT_CAP};

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};

/// Helper to build and encode a signed EIP-1559 transaction with a specific gas limit.
fn build_tx(
    signer: &alloy::signers::local::PrivateKeySigner,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
) -> Bytes {
    let mut tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        to: Address::ZERO.into(),
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        ..Default::default()
    };
    let signature = signer.sign_transaction_sync(&mut tx).unwrap();
    TxEnvelope::Eip1559(tx.into_signed(signature))
        .encoded_2718()
        .into()
}

/// Post-T1A: tx at the Osaka limit (16M) should be accepted by the pool and
/// included in a block.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1a_tx_at_osaka_limit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(&signer, chain_id, 0, MAX_TX_GAS_LIMIT_OSAKA);
    let pending = provider.send_raw_transaction(&raw_tx).await?;
    let expected_hash = *pending.tx_hash();
    let payload = setup.node.advance_block().await?;

    let included = payload
        .block()
        .body()
        .transactions()
        .any(|tx| *tx.tx_hash() == expected_hash);
    assert!(included, "tx at 16M should be included in block");

    Ok(())
}

/// Post-T1A: tx between the Osaka limit (16M) and Tempo's T1A cap (30M) should
/// be accepted by the pool and included in a block.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1a_tx_above_osaka_below_tempo_cap() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(&signer, chain_id, 0, 20_000_000);
    let pending = provider.send_raw_transaction(&raw_tx).await?;
    let expected_hash = *pending.tx_hash();
    let payload = setup.node.advance_block().await?;

    let included = payload
        .block()
        .body()
        .transactions()
        .any(|tx| *tx.tx_hash() == expected_hash);
    assert!(
        included,
        "tx at 20M should be included in block (TIP-1010 cap is 30M)"
    );

    Ok(())
}

/// Post-T1A: tx at exactly the Tempo T1A cap (30M) should be accepted by the
/// pool and included in a block.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1a_tx_at_tempo_cap() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(&signer, chain_id, 0, TEMPO_T1_TX_GAS_LIMIT_CAP);
    let pending = provider.send_raw_transaction(&raw_tx).await?;
    let expected_hash = *pending.tx_hash();
    let payload = setup.node.advance_block().await?;

    let included = payload
        .block()
        .body()
        .transactions()
        .any(|tx| *tx.tx_hash() == expected_hash);
    assert!(
        included,
        "tx at Tempo's 30M cap should be included in block"
    );

    Ok(())
}

/// Post-T1A: tx exceeding Tempo's 30M cap should be rejected by the pool.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1a_tx_exceeding_tempo_cap() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(&signer, chain_id, 0, TEMPO_T1_TX_GAS_LIMIT_CAP + 1);
    let result = provider.send_raw_transaction(&raw_tx).await;
    assert!(
        result.is_err(),
        "tx with gas_limit > 30M should be rejected post-T1A"
    );

    Ok(())
}

/// Pre-T1A (T0 only): tx at the Osaka limit (16M) should be accepted.
#[tokio::test(flavor = "multi_thread")]
async fn test_pre_t1a_tx_at_osaka_limit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let genesis_str = include_str!("../assets/test-genesis.json");
    let mut genesis: serde_json::Value = serde_json::from_str(genesis_str)?;
    genesis["config"].as_object_mut().unwrap().remove("t1Time");
    genesis["config"].as_object_mut().unwrap().remove("t1aTime");
    genesis["config"].as_object_mut().unwrap().remove("t1bTime");
    genesis["config"].as_object_mut().unwrap().remove("t2Time");
    let pre_t1a_genesis = serde_json::to_string(&genesis)?;

    let mut setup = TestNodeBuilder::new()
        .with_genesis(pre_t1a_genesis)
        .build_with_node_access()
        .await?;

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(&signer, chain_id, 0, MAX_TX_GAS_LIMIT_OSAKA);
    let pending = provider.send_raw_transaction(&raw_tx).await?;
    let expected_hash = *pending.tx_hash();
    let payload = setup.node.advance_block().await?;

    let included = payload
        .block()
        .body()
        .transactions()
        .any(|tx| *tx.tx_hash() == expected_hash);
    assert!(included, "pre-T1A should accept tx at Osaka limit (16M)");

    Ok(())
}

/// Pre-T1A (T0 only): tx above the Osaka limit (16M) should be rejected.
#[tokio::test(flavor = "multi_thread")]
async fn test_pre_t1a_tx_above_osaka_limit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let genesis_str = include_str!("../assets/test-genesis.json");
    let mut genesis: serde_json::Value = serde_json::from_str(genesis_str)?;
    genesis["config"].as_object_mut().unwrap().remove("t1Time");
    genesis["config"].as_object_mut().unwrap().remove("t1aTime");
    genesis["config"].as_object_mut().unwrap().remove("t1bTime");
    genesis["config"].as_object_mut().unwrap().remove("t2Time");
    let pre_t1a_genesis = serde_json::to_string(&genesis)?;

    let setup = TestNodeBuilder::new()
        .with_genesis(pre_t1a_genesis)
        .build_with_node_access()
        .await?;

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(&signer, chain_id, 0, MAX_TX_GAS_LIMIT_OSAKA + 1);
    let result = provider.send_raw_transaction(&raw_tx).await;
    assert!(
        result.is_err(),
        "pre-T1A should reject tx above Osaka limit (16M)"
    );

    Ok(())
}
