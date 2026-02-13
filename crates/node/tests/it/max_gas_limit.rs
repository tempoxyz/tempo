//! Tests for per-transaction gas limit caps across hardforks (TIP-1000/1010).
//!
//! Pre-T1: no per-tx gas cap (effectively unlimited).
//! Post-T1 (TIP-1010): per-tx gas limit cap is 30M (`TEMPO_T1_TX_GAS_LIMIT_CAP`).

use alloy::{
    consensus::{SignableTransaction, Transaction, TxEip1559, TxEnvelope},
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_eips::{eip2718::Encodable2718, eip7825::MAX_TX_GAS_LIMIT_OSAKA};
use alloy_network::TxSignerSync;
use alloy_primitives::Bytes;
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

/// Post-T1: a transaction at the Osaka limit (16M) should succeed.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1_tx_at_osaka_limit_succeeds() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).index(0)?.build()?;
    let http_url = setup.node.rpc_url();
    let provider = ProviderBuilder::new().connect_http(http_url);
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(&signer, chain_id, 0, MAX_TX_GAS_LIMIT_OSAKA);
    setup.node.rpc.inject_tx(raw_tx).await?;
    let payload = setup.node.advance_block().await?;

    let block = payload.block();
    let all_txs: Vec<_> = block.body().transactions().cloned().collect();
    let user_txs: Vec<_> = all_txs.into_iter().filter(|tx| tx.gas_limit() > 0).collect();
    assert_eq!(user_txs.len(), 1, "tx at 16M should be included");

    Ok(())
}

/// Post-T1: a transaction between the Osaka limit (16M) and the Tempo cap (30M)
/// should succeed — TIP-1010 raises the per-tx cap to 30M.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1_tx_between_osaka_and_tempo_cap_succeeds() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).index(0)?.build()?;
    let http_url = setup.node.rpc_url();
    let provider = ProviderBuilder::new().connect_http(http_url);
    let chain_id = provider.get_chain_id().await?;

    // 20M gas — above Osaka's 16M, below Tempo's 30M cap
    let gas_limit = 20_000_000;
    let raw_tx = build_tx(&signer, chain_id, 0, gas_limit);
    setup.node.rpc.inject_tx(raw_tx).await?;
    let payload = setup.node.advance_block().await?;

    let block = payload.block();
    let all_txs: Vec<_> = block.body().transactions().cloned().collect();
    let user_txs: Vec<_> = all_txs.into_iter().filter(|tx| tx.gas_limit() > 0).collect();
    assert_eq!(
        user_txs.len(),
        1,
        "tx at 20M should be included (TIP-1010 cap is 30M)"
    );

    Ok(())
}

/// Post-T1: a transaction at exactly the Tempo T1 cap (30M) should succeed.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1_tx_at_tempo_cap_succeeds() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).index(0)?.build()?;
    let http_url = setup.node.rpc_url();
    let provider = ProviderBuilder::new().connect_http(http_url);
    let chain_id = provider.get_chain_id().await?;

    let raw_tx = build_tx(&signer, chain_id, 0, TEMPO_T1_TX_GAS_LIMIT_CAP);
    setup.node.rpc.inject_tx(raw_tx).await?;
    let payload = setup.node.advance_block().await?;

    let block = payload.block();
    let all_txs: Vec<_> = block.body().transactions().cloned().collect();
    let user_txs: Vec<_> = all_txs.into_iter().filter(|tx| tx.gas_limit() > 0).collect();
    assert_eq!(
        user_txs.len(),
        1,
        "tx at Tempo's 30M cap should be included"
    );

    Ok(())
}

/// Post-T1: a transaction exceeding Tempo's 30M cap should be rejected.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1_tx_exceeding_tempo_cap_rejected() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new().wallet(wallet.clone()).connect_http(http_url);
    let chain_id = provider.get_chain_id().await?;

    let over_cap = TEMPO_T1_TX_GAS_LIMIT_CAP + 1;
    let raw_tx = build_tx(&wallet, chain_id, 0, over_cap);

    let result = provider.send_raw_transaction(&raw_tx).await;
    assert!(
        result.is_err(),
        "tx with gas_limit > 30M should be rejected post-T1"
    );

    Ok(())
}

/// Pre-T1 (T0 only): a transaction with gas_limit above 30M should succeed
/// because there is no per-tx gas cap before T1.
#[tokio::test(flavor = "multi_thread")]
async fn test_pre_t1_tx_above_30m_succeeds() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Create a genesis without T1 activated
    let genesis_str = include_str!("../assets/test-genesis.json");
    let mut genesis: serde_json::Value = serde_json::from_str(genesis_str)?;
    genesis["config"].as_object_mut().unwrap().remove("t1Time");
    genesis["config"].as_object_mut().unwrap().remove("t2Time");
    let pre_t1_genesis = serde_json::to_string(&genesis)?;

    let mut setup = TestNodeBuilder::new()
        .with_genesis(pre_t1_genesis)
        .build_with_node_access()
        .await?;

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).index(0)?.build()?;
    let http_url = setup.node.rpc_url();
    let provider = ProviderBuilder::new().connect_http(http_url);
    let chain_id = provider.get_chain_id().await?;

    let gas_limit = 50_000_000;
    let raw_tx = build_tx(&signer, chain_id, 0, gas_limit);
    setup.node.rpc.inject_tx(raw_tx).await?;
    let payload = setup.node.advance_block().await?;

    let block = payload.block();
    let all_txs: Vec<_> = block.body().transactions().cloned().collect();
    let user_txs: Vec<_> = all_txs.into_iter().filter(|tx| tx.gas_limit() > 0).collect();
    assert_eq!(
        user_txs.len(),
        1,
        "pre-T1 should allow tx with gas_limit > 30M"
    );

    Ok(())
}
