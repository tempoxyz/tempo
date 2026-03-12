//! Regression test for zeroed `from`/`to` in callTracer output for AA (type 0x76) transactions.
//!
//! When `debug_traceTransaction` is called with the `callTracer` on a type 0x76 transaction,
//! the top-level call frame currently shows `from: 0x0` and `to: 0x0` because the multi-call
//! execution path doesn't emit a root-level EVM call with the actual sender/recipient.
//!
//! The real addresses only appear nested inside `calls[]`, which is confusing for consumers
//! expecting the same shape as standard transaction traces.
//!
//! See: <https://tempoxyz.slack.com/archives/C09BJKXFX4P/p1773319887086959>

use crate::utils::{ForkSchedule, TestNodeBuilder};
use alloy::{
    network::Ethereum,
    primitives::{Address, Bytes, U256},
    providers::{Provider, RootProvider},
    signers::{SignerSync, local::MnemonicBuilder},
};
use alloy_eips::Encodable2718;
use reth_primitives_traits::transaction::TxHashRef;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::tempo_transaction::Call,
};

/// Sends a basic AA transaction and traces it with `callTracer`, asserting the
/// top-level `from` and `to` are NOT zero addresses.
///
/// Currently fails — the root call frame has `from: 0x0` / `to: 0x0`.
#[tokio::test(flavor = "multi_thread")]
async fn test_debug_trace_aa_tx_call_tracer_has_correct_from_to() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new()
        .with_schedule(ForkSchedule::Devnet)
        .build_with_node_access()
        .await?;
    let provider: RootProvider<Ethereum> =
        RootProvider::new_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let sender = signer.address();

    let recipient = Address::random();

    // Build a simple AA transaction: single call transferring 0 value
    let nonce = provider.get_transaction_count(sender).await?;
    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: None,
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    // Sign and encode
    let sig_hash = tx.signature_hash();
    let signature = signer.sign_hash_sync(&sig_hash)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);
    let tx_hash = *envelope.tx_hash();

    // Submit and mine
    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    // Verify receipt exists and succeeded
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;
    let receipt = receipt.expect("receipt should exist");
    assert_eq!(
        receipt["status"].as_str(),
        Some("0x1"),
        "AA tx should succeed"
    );

    // Call debug_traceTransaction with callTracer
    let trace: serde_json::Value = provider
        .raw_request(
            "debug_traceTransaction".into(),
            (
                tx_hash,
                serde_json::json!({
                    "tracer": "callTracer"
                }),
            ),
        )
        .await?;

    println!("callTracer output:\n{}", serde_json::to_string_pretty(&trace)?);

    // The top-level frame should have the actual sender as `from`
    let trace_from = trace["from"]
        .as_str()
        .expect("trace should have 'from' field");
    let trace_to = trace["to"]
        .as_str()
        .expect("trace should have 'to' field");

    let trace_from_addr: Address = trace_from.parse().expect("from should be valid address");
    let trace_to_addr: Address = trace_to.parse().expect("to should be valid address");

    // BUG: Currently both are 0x0 for AA transactions.
    // After fix, `from` should be the AA sender and `to` should be the first call's target.
    assert_ne!(
        trace_from_addr,
        Address::ZERO,
        "Top-level 'from' should be the AA sender ({sender}), not zero address. \
         Got: {trace_from}"
    );
    assert_ne!(
        trace_to_addr,
        Address::ZERO,
        "Top-level 'to' should be the call target ({recipient}), not zero address. \
         Got: {trace_to}"
    );

    // Verify the addresses match the actual sender/recipient
    assert_eq!(
        trace_from_addr, sender,
        "Top-level 'from' should match the AA sender"
    );
    assert_eq!(
        trace_to_addr, recipient,
        "Top-level 'to' should match the call recipient"
    );

    // Verify nested calls exist (the actual execution happens there today)
    if let Some(calls) = trace["calls"].as_array() {
        assert!(
            !calls.is_empty(),
            "Trace should have nested calls for AA transaction"
        );
    }

    Ok(())
}

/// Same test but with multiple calls in the AA batch.
/// Verifies the top-level frame represents the "wrapper" correctly even with >1 call.
#[tokio::test(flavor = "multi_thread")]
async fn test_debug_trace_aa_tx_multi_call_tracer() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new()
        .with_schedule(ForkSchedule::Devnet)
        .build_with_node_access()
        .await?;
    let provider: RootProvider<Ethereum> =
        RootProvider::new_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let sender = signer.address();

    let recipient_a = Address::random();
    let recipient_b = Address::random();

    let nonce = provider.get_transaction_count(sender).await?;
    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![
            Call {
                to: recipient_a.into(),
                value: U256::ZERO,
                input: Bytes::new(),
            },
            Call {
                to: recipient_b.into(),
                value: U256::ZERO,
                input: Bytes::new(),
            },
        ],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: None,
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    let sig_hash = tx.signature_hash();
    let signature = signer.sign_hash_sync(&sig_hash)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);
    let tx_hash = *envelope.tx_hash();

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;
    let receipt = receipt.expect("receipt should exist");
    assert_eq!(receipt["status"].as_str(), Some("0x1"));

    let trace: serde_json::Value = provider
        .raw_request(
            "debug_traceTransaction".into(),
            (
                tx_hash,
                serde_json::json!({
                    "tracer": "callTracer"
                }),
            ),
        )
        .await?;

    println!(
        "Multi-call callTracer output:\n{}",
        serde_json::to_string_pretty(&trace)?
    );

    let trace_from: Address = trace["from"]
        .as_str()
        .expect("trace should have 'from'")
        .parse()?;

    // Top-level from should be the AA sender, not zero
    assert_ne!(
        trace_from,
        Address::ZERO,
        "Top-level 'from' must not be zero for multi-call AA tx"
    );
    assert_eq!(
        trace_from, sender,
        "Top-level 'from' should be the AA sender"
    );

    // With multiple calls, the nested calls[] should contain both sub-calls
    let calls = trace["calls"]
        .as_array()
        .expect("multi-call trace should have nested calls");
    assert!(
        calls.len() >= 2,
        "Should have at least 2 nested calls for a 2-call AA batch, got {}",
        calls.len()
    );

    Ok(())
}
