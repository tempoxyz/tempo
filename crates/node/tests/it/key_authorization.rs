use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::MnemonicBuilder},
};
use alloy_eips::Encodable2718;
use alloy_primitives::TxKind;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, ITIP20};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{
        KeyAuthorization,
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature},
    },
};

/// Build a CREATE+KeyAuthorization tx with configurable priority fee.
///
/// gas_limit=1,050,000 passes intrinsic validation (~801k on T1) but leaves
/// ~249k for the keychain precompile — just below the 250k SSTORE cost → OOG.
fn build_create_key_auth_tx(
    signer: &impl SignerSync,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    max_priority_fee_per_gas: u128,
) -> eyre::Result<Vec<u8>> {
    let key_auth = KeyAuthorization {
        chain_id,
        key_type: tempo_primitives::SignatureType::Secp256k1,
        key_id: Address::random(),
        expiry: None,
        limits: None,
    };
    let sig = signer.sign_hash_sync(&key_auth.signature_hash())?;
    let signed_key_auth = key_auth.into_signed(PrimitiveSignature::Secp256k1(sig));

    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas,
        max_fee_per_gas: core::cmp::max(max_priority_fee_per_gas, TEMPO_T1_BASE_FEE as u128),
        gas_limit,
        calls: vec![Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::from_static(&[
                0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
            ]),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        valid_before: Some(u64::MAX),
        key_authorization: Some(signed_key_auth),
        ..Default::default()
    };

    let tx_sig = signer.sign_hash_sync(&tx.signature_hash())?;
    let envelope: TempoTxEnvelope = tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            tx_sig,
        )))
        .into();

    Ok(envelope.encoded_2718())
}

/// Build a simple CALL tx using 2D nonce (avoids protocol nonce conflicts).
fn build_2d_nonce_transfer_tx(
    signer: &impl SignerSync,
    chain_id: u64,
    nonce_key: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
) -> eyre::Result<Vec<u8>> {
    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas,
        max_fee_per_gas: core::cmp::max(max_priority_fee_per_gas, TEMPO_T1_BASE_FEE as u128),
        // 21k base + 250k new_account_cost (2D nonce with nonce=0 creates account) + margin
        gas_limit: 300_000,
        calls: vec![Call {
            to: TxKind::Call(Address::repeat_byte(0x42)),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::from(nonce_key),
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    let tx_sig = signer.sign_hash_sync(&tx.signature_hash())?;
    let envelope: TempoTxEnvelope = tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            tx_sig,
        )))
        .into();

    Ok(envelope.encoded_2718())
}

fn make_pre_t1b_genesis() -> eyre::Result<String> {
    let genesis_str = include_str!("../assets/test-genesis.json");
    let mut genesis: serde_json::Value = serde_json::from_str(genesis_str)?;
    genesis["config"].as_object_mut().unwrap().remove("t1bTime");
    genesis["config"].as_object_mut().unwrap().remove("t2Time");
    Ok(serde_json::to_string(&genesis)?)
}

/// Pre-T1B fee-drain replay: the poisoned KeyAuth CREATE tx is followed by a
/// normal tx in the same block. The normal tx's `validate()` overwrites
/// `evm.initial_gas`, so the system tx succeeds and the block is produced.
///
/// The poisoned tx burns the full gas_limit as fees but does NOT bump the
/// protocol nonce (CREATE nonce only bumps in `make_create_frame`, never
/// reached due to OOG). This means:
///   - Fees are burned each block the tx is included in
///   - The exact same signed bytes can be resubmitted (nonce unchanged)
///   - Repeatable across multiple blocks → fee drain
///
/// The test submits the same poisoned tx across two blocks and asserts that
/// fees are drained each time while the nonce never advances.
#[tokio::test(flavor = "multi_thread")]
async fn test_pre_t1b_keyauth_oog_replay() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new()
        .with_genesis(make_pre_t1b_genesis()?)
        .build_with_node_access()
        .await?;

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let signer_addr = signer.address();
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());

    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(signer_addr).await?;

    let balance_before = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(signer_addr)
        .call()
        .await?;

    // Poisoned tx: high priority fee so it sorts FIRST (before the trailing tx).
    let poisoned_tx = build_create_key_auth_tx(
        &signer,
        chain_id,
        nonce,
        1_050_000,
        (TEMPO_T1_BASE_FEE * 2) as u128,
    )?;

    // ── Block 1 ──────────────────────────────────────────────────────────
    // Trailing tx (low priority) resets evm.initial_gas so system tx succeeds.
    let trailing_tx_1 = build_2d_nonce_transfer_tx(
        &signer,
        chain_id,
        1, // nonce_key=1
        0, // first tx on this 2D nonce
        TEMPO_T1_BASE_FEE as u128,
    )?;

    let _ = provider.send_raw_transaction(&poisoned_tx).await?;
    let _ = provider.send_raw_transaction(&trailing_tx_1).await?;

    setup.node.advance_block().await?;

    // Fees burned — block produced with both txs.
    let balance_after_block1 = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(signer_addr)
        .call()
        .await?;
    assert!(
        balance_after_block1 < balance_before,
        "Block 1: fees must be burned"
    );

    // Protocol nonce NOT bumped — poisoned tx's CREATE frame was never reached.
    let nonce_after_block1 = provider.get_transaction_count(signer_addr).await?;
    assert_eq!(
        nonce_after_block1, nonce,
        "Block 1: protocol nonce must NOT be bumped — CREATE frame never reached"
    );

    // ── Block 2 — replay the exact same poisoned tx bytes ────────────────
    // Since the protocol nonce didn't advance, the same signed payload is valid.
    let trailing_tx_2 = build_2d_nonce_transfer_tx(
        &signer,
        chain_id,
        2, // different nonce_key to avoid replay on the 2D nonce
        0,
        TEMPO_T1_BASE_FEE as u128,
    )?;

    let _ = provider.send_raw_transaction(&poisoned_tx).await?;
    let _ = provider.send_raw_transaction(&trailing_tx_2).await?;

    setup.node.advance_block().await?;

    // More fees drained on the second block.
    let balance_after_block2 = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(signer_addr)
        .call()
        .await?;
    assert!(
        balance_after_block2 < balance_after_block1,
        "Block 2: more fees drained — same tx replayed"
    );

    // Protocol nonce STILL not bumped — same signed payload remains valid forever.
    let nonce_after_block2 = provider.get_transaction_count(signer_addr).await?;
    assert_eq!(
        nonce_after_block2, nonce,
        "Block 2: protocol nonce still not bumped — indefinitely replayable"
    );

    Ok(())
}

/// Pre-T1B single poisoned tx: the poisoned KeyAuth CREATE tx is the only
/// user tx in the block. The block still produces (the builder skips the
/// invalid tx or handles the OOG gracefully), but the protocol nonce is
/// NOT bumped — the signed tx remains valid in the pool indefinitely.
#[tokio::test(flavor = "multi_thread")]
async fn test_pre_t1b_keyauth_oog_single_tx_nonce_not_bumped() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new()
        .with_genesis(make_pre_t1b_genesis()?)
        .build_with_node_access()
        .await?;

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let signer_addr = signer.address();
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());

    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(signer_addr).await?;

    // Single poisoned tx — no trailing tx.
    let encoded = build_create_key_auth_tx(
        &signer,
        chain_id,
        nonce,
        1_050_000,
        TEMPO_T1_BASE_FEE as u128,
    )?;

    let _ = provider.send_raw_transaction(&encoded).await?;

    // Block is produced — the builder handles the poisoned tx gracefully.
    setup.node.advance_block().await?;

    // Protocol nonce NOT bumped — CREATE frame was never reached.
    let nonce_after = provider.get_transaction_count(signer_addr).await?;
    assert_eq!(
        nonce_after, nonce,
        "Pre-T1B: protocol nonce must NOT be bumped — CREATE frame never reached"
    );

    Ok(())
}

/// Post-T1B: the same CREATE+KeyAuth tx that causes DoS/fee-drain on pre-T1B
/// works correctly. The precompile runs with unlimited gas → no OOG →
/// `evm.initial_gas` is never set to `u64::MAX` → block produces normally.
/// Nonce is bumped and fees are burned, so replay is rejected.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_t1b_keyauth_oog_fixed() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let signer_addr = signer.address();
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());

    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(signer_addr).await?;

    let balance_before = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(signer_addr)
        .call()
        .await?;

    // Same gas_limit that triggers OOG on pre-T1B. On T1B+ the precompile
    // runs with unlimited gas so it never OOGs.
    let encoded = build_create_key_auth_tx(
        &signer,
        chain_id,
        nonce,
        1_050_000,
        TEMPO_T1_BASE_FEE as u128,
    )?;

    let _ = provider.send_raw_transaction(&encoded).await?;

    // Block MUST be produced.
    setup.node.advance_block().await?;

    // Fees burned.
    let balance_after = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(signer_addr)
        .call()
        .await?;
    assert!(
        balance_after < balance_before,
        "Post-T1B: fees must be burned"
    );

    // Nonce bumped — make_create_frame reached, CREATE address consumed.
    let nonce_after = provider.get_transaction_count(signer_addr).await?;
    assert_eq!(nonce_after, nonce + 1, "Post-T1B: nonce must be bumped");

    // Replay rejected — nonce already advanced.
    let replay_err = provider
        .send_raw_transaction(&encoded)
        .await
        .expect_err("Post-T1B: replay must be rejected");
    let err_msg = replay_err.to_string();
    assert!(
        err_msg.contains("nonce too low: next nonce 1, tx nonce 0"),
        "Post-T1B: replay error must be nonce-too-low, got: {err_msg}"
    );

    Ok(())
}
