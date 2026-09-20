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
    let key_auth = KeyAuthorization::unrestricted(
        chain_id,
        tempo_primitives::SignatureType::Secp256k1,
        Address::random(),
    );
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
        valid_before: None,
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
        err_msg.contains("KeyAlreadyExists"),
        "Post-T1B: replay error must be KeyAlreadyExists, got: {err_msg}"
    );

    Ok(())
}
