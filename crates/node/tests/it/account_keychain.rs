//! Integration tests for AccountKeychain precompile
//!
//! These tests verify the transaction context enforcement (TEMPO-KEY20):
//! - Only Root Keys can call `authorizeKey`, `revokeKey`, `updateSpendingLimit`
//! - Access Keys attempting these operations receive `UnauthorizedCaller`

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::MnemonicBuilder},
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use reth_primitives_traits::transaction::TxHashRef;
use sha2::{Digest, Sha256};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    account_keychain::{SignatureType, authorizeKeyCall, revokeKeyCall, updateSpendingLimitCall},
};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{
        KeyAuthorization, SignedKeyAuthorization, TokenLimit,
        tempo_transaction::Call,
        tt_signature::{
            KeychainSignature, P256SignatureWithPreHash, PrimitiveSignature, TempoSignature,
            derive_p256_address, normalize_p256_s,
        },
        tt_signed::AASigned,
    },
};

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};

/// Helper to generate a P256 access key
fn generate_p256_access_key() -> (
    p256::ecdsa::SigningKey,
    B256,
    B256,
    Address,
) {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = B256::from_slice(encoded_point.x().unwrap().as_slice());
    let pub_key_y = B256::from_slice(encoded_point.y().unwrap().as_slice());
    let key_addr = derive_p256_address(&pub_key_x, &pub_key_y);
    (signing_key, pub_key_x, pub_key_y, key_addr)
}

/// Helper to create a key authorization
fn create_key_authorization(
    root_signer: &impl SignerSync,
    access_key_addr: Address,
    access_key_signature: TempoSignature,
    chain_id: u64,
    expiry: Option<u64>,
    spending_limits: Option<Vec<TokenLimit>>,
) -> eyre::Result<SignedKeyAuthorization> {
    let key_type = access_key_signature.signature_type();

    let key_auth = KeyAuthorization {
        chain_id,
        key_type,
        key_id: access_key_addr,
        expiry,
        limits: spending_limits,
    };

    let root_auth_signature = root_signer.sign_hash_sync(&key_auth.signature_hash())?;

    Ok(key_auth.into_signed(PrimitiveSignature::Secp256k1(root_auth_signature)))
}

/// Helper to sign AA transaction with P256 access key (wrapped in Keychain signature)
fn sign_aa_tx_with_p256_access_key(
    tx: &TempoTransaction,
    access_key_signing_key: &p256::ecdsa::SigningKey,
    access_pub_key_x: &B256,
    access_pub_key_y: &B256,
    root_key_addr: Address,
) -> eyre::Result<TempoSignature> {
    let sig_hash = tx.signature_hash();
    let pre_hashed = Sha256::digest(sig_hash.as_slice());
    let p256_signature: p256::ecdsa::Signature =
        access_key_signing_key.sign_prehash(&pre_hashed)?;
    let sig_bytes = p256_signature.to_bytes();

    let inner_signature = PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: B256::from_slice(&sig_bytes[0..32]),
        s: normalize_p256_s(&sig_bytes[32..64]),
        pub_key_x: *access_pub_key_x,
        pub_key_y: *access_pub_key_y,
        pre_hash: true,
    });

    Ok(TempoSignature::Keychain(KeychainSignature::new(
        root_key_addr,
        inner_signature,
    )))
}

/// Helper to create a mock P256 signature for key authorization
fn create_mock_p256_sig(pub_key_x: B256, pub_key_y: B256) -> TempoSignature {
    TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: B256::ZERO,
        s: B256::ZERO,
        pub_key_x,
        pub_key_y,
        pre_hash: false,
    }))
}

/// Test TEMPO-KEY20: Access key cannot call `revokeKey`
///
/// This test verifies that when an access key signs a transaction that calls
/// `revokeKey`, the transaction is included but reverts with `UnauthorizedCaller`.
#[tokio::test]
async fn test_access_key_cannot_revoke_key() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    println!("\n=== Test: Access Key Cannot Revoke Key (TEMPO-KEY20) ===\n");

    // Step 1: Generate and authorize an access key using root key
    let (access_key_signing, pub_x, pub_y, access_key_addr) = generate_p256_access_key();
    println!("Generated access key: {access_key_addr}");

    let mock_p256_sig = create_mock_p256_sig(pub_x, pub_y);

    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        mock_p256_sig,
        chain_id,
        None, // Never expires
        Some(vec![TokenLimit {
            token: DEFAULT_FEE_TOKEN,
            limit: U256::from(10u64) * U256::from(10).pow(U256::from(18)),
        }]),
    )?;

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Authorize the access key with root key
    let auth_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 400_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: Some(key_auth),
        tempo_authorization_list: vec![],
    };

    let sig_hash = auth_tx.signature_hash();
    let signature = root_signer.sign_hash_sync(&sig_hash)?;
    let signed_tx = AASigned::new_unhashed(
        auth_tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;
    nonce += 1;
    println!("✓ Access key authorized");

    // Step 2: Try to call revokeKey using the access key (should fail)
    let revoke_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: revokeKeyCall {
                keyId: access_key_addr,
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    let access_sig = sign_aa_tx_with_p256_access_key(
        &revoke_tx,
        &access_key_signing,
        &pub_x,
        &pub_y,
        root_addr,
    )?;

    let signed_tx = AASigned::new_unhashed(revoke_tx, access_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);
    let tx_hash = *envelope.tx_hash();

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    // Check that the transaction reverted
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;

    let receipt_json = receipt.expect("Transaction must be included in block");
    let status = receipt_json
        .get("status")
        .and_then(|v| v.as_str())
        .expect("Receipt must have status field");

    assert_eq!(
        status, "0x0",
        "TEMPO-KEY20: Access key calling revokeKey must revert with UnauthorizedCaller"
    );

    println!("✓ revokeKey correctly reverted when called by access key");
    println!("\n=== TEMPO-KEY20 revokeKey Test Passed ===");

    Ok(())
}

/// Test TEMPO-KEY20: Access key cannot directly call `authorizeKey`
///
/// This test verifies that when an access key signs a transaction that calls
/// `authorizeKey` directly (not via key_authorization), the transaction reverts.
#[tokio::test]
async fn test_access_key_cannot_authorize_key_directly() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    println!("\n=== Test: Access Key Cannot Authorize Key Directly (TEMPO-KEY20) ===\n");

    // Step 1: Generate and authorize an access key using root key
    let (access_key_signing, pub_x, pub_y, access_key_addr) = generate_p256_access_key();
    println!("Generated access key 1: {access_key_addr}");

    let mock_p256_sig = create_mock_p256_sig(pub_x, pub_y);

    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        mock_p256_sig,
        chain_id,
        None, // Never expires
        Some(vec![TokenLimit {
            token: DEFAULT_FEE_TOKEN,
            limit: U256::from(10u64) * U256::from(10).pow(U256::from(18)),
        }]),
    )?;

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Authorize access key 1 with root key
    let auth_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 400_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: Some(key_auth),
        tempo_authorization_list: vec![],
    };

    let sig_hash = auth_tx.signature_hash();
    let signature = root_signer.sign_hash_sync(&sig_hash)?;
    let signed_tx = AASigned::new_unhashed(
        auth_tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;
    nonce += 1;
    println!("✓ Access key 1 authorized");

    // Step 2: Generate a second key that we'll try to authorize via access key
    let (_, _pub_x_2, _pub_y_2, access_key_addr_2) = generate_p256_access_key();
    println!("Generated access key 2: {access_key_addr_2}");

    // Step 3: Try to directly call authorizeKey using access key 1 (should fail)
    let authorize_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: authorizeKeyCall {
                keyId: access_key_addr_2,
                signatureType: SignatureType::P256,
                expiry: u64::MAX,
                enforceLimits: false,
                limits: vec![],
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    let access_sig = sign_aa_tx_with_p256_access_key(
        &authorize_tx,
        &access_key_signing,
        &pub_x,
        &pub_y,
        root_addr,
    )?;

    let signed_tx = AASigned::new_unhashed(authorize_tx, access_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);
    let tx_hash = *envelope.tx_hash();

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    // Check that the transaction reverted
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;

    let receipt_json = receipt.expect("Transaction must be included in block");
    let status = receipt_json
        .get("status")
        .and_then(|v| v.as_str())
        .expect("Receipt must have status field");

    assert_eq!(
        status, "0x0",
        "TEMPO-KEY20: Access key calling authorizeKey directly must revert with UnauthorizedCaller"
    );

    println!("✓ authorizeKey correctly reverted when called directly by access key");
    println!("\n=== TEMPO-KEY20 authorizeKey Test Passed ===");

    Ok(())
}

/// Test TEMPO-KEY20: Access key cannot call `updateSpendingLimit`
///
/// This verifies that access keys cannot modify their own spending limits.
#[tokio::test]
async fn test_access_key_cannot_update_spending_limit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    println!("\n=== Test: Access Key Cannot Update Spending Limit (TEMPO-KEY20) ===\n");

    // Step 1: Generate and authorize an access key using root key
    let (access_key_signing, pub_x, pub_y, access_key_addr) = generate_p256_access_key();
    println!("Generated access key: {access_key_addr}");

    let mock_p256_sig = create_mock_p256_sig(pub_x, pub_y);

    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        mock_p256_sig,
        chain_id,
        None, // Never expires
        Some(vec![TokenLimit {
            token: DEFAULT_FEE_TOKEN,
            limit: U256::from(5u64) * U256::from(10).pow(U256::from(18)),
        }]),
    )?;

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Authorize the access key with root key
    let auth_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 400_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: Some(key_auth),
        tempo_authorization_list: vec![],
    };

    let sig_hash = auth_tx.signature_hash();
    let signature = root_signer.sign_hash_sync(&sig_hash)?;
    let signed_tx = AASigned::new_unhashed(
        auth_tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;
    nonce += 1;
    println!("✓ Access key authorized with 5 token limit");

    // Step 2: Try to call updateSpendingLimit using the access key (should fail)
    let update_limit_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: updateSpendingLimitCall {
                keyId: access_key_addr,
                token: DEFAULT_FEE_TOKEN,
                newLimit: U256::from(100u64) * U256::from(10).pow(U256::from(18)),
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    let access_sig = sign_aa_tx_with_p256_access_key(
        &update_limit_tx,
        &access_key_signing,
        &pub_x,
        &pub_y,
        root_addr,
    )?;

    let signed_tx = AASigned::new_unhashed(update_limit_tx, access_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);
    let tx_hash = *envelope.tx_hash();

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    // Check that the transaction reverted
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;

    let receipt_json = receipt.expect("Transaction must be included in block");
    let status = receipt_json
        .get("status")
        .and_then(|v| v.as_str())
        .expect("Receipt must have status field");

    assert_eq!(
        status, "0x0",
        "TEMPO-KEY20: Access key calling updateSpendingLimit must revert with UnauthorizedCaller"
    );

    println!("✓ updateSpendingLimit correctly reverted when called by access key");
    println!("\n=== TEMPO-KEY20 updateSpendingLimit Test Passed ===");

    Ok(())
}
