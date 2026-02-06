//! E2E tests for the SignatureVerification precompile (TIP-1020)
//!
//! Tests verify that the precompile correctly verifies different signature types
//! and charges appropriate gas costs.

use alloy::{
    primitives::{Address, B256, Bytes, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::{SignerSync, local::MnemonicBuilder},
    sol_types::SolCall,
};
use alloy_rpc_types_eth::TransactionInput;
use p256::{ecdsa::SigningKey, ecdsa::signature::hazmat::PrehashSigner, elliptic_curve::rand_core::OsRng};
use tempo_contracts::precompiles::ISignatureVerification::verifyCall;
use tempo_precompiles::SIGNATURE_VERIFICATION_ADDRESS;
use tempo_primitives::transaction::tt_signature::{
    P256SignatureWithPreHash, PrimitiveSignature, TempoSignature, normalize_p256_s,
};

use crate::utils::TestNodeBuilder;

/// Gas cost constants for signature verification (from signature_gas.rs)
const ECRECOVER_GAS: u64 = 3_000;
const P256_VERIFY_GAS: u64 = 5_000;

/// Expected precompile gas costs
const SECP256K1_PRECOMPILE_GAS: u64 = ECRECOVER_GAS; // 3000
const P256_PRECOMPILE_GAS: u64 = ECRECOVER_GAS + P256_VERIFY_GAS; // 8000

#[tokio::test(flavor = "multi_thread")]
async fn test_signature_verification_secp256k1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let signer_addr = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet.clone()).connect_http(http_url);

    println!("\n=== Testing SignatureVerification Precompile: secp256k1 ===\n");
    println!("Signer address: {signer_addr}");

    // Create a message hash and sign it
    let message = b"test message for signature verification";
    let message_hash = keccak256(message);
    println!("Message hash: {message_hash}");

    // Sign with secp256k1
    let signature = wallet.sign_hash_sync(&message_hash)?;
    let tempo_sig = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature));
    let sig_bytes = Bytes::from(tempo_sig.to_bytes());
    println!("Signature bytes length: {} (expected 65 for secp256k1)", sig_bytes.len());

    // Call the verify function
    let verify_calldata = verifyCall {
        signer: signer_addr,
        hash: message_hash,
        signature: sig_bytes.clone(),
    }
    .abi_encode();

    let tx = TransactionRequest::default()
        .to(SIGNATURE_VERIFICATION_ADDRESS)
        .gas_price(0)
        .input(TransactionInput::new(verify_calldata.into()));

    let result = provider.call(tx).await?;
    let verified = verifyCall::abi_decode_returns(&result)?;
    assert!(verified, "secp256k1 signature should verify successfully");
    println!("✓ secp256k1 signature verified successfully");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signature_verification_p256() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    println!("\n=== Testing SignatureVerification Precompile: P256 ===\n");

    // Generate a P256 key pair
    let p256_secret = SigningKey::random(&mut OsRng);
    let p256_public = p256_secret.verifying_key();
    let encoded_point = p256_public.to_encoded_point(false);
    let pub_x: [u8; 32] = encoded_point.x().unwrap().as_slice().try_into()?;
    let pub_y: [u8; 32] = encoded_point.y().unwrap().as_slice().try_into()?;

    // Derive the P256 address (keccak256 of pubX || pubY, take last 20 bytes)
    let mut pub_bytes = [0u8; 64];
    pub_bytes[..32].copy_from_slice(&pub_x);
    pub_bytes[32..].copy_from_slice(&pub_y);
    let p256_addr = Address::from_slice(&keccak256(pub_bytes)[12..]);
    println!("P256 signer address: {p256_addr}");

    // Create a message hash and sign it
    let message = b"test message for P256 signature verification";
    let message_hash = keccak256(message);
    println!("Message hash: {message_hash}");

    // Sign with P256
    let (p256_sig, _recovery_id) = p256_secret.sign_prehash(&message_hash.0)?;
    let r_bytes: [u8; 32] = p256_sig.r().to_bytes().as_slice().try_into()?;
    let s_bytes: [u8; 32] = p256_sig.s().to_bytes().as_slice().try_into()?;

    // Normalize S to low-S form
    let s_normalized = normalize_p256_s(&s_bytes);

    let p256_tempo_sig = P256SignatureWithPreHash {
        r: B256::from(r_bytes),
        s: s_normalized,
        pub_key_x: B256::from(pub_x),
        pub_key_y: B256::from(pub_y),
        pre_hash: false,
    };
    let tempo_sig = TempoSignature::Primitive(PrimitiveSignature::P256(p256_tempo_sig));
    let sig_bytes = Bytes::from(tempo_sig.to_bytes());
    println!("Signature bytes length: {} (expected 130 for P256)", sig_bytes.len());

    // Call the verify function
    let verify_calldata = verifyCall {
        signer: p256_addr,
        hash: message_hash,
        signature: sig_bytes,
    }
    .abi_encode();

    let tx = TransactionRequest::default()
        .to(SIGNATURE_VERIFICATION_ADDRESS)
        .gas_price(0)
        .input(TransactionInput::new(verify_calldata.into()));

    let result = provider.call(tx).await?;
    let verified = verifyCall::abi_decode_returns(&result)?;
    assert!(verified, "P256 signature should verify successfully");
    println!("✓ P256 signature verified successfully");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signature_verification_wrong_signer() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let actual_signer = wallet.address();
    let wrong_signer = Address::random();
    let provider = ProviderBuilder::new().wallet(wallet.clone()).connect_http(http_url);

    println!("\n=== Testing SignatureVerification Precompile: Wrong Signer ===\n");
    println!("Actual signer: {actual_signer}");
    println!("Wrong signer: {wrong_signer}");

    // Create a message hash and sign it
    let message = b"test message for wrong signer test";
    let message_hash = keccak256(message);

    // Sign with actual signer
    let signature = wallet.sign_hash_sync(&message_hash)?;
    let tempo_sig = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature));
    let sig_bytes = Bytes::from(tempo_sig.to_bytes());

    // Call verify with wrong signer - should revert with SignerMismatch
    let verify_calldata = verifyCall {
        signer: wrong_signer,
        hash: message_hash,
        signature: sig_bytes,
    }
    .abi_encode();

    let tx = TransactionRequest::default()
        .to(SIGNATURE_VERIFICATION_ADDRESS)
        .gas_price(0)
        .input(TransactionInput::new(verify_calldata.into()));

    let result = provider.call(tx).await;
    assert!(result.is_err(), "Wrong signer should cause revert");

    let err = result.unwrap_err();
    let err_str = err.to_string();
    println!("Expected error received: {err_str}");

    // The error should contain SignerMismatch indicator
    assert!(
        err_str.contains("SignerMismatch") || err_str.contains("execution reverted"),
        "Should revert with SignerMismatch error"
    );
    println!("✓ Wrong signer correctly rejected with SignerMismatch");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signature_verification_invalid_signature() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let signer_addr = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    println!("\n=== Testing SignatureVerification Precompile: Invalid Signature ===\n");

    let message_hash = keccak256(b"test message");

    // Create invalid signature bytes (wrong length)
    let invalid_sig = Bytes::from(vec![0u8; 10]);

    let verify_calldata = verifyCall {
        signer: signer_addr,
        hash: message_hash,
        signature: invalid_sig,
    }
    .abi_encode();

    let tx = TransactionRequest::default()
        .to(SIGNATURE_VERIFICATION_ADDRESS)
        .gas_price(0)
        .input(TransactionInput::new(verify_calldata.into()));

    let result = provider.call(tx).await;
    assert!(result.is_err(), "Invalid signature should cause revert");

    let err = result.unwrap_err();
    let err_str = err.to_string();
    println!("Expected error received: {err_str}");

    assert!(
        err_str.contains("InvalidSignature") || err_str.contains("execution reverted"),
        "Should revert with InvalidSignature error"
    );
    println!("✓ Invalid signature correctly rejected");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signature_verification_gas_costs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let signer_addr = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet.clone()).connect_http(http_url);

    println!("\n=== Testing SignatureVerification Gas Costs ===\n");

    let message_hash = keccak256(b"gas test message");

    // Test 1: secp256k1 gas cost
    println!("Test 1: secp256k1 gas cost");
    let secp_sig = wallet.sign_hash_sync(&message_hash)?;
    let secp_tempo_sig = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(secp_sig));
    let secp_sig_bytes = Bytes::from(secp_tempo_sig.to_bytes());

    let secp_calldata = verifyCall {
        signer: signer_addr,
        hash: message_hash,
        signature: secp_sig_bytes,
    }
    .abi_encode();

    let secp_tx = TransactionRequest::default()
        .from(signer_addr)
        .to(SIGNATURE_VERIFICATION_ADDRESS)
        .input(TransactionInput::new(secp_calldata.into()));

    let secp_gas: String = provider
        .raw_request("eth_estimateGas".into(), [serde_json::to_value(&secp_tx)?])
        .await?;
    let secp_gas_u64 = u64::from_str_radix(secp_gas.trim_start_matches("0x"), 16)?;
    println!("  secp256k1 estimated gas: {secp_gas_u64}");
    println!("  Expected verification gas: {SECP256K1_PRECOMPILE_GAS}");

    // Test 2: P256 gas cost
    println!("\nTest 2: P256 gas cost");
    let p256_secret = SigningKey::random(&mut OsRng);
    let p256_public = p256_secret.verifying_key();
    let encoded_point = p256_public.to_encoded_point(false);
    let pub_x: [u8; 32] = encoded_point.x().unwrap().as_slice().try_into()?;
    let pub_y: [u8; 32] = encoded_point.y().unwrap().as_slice().try_into()?;

    let mut pub_bytes = [0u8; 64];
    pub_bytes[..32].copy_from_slice(&pub_x);
    pub_bytes[32..].copy_from_slice(&pub_y);
    let p256_addr = Address::from_slice(&keccak256(pub_bytes)[12..]);

    let (p256_sig, _) = p256_secret.sign_prehash(&message_hash.0)?;
    let r_bytes: [u8; 32] = p256_sig.r().to_bytes().as_slice().try_into()?;
    let s_bytes: [u8; 32] = p256_sig.s().to_bytes().as_slice().try_into()?;
    let s_normalized = normalize_p256_s(&s_bytes);

    let p256_tempo_sig = TempoSignature::Primitive(PrimitiveSignature::P256(
        P256SignatureWithPreHash {
            r: B256::from(r_bytes),
            s: s_normalized,
            pub_key_x: B256::from(pub_x),
            pub_key_y: B256::from(pub_y),
            pre_hash: false,
        },
    ));
    let p256_sig_bytes = Bytes::from(p256_tempo_sig.to_bytes());

    let p256_calldata = verifyCall {
        signer: p256_addr,
        hash: message_hash,
        signature: p256_sig_bytes,
    }
    .abi_encode();

    let p256_tx = TransactionRequest::default()
        .from(signer_addr)
        .to(SIGNATURE_VERIFICATION_ADDRESS)
        .input(TransactionInput::new(p256_calldata.into()));

    let p256_gas: String = provider
        .raw_request("eth_estimateGas".into(), [serde_json::to_value(&p256_tx)?])
        .await?;
    let p256_gas_u64 = u64::from_str_radix(p256_gas.trim_start_matches("0x"), 16)?;
    println!("  P256 estimated gas: {p256_gas_u64}");
    println!("  Expected verification gas: {P256_PRECOMPILE_GAS}");

    // Verify P256 costs more than secp256k1
    let gas_diff = p256_gas_u64.saturating_sub(secp_gas_u64);
    println!("\n  Gas difference (P256 - secp256k1): {gas_diff}");
    println!("  Expected difference: ~{P256_VERIFY_GAS}");

    // Allow some tolerance for calldata cost differences (P256 signature is larger)
    assert!(
        gas_diff >= P256_VERIFY_GAS - 500 && gas_diff <= P256_VERIFY_GAS + 2000,
        "P256 should cost approximately {} more gas than secp256k1, got {gas_diff}",
        P256_VERIFY_GAS
    );
    println!("✓ Gas costs match expected specification");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signature_verification_empty_signature() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let signer_addr = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    println!("\n=== Testing SignatureVerification Precompile: Empty Signature ===\n");

    let message_hash = keccak256(b"test message");

    let verify_calldata = verifyCall {
        signer: signer_addr,
        hash: message_hash,
        signature: Bytes::new(),
    }
    .abi_encode();

    let tx = TransactionRequest::default()
        .to(SIGNATURE_VERIFICATION_ADDRESS)
        .gas_price(0)
        .input(TransactionInput::new(verify_calldata.into()));

    let result = provider.call(tx).await;
    assert!(result.is_err(), "Empty signature should cause revert");

    let err = result.unwrap_err();
    println!("Expected error received: {}", err);
    println!("✓ Empty signature correctly rejected");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signature_verification_wrong_hash() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let signer_addr = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet.clone()).connect_http(http_url);

    println!("\n=== Testing SignatureVerification Precompile: Wrong Hash ===\n");

    // Sign one hash but verify against a different hash
    let original_hash = keccak256(b"original message");
    let wrong_hash = keccak256(b"different message");

    let signature = wallet.sign_hash_sync(&original_hash)?;
    let tempo_sig = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature));
    let sig_bytes = Bytes::from(tempo_sig.to_bytes());

    // Try to verify with wrong hash
    let verify_calldata = verifyCall {
        signer: signer_addr,
        hash: wrong_hash,
        signature: sig_bytes,
    }
    .abi_encode();

    let tx = TransactionRequest::default()
        .to(SIGNATURE_VERIFICATION_ADDRESS)
        .gas_price(0)
        .input(TransactionInput::new(verify_calldata.into()));

    let result = provider.call(tx).await;
    assert!(result.is_err(), "Wrong hash should cause revert");

    let err = result.unwrap_err();
    println!("Expected error received: {}", err);
    println!("✓ Wrong hash correctly rejected (signature bound to original hash)");

    Ok(())
}
