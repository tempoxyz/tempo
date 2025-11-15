use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, Bytes, Signature, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::MnemonicBuilder},
    sol_types::SolCall,
};
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_primitives::TxKind;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN,
    tip20::{ITIP20, ITIP20::transferCall},
};
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        TxAA,
        aa_signature::{AASignature, P256SignatureWithPreHash, WebAuthnSignature},
        aa_signed::AASigned,
        account_abstraction::Call,
    },
};

/// Helper function to fund an address with fee tokens
async fn fund_address_with_fee_tokens(
    setup: &mut crate::utils::SingleNodeSetup,
    provider: &impl Provider,
    funder_signer: &impl SignerSync,
    funder_addr: Address,
    recipient: Address,
    amount: U256,
    chain_id: u64,
) -> eyre::Result<()> {
    let transfer_calldata = transferCall {
        to: recipient,
        amount,
    }
    .abi_encode();

    let funding_tx = TxAA {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: transfer_calldata.into(),
        }],
        nonce_key: U256::ZERO,
        nonce: provider.get_transaction_count(funder_addr).await?,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    // Sign and send the funding transaction
    let sig_hash = funding_tx.signature_hash();
    let signature = funder_signer.sign_hash_sync(&sig_hash)?;
    let aa_signature = AASignature::Secp256k1(signature);
    let signed_funding_tx = AASigned::new_unhashed(funding_tx, aa_signature);
    let funding_envelope: TempoTxEnvelope = signed_funding_tx.into();
    let mut encoded_funding = Vec::new();
    funding_envelope.encode_2718(&mut encoded_funding);

    setup.node.rpc.inject_tx(encoded_funding.into()).await?;
    let funding_payload = setup.node.advance_block().await?;
    println!(
        "✓ Funded {} with {} tokens in block {}",
        recipient,
        amount,
        funding_payload.block().inner.number
    );

    Ok(())
}

/// Helper function to verify a transaction exists in the blockchain via eth_getTransactionByHash
/// and that it matches the original transaction
async fn verify_tx_in_block_via_rpc(
    provider: &impl Provider,
    encoded_tx: &[u8],
    expected_envelope: &TempoTxEnvelope,
) -> eyre::Result<()> {
    // Compute transaction hash from encoded bytes
    let tx_hash = keccak256(encoded_tx);

    println!("\nVerifying transaction via eth_getTransactionByHash...");
    println!("Transaction hash: {}", B256::from(tx_hash));

    // Use raw RPC call to fetch transaction since Alloy doesn't support custom tx type 0x5
    let raw_tx: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionByHash".into(), [tx_hash])
        .await?;

    // Verify transaction exists
    let tx_data = raw_tx.ok_or_else(|| eyre::eyre!("Transaction not found in blockchain"))?;

    println!("✓ Transaction found in blockchain");

    // Extract and verify key fields from the JSON response
    let tx_obj = tx_data
        .as_object()
        .ok_or_else(|| eyre::eyre!("Transaction response is not an object"))?;

    // Verify basic sanity checks
    let hash_str = tx_obj
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("Transaction hash not found in response"))?;
    let returned_hash = hash_str.parse::<B256>()?;
    assert_eq!(
        returned_hash, tx_hash,
        "Returned hash should match request hash"
    );

    // Verify it's an AA transaction (type 0x76)
    let tx_type = tx_obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("Transaction type not found in response"))?;
    assert_eq!(tx_type, "0x76", "Transaction should be AA type (0x76)");

    // Verify key fields match what we expect
    if let TempoTxEnvelope::AA(expected_aa) = expected_envelope {
        // Check chain ID
        if let Some(chain_id) = tx_obj.get("chainId").and_then(|v| v.as_str()) {
            let chain_id_u64 = u64::from_str_radix(chain_id.trim_start_matches("0x"), 16)?;
            assert_eq!(
                chain_id_u64,
                expected_aa.tx().chain_id,
                "Chain ID should match"
            );
        }

        // Check nonce
        if let Some(nonce) = tx_obj.get("nonce").and_then(|v| v.as_str()) {
            let nonce_u64 = u64::from_str_radix(nonce.trim_start_matches("0x"), 16)?;
            assert_eq!(nonce_u64, expected_aa.tx().nonce, "Nonce should match");
        }

        // Check number of calls
        if let Some(calls) = tx_obj.get("calls").and_then(|v| v.as_array()) {
            assert_eq!(
                calls.len(),
                expected_aa.tx().calls.len(),
                "Number of calls should match"
            );
        }

        println!(
            "✓ Transaction verified: type=0x76, chain_id={}, nonce={}, calls={}",
            expected_aa.tx().chain_id,
            expected_aa.tx().nonce,
            expected_aa.tx().calls.len()
        );
    }

    // Verify encoding roundtrip on our end
    let mut encoded_slice = encoded_tx;
    let decoded = TempoTxEnvelope::decode_2718(&mut encoded_slice)?;
    assert!(
        matches!(decoded, TempoTxEnvelope::AA(_)),
        "Decoded transaction should be AA type"
    );

    println!("✓ Transaction encoding/decoding verified successfully");

    Ok(())
}

/// Helper function to verify a transaction does NOT exist in the blockchain
async fn verify_tx_not_in_block_via_rpc(
    provider: &impl Provider,
    encoded_tx: &[u8],
) -> eyre::Result<()> {
    // Compute transaction hash from encoded bytes
    let tx_hash = keccak256(encoded_tx);

    println!("\nVerifying transaction is NOT in blockchain...");
    println!("Transaction hash: {}", B256::from(tx_hash));

    // Use raw RPC call to try to fetch the transaction
    let raw_tx: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionByHash".into(), [tx_hash])
        .await?;

    // Verify transaction does NOT exist
    assert!(
        raw_tx.is_none(),
        "Transaction should not exist in blockchain (rejected transaction should not be retrievable)"
    );

    println!("✓ Confirmed: Transaction not found in blockchain (as expected)");

    Ok(())
}

/// Helper function to set up common test infrastructure
/// Returns: (setup, provider, signer, signer_addr)
async fn setup_test_with_funded_account() -> eyre::Result<(
    crate::utils::SingleNodeSetup,
    impl Provider + Clone,
    impl SignerSync,
    Address,
)> {
    // Setup test node with direct access
    let setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Use TEST_MNEMONIC account (has balance in DEFAULT_FEE_TOKEN from genesis)
    let signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let signer_addr = signer.address();

    // Create provider with wallet
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    Ok((setup, provider, signer, signer_addr))
}

/// Helper function to compute authorization signature hash (EIP-7702)
fn compute_authorization_signature_hash(auth: &alloy_eips::eip7702::Authorization) -> B256 {
    use alloy_rlp::Encodable as _;
    let mut sig_buf = Vec::new();
    sig_buf.push(tempo_primitives::transaction::aa_authorization::MAGIC);
    auth.encode(&mut sig_buf);
    alloy::primitives::keccak256(&sig_buf)
}

/// Helper function to create a signed Secp256k1 authorization
fn create_secp256k1_authorization<T>(
    chain_id: u64,
    delegate_address: Address,
    signer: &T,
) -> eyre::Result<(
    tempo_primitives::transaction::AASignedAuthorization,
    Address,
)>
where
    T: SignerSync + alloy::signers::Signer,
{
    use alloy_eips::eip7702::Authorization;
    use tempo_primitives::transaction::AASignedAuthorization;

    let authority_addr = signer.address();

    let auth = Authorization {
        chain_id: alloy_primitives::U256::from(chain_id),
        address: delegate_address,
        nonce: 0,
    };

    let sig_hash = compute_authorization_signature_hash(&auth);
    let signature = signer.sign_hash_sync(&sig_hash)?;
    let aa_sig = tempo_primitives::transaction::aa_signature::AASignature::Secp256k1(signature);
    let signed_auth = AASignedAuthorization::new_unchecked(auth, aa_sig);

    Ok((signed_auth, authority_addr))
}

/// Helper function to create a signed P256 authorization
fn create_p256_authorization(
    chain_id: u64,
    delegate_address: Address,
) -> eyre::Result<(
    tempo_primitives::transaction::AASignedAuthorization,
    Address,
    p256::ecdsa::SigningKey,
)> {
    use alloy_eips::eip7702::Authorization;
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
    use sha2::{Digest, Sha256};
    use tempo_primitives::transaction::{
        AASignedAuthorization,
        aa_signature::{AASignature, P256SignatureWithPreHash},
    };

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Extract P256 public key coordinates
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_slice());
    let pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_slice());

    // Derive P256 address
    let authority_addr =
        tempo_primitives::transaction::aa_signature::derive_p256_address(&pub_key_x, &pub_key_y);

    let auth = Authorization {
        chain_id: alloy_primitives::U256::from(chain_id),
        address: delegate_address,
        nonce: 0,
    };

    let sig_hash = compute_authorization_signature_hash(&auth);

    // Sign with P256 (using pre-hash)
    let pre_hashed = Sha256::digest(sig_hash.as_slice());
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&pre_hashed)?;
    let sig_bytes = signature.to_bytes();

    let aa_sig = AASignature::P256(P256SignatureWithPreHash {
        r: alloy::primitives::B256::from_slice(&sig_bytes[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes[32..64]),
        pub_key_x,
        pub_key_y,
        pre_hash: true,
    });
    let signed_auth = AASignedAuthorization::new_unchecked(auth, aa_sig);

    Ok((signed_auth, authority_addr, signing_key))
}

/// Helper function to create a signed WebAuthn authorization
fn create_webauthn_authorization(
    chain_id: u64,
    delegate_address: Address,
) -> eyre::Result<(
    tempo_primitives::transaction::AASignedAuthorization,
    Address,
    p256::ecdsa::SigningKey,
)> {
    use alloy_eips::eip7702::Authorization;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
    use sha2::{Digest, Sha256};
    use tempo_primitives::transaction::{
        AASignedAuthorization,
        aa_signature::{AASignature, WebAuthnSignature},
    };

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Extract WebAuthn public key coordinates
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_slice());
    let pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_slice());

    // Derive WebAuthn address (same derivation as P256)
    let authority_addr =
        tempo_primitives::transaction::aa_signature::derive_p256_address(&pub_key_x, &pub_key_y);

    let auth = Authorization {
        chain_id: alloy_primitives::U256::from(chain_id),
        address: delegate_address,
        nonce: 0,
    };

    let sig_hash = compute_authorization_signature_hash(&auth);

    // Create WebAuthn signature
    let mut authenticator_data = vec![0u8; 37];
    authenticator_data[0..32].copy_from_slice(&[0xBB; 32]); // rpIdHash
    authenticator_data[32] = 0x01; // UP flag set
    authenticator_data[33..37].copy_from_slice(&[0, 0, 0, 0]); // signCount

    let challenge_b64url = URL_SAFE_NO_PAD.encode(sig_hash.as_slice());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute WebAuthn message hash
    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data);
    final_hasher.update(client_data_hash);
    let message_hash = final_hasher.finalize();

    // Sign with P256
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&message_hash)?;
    let sig_bytes = signature.to_bytes();

    // Construct WebAuthn data
    let mut webauthn_data = Vec::new();
    webauthn_data.extend_from_slice(&authenticator_data);
    webauthn_data.extend_from_slice(client_data_json.as_bytes());

    let aa_sig = AASignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(webauthn_data),
        r: alloy::primitives::B256::from_slice(&sig_bytes[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes[32..64]),
        pub_key_x,
        pub_key_y,
    });
    let signed_auth = AASignedAuthorization::new_unchecked(auth, aa_sig);

    Ok((signed_auth, authority_addr, signing_key))
}

/// Helper function to verify EIP-7702 delegation code
fn verify_delegation_code(code: &Bytes, expected_delegate: Address, authority_name: &str) {
    // EIP-7702 delegation code format: 0xef0100 || address (23 bytes total)
    // 0xef = magic byte, 0x01 = version, 0x00 = reserved
    assert_eq!(
        code.len(),
        23,
        "{authority_name} should have EIP-7702 delegation code (23 bytes), got {} bytes",
        code.len()
    );
    assert_eq!(
        &code[0..3],
        &[0xef, 0x01, 0x00],
        "{authority_name} should have correct EIP-7702 magic bytes [0xef, 0x01, 0x00], got [{:02x}, {:02x}, {:02x}]",
        code[0],
        code[1],
        code[2]
    );
    assert_eq!(
        &code[3..23],
        expected_delegate.as_slice(),
        "{authority_name} should delegate to correct address {expected_delegate}"
    );
}

/// Helper function to set up P256 test infrastructure with funded account
/// Returns: (setup, provider, signing_key, pub_key_x, pub_key_y, signer_addr, funder_signer, funder_addr, chain_id)
async fn setup_test_with_p256_funded_account(
    funding_amount: U256,
) -> eyre::Result<(
    crate::utils::SingleNodeSetup,
    impl Provider + Clone,
    p256::ecdsa::SigningKey,
    alloy::primitives::B256,
    alloy::primitives::B256,
    Address,
    impl SignerSync,
    Address,
    u64,
)> {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

    // Setup test node with direct access
    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Generate a P256 key pair
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Extract public key coordinates
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_slice());
    let pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_slice());

    // Derive the P256 signer's address
    let signer_addr =
        tempo_primitives::transaction::aa_signature::derive_p256_address(&pub_key_x, &pub_key_y);

    // Use TEST_MNEMONIC account to fund the P256 signer
    let funder_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let funder_addr = funder_signer.address();

    // Create provider with funder's wallet
    let funder_wallet = EthereumWallet::from(funder_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(funder_wallet)
        .connect_http(http_url.clone());

    // Get chain ID
    let chain_id = provider.get_chain_id().await?;

    // Fund the P256 signer with fee tokens
    fund_address_with_fee_tokens(
        &mut setup,
        &provider,
        &funder_signer,
        funder_addr,
        signer_addr,
        funding_amount,
        chain_id,
    )
    .await?;

    Ok((
        setup,
        provider,
        signing_key,
        pub_key_x,
        pub_key_y,
        signer_addr,
        funder_signer,
        funder_addr,
        chain_id,
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_basic_transfer_secp256k1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    // Verify alice has zero native balance
    let alice_eth_balance = provider.get_account_info(alice_addr).await?.balance;
    assert_eq!(
        alice_eth_balance,
        U256::ZERO,
        "Test accounts should have zero ETH balance"
    );

    println!("Alice address: {alice_addr}");
    println!("Alice ETH balance: {alice_eth_balance} (expected: 0)");

    // Create recipient address
    let recipient = Address::random();

    // Get alice's current nonce (protocol nonce, key 0)
    let nonce = provider.get_transaction_count(alice_addr).await?;
    println!("Alice nonce: {nonce}");

    // Create AA transaction with secp256k1 signature and protocol nonce
    let tx = TxAA {
        chain_id: provider.get_chain_id().await?,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO, // Protocol nonce (key 0)
        nonce,
        fee_token: None, // Will use DEFAULT_FEE_TOKEN from genesis
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    println!("Created AA transaction with secp256k1 signature");

    // Sign the transaction with secp256k1
    let sig_hash = tx.signature_hash();
    let signature = alice_signer.sign_hash_sync(&sig_hash)?;
    let aa_signature = AASignature::Secp256k1(signature);
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);

    // Convert to envelope and encode
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!(
        "Encoded AA transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Test encoding/decoding roundtrip
    let decoded = TempoTxEnvelope::decode_2718(&mut encoded.as_slice())?;
    assert!(
        matches!(decoded, TempoTxEnvelope::AA(_)),
        "Should decode as AA transaction"
    );
    println!("✓ Encoding/decoding roundtrip successful");

    // Inject transaction and mine block
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "✓ AA transaction mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded, &envelope).await?;

    // Verify alice's nonce incremented (protocol nonce)
    // This proves the transaction was successfully mined and executed
    let alice_nonce_after = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        alice_nonce_after,
        nonce + 1,
        "Protocol nonce should increment"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_2d_nonce_system() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    println!("\nTesting AA 2D Nonce System (nonce_key restriction)");
    println!("Alice address: {alice_addr}");

    let recipient = Address::random();
    let chain_id = provider.get_chain_id().await?;

    // Step 1: Verify that nonce_key = 0 (protocol nonce) works
    println!("\n1. Testing nonce_key = 0 (should succeed)");

    let nonce = provider.get_transaction_count(alice_addr).await?;
    let tx_protocol = TxAA {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO, // Protocol nonce - should work
        nonce,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    // Sign and encode transaction
    let sig_hash = tx_protocol.signature_hash();
    let signature = alice_signer.sign_hash_sync(&sig_hash)?;
    let signed_tx_protocol = AASigned::new_unhashed(tx_protocol, AASignature::Secp256k1(signature));
    let envelope_protocol: TempoTxEnvelope = signed_tx_protocol.into();
    let mut encoded_protocol = Vec::new();
    envelope_protocol.encode_2718(&mut encoded_protocol);

    println!(
        "Transaction with nonce_key=0 encoded, size: {} bytes",
        encoded_protocol.len()
    );

    // Inject transaction and mine block - should succeed
    setup
        .node
        .rpc
        .inject_tx(encoded_protocol.clone().into())
        .await?;
    let payload = setup.node.advance_block().await?;
    println!(
        "✓ Transaction with nonce_key=0 mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded_protocol, &envelope_protocol).await?;

    // Step 2: Verify that nonce_key != 0 is rejected
    println!("\n2. Testing nonce_key = 1 (should be rejected)");

    let tx_parallel = TxAA {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ONE, // Parallel nonce - should be rejected
        nonce: 0,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    // Sign and encode transaction
    let sig_hash = tx_parallel.signature_hash();
    let signature = alice_signer.sign_hash_sync(&sig_hash)?;
    let signed_tx_parallel = AASigned::new_unhashed(tx_parallel, AASignature::Secp256k1(signature));
    let envelope_parallel: TempoTxEnvelope = signed_tx_parallel.into();
    let mut encoded_parallel = Vec::new();
    envelope_parallel.encode_2718(&mut encoded_parallel);

    println!(
        "Transaction with nonce_key=1 encoded, size: {} bytes",
        encoded_parallel.len()
    );

    // Try to inject transaction - should fail due to nonce_key != 0
    let result = setup
        .node
        .rpc
        .inject_tx(encoded_parallel.clone().into())
        .await;

    // The transaction should be rejected
    assert!(
        result.is_err(),
        "Transaction with nonce_key != 0 should be rejected"
    );

    if let Err(e) = result {
        println!("✓ Transaction with nonce_key=1 correctly rejected: {e}");

        // Verify the error is about unsupported nonce_key or decode failure (validation happens during decode)
        let error_msg = e.to_string();
        assert!(
            error_msg.contains("nonce")
                || error_msg.contains("protocol nonce")
                || error_msg.contains("supported")
                || error_msg.contains("decode"),
            "Error should indicate nonce_key issue or decode failure, got: {error_msg}"
        );
    }

    // Verify the rejected transaction is NOT available via eth_getTransactionByHash
    verify_tx_not_in_block_via_rpc(&provider, &encoded_parallel).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_webauthn_signature_flow() -> eyre::Result<()> {
    use sha2::{Digest, Sha256};

    reth_tracing::init_test_tracing();

    let transfer_amount = U256::from(10_000_000_000_000_000_000u64); // 10 tokens
    let (
        mut setup,
        provider,
        signing_key,
        pub_key_x,
        pub_key_y,
        signer_addr,
        _funder_signer,
        _funder_addr,
        chain_id,
    ) = setup_test_with_p256_funded_account(transfer_amount).await?;

    println!("WebAuthn signer address: {signer_addr}");
    println!("Public key X: {pub_key_x}");
    println!("Public key Y: {pub_key_y}");

    // Create recipient address for the actual test
    let recipient = Address::random();

    // Create AA transaction with WebAuthn signature
    let tx = TxAA {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 200_000, // Higher gas limit for WebAuthn verification
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO,              // Protocol nonce
        nonce: 0,                           // First transaction
        fee_token: Some(DEFAULT_FEE_TOKEN), // Will use DEFAULT_FEE_TOKEN from genesis
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    println!("Created AA transaction for WebAuthn signature");

    // Get the signature hash
    let sig_hash = tx.signature_hash();
    println!("Transaction signature hash: {sig_hash}");

    // Create WebAuthn authenticator data (mock)
    // Minimum authenticatorData: 37 bytes (32 rpIdHash + 1 flags + 4 signCount)
    let mut authenticator_data = vec![0u8; 37];
    // Set rpIdHash (32 bytes) - using a test value
    authenticator_data[0..32].copy_from_slice(&[0xAA; 32]);
    // Set flags byte (byte 32): UP flag (bit 0) must be set
    authenticator_data[32] = 0x01; // User Present flag set
    // Set signCount (4 bytes) - can be 0 for test
    authenticator_data[33..37].copy_from_slice(&[0, 0, 0, 0]);

    // Create clientDataJSON with proper challenge
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let challenge_b64url = URL_SAFE_NO_PAD.encode(sig_hash.as_slice());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
    );

    println!("ClientDataJSON: {client_data_json}");

    // Compute the message hash for P256 signature according to WebAuthn spec:
    // messageHash = sha256(authenticatorData || sha256(clientDataJSON))
    let client_data_hash = Sha256::digest(client_data_json.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data);
    final_hasher.update(client_data_hash);
    let message_hash = final_hasher.finalize();

    // Sign the message hash with P256 (use sign_prehash since message_hash is already hashed)
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&message_hash)?;
    let sig_bytes = signature.to_bytes();

    // Construct WebAuthn data: authenticatorData || clientDataJSON
    let mut webauthn_data = Vec::new();
    webauthn_data.extend_from_slice(&authenticator_data);
    webauthn_data.extend_from_slice(client_data_json.as_bytes());

    // Create WebAuthn AA signature
    let aa_signature = AASignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(webauthn_data),
        r: alloy::primitives::B256::from_slice(&sig_bytes[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes[32..64]),
        pub_key_x,
        pub_key_y,
    });

    println!("Created WebAuthn signature");

    // Sign the transaction with WebAuthn signature
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);

    // Convert to envelope and encode
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!(
        "Encoded AA transaction with WebAuthn: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Test encoding/decoding roundtrip
    let decoded = TempoTxEnvelope::decode_2718(&mut encoded.as_slice())?;
    assert!(
        matches!(decoded, TempoTxEnvelope::AA(_)),
        "Should decode as AA transaction"
    );

    if let TempoTxEnvelope::AA(decoded_tx) = &decoded {
        // Verify the signature can be recovered
        let recovered_signer = decoded_tx
            .signature()
            .recover_signer(&decoded_tx.signature_hash())
            .expect("Should recover signer from WebAuthn signature");

        assert_eq!(
            recovered_signer, signer_addr,
            "Recovered signer should match expected WebAuthn address"
        );
        println!("✓ WebAuthn signature recovery successful");
    }

    println!("✓ Encoding/decoding roundtrip successful");

    // Inject transaction and mine block
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "✓ AA transaction with WebAuthn signature mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded, &envelope).await?;

    // Verify the block contains transactions
    assert!(
        !payload.block().body().transactions.is_empty(),
        "Block should contain the WebAuthn transaction"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_webauthn_signature_negative_cases() -> eyre::Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{
        ecdsa::{SigningKey, signature::Signer},
        elliptic_curve::rand_core::OsRng,
    };
    use sha2::{Digest, Sha256};

    reth_tracing::init_test_tracing();

    // Setup test node with direct access
    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Generate the correct P256 key pair for WebAuthn
    let correct_signing_key = SigningKey::random(&mut OsRng);
    let correct_verifying_key = correct_signing_key.verifying_key();

    // Extract correct public key coordinates
    let correct_encoded_point = correct_verifying_key.to_encoded_point(false);
    let correct_pub_key_x =
        alloy::primitives::B256::from_slice(correct_encoded_point.x().unwrap().as_slice());
    let correct_pub_key_y =
        alloy::primitives::B256::from_slice(correct_encoded_point.y().unwrap().as_slice());

    // Generate a different (wrong) P256 key pair
    let wrong_signing_key = SigningKey::random(&mut OsRng);
    let wrong_verifying_key = wrong_signing_key.verifying_key();

    // Extract wrong public key coordinates
    let wrong_encoded_point = wrong_verifying_key.to_encoded_point(false);
    let wrong_pub_key_x =
        alloy::primitives::B256::from_slice(wrong_encoded_point.x().unwrap().as_slice());
    let wrong_pub_key_y =
        alloy::primitives::B256::from_slice(wrong_encoded_point.y().unwrap().as_slice());

    // Use TEST_MNEMONIC account to fund the WebAuthn signers
    let funder_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let funder_addr = funder_signer.address();

    // Create provider with funder's wallet
    let funder_wallet = EthereumWallet::from(funder_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(funder_wallet)
        .connect_http(http_url.clone());

    println!("\n=== Testing WebAuthn Negative Cases ===\n");

    // Get chain ID
    let chain_id = provider.get_chain_id().await?;

    // Create recipient address for test transactions
    let recipient = Address::random();

    // Helper function to create a test AA transaction
    let create_test_tx = |nonce_seq: u64| TxAA {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 200_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO,
        nonce: nonce_seq,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    // ===========================================
    // Test Case 1: Wrong Public Key
    // ===========================================
    println!("Test 1: Wrong public key in signature");

    let tx1 = create_test_tx(100);
    let sig_hash1 = tx1.signature_hash();

    // Create correct WebAuthn data
    let mut authenticator_data1 = vec![0u8; 37];
    authenticator_data1[32] = 0x01; // UP flag set

    let challenge_b64url1 = URL_SAFE_NO_PAD.encode(sig_hash1.as_slice());
    let client_data_json1 = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url1}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash1 = Sha256::digest(client_data_json1.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data1);
    final_hasher.update(client_data_hash1);
    let message_hash1 = final_hasher.finalize();

    // Sign with CORRECT private key
    let signature1: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash1);
    let sig_bytes1 = signature1.to_bytes();

    // But use WRONG public key in the signature
    let mut webauthn_data1 = Vec::new();
    webauthn_data1.extend_from_slice(&authenticator_data1);
    webauthn_data1.extend_from_slice(client_data_json1.as_bytes());

    let aa_signature1 = AASignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(webauthn_data1),
        r: alloy::primitives::B256::from_slice(&sig_bytes1[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes1[32..64]),
        pub_key_x: wrong_pub_key_x, // WRONG public key
        pub_key_y: wrong_pub_key_y, // WRONG public key
    });

    // Try to verify - should fail
    let recovery_result1 = aa_signature1.recover_signer(&sig_hash1);
    assert!(
        recovery_result1.is_err(),
        "Should fail with wrong public key"
    );
    println!("✓ Signature recovery correctly failed with wrong public key");

    // ===========================================
    // Test Case 2: Wrong Private Key (signature doesn't match public key)
    // ===========================================
    println!("\nTest 2: Wrong private key (signature doesn't match public key)");

    let tx2 = create_test_tx(101);
    let sig_hash2 = tx2.signature_hash();

    // Create correct WebAuthn data
    let mut authenticator_data2 = vec![0u8; 37];
    authenticator_data2[32] = 0x01; // UP flag set

    let challenge_b64url2 = URL_SAFE_NO_PAD.encode(sig_hash2.as_slice());
    let client_data_json2 = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url2}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash2 = Sha256::digest(client_data_json2.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data2);
    final_hasher.update(client_data_hash2);
    let message_hash2 = final_hasher.finalize();

    // Sign with WRONG private key
    let signature2: p256::ecdsa::Signature = wrong_signing_key.sign(&message_hash2);
    let sig_bytes2 = signature2.to_bytes();

    // But use CORRECT public key in the signature
    let mut webauthn_data2 = Vec::new();
    webauthn_data2.extend_from_slice(&authenticator_data2);
    webauthn_data2.extend_from_slice(client_data_json2.as_bytes());

    let aa_signature2 = AASignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(webauthn_data2),
        r: alloy::primitives::B256::from_slice(&sig_bytes2[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes2[32..64]),
        pub_key_x: correct_pub_key_x, // Correct public key
        pub_key_y: correct_pub_key_y, // But signature is from wrong private key
    });

    // Try to verify - should fail
    let recovery_result2 = aa_signature2.recover_signer(&sig_hash2);
    assert!(
        recovery_result2.is_err(),
        "Should fail with wrong private key"
    );
    println!("✓ Signature recovery correctly failed with wrong private key");

    // ===========================================
    // Test Case 3: Wrong Challenge in clientDataJSON
    // ===========================================
    println!("\nTest 3: Wrong challenge in clientDataJSON");

    let tx3 = create_test_tx(102);
    let sig_hash3 = tx3.signature_hash();

    // Create WebAuthn data with WRONG challenge
    let mut authenticator_data3 = vec![0u8; 37];
    authenticator_data3[32] = 0x01; // UP flag set

    let wrong_challenge = B256::from([0xFF; 32]); // Different hash
    let wrong_challenge_b64url = URL_SAFE_NO_PAD.encode(wrong_challenge.as_slice());
    let client_data_json3 = format!(
        r#"{{"type":"webauthn.get","challenge":"{wrong_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash3 = Sha256::digest(client_data_json3.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data3);
    final_hasher.update(client_data_hash3);
    let message_hash3 = final_hasher.finalize();

    // Sign with correct private key
    let signature3: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash3);
    let sig_bytes3 = signature3.to_bytes();

    let mut webauthn_data3 = Vec::new();
    webauthn_data3.extend_from_slice(&authenticator_data3);
    webauthn_data3.extend_from_slice(client_data_json3.as_bytes());

    let aa_signature3 = AASignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(webauthn_data3),
        r: alloy::primitives::B256::from_slice(&sig_bytes3[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes3[32..64]),
        pub_key_x: correct_pub_key_x,
        pub_key_y: correct_pub_key_y,
    });

    // Try to verify - should fail during WebAuthn data validation
    let recovery_result3 = aa_signature3.recover_signer(&sig_hash3);
    assert!(
        recovery_result3.is_err(),
        "Should fail with wrong challenge"
    );
    println!("✓ Signature recovery correctly failed with wrong challenge");

    // ===========================================
    // Test Case 4: Wrong Authenticator Data
    // ===========================================
    println!("\nTest 4: Wrong authenticator data (UP flag not set)");

    let tx4 = create_test_tx(103);
    let sig_hash4 = tx4.signature_hash();

    // Create WebAuthn data with UP flag NOT set
    let mut authenticator_data4 = vec![0u8; 37];
    authenticator_data4[32] = 0x00; // UP flag NOT set (should be 0x01)

    let challenge_b64url4 = URL_SAFE_NO_PAD.encode(sig_hash4.as_slice());
    let client_data_json4 = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url4}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash4 = Sha256::digest(client_data_json4.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data4);
    final_hasher.update(client_data_hash4);
    let message_hash4 = final_hasher.finalize();

    // Sign with correct private key
    let signature4: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash4);
    let sig_bytes4 = signature4.to_bytes();

    let mut webauthn_data4 = Vec::new();
    webauthn_data4.extend_from_slice(&authenticator_data4);
    webauthn_data4.extend_from_slice(client_data_json4.as_bytes());

    let aa_signature4 = AASignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(webauthn_data4),
        r: alloy::primitives::B256::from_slice(&sig_bytes4[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes4[32..64]),
        pub_key_x: correct_pub_key_x,
        pub_key_y: correct_pub_key_y,
    });

    // Try to verify - should fail during WebAuthn data validation
    let recovery_result4 = aa_signature4.recover_signer(&sig_hash4);
    assert!(
        recovery_result4.is_err(),
        "Should fail with wrong authenticator data"
    );
    println!("✓ Signature recovery correctly failed with wrong authenticator data");

    // ===========================================
    // Test Case 5: Transaction Injection Should Fail
    // ===========================================
    println!("\nTest 5: Transaction injection with invalid signature");

    // Fund one of the addresses to test transaction injection
    let test_signer_addr = tempo_primitives::transaction::aa_signature::derive_p256_address(
        &correct_pub_key_x,
        &correct_pub_key_y,
    );

    // Fund the test signer
    let transfer_amount = U256::from(10_000_000_000_000_000_000u64);
    fund_address_with_fee_tokens(
        &mut setup,
        &provider,
        &funder_signer,
        funder_addr,
        test_signer_addr,
        transfer_amount,
        chain_id,
    )
    .await?;

    // Now try to inject a transaction with wrong signature
    let bad_tx = create_test_tx(0);
    let _bad_sig_hash = bad_tx.signature_hash();

    // Create WebAuthn data with wrong challenge (like test case 3)
    let mut bad_auth_data = vec![0u8; 37];
    bad_auth_data[32] = 0x01;

    let wrong_challenge = B256::from([0xAA; 32]);
    let wrong_challenge_b64 = URL_SAFE_NO_PAD.encode(wrong_challenge.as_slice());
    let bad_client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{wrong_challenge_b64}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Sign with correct key but wrong data
    let client_hash = Sha256::digest(bad_client_data.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&bad_auth_data);
    final_hasher.update(client_hash);
    let bad_message_hash = final_hasher.finalize();

    let bad_signature: p256::ecdsa::Signature = correct_signing_key.sign(&bad_message_hash);
    let bad_sig_bytes = bad_signature.to_bytes();

    let mut bad_webauthn_data = Vec::new();
    bad_webauthn_data.extend_from_slice(&bad_auth_data);
    bad_webauthn_data.extend_from_slice(bad_client_data.as_bytes());

    let bad_aa_signature = AASignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(bad_webauthn_data),
        r: alloy::primitives::B256::from_slice(&bad_sig_bytes[0..32]),
        s: alloy::primitives::B256::from_slice(&bad_sig_bytes[32..64]),
        pub_key_x: correct_pub_key_x,
        pub_key_y: correct_pub_key_y,
    });

    let signed_bad_tx = AASigned::new_unhashed(bad_tx, bad_aa_signature);
    let bad_envelope: TempoTxEnvelope = signed_bad_tx.into();
    let mut encoded_bad = Vec::new();
    bad_envelope.encode_2718(&mut encoded_bad);

    // Try to inject - should fail
    let inject_result = setup.node.rpc.inject_tx(encoded_bad.clone().into()).await;
    assert!(
        inject_result.is_err(),
        "Transaction with invalid signature should be rejected"
    );
    println!("✓ Transaction with invalid WebAuthn signature correctly rejected");

    // Verify the rejected transaction is NOT available via eth_getTransactionByHash
    verify_tx_not_in_block_via_rpc(&provider, &encoded_bad).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_p256_call_batching() -> eyre::Result<()> {
    use sha2::{Digest, Sha256};
    use tempo_contracts::precompiles::ITIP20;

    reth_tracing::init_test_tracing();

    let initial_funding_amount = U256::from(20u64) * U256::from(10).pow(U256::from(18)); // 20 tokens with 18 decimals
    let (
        mut setup,
        provider,
        signing_key,
        pub_key_x,
        pub_key_y,
        signer_addr,
        _funder_signer,
        _funder_addr,
        chain_id,
    ) = setup_test_with_p256_funded_account(initial_funding_amount).await?;

    println!("\n=== Testing P256 Call Batching ===\n");
    println!("P256 signer address: {signer_addr}");

    // Create multiple recipient addresses for batch transfers
    let num_recipients = 5;
    let mut recipients = Vec::new();
    for i in 0..num_recipients {
        recipients.push((Address::random(), i + 1)); // Each gets different amount
    }

    println!("\nPreparing batch transfer to {num_recipients} recipients:");
    for (i, (addr, multiplier)) in recipients.iter().enumerate() {
        println!(
            "  Recipient {}: {} (amount: {} tokens)",
            i + 1,
            addr,
            multiplier
        );
    }

    // Create batch calls - transfer different amounts to each recipient
    let transfer_base_amount = U256::from(1_000_000_000_000_000_000u64); // 1 token base
    let mut calls = Vec::new();

    for (recipient, multiplier) in &recipients {
        let amount = transfer_base_amount * U256::from(*multiplier);
        let calldata = transferCall {
            to: *recipient,
            amount,
        }
        .abi_encode();

        calls.push(Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: calldata.into(),
        });
    }

    println!(
        "\nCreating AA transaction with {} batched calls",
        calls.len()
    );

    // Create AA transaction with batched calls and P256 signature
    let batch_tx = TxAA {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 500_000, // Higher gas limit for multiple calls
        calls,              // Multiple batched calls
        nonce_key: U256::ZERO,
        nonce: 0, // First transaction from P256 signer
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    // Sign with P256
    let batch_sig_hash = batch_tx.signature_hash();
    println!("Batch transaction signature hash: {batch_sig_hash}");

    // For P256, we need to optionally pre-hash the message
    // Let's test with pre_hash = true (common for Web Crypto API)
    let pre_hashed = Sha256::digest(batch_sig_hash.as_slice());

    // Sign the pre-hashed message
    let p256_signature: p256::ecdsa::Signature = signing_key.sign_prehash(&pre_hashed)?;
    let sig_bytes = p256_signature.to_bytes();

    // Create P256 AA signature
    let aa_batch_signature = AASignature::P256(P256SignatureWithPreHash {
        r: alloy::primitives::B256::from_slice(&sig_bytes[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes[32..64]),
        pub_key_x,
        pub_key_y,
        pre_hash: true, // We pre-hashed the message
    });

    println!("✓ Created P256 signature for batch transaction");

    // Verify signature recovery works
    let recovered_signer = aa_batch_signature
        .recover_signer(&batch_sig_hash)
        .expect("Should recover signer from P256 signature");
    assert_eq!(
        recovered_signer, signer_addr,
        "Recovered signer should match P256 address"
    );
    println!("✓ P256 signature recovery successful");

    // Sign and encode the batch transaction
    let signed_batch_tx = AASigned::new_unhashed(batch_tx, aa_batch_signature);
    let batch_envelope: TempoTxEnvelope = signed_batch_tx.into();
    let mut encoded_batch = Vec::new();
    batch_envelope.encode_2718(&mut encoded_batch);

    println!(
        "Encoded batch transaction: {} bytes (type: 0x{:02x})",
        encoded_batch.len(),
        encoded_batch[0]
    );

    // Get initial balances of all recipients (should be 0)
    let token = ITIP20::new(DEFAULT_FEE_TOKEN, provider.clone());
    let mut initial_balances = Vec::new();

    println!("\nChecking initial recipient balances:");
    for (i, (recipient, _)) in recipients.iter().enumerate() {
        let balance = token.balanceOf(*recipient).call().await?;
        initial_balances.push(balance);
        assert_eq!(
            balance,
            U256::ZERO,
            "Recipient {} should have 0 initial balance",
            i + 1
        );
        println!("  Recipient {}: {} tokens", i + 1, balance);
    }

    // Inject and mine the batch transaction
    println!("\nExecuting batch transaction...");
    setup
        .node
        .rpc
        .inject_tx(encoded_batch.clone().into())
        .await?;
    let batch_payload = setup.node.advance_block().await?;

    println!(
        "✓ Batch transaction mined in block {}",
        batch_payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded_batch, &batch_envelope).await?;

    // Verify the block contains the transaction
    assert!(
        !batch_payload.block().body().transactions.is_empty(),
        "Block should contain the batch transaction"
    );

    // Check that the transaction in the block is our AA transaction
    // Skip the rewards registry system tx at index 0
    let block_tx = &batch_payload.block().body().transactions[1];
    if let TempoTxEnvelope::AA(aa_tx) = block_tx {
        assert_eq!(
            aa_tx.tx().calls.len(),
            num_recipients,
            "Transaction should have {num_recipients} calls"
        );
        println!(
            "✓ Block contains AA transaction with {} calls",
            aa_tx.tx().calls.len()
        );

        // Verify it used P256 signature
        match aa_tx.signature() {
            AASignature::P256(P256SignatureWithPreHash { pre_hash, .. }) => {
                assert!(*pre_hash, "Should have pre_hash flag set");
                println!("✓ Transaction used P256 signature with pre-hash");
            }
            _ => panic!("Transaction should have P256 signature"),
        }
    } else {
        panic!("Expected AA transaction in block");
    }

    // Verify all recipients received their tokens
    println!("\nVerifying recipient balances after batch transfer:");
    for (i, ((recipient, multiplier), initial_balance)) in
        recipients.iter().zip(initial_balances.iter()).enumerate()
    {
        let expected_amount = transfer_base_amount * U256::from(*multiplier);
        let final_balance = token.balanceOf(*recipient).call().await?;

        assert_eq!(
            final_balance,
            expected_amount,
            "Recipient {} should have received {} tokens",
            i + 1,
            expected_amount
        );

        println!(
            "  Recipient {}: {} → {} tokens (expected: {})",
            i + 1,
            initial_balance,
            final_balance,
            expected_amount
        );
    }

    // Verify the P256 signer's balance decreased by the total transferred amount
    let total_transferred = (1..=num_recipients as u64)
        .map(|i| transfer_base_amount * U256::from(i))
        .fold(U256::ZERO, |acc, x| acc + x);

    let signer_final_balance = token.balanceOf(signer_addr).call().await?;
    let expected_signer_balance = initial_funding_amount - total_transferred;

    // Account for gas fees paid
    assert!(
        signer_final_balance < expected_signer_balance,
        "Signer balance should be less than initial minus transferred (due to gas fees)"
    );

    println!(
        "\n✓ P256 signer balance: {signer_final_balance} tokens (transferred: {total_transferred}, plus gas fees)"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_fee_payer_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup test node
    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Fee payer is the funded TEST_MNEMONIC account
    let fee_payer_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let fee_payer_addr = fee_payer_signer.address();

    // User is a fresh random account with no balance
    let user_signer = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = user_signer.address();

    // Create provider without wallet (we'll sign manually)
    let provider = ProviderBuilder::new().connect_http(http_url.clone());

    let chain_id = provider.get_chain_id().await?;

    println!("\n=== Testing AA Fee Payer Transaction ===\n");
    println!("Fee payer address: {fee_payer_addr}");
    println!("User address: {user_addr} (unfunded)");

    // Verify user has ZERO balance in DEFAULT_FEE_TOKEN
    let user_token_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(user_addr)
        .call()
        .await?;
    assert_eq!(
        user_token_balance,
        U256::ZERO,
        "User should have zero balance"
    );
    println!("User token balance: {user_token_balance} (expected: 0)");

    // Get fee payer's balance before transaction
    let fee_payer_balance_before = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(fee_payer_addr)
        .call()
        .await?;
    println!("Fee payer balance before: {fee_payer_balance_before} tokens");

    // Create AA transaction with fee payer signature placeholder
    let recipient = Address::random();
    let mut tx = TxAA {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO, // Protocol nonce
        nonce: 0,              // First transaction for user
        fee_token: None,       // Use DEFAULT_FEE_TOKEN
        fee_payer_signature: Some(Signature::new(U256::ZERO, U256::ZERO, false)), // Placeholder
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    println!("Created AA transaction with fee payer placeholder");

    // Step 1: User signs the transaction
    let user_sig_hash = tx.signature_hash();
    let user_signature = user_signer.sign_hash_sync(&user_sig_hash)?;
    println!("✓ User signed transaction");

    // Verify user signature is valid
    assert_eq!(
        user_signature
            .recover_address_from_prehash(&user_sig_hash)
            .unwrap(),
        user_addr,
        "User signature should recover to user address"
    );

    // Step 2: Fee payer signs the fee payer signature hash
    let fee_payer_sig_hash = tx.fee_payer_signature_hash(user_addr);
    let fee_payer_signature = fee_payer_signer.sign_hash_sync(&fee_payer_sig_hash)?;
    println!("✓ Fee payer signed fee payer hash");

    // Verify fee payer signature is valid
    assert_eq!(
        fee_payer_signature
            .recover_address_from_prehash(&fee_payer_sig_hash)
            .unwrap(),
        fee_payer_addr,
        "Fee payer signature should recover to fee payer address"
    );

    // Step 3: Update transaction with real fee payer signature
    tx.fee_payer_signature = Some(fee_payer_signature);

    // Create signed transaction with user's signature
    let aa_signature = AASignature::Secp256k1(user_signature);
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);

    // Convert to envelope and encode
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!(
        "Encoded AA transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Inject transaction and mine block
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "✓ AA fee payer transaction mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded, &envelope).await?;

    // Verify the transaction was successful
    assert!(
        !payload.block().body().transactions.is_empty(),
        "Block should contain the fee payer transaction"
    );

    // Verify user still has ZERO balance (fee payer paid)
    let user_token_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(user_addr)
        .call()
        .await?;
    assert_eq!(
        user_token_balance_after,
        U256::ZERO,
        "User should still have zero balance"
    );

    // Verify fee payer's balance decreased
    let fee_payer_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(fee_payer_addr)
        .call()
        .await?;

    println!("Fee payer balance after: {fee_payer_balance_after} tokens");

    assert!(
        fee_payer_balance_after < fee_payer_balance_before,
        "Fee payer balance should have decreased"
    );

    let gas_cost = fee_payer_balance_before - fee_payer_balance_after;
    println!("Gas cost paid by fee payer: {gas_cost} tokens");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_empty_call_batch_should_fail() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    println!("\n=== Testing AA Empty Call Batch (should fail) ===\n");
    println!("Alice address: {alice_addr}");

    // Get alice's current nonce (protocol nonce, key 0)
    let nonce = provider.get_transaction_count(alice_addr).await?;
    println!("Alice nonce: {nonce}");

    // Create AA transaction with EMPTY call batch
    // The empty vector will be properly RLP-encoded as 0xc0 (empty list)
    let tx = TxAA {
        chain_id: provider.get_chain_id().await?,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![], // EMPTY call batch - properly encoded but fails validation
        nonce_key: U256::ZERO,
        nonce,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    println!("Created AA transaction with empty call batch");

    // Sign the transaction with secp256k1
    let sig_hash = tx.signature_hash();
    let signature = alice_signer.sign_hash_sync(&sig_hash)?;
    let aa_signature = AASignature::Secp256k1(signature);
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);

    // Convert to envelope and encode
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!(
        "Encoded AA transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Try to inject transaction - should fail due to empty call batch
    let result = setup.node.rpc.inject_tx(encoded.clone().into()).await;

    // The transaction should be rejected with a specific error
    let e = result.expect_err("Transaction with empty call batch should be rejected");
    println!("✓ Transaction with empty call batch correctly rejected: {e}");

    // Verify the error is about decode failure or validation
    // Empty call batch should fail during decoding/validation
    let error_msg = e.to_string();
    assert!(
        error_msg.contains("decode")
            || error_msg.contains("empty")
            || error_msg.contains("call")
            || error_msg.contains("valid"),
        "Error should indicate decode/validation failure for empty calls, got: {error_msg}"
    );

    // Verify the rejected transaction is NOT available via eth_getTransactionByHash
    verify_tx_not_in_block_via_rpc(&provider, &encoded).await?;

    // Verify alice's nonce did NOT increment (transaction was rejected)
    let alice_nonce_after = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        alice_nonce_after, nonce,
        "Nonce should not increment for rejected transaction"
    );

    println!("✓ Test completed: Empty call batch correctly rejected");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_estimate_gas_with_key_types() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (_setup, provider, _signer, signer_addr) = setup_test_with_funded_account().await?;
    // Keep setup alive for the duration of the test
    let _ = &_setup;

    println!("\n=== Testing eth_estimateGas with keyType and keyData ===\n");
    println!("Test address: {signer_addr}");

    let recipient = Address::random();

    // Create a simple AA transaction request for gas estimation (based on issue #516 format)
    // Note: We provide maxFeePerGas and maxPriorityFeePerGas but NOT gas - gas is what we're estimating!
    let tx_request = serde_json::json!({
        "from": signer_addr.to_string(),
        "calls": [{
            "to": recipient.to_string(),
            "value": "0x0",
            "input": "0x"
        }],
    });

    // Test 1: Estimate gas WITHOUT keyType (baseline - uses secp256k1)
    println!("Test 1: Estimating gas WITHOUT keyType (baseline)");
    let baseline_gas: String = provider
        .raw_request("eth_estimateGas".into(), [tx_request.clone()])
        .await?;
    let baseline_gas_u64 = u64::from_str_radix(baseline_gas.trim_start_matches("0x"), 16)?;
    println!("  Baseline gas: {baseline_gas_u64}");

    // Test 2: Estimate gas WITH keyType="p256"
    println!("\nTest 2: Estimating gas WITH keyType='p256'");
    let mut tx_request_p256 = tx_request.clone();
    tx_request_p256
        .as_object_mut()
        .unwrap()
        .insert("keyType".to_string(), serde_json::json!("p256"));

    let p256_gas: String = provider
        .raw_request("eth_estimateGas".into(), [tx_request_p256])
        .await?;
    let p256_gas_u64 = u64::from_str_radix(p256_gas.trim_start_matches("0x"), 16)?;
    println!("  P256 gas: {p256_gas_u64}");
    // P256 should add approximately 5,000 gas (allow small tolerance for gas estimation variance)
    let p256_diff = (p256_gas_u64 as i64 - baseline_gas_u64 as i64).unsigned_abs();
    assert!(
        (4_985..=5_015).contains(&p256_diff),
        "P256 should add ~5,000 gas: actual diff {p256_diff} (expected 5,000 ±15)",
    );
    println!("  ✓ P256 adds {p256_diff} gas (expected ~5,000)");

    // Test 3: Estimate gas WITH keyType="webauthn" and keyData
    println!("\nTest 3: Estimating gas WITH keyType='webauthn' and keyData");

    // Specify WebAuthn data size (excluding 128 bytes for public keys)
    // Encoded as hex: 116 = 0x74 (1 byte) or 0x0074 (2 bytes)
    let webauthn_size = 116u16;
    let key_data_hex = format!("0x{webauthn_size:04x}"); // 2-byte encoding: "0x0074"
    println!("  Requesting WebAuthn data size: {webauthn_size} bytes (keyData: {key_data_hex})",);

    let mut tx_request_webauthn = tx_request.clone();
    tx_request_webauthn
        .as_object_mut()
        .unwrap()
        .insert("keyType".to_string(), serde_json::json!("webAuthn"));
    tx_request_webauthn
        .as_object_mut()
        .unwrap()
        .insert("keyData".to_string(), serde_json::json!(key_data_hex));

    let webauthn_gas: String = provider
        .raw_request("eth_estimateGas".into(), [tx_request_webauthn])
        .await?;
    let webauthn_gas_u64 = u64::from_str_radix(webauthn_gas.trim_start_matches("0x"), 16)?;
    println!("  WebAuthn gas: {webauthn_gas_u64}");

    // WebAuthn should add 5,000 + calldata gas
    assert!(
        webauthn_gas_u64 > p256_gas_u64,
        "WebAuthn should cost more than P256"
    );
    println!("  ✓ WebAuthn adds signature verification + calldata gas");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_authorization_list() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing EIP-7702 Authorization List with AA Signatures ===\n");

    // Setup test node with funded account
    let (mut setup, provider, sender_signer, sender_addr) =
        setup_test_with_funded_account().await?;
    let chain_id = provider.get_chain_id().await?;

    println!("Transaction sender: {sender_addr}");

    // The delegate address that all EOAs will delegate to (using default 7702 delegate)
    let delegate_address = tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;
    println!("Delegate address: {delegate_address}");

    // ========================================================================
    // Authority 1: Secp256k1 signature
    // ========================================================================
    println!("\n--- Authority 1: Secp256k1 ---");

    let auth1_signer = alloy::signers::local::PrivateKeySigner::random();
    let (auth1_signed, auth1_addr) =
        create_secp256k1_authorization(chain_id, delegate_address, &auth1_signer)?;
    println!("Authority 1 address: {auth1_addr}");
    println!("  ✓ Created Secp256k1 authorization");

    // ========================================================================
    // Authority 2: P256 signature
    // ========================================================================
    println!("\n--- Authority 2: P256 ---");

    let (auth2_signed, auth2_addr, _auth2_signing_key) =
        create_p256_authorization(chain_id, delegate_address)?;
    println!("Authority 2 address: {auth2_addr}");
    println!("  ✓ Created P256 authorization");

    // ========================================================================
    // Authority 3: WebAuthn signature
    // ========================================================================
    println!("\n--- Authority 3: WebAuthn ---");

    let (auth3_signed, auth3_addr, _auth3_signing_key) =
        create_webauthn_authorization(chain_id, delegate_address)?;
    println!("Authority 3 address: {auth3_addr}");
    println!("  ✓ Created WebAuthn authorization");

    // ========================================================================
    // Verify BEFORE state: All authority accounts should have no code
    // ========================================================================
    println!("\n--- Verifying BEFORE state ---");

    let auth1_code_before = provider.get_code_at(auth1_addr).await?;
    let auth2_code_before = provider.get_code_at(auth2_addr).await?;
    let auth3_code_before = provider.get_code_at(auth3_addr).await?;

    assert_eq!(
        auth1_code_before.len(),
        0,
        "Authority 1 should have no code before delegation"
    );
    assert_eq!(
        auth2_code_before.len(),
        0,
        "Authority 2 should have no code before delegation"
    );
    assert_eq!(
        auth3_code_before.len(),
        0,
        "Authority 3 should have no code before delegation"
    );
    // ========================================================================
    // Create AA transaction with authorization list using RPC
    // ========================================================================
    println!("\n--- Creating AA transaction with authorization list via RPC ---");

    let recipient = Address::random();

    // Create transaction request using RPC interface
    use alloy::rpc::types::TransactionRequest;
    use tempo_node::rpc::TempoTransactionRequest;

    let tx_request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(sender_addr),
            to: Some(recipient.into()),
            value: Some(U256::ZERO),
            gas: Some(300_000), // Higher gas for authorization list processing
            max_fee_per_gas: Some(TEMPO_BASE_FEE as u128),
            max_priority_fee_per_gas: Some(TEMPO_BASE_FEE as u128),
            nonce: Some(provider.get_transaction_count(sender_addr).await?),
            chain_id: Some(chain_id),
            ..Default::default()
        },
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        aa_authorization_list: vec![auth1_signed, auth2_signed, auth3_signed], // All 3 authorizations
        ..Default::default()
    };

    println!(
        "  Created tx request with {} authorizations (Secp256k1, P256, WebAuthn)",
        tx_request.aa_authorization_list.len()
    );

    // Build the AA transaction from the request
    let tx = tx_request
        .build_aa()
        .map_err(|e| eyre::eyre!("Failed to build AA tx: {:?}", e))?;

    // Sign the transaction with sender's secp256k1 key
    let tx_sig_hash = tx.signature_hash();
    let tx_signature = sender_signer.sign_hash_sync(&tx_sig_hash)?;
    let tx_aa_signature = AASignature::Secp256k1(tx_signature);
    let signed_tx = AASigned::new_unhashed(tx, tx_aa_signature);

    // Convert to envelope and encode
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!(
        "  Encoded transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Test encoding/decoding roundtrip
    let decoded = TempoTxEnvelope::decode_2718(&mut encoded.as_slice())?;
    assert!(
        matches!(decoded, TempoTxEnvelope::AA(_)),
        "Should decode as AA transaction"
    );
    println!("  ✓ Encoding/decoding roundtrip successful");

    // Submit transaction via RPC
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "  ✓ Transaction mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction via RPC
    verify_tx_in_block_via_rpc(&provider, &encoded, &envelope).await?;

    // Verify the authorization list was included in the transaction and get recovered addresses
    let mut recovered_authorities = Vec::new();
    if let TempoTxEnvelope::AA(aa_tx) = &envelope {
        println!("\n--- Verifying authorization list in transaction ---");
        println!(
            "  Authorization list length: {}",
            aa_tx.tx().aa_authorization_list.len()
        );

        // Verify each authorization can be recovered
        for (i, aa_auth) in aa_tx.tx().aa_authorization_list.iter().enumerate() {
            match aa_auth.recover_authority() {
                Ok(authority) => {
                    println!("  ✓ Authorization {} recovered: {}", i + 1, authority);
                    recovered_authorities.push(authority);
                }
                Err(e) => {
                    println!("  ✗ Authorization {} recovery failed: {:?}", i + 1, e);
                    panic!("Authorization recovery failed");
                }
            }
        }
    }

    // Verify that recovered authorities match expected addresses
    assert_eq!(
        recovered_authorities[0], auth1_addr,
        "Secp256k1 authority should match expected address"
    );
    assert_eq!(
        recovered_authorities[1], auth2_addr,
        "P256 authority should match expected address"
    );
    assert_eq!(
        recovered_authorities[2], auth3_addr,
        "WebAuthn authority should match expected address"
    );

    // ========================================================================
    // Verify AFTER state: All authority accounts should have delegation code
    // ========================================================================
    println!("\n--- Verifying AFTER state ---");

    let auth1_code_after = provider.get_code_at(recovered_authorities[0]).await?;
    let auth2_code_after = provider.get_code_at(recovered_authorities[1]).await?;
    let auth3_code_after = provider.get_code_at(recovered_authorities[2]).await?;

    // Verify each authority has correct EIP-7702 delegation code
    verify_delegation_code(
        &auth1_code_after,
        delegate_address,
        "Authority 1 (Secp256k1)",
    );
    verify_delegation_code(&auth2_code_after, delegate_address, "Authority 2 (P256)");
    verify_delegation_code(
        &auth3_code_after,
        delegate_address,
        "Authority 3 (WebAuthn)",
    );

    println!("verification successful");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_bump_nonce_on_failure() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    // Verify alice has zero native balance
    let alice_eth_balance = provider.get_account_info(alice_addr).await?.balance;
    assert_eq!(
        alice_eth_balance,
        U256::ZERO,
        "Test accounts should have zero ETH balance"
    );

    println!("Alice address: {alice_addr}");
    println!("Alice ETH balance: {alice_eth_balance} (expected: 0)");

    // Get alice's current nonce (protocol nonce, key 0)
    let nonce = provider.get_transaction_count(alice_addr).await?;
    println!("Alice nonce: {nonce}");

    // Create AA transaction with secp256k1 signature and protocol nonce
    let tx = TxAA {
        chain_id: provider.get_chain_id().await?,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: alloy_primitives::bytes!("0xef"),
        }],
        nonce_key: U256::ZERO, // Protocol nonce (key 0)
        nonce,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    println!("Created AA transaction with secp256k1 signature");

    // Sign the transaction with secp256k1
    let sig_hash = tx.signature_hash();
    let signature = alice_signer.sign_hash_sync(&sig_hash)?;
    let aa_signature = AASignature::Secp256k1(signature);
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);

    // Convert to envelope and encode
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!(
        "Encoded AA transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Inject transaction and mine block
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "✓ AA transaction mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded, &envelope).await?;

    // Verify alice's nonce incremented (protocol nonce)
    // This proves the transaction was successfully mined and executed
    let alice_nonce_after = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        alice_nonce_after,
        nonce + 1,
        "Protocol nonce should increment"
    );
    Ok(())
}
