use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::MnemonicBuilder},
    sol_types::SolCall,
};
use alloy_eips::{Decodable2718, Encodable2718};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS,
    contracts::{INonce, ITIP20::transferCall},
};
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        TxAA, aa_signature::AASignature, aa_signed::AASigned, account_abstraction::Call,
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_basic_transfer_secp256k1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup test node with direct access
    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Use TEST_MNEMONIC account (has balance in DEFAULT_FEE_TOKEN from genesis)
    let alice_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let alice_addr = alice_signer.address();

    // Create provider with wallet
    let wallet = EthereumWallet::from(alice_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    // Verify alice has ZERO native ETH (this is expected - gas paid via fee tokens)
    let alice_eth_balance = provider.get_balance(alice_addr).await?;
    assert_eq!(
        alice_eth_balance,
        U256::ZERO,
        "Test accounts should have zero ETH balance"
    );

    println!("Alice address: {}", alice_addr);
    println!("Alice ETH balance: {} (expected: 0)", alice_eth_balance);

    // Create recipient address
    let recipient = Address::random();

    // Get alice's current nonce (protocol nonce, key 0)
    let nonce = provider.get_transaction_count(alice_addr).await?;
    println!("Alice nonce: {}", nonce);

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
        nonce_key: 0, // Protocol nonce (key 0)
        nonce_sequence: nonce,
        fee_token: None, // Will use DEFAULT_FEE_TOKEN from genesis
        fee_payer_signature: None,
        valid_before: 0,
        valid_after: None,
        access_list: Default::default(),
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
    setup.node.rpc.inject_tx(encoded.into()).await?;
    let payload = setup.node.advance_block().await?;

    println!("✓ AA transaction mined in block {}", payload.block().number);

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

    // Setup test node
    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Use TEST_MNEMONIC account
    let alice_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let alice_addr = alice_signer.address();

    // Create provider with wallet
    let wallet = EthereumWallet::from(alice_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    // Create nonce precompile contract instance
    let nonce_contract = INonce::new(NONCE_PRECOMPILE_ADDRESS, provider.clone());

    println!("\nTesting AA 2D Nonce System");
    println!("Alice address: {}", alice_addr);

    // Check initial state
    let initial_nonce = nonce_contract.getNonce(alice_addr, 1).call().await?;
    println!("Initial nonce[key=1]: {}", initial_nonce);
    assert_eq!(initial_nonce, 0, "Initial nonce should be 0");

    let recipient = Address::random();
    let chain_id = provider.get_chain_id().await?;

    // Step 1: Send first AA transaction with nonce_key=1, sequence=0
    println!("\n1. Sending first AA transaction (nonce_key=1, sequence=0)");

    let tx1 = TxAA {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: 1,
        nonce_sequence: 0,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: 0,
        valid_after: None,
        access_list: Default::default(),
    };

    // Sign and encode transaction
    let sig_hash = tx1.signature_hash();
    let signature = alice_signer.sign_hash_sync(&sig_hash)?;
    let signed_tx1 = AASigned::new_unhashed(tx1, AASignature::Secp256k1(signature));
    let envelope1: TempoTxEnvelope = signed_tx1.into();
    let mut encoded1 = Vec::new();
    envelope1.encode_2718(&mut encoded1);

    println!("Transaction encoded, size: {} bytes", encoded1.len());

    // Inject transaction and mine block
    setup.node.rpc.inject_tx(encoded1.into()).await?;
    let payload = setup.node.advance_block().await?;
    println!("✓ Transaction mined in block {}", payload.block().number);

    // Step 2: Verify nonce was incremented
    println!("\n2. Verifying nonce increment");
    let nonce_after_tx = nonce_contract.getNonce(alice_addr, 1).call().await?;
    println!("Nonce[key=1] after transaction: {}", nonce_after_tx);
    assert_eq!(nonce_after_tx, 1, "Nonce should be incremented to 1");

    // Step 3: Try to send duplicate transaction with same nonce sequence
    println!("\n3. Testing duplicate nonce rejection");

    let tx2 = TxAA {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: 1,
        nonce_sequence: 0, // DUPLICATE - should fail
        fee_token: None,
        fee_payer_signature: None,
        valid_before: 0,
        valid_after: None,
        access_list: Default::default(),
    };

    let sig_hash = tx2.signature_hash();
    let signature = alice_signer.sign_hash_sync(&sig_hash)?;
    let signed_tx2 = AASigned::new_unhashed(tx2, AASignature::Secp256k1(signature));
    let envelope2: TempoTxEnvelope = signed_tx2.into();
    let mut encoded2 = Vec::new();
    envelope2.encode_2718(&mut encoded2);

    // Try to inject duplicate transaction - this SHOULD fail
    let result = setup.node.rpc.inject_tx(encoded2.into()).await;

    // The transaction should be rejected
    assert!(
        result.is_err(),
        "Duplicate nonce transaction should be rejected"
    );

    if let Err(e) = result {
        println!("✓ Transaction correctly rejected: {}", e);

        // Verify the error is about nonce
        let error_msg = e.to_string();
        assert!(
            error_msg.contains("nonce") || error_msg.contains("Invalid2DNonce"),
            "Error should indicate nonce issue, got: {}",
            error_msg
        );
    }

    println!("\n✅ AA 2D Nonce System Test Passed!");
    println!("  • Nonce correctly incremented from 0 to 1");
    println!("  • Duplicate nonce transaction properly rejected");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_webauthn_signature_flow() -> eyre::Result<()> {
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::elliptic_curve::rand_core::OsRng;
    use sha2::{Digest, Sha256};

    reth_tracing::init_test_tracing();

    // Setup test node with direct access
    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Generate a P256 key pair for WebAuthn
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Extract public key coordinates
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_slice());
    let pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_slice());

    // Derive the WebAuthn signer's address
    let signer_addr =
        tempo_primitives::transaction::aa_signature::derive_p256_address(&pub_key_x, &pub_key_y);

    println!("WebAuthn signer address: {}", signer_addr);
    println!("Public key X: {}", pub_key_x);
    println!("Public key Y: {}", pub_key_y);

    // Use TEST_MNEMONIC account to fund the WebAuthn signer
    let funder_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let funder_addr = funder_signer.address();

    // Create provider with funder's wallet
    let funder_wallet = EthereumWallet::from(funder_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(funder_wallet)
        .connect_http(http_url.clone());

    println!("Funder address: {}", funder_addr);

    // Get chain ID
    let chain_id = provider.get_chain_id().await?;

    // First, fund the WebAuthn signer with fee tokens using an AA transaction from the funder
    println!("\nFunding WebAuthn signer with fee tokens...");

    // The funder should transfer DEFAULT_FEE_TOKEN to the WebAuthn signer
    // Encode ERC20 transfer call
    let transfer_amount = U256::from(10_000_000_000_000_000_000u64); // 10 tokens (assuming 18 decimals)
    let transfer_calldata = transferCall {
        to: signer_addr,
        amount: transfer_amount,
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
        nonce_key: 0,
        nonce_sequence: provider.get_transaction_count(funder_addr).await?,
        fee_token: None, // Uses DEFAULT_FEE_TOKEN
        fee_payer_signature: None,
        valid_before: 0,
        valid_after: None,
        access_list: Default::default(),
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
        "✓ Funding transaction mined in block {}",
        funding_payload.block().number
    );

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
        nonce_key: 0,      // Protocol nonce
        nonce_sequence: 0, // First transaction
        fee_token: None,   // Will use DEFAULT_FEE_TOKEN from genesis
        fee_payer_signature: None,
        valid_before: 0,
        valid_after: None,
        access_list: Default::default(),
    };

    println!("Created AA transaction for WebAuthn signature");

    // Get the signature hash
    let sig_hash = tx.signature_hash();
    println!("Transaction signature hash: {}", sig_hash);

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
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","crossOrigin":false}}"#,
        challenge_b64url
    );

    println!("ClientDataJSON: {}", client_data_json);

    // Compute the message hash for P256 signature according to WebAuthn spec:
    // messageHash = sha256(authenticatorData || sha256(clientDataJSON))
    let mut hasher = Sha256::new();
    hasher.update(client_data_json.as_bytes());
    let client_data_hash = hasher.finalize();

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data);
    final_hasher.update(&client_data_hash);
    let message_hash = final_hasher.finalize();

    // Sign the message hash with P256
    let signature: p256::ecdsa::Signature = signing_key.sign(&message_hash);
    let sig_bytes = signature.to_bytes();

    // Construct WebAuthn data: authenticatorData || clientDataJSON
    let mut webauthn_data = Vec::new();
    webauthn_data.extend_from_slice(&authenticator_data);
    webauthn_data.extend_from_slice(client_data_json.as_bytes());

    // Create WebAuthn AA signature
    let aa_signature = AASignature::WebAuthn {
        webauthn_data: Bytes::from(webauthn_data),
        r: alloy::primitives::B256::from_slice(&sig_bytes[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes[32..64]),
        pub_key_x,
        pub_key_y,
    };

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
    setup.node.rpc.inject_tx(encoded.into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "✓ AA transaction with WebAuthn signature mined in block {}",
        payload.block().number
    );

    // Verify the block contains transactions
    assert!(
        payload.block().body().transactions.len() > 0,
        "Block should contain the WebAuthn transaction"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_webauthn_signature_negative_cases() -> eyre::Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::elliptic_curve::rand_core::OsRng;
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
        nonce_key: 0,
        nonce_sequence: nonce_seq,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: 0,
        valid_after: None,
        access_list: Default::default(),
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
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","crossOrigin":false}}"#,
        challenge_b64url1
    );

    // Compute message hash
    let mut hasher = Sha256::new();
    hasher.update(client_data_json1.as_bytes());
    let client_data_hash1 = hasher.finalize();

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data1);
    final_hasher.update(&client_data_hash1);
    let message_hash1 = final_hasher.finalize();

    // Sign with CORRECT private key
    let signature1: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash1);
    let sig_bytes1 = signature1.to_bytes();

    // But use WRONG public key in the signature
    let mut webauthn_data1 = Vec::new();
    webauthn_data1.extend_from_slice(&authenticator_data1);
    webauthn_data1.extend_from_slice(client_data_json1.as_bytes());

    let aa_signature1 = AASignature::WebAuthn {
        webauthn_data: Bytes::from(webauthn_data1),
        r: alloy::primitives::B256::from_slice(&sig_bytes1[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes1[32..64]),
        pub_key_x: wrong_pub_key_x, // WRONG public key
        pub_key_y: wrong_pub_key_y, // WRONG public key
    };

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
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","crossOrigin":false}}"#,
        challenge_b64url2
    );

    // Compute message hash
    let mut hasher = Sha256::new();
    hasher.update(client_data_json2.as_bytes());
    let client_data_hash2 = hasher.finalize();

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data2);
    final_hasher.update(&client_data_hash2);
    let message_hash2 = final_hasher.finalize();

    // Sign with WRONG private key
    let signature2: p256::ecdsa::Signature = wrong_signing_key.sign(&message_hash2);
    let sig_bytes2 = signature2.to_bytes();

    // But use CORRECT public key in the signature
    let mut webauthn_data2 = Vec::new();
    webauthn_data2.extend_from_slice(&authenticator_data2);
    webauthn_data2.extend_from_slice(client_data_json2.as_bytes());

    let aa_signature2 = AASignature::WebAuthn {
        webauthn_data: Bytes::from(webauthn_data2),
        r: alloy::primitives::B256::from_slice(&sig_bytes2[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes2[32..64]),
        pub_key_x: correct_pub_key_x, // Correct public key
        pub_key_y: correct_pub_key_y, // But signature is from wrong private key
    };

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
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","crossOrigin":false}}"#,
        wrong_challenge_b64url
    );

    // Compute message hash
    let mut hasher = Sha256::new();
    hasher.update(client_data_json3.as_bytes());
    let client_data_hash3 = hasher.finalize();

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data3);
    final_hasher.update(&client_data_hash3);
    let message_hash3 = final_hasher.finalize();

    // Sign with correct private key
    let signature3: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash3);
    let sig_bytes3 = signature3.to_bytes();

    let mut webauthn_data3 = Vec::new();
    webauthn_data3.extend_from_slice(&authenticator_data3);
    webauthn_data3.extend_from_slice(client_data_json3.as_bytes());

    let aa_signature3 = AASignature::WebAuthn {
        webauthn_data: Bytes::from(webauthn_data3),
        r: alloy::primitives::B256::from_slice(&sig_bytes3[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes3[32..64]),
        pub_key_x: correct_pub_key_x,
        pub_key_y: correct_pub_key_y,
    };

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
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","crossOrigin":false}}"#,
        challenge_b64url4
    );

    // Compute message hash
    let mut hasher = Sha256::new();
    hasher.update(client_data_json4.as_bytes());
    let client_data_hash4 = hasher.finalize();

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data4);
    final_hasher.update(&client_data_hash4);
    let message_hash4 = final_hasher.finalize();

    // Sign with correct private key
    let signature4: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash4);
    let sig_bytes4 = signature4.to_bytes();

    let mut webauthn_data4 = Vec::new();
    webauthn_data4.extend_from_slice(&authenticator_data4);
    webauthn_data4.extend_from_slice(client_data_json4.as_bytes());

    let aa_signature4 = AASignature::WebAuthn {
        webauthn_data: Bytes::from(webauthn_data4),
        r: alloy::primitives::B256::from_slice(&sig_bytes4[0..32]),
        s: alloy::primitives::B256::from_slice(&sig_bytes4[32..64]),
        pub_key_x: correct_pub_key_x,
        pub_key_y: correct_pub_key_y,
    };

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
    let transfer_calldata = transferCall {
        to: test_signer_addr,
        amount: transfer_amount,
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
        nonce_key: 0,
        nonce_sequence: provider.get_transaction_count(funder_addr).await?,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: 0,
        valid_after: None,
        access_list: Default::default(),
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
    let _funding_payload = setup.node.advance_block().await?;
    println!("✓ Test signer funded with fee tokens");

    // Now try to inject a transaction with wrong signature
    let bad_tx = create_test_tx(0);
    let _bad_sig_hash = bad_tx.signature_hash();

    // Create WebAuthn data with wrong challenge (like test case 3)
    let mut bad_auth_data = vec![0u8; 37];
    bad_auth_data[32] = 0x01;

    let wrong_challenge = B256::from([0xAA; 32]);
    let wrong_challenge_b64 = URL_SAFE_NO_PAD.encode(wrong_challenge.as_slice());
    let bad_client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","crossOrigin":false}}"#,
        wrong_challenge_b64
    );

    // Sign with correct key but wrong data
    let mut hasher = Sha256::new();
    hasher.update(bad_client_data.as_bytes());
    let client_hash = hasher.finalize();

    let mut final_hasher = Sha256::new();
    final_hasher.update(&bad_auth_data);
    final_hasher.update(&client_hash);
    let bad_message_hash = final_hasher.finalize();

    let bad_signature: p256::ecdsa::Signature = correct_signing_key.sign(&bad_message_hash);
    let bad_sig_bytes = bad_signature.to_bytes();

    let mut bad_webauthn_data = Vec::new();
    bad_webauthn_data.extend_from_slice(&bad_auth_data);
    bad_webauthn_data.extend_from_slice(bad_client_data.as_bytes());

    let bad_aa_signature = AASignature::WebAuthn {
        webauthn_data: Bytes::from(bad_webauthn_data),
        r: alloy::primitives::B256::from_slice(&bad_sig_bytes[0..32]),
        s: alloy::primitives::B256::from_slice(&bad_sig_bytes[32..64]),
        pub_key_x: correct_pub_key_x,
        pub_key_y: correct_pub_key_y,
    };

    let signed_bad_tx = AASigned::new_unhashed(bad_tx, bad_aa_signature);
    let bad_envelope: TempoTxEnvelope = signed_bad_tx.into();
    let mut encoded_bad = Vec::new();
    bad_envelope.encode_2718(&mut encoded_bad);

    // Try to inject - should fail
    let inject_result = setup.node.rpc.inject_tx(encoded_bad.into()).await;
    assert!(
        inject_result.is_err(),
        "Transaction with invalid signature should be rejected"
    );
    println!("✓ Transaction with invalid WebAuthn signature correctly rejected");

    println!("\n✅ All WebAuthn Negative Test Cases Passed!");
    println!("  • Wrong public key: signature verification failed ✓");
    println!("  • Wrong private key: signature verification failed ✓");
    println!("  • Wrong challenge: WebAuthn validation failed ✓");
    println!("  • Wrong authenticator data: WebAuthn validation failed ✓");
    println!("  • Invalid signature transaction: injection rejected ✓");

    Ok(())
}
