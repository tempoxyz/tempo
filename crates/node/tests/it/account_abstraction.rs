use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::MnemonicBuilder},
};
use alloy_eips::{Decodable2718, Encodable2718};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, contracts::INonce};
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
