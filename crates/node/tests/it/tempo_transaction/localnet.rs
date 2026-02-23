use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    consensus::{BlockHeader, Transaction},
    network::EthereumWallet,
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::MnemonicBuilder},
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use reth_ethereum::network::{NetworkSyncUpdater, SyncState};
use reth_primitives_traits::transaction::TxHashRef;
use reth_transaction_pool::TransactionPool;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, account_keychain::IAccountKeychain::revokeKeyCall,
};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    tip20::ITIP20::{self},
};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature, WebAuthnSignature},
        tt_signed::AASigned,
    },
};

use super::helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_2d_nonce_pool_comprehensive() -> eyre::Result<()> {
    let localnet = super::helpers::Localnet::new().await?;
    let super::helpers::Localnet {
        mut setup,
        provider,
        chain_id,
        funder_signer: alice_signer,
        funder_addr: alice_addr,
    } = localnet;

    println!("\n=== Comprehensive 2D Nonce Pool Test ===\n");
    println!("Alice address: {alice_addr}");

    let recipient = Address::random();

    // ===========================================================================
    // Scenario 1: Pool Routing & Independence
    // ===========================================================================
    println!("\n--- Scenario 1: Pool Routing & Independence ---");

    let initial_nonce = provider.get_transaction_count(alice_addr).await?;
    println!("Initial protocol nonce: {initial_nonce}");

    // Send 3 transactions with different nonce_keys
    let mut sent = vec![];
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            0,
            initial_nonce,
            TEMPO_T1_BASE_FEE as u128,
        )
        .await?,
    ); // Protocol pool
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            1,
            0,
            TEMPO_T1_BASE_FEE as u128,
        )
        .await?,
    ); // 2D pool
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            2,
            0,
            TEMPO_T1_BASE_FEE as u128,
        )
        .await?,
    ); // 2D pool

    for tx_hash in &sent {
        // Assert that transactions are in the pool
        assert!(
            setup.node.inner.pool.contains(tx_hash),
            "Transaction should be in the pool"
        );
    }

    // Mine block
    let payload1 = setup.node.advance_block().await?;
    let block1_txs = &payload1.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload1.block().inner.number,
        block1_txs.len()
    );

    // Verify all submitted transactions were included in the block
    for tx_hash in &sent {
        assert!(
            block1_txs.iter().any(|tx| tx.tx_hash() == tx_hash),
            "Submitted tx {tx_hash} should be in the block"
        );
    }

    // Verify protocol nonce incremented
    let protocol_nonce_after = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        protocol_nonce_after,
        initial_nonce + 1,
        "Protocol nonce should increment only once"
    );
    println!("  ✓ Protocol nonce: {initial_nonce} → {protocol_nonce_after}",);

    for tx_hash in &sent {
        wait_until_pool_not_contains(&setup.node.inner.pool, tx_hash, "scenario 1").await?;
    }
    println!("  ✓ All 3 transactions from different pools included in block");

    // ===========================================================================
    // Scenario 2: Priority Fee Ordering (with subsequent nonces)
    // ===========================================================================
    println!("\n--- Scenario 2: Priority Fee Ordering ---");

    // Send transactions with different priority fees
    let low_fee = 1_000_000_000u128; // 1 gwei
    let mid_fee = 5_000_000_000u128; // 5 gwei
    let high_fee = 10_000_000_000u128; // 10 gwei

    let mut sent = vec![];
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            0,
            protocol_nonce_after,
            low_fee,
        )
        .await?,
    ); // Protocol pool, low fee
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            1,
            1,
            high_fee,
        )
        .await?,
    ); // 2D pool, highest fee
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            2,
            1,
            mid_fee,
        )
        .await?,
    ); // 2D pool, medium fee

    for tx_hash in &sent {
        // Assert that transactions are in the pool
        assert!(
            setup.node.inner.pool.contains(tx_hash),
            "Transaction should be in the pool"
        );
    }

    // Mine block
    let payload2 = setup.node.advance_block().await?;
    let block2_txs = &payload2.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload2.block().inner.number,
        block2_txs.len()
    );

    assert_eq!(
        provider.get_transaction_count(alice_addr).await?,
        initial_nonce + 2,
        "Protocol nonce should have incremented twice"
    );

    // Verify all submitted transactions were included in the block
    for tx_hash in &sent {
        assert!(
            block2_txs.iter().any(|tx| tx.tx_hash() == tx_hash),
            "Submitted tx {tx_hash} should be in the block"
        );
    }

    // Extract priority fees in block order, filtered to only our submitted txs
    let priority_fees: Vec<u128> = block2_txs
        .iter()
        .filter(|tx| sent.contains(tx.tx_hash()))
        .filter_map(|tx| match tx {
            TempoTxEnvelope::AA(aa_tx) => {
                println!(
                    "    TX with nonce_key={}, nonce={}, priority_fee={} gwei",
                    aa_tx.tx().nonce_key,
                    aa_tx.tx().nonce,
                    aa_tx.tx().max_priority_fee_per_gas / 1_000_000_000
                );
                Some(aa_tx.tx().max_priority_fee_per_gas)
            }
            _ => None,
        })
        .collect();

    // Verify all 3 transactions are included and ordered by descending priority fee
    assert_eq!(priority_fees.len(), 3, "Should have 3 AA transactions");
    assert!(
        priority_fees.windows(2).all(|w| w[0] >= w[1]),
        "Transactions should be ordered by descending priority fee, got: {priority_fees:?}"
    );
    println!("  ✓ All transactions included and ordered by descending priority fee");

    for tx_hash in &sent {
        wait_until_pool_not_contains(&setup.node.inner.pool, tx_hash, "scenario 2").await?;
    }

    // ===========================================================================
    // Scenario 3: Nonce Gap Handling
    // ===========================================================================
    println!("\n--- Scenario 3: Nonce Gap Handling ---");

    // Send nonce=0 for nonce_key=3 (should be pending)
    let pending = send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        3,
        0,
        TEMPO_T1_BASE_FEE as u128,
    )
    .await?;
    println!("  Sent nonce_key=3, nonce=0 (should be pending)");

    // Send nonce=2 for nonce_key=3 (should be queued - gap at nonce=1)
    let queued = send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        3,
        2,
        TEMPO_T1_BASE_FEE as u128,
    )
    .await?;
    println!("  Sent nonce_key=3, nonce=2 (should be queued - gap at nonce=1)");

    // Assert that both transactions are in the pool and tracked correctly
    assert!(
        setup
            .node
            .inner
            .pool
            .pending_transactions()
            .iter()
            .any(|tx| tx.hash() == &pending)
    );
    assert!(
        setup
            .node
            .inner
            .pool
            .queued_transactions()
            .iter()
            .any(|tx| tx.hash() == &queued)
    );

    // Mine block - only nonce=0 should be included
    let payload3 = setup.node.advance_block().await?;
    let block3_txs = &payload3.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload3.block().inner.number,
        block3_txs.len()
    );

    // Count AA transactions with nonce_key=3
    let nonce_key_3_txs: Vec<_> = block3_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(3)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        nonce_key_3_txs.len(),
        1,
        "Only 1 transaction (nonce=0) should be included, nonce=2 should be queued"
    );
    assert_eq!(
        nonce_key_3_txs[0], 0,
        "The included transaction should have nonce=0"
    );
    println!("  ✓ Only nonce=0 included, nonce=2 correctly queued due to gap");

    // Fill the gap - send nonce=1
    let new_pending = send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        3,
        1,
        TEMPO_T1_BASE_FEE as u128,
    )
    .await?;
    println!("\n  Sent nonce_key=3, nonce=1 (fills the gap)");

    assert!(
        setup
            .node
            .inner
            .pool
            .pending_transactions()
            .iter()
            .any(|tx| tx.hash() == &new_pending)
    );
    assert!(
        setup
            .node
            .inner
            .pool
            .pending_transactions()
            .iter()
            .any(|tx| tx.hash() == &queued)
    );

    // Mine block - both nonce=1 and nonce=2 should be included now
    let payload4 = setup.node.advance_block().await?;
    let block4_txs = &payload4.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload4.block().inner.number,
        block4_txs.len()
    );

    // Count AA transactions with nonce_key=3
    let mut nonce_key_3_txs_after: Vec<_> = block4_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(3)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();

    nonce_key_3_txs_after.sort();

    // After filling the gap, both nonce=1 and nonce=2 should be mined
    assert!(
        nonce_key_3_txs_after.contains(&1),
        "nonce=1 should be included after filling gap"
    );
    assert!(
        nonce_key_3_txs_after.contains(&2),
        "nonce=2 should be promoted from queue after gap is filled"
    );
    println!("  ✓ Both nonce=1 and nonce=2 included");

    wait_until_pool_not_contains(&setup.node.inner.pool, &pending, "scenario 3 pending").await?;
    wait_until_pool_not_contains(&setup.node.inner.pool, &queued, "scenario 3 queued").await?;
    wait_until_pool_not_contains(
        &setup.node.inner.pool,
        &new_pending,
        "scenario 3 new_pending",
    )
    .await?;

    Ok(())
}
/// Sign and inject a secp256k1 AA transaction with a custom nonce key and priority fee.
async fn send_tx(
    setup: &mut crate::utils::SingleNodeSetup,
    signer: &impl SignerSync,
    chain_id: u64,
    recipient: Address,
    nonce_key: u64,
    nonce: u64,
    priority_fee: u128,
) -> eyre::Result<B256> {
    let mut tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx.nonce_key = U256::from(nonce_key);
    tx.max_priority_fee_per_gas = priority_fee;
    tx.max_fee_per_gas = TEMPO_T1_BASE_FEE as u128 + priority_fee;
    tx.fee_token = None;

    let signature = sign_aa_tx_secp256k1(&tx, signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let tx_hash = *envelope.tx_hash();
    setup
        .node
        .rpc
        .inject_tx(envelope.encoded_2718().into())
        .await?;
    println!(
        "  ✓ Sent tx: nonce_key={nonce_key}, nonce={nonce}, priority_fee={} gwei",
        priority_fee / 1_000_000_000
    );
    Ok(tx_hash)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_2d_nonce_out_of_order_arrival() -> eyre::Result<()> {
    let super::helpers::Localnet {
        mut setup,
        chain_id,
        funder_signer: alice_signer,
        ..
    } = super::helpers::Localnet::new().await?;

    let recipient = Address::random();

    println!("\n=== Out-of-Order Nonce Arrival Test ===");
    println!("Testing nonce_key=4 with nonces arriving as: [5, 0, 2]");
    println!("Expected: Only execute in order, queue out-of-order txs\n");

    // Step 1: Send nonce=5 (should be queued - large gap)
    println!("Step 1: Send nonce=5 (should be queued - gap at 0,1,2,3,4)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        5,
        10_000_000_000,
    )
    .await?;

    // Step 2: Send nonce=0 (should be pending - ready to execute)
    println!("\nStep 2: Send nonce=0 (should be pending - ready to execute)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        0,
        10_000_000_000,
    )
    .await?;

    // Step 3: Send nonce=2 (should be queued - gap at 1)
    println!("\nStep 3: Send nonce=2 (should be queued - gap at 1)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        2,
        10_000_000_000,
    )
    .await?;

    // Mine block - only nonce=0 should execute
    println!("\nMining block (should only include nonce=0)...");
    let payload1 = setup.node.advance_block().await?;
    let block1_txs = &payload1.block().body().transactions;

    let executed_nonces: Vec<u64> = block1_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(4)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(executed_nonces, vec![0], "Only nonce=0 should execute");
    println!("  ✓ Block 1: Only nonce=0 executed (nonce=2 and nonce=5 correctly queued)");

    // Step 4: Send nonce=1 (fills first gap)
    println!("\nStep 4: Send nonce=1 (fills gap before nonce=2)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        1,
        10_000_000_000,
    )
    .await?;

    // Mine block - nonce=1 and nonce=2 should both execute (promotion!)
    println!("\nMining block (should include nonce=1 AND nonce=2 via promotion)...");
    let payload2 = setup.node.advance_block().await?;
    let block2_txs = &payload2.block().body().transactions;

    let mut executed_nonces: Vec<u64> = block2_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(4)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();
    executed_nonces.sort();

    assert!(executed_nonces.contains(&1), "nonce=1 should execute");
    assert!(
        executed_nonces.contains(&2),
        "nonce=2 should promote and execute"
    );
    println!("  ✓ Block 2: nonce=1 and nonce=2 executed (promotion worked!)");

    // Step 5: Send nonces 3 and 4 (fills remaining gaps)
    println!("\nStep 5: Send nonces 3 and 4 (fills gaps before nonce=5)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        3,
        10_000_000_000,
    )
    .await?;
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        4,
        10_000_000_000,
    )
    .await?;

    // Mine block - nonces 3, 4, and 5 should all execute
    println!("\nMining block (should include nonces 3, 4, AND 5 via promotion)...");
    let payload3 = setup.node.advance_block().await?;
    let block3_txs = &payload3.block().body().transactions;

    let mut executed_nonces: Vec<u64> = block3_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(4)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();
    executed_nonces.sort();

    assert!(executed_nonces.contains(&3), "nonce=3 should execute");
    assert!(executed_nonces.contains(&4), "nonce=4 should execute");
    assert!(
        executed_nonces.contains(&5),
        "nonce=5 should finally promote and execute"
    );
    Ok(())
}

#[tokio::test]
async fn test_aa_webauthn_signature_negative_cases() -> eyre::Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{
        ecdsa::{SigningKey, signature::Signer},
        elliptic_curve::rand_core::OsRng,
    };
    use sha2::{Digest, Sha256};

    reth_tracing::init_test_tracing();

    // Setup test node with direct access
    let setup = TestNodeBuilder::new().build_with_node_access().await?;

    let http_url = setup.node.rpc_url();

    // Generate the correct P256 key pair for WebAuthn
    let correct_signing_key = SigningKey::random(&mut OsRng);
    let correct_verifying_key = correct_signing_key.verifying_key();

    // Extract correct public key coordinates
    let correct_encoded_point = correct_verifying_key.to_encoded_point(false);
    let correct_pub_key_x =
        alloy::primitives::B256::from_slice(correct_encoded_point.x().unwrap().as_ref());
    let correct_pub_key_y =
        alloy::primitives::B256::from_slice(correct_encoded_point.y().unwrap().as_ref());

    // Generate a different (wrong) P256 key pair
    let wrong_signing_key = SigningKey::random(&mut OsRng);
    let wrong_verifying_key = wrong_signing_key.verifying_key();

    // Extract wrong public key coordinates
    let wrong_encoded_point = wrong_verifying_key.to_encoded_point(false);
    let wrong_pub_key_x =
        alloy::primitives::B256::from_slice(wrong_encoded_point.x().unwrap().as_ref());
    let wrong_pub_key_y =
        alloy::primitives::B256::from_slice(wrong_encoded_point.y().unwrap().as_ref());

    // Use TEST_MNEMONIC account for provider wallet
    let funder_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;

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

    let create_test_tx = |nonce_seq: u64| {
        let mut tx = create_basic_aa_tx(
            chain_id,
            nonce_seq,
            vec![Call {
                to: recipient.into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            2_000_000,
        );
        tx.fee_token = None;
        tx
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

    let aa_signature1 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data1),
            r: alloy::primitives::B256::from_slice(&sig_bytes1[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes1[32..64]),
            pub_key_x: wrong_pub_key_x, // WRONG public key
            pub_key_y: wrong_pub_key_y, // WRONG public key
        }));

    // Try to verify - should fail
    let recovery_result1 = aa_signature1.recover_signer(&sig_hash1);
    assert!(
        recovery_result1.is_err(),
        "Should fail with wrong public key"
    );
    println!("✓ Signature recovery correctly failed with wrong public key");

    // Also verify pool rejects the transaction
    let signed_tx1 = AASigned::new_unhashed(tx1, aa_signature1);
    let envelope1: TempoTxEnvelope = signed_tx1.into();
    let mut encoded1 = Vec::new();
    envelope1.encode_2718(&mut encoded1);
    let inject_result1 = setup.node.rpc.inject_tx(encoded1.into()).await;
    assert!(
        inject_result1.is_err(),
        "Tx with wrong public key should be rejected by pool"
    );
    println!("  ✓ Pool correctly rejected transaction with wrong public key");

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

    let aa_signature2 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data2),
            r: alloy::primitives::B256::from_slice(&sig_bytes2[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes2[32..64]),
            pub_key_x: correct_pub_key_x, // Correct public key
            pub_key_y: correct_pub_key_y, // But signature is from wrong private key
        }));

    // Try to verify - should fail
    let recovery_result2 = aa_signature2.recover_signer(&sig_hash2);
    assert!(
        recovery_result2.is_err(),
        "Should fail with wrong private key"
    );
    println!("✓ Signature recovery correctly failed with wrong private key");

    let signed_tx2 = AASigned::new_unhashed(tx2, aa_signature2);
    let envelope2: TempoTxEnvelope = signed_tx2.into();
    let mut encoded2 = Vec::new();
    envelope2.encode_2718(&mut encoded2);
    let inject_result2 = setup.node.rpc.inject_tx(encoded2.into()).await;
    assert!(
        inject_result2.is_err(),
        "Tx with wrong private key should be rejected by pool"
    );
    println!("  ✓ Pool correctly rejected transaction with wrong private key");

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

    let aa_signature3 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data3),
            r: alloy::primitives::B256::from_slice(&sig_bytes3[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes3[32..64]),
            pub_key_x: correct_pub_key_x,
            pub_key_y: correct_pub_key_y,
        }));

    // Try to verify - should fail during WebAuthn data validation
    let recovery_result3 = aa_signature3.recover_signer(&sig_hash3);
    assert!(
        recovery_result3.is_err(),
        "Should fail with wrong challenge"
    );
    println!("✓ Signature recovery correctly failed with wrong challenge");

    let signed_tx3 = AASigned::new_unhashed(tx3, aa_signature3);
    let envelope3: TempoTxEnvelope = signed_tx3.into();
    let mut encoded3 = Vec::new();
    envelope3.encode_2718(&mut encoded3);
    let inject_result3 = setup.node.rpc.inject_tx(encoded3.into()).await;
    assert!(
        inject_result3.is_err(),
        "Tx with wrong challenge should be rejected by pool"
    );
    println!("  ✓ Pool correctly rejected transaction with wrong challenge");

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

    let aa_signature4 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data4),
            r: alloy::primitives::B256::from_slice(&sig_bytes4[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes4[32..64]),
            pub_key_x: correct_pub_key_x,
            pub_key_y: correct_pub_key_y,
        }));

    // Try to verify - should fail during WebAuthn data validation
    let recovery_result4 = aa_signature4.recover_signer(&sig_hash4);
    assert!(
        recovery_result4.is_err(),
        "Should fail with wrong authenticator data"
    );
    println!("✓ Signature recovery correctly failed with wrong authenticator data");

    let signed_tx4 = AASigned::new_unhashed(tx4, aa_signature4);
    let envelope4: TempoTxEnvelope = signed_tx4.into();
    let mut encoded4 = Vec::new();
    envelope4.encode_2718(&mut encoded4);
    let inject_result4 = setup.node.rpc.inject_tx(encoded4.into()).await;
    assert!(
        inject_result4.is_err(),
        "Tx with wrong authenticator data should be rejected by pool"
    );
    println!("  ✓ Pool correctly rejected transaction with wrong authenticator data");

    // ===========================================
    // Test Case 5: Transaction Injection Should Fail
    // ===========================================
    println!("\nTest 5: Transaction injection with invalid signature");

    // Try to inject a transaction with wrong signature
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

    let bad_tempo_signature =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(bad_webauthn_data),
            r: alloy::primitives::B256::from_slice(&bad_sig_bytes[0..32]),
            s: alloy::primitives::B256::from_slice(&bad_sig_bytes[32..64]),
            pub_key_x: correct_pub_key_x,
            pub_key_y: correct_pub_key_y,
        }));

    let signed_bad_tx = AASigned::new_unhashed(bad_tx, bad_tempo_signature);
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

/// Test that verifies that we can propagate 2d transactions
#[tokio::test(flavor = "multi_thread")]
async fn test_propagate_2d_transactions() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Create wallet from mnemonic
    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(0)?
        .build()?;

    let mut setup = crate::utils::TestNodeBuilder::new()
        .with_node_count(2)
        .build_multi_node()
        .await?;

    let node1 = setup.nodes.remove(0);
    let node2 = setup.nodes.remove(0);

    // make sure both nodes are ready to broadcast
    node1.inner.network.update_sync_state(SyncState::Idle);
    node2.inner.network.update_sync_state(SyncState::Idle);

    let mut tx_listener1 = node1.inner.pool.pending_transactions_listener();
    let mut tx_listener2 = node2.inner.pool.pending_transactions_listener();

    let provider1 =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(node1.rpc_url());
    let chain_id = provider1.get_chain_id().await?;

    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: 1_000_000_000u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: Address::random().into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::from(123),
        nonce: 0,
        ..Default::default()
    };

    let sig_hash = tx.signature_hash();
    let signature = wallet.sign_hash_sync(&sig_hash)?;
    let signed_tx = AASigned::new_unhashed(
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );
    let envelope: TempoTxEnvelope = signed_tx.into();
    let encoded = envelope.encoded_2718();

    // Submitting transaction to first peer
    let _ = provider1.send_raw_transaction(&encoded).await.unwrap();

    // ensure we see it as pending from the first peer
    let pending_hash1 =
        tokio::time::timeout(std::time::Duration::from_secs(30), tx_listener1.recv())
            .await
            .expect("timed out waiting for tx on node1")
            .expect("tx listener1 channel closed");
    assert_eq!(pending_hash1, *envelope.tx_hash());
    let _rpc_tx = provider1
        .get_transaction_by_hash(pending_hash1)
        .await
        .unwrap();

    // ensure we see it as pending on the second peer as well (should be broadcasted from first to second)
    let pending_hash2 =
        tokio::time::timeout(std::time::Duration::from_secs(30), tx_listener2.recv())
            .await
            .expect("timed out waiting for tx on node2")
            .expect("tx listener2 channel closed");
    assert_eq!(pending_hash2, *envelope.tx_hash());

    // check we can fetch it from the second peer now
    let provider2 =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(node2.rpc_url());
    let _rpc_tx = provider2
        .get_transaction_by_hash(pending_hash2)
        .await
        .unwrap();

    Ok(())
}

/// Verifies that transactions signed with a revoked access key cannot be executed.
#[tokio::test]
async fn test_aa_keychain_revocation_toctou_dos() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing AA Keychain Revocation TOCTOU DoS ===\n");

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Generate an access key for the attack
    let (access_key_signing, access_pub_x, access_pub_y, access_key_addr) =
        generate_p256_access_key();

    println!("Access key address: {access_key_addr}");

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    println!("Current block timestamp: {current_timestamp}");

    // ========================================
    // STEP 1: Authorize the access key
    // ========================================
    println!("\n=== STEP 1: Authorize the access key ===");

    let funded = rand_funding_amount();
    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        create_mock_p256_sig(access_pub_x, access_pub_y),
        chain_id,
        None, // Never expires
        Some(create_default_token_limit(funded)),
    )?;

    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    auth_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_tx.key_authorization = Some(key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_tx, root_sig).await?;
    nonce += 1;

    println!("Access key authorized");

    // ========================================
    // STEP 2: Submit a transaction with valid_after in the future using the access key
    // ========================================
    println!("\n=== STEP 2: Submit transaction with future valid_after using access key ===");

    // Advance a couple blocks to get a fresh timestamp
    for _ in 0..2 {
        setup.node.advance_block().await?;
    }

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let new_timestamp = block.header.timestamp();

    // Set valid_after to be 10 seconds in the future (enough time to revoke the key)
    let valid_after_time = new_timestamp + 10;
    println!("Setting valid_after to {valid_after_time} (current: {new_timestamp})");

    // Create a transaction that uses the access key with valid_after
    let recipient = Address::random();
    let transfer_amount = rand_sub_amount(funded);

    let mut delayed_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            recipient,
            transfer_amount,
        )],
        2_000_000,
    );
    delayed_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    delayed_tx.valid_after = Some(valid_after_time);

    // Sign with the access key (wrapped in Keychain signature)
    let access_key_sig = sign_aa_tx_with_p256_access_key(
        &delayed_tx,
        &access_key_signing,
        &access_pub_x,
        &access_pub_y,
        root_addr,
    )?;

    // Submit the transaction - it should pass validation because the key is still authorized
    let delayed_tx_envelope: TempoTxEnvelope = delayed_tx.into_signed(access_key_sig).into();
    let delayed_tx_hash = *delayed_tx_envelope.tx_hash();
    setup
        .node
        .rpc
        .inject_tx(delayed_tx_envelope.encoded_2718().into())
        .await?;
    // Note: We don't increment nonce here because the delayed tx won't be mined until valid_after.
    // The revoke tx below uses a different nonce_key (2D nonce) to be mined independently.

    println!("Delayed transaction submitted (hash: {delayed_tx_hash})");

    // Verify transaction is in the pool
    assert!(
        setup.node.inner.pool.contains(&delayed_tx_hash),
        "Delayed transaction should be in the pool"
    );
    println!("Transaction is in the mempool");

    // ========================================
    // STEP 3: Revoke the access key before valid_after is reached
    // ========================================
    println!("\n=== STEP 3: Revoke the access key ===");

    let revoke_call = revokeKeyCall {
        keyId: access_key_addr,
    };

    // Use a 2D nonce (different nonce_key) so this tx can be mined independently
    // of the delayed tx which is also using the root account but blocking on valid_after
    let mut revoke_tx = create_basic_aa_tx(
        chain_id,
        0, // nonce 0 for this new nonce_key
        vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: revoke_call.abi_encode().into(),
        }],
        2_000_000,
    );
    revoke_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    revoke_tx.nonce_key = U256::from(1); // Use a different nonce key so it's independent

    let revoke_sig = sign_aa_tx_secp256k1(&revoke_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, revoke_tx, revoke_sig).await?;

    // Verify the key is actually revoked by querying the keychain
    use tempo_contracts::precompiles::account_keychain::IAccountKeychain::IAccountKeychainInstance;
    let keychain = IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider);
    let key_info = keychain.getKey(root_addr, access_key_addr).call().await?;
    assert!(key_info.isRevoked, "Key should be marked as revoked");
    println!("Access key revoked");

    // The evict_revoked_keychain_txs maintenance task has a 1-second startup delay,
    // then monitors storage changes on block commits and evicts transactions signed
    // with revoked keys. We need to advance a block to trigger the commit notification,
    // then wait for the maintenance task to process it.
    // Advance another block to trigger the commit notification
    setup.node.advance_block().await?;

    wait_until_pool_not_contains(
        &setup.node.inner.pool,
        &delayed_tx_hash,
        "keychain eviction",
    )
    .await?;

    // ========================================
    // STEP 4: Verify transaction is evicted from the pool
    // ========================================
    println!("\n=== STEP 4: Verify transaction is evicted from pool ===");

    // Check pool state immediately after revocation
    let tx_still_in_pool = setup.node.inner.pool.contains(&delayed_tx_hash);

    // Check if transaction was mined (should not be, since it had valid_after in future)
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [delayed_tx_hash])
        .await?;

    // Check the transfer recipient balance to verify if the transaction actually executed
    let recipient_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient)
        .call()
        .await?;

    println!("\n=== RESULTS ===");
    println!("Transaction still in pool: {tx_still_in_pool}");
    println!("Transaction mined: {}", receipt.is_some());
    println!("Recipient balance: {recipient_balance}");
    println!("Expected transfer amount: {transfer_amount}");

    assert!(
        !tx_still_in_pool,
        "DoS via AA keychain revocation TOCTOU: \
         Transaction signed with revoked key should be evicted from the mempool"
    );
    assert!(
        receipt.is_none(),
        "Transaction signed with revoked key should be evicted, not mined. \
         If it was mined (even if reverted), the eviction mechanism is not working."
    );
    assert_eq!(
        recipient_balance,
        U256::ZERO,
        "Recipient should have no balance since transaction was evicted"
    );

    Ok(())
}

// ============================================================================
// Expiring Nonce Tests
// ============================================================================

/// Test expiring nonce replay protection - same tx hash should be rejected
#[tokio::test(flavor = "multi_thread")]
async fn test_aa_expiring_nonce_replay_protection() -> eyre::Result<()> {
    println!("\n=== Testing Expiring Nonce Replay Protection ===\n");

    let super::helpers::Localnet {
        mut setup,
        provider,
        chain_id,
        funder_signer: alice_signer,
        ..
    } = super::helpers::Localnet::new().await?;

    let recipient = Address::random();

    // Advance a few blocks to get a meaningful timestamp
    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();

    // Create expiring nonce transaction
    let valid_before = current_timestamp + 25;

    let tx = create_expiring_nonce_tx(chain_id, valid_before, recipient);

    let aa_signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(aa_signature).into();
    let tx_hash = *envelope.tx_hash();
    let encoded = envelope.encoded_2718();

    println!("First submission - tx hash: {tx_hash}");

    // First submission should succeed
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    setup.node.advance_block().await?;

    assert_receipt_status(&provider, tx_hash, true).await?;
    println!("✓ First submission succeeded");

    // Second submission with SAME encoded tx (same hash) should fail
    println!("\nSecond submission - attempting replay with same tx hash...");

    // Try to inject the same transaction again - should be rejected at pool level
    let replay_result = setup.node.rpc.inject_tx(encoded.clone().into()).await;

    // The replay MUST be rejected at pool validation (we check seen[tx_hash] in validator)
    assert!(
        replay_result.is_err(),
        "Replay should be rejected at transaction pool level"
    );
    println!("✓ Replay rejected at transaction pool level");

    Ok(())
}

/// Verifies that transactions signed with a keychain key are evicted when spending limits change.
///
/// This tests the TOCTOU vulnerability (CHAIN-444) where:
/// 1. An attacker funds and authorizes an address with balance > spending limit
/// 2. Submits transactions that pass validation
/// 3. Reduces spending limit so execution would fail
/// 4. Transactions should be evicted from the mempool
#[tokio::test]
async fn test_aa_keychain_spending_limit_toctou_dos() -> eyre::Result<()> {
    use tempo_precompiles::account_keychain::updateSpendingLimitCall;

    reth_tracing::init_test_tracing();

    println!("\n=== Testing AA Keychain Spending Limit TOCTOU DoS ===\n");

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Generate an access key for the attack
    let (access_key_signing, access_pub_x, access_pub_y, access_key_addr) =
        generate_p256_access_key();

    println!("Access key address: {access_key_addr}");

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    println!("Current block timestamp: {current_timestamp}");

    // ========================================
    // STEP 1: Authorize the access key with a spending limit
    // ========================================
    println!("\n=== STEP 1: Authorize the access key with spending limit ===");

    let funded = rand_funding_amount();
    let initial_spending_limit = funded / U256::from(2);

    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        create_mock_p256_sig(access_pub_x, access_pub_y),
        chain_id,
        None, // Never expires
        Some(vec![tempo_primitives::transaction::TokenLimit {
            token: DEFAULT_FEE_TOKEN,
            limit: initial_spending_limit,
        }]),
    )?;

    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    auth_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_tx.key_authorization = Some(key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_tx, root_sig).await?;
    nonce += 1;

    println!("Access key authorized with spending limit: {initial_spending_limit}");

    // ========================================
    // STEP 2: Submit a transaction with valid_after in the future using the access key
    // ========================================
    println!("\n=== STEP 2: Submit transaction with future valid_after using access key ===");

    // Advance a couple blocks to get a fresh timestamp
    for _ in 0..2 {
        setup.node.advance_block().await?;
    }

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let new_timestamp = block.header.timestamp();

    // Set valid_after to be 10 seconds in the future (enough time to reduce spending limit)
    let valid_after_time = new_timestamp + 10;
    println!("Setting valid_after to {valid_after_time} (current: {new_timestamp})");

    // Create a transaction that uses the access key with valid_after
    let recipient = Address::random();
    let transfer_amount = rand_sub_amount(initial_spending_limit);

    let mut delayed_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            recipient,
            transfer_amount,
        )],
        2_000_000,
    );
    delayed_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    delayed_tx.valid_after = Some(valid_after_time);

    // Sign with the access key (wrapped in Keychain signature)
    let access_key_sig = sign_aa_tx_with_p256_access_key(
        &delayed_tx,
        &access_key_signing,
        &access_pub_x,
        &access_pub_y,
        root_addr,
    )?;

    // Submit the transaction - it should pass validation because the spending limit is still high
    let delayed_tx_envelope: TempoTxEnvelope = delayed_tx.into_signed(access_key_sig).into();
    let delayed_tx_hash = *delayed_tx_envelope.tx_hash();
    setup
        .node
        .rpc
        .inject_tx(delayed_tx_envelope.encoded_2718().into())
        .await?;

    println!("Delayed transaction submitted (hash: {delayed_tx_hash})");

    // Verify transaction is in the pool
    assert!(
        setup.node.inner.pool.contains(&delayed_tx_hash),
        "Delayed transaction should be in the pool"
    );
    println!("Transaction is in the mempool");

    // ========================================
    // STEP 3: Reduce the spending limit to 0 before valid_after is reached
    // ========================================
    println!("\n=== STEP 3: Reduce spending limit to 0 ===");

    let update_limit_call = updateSpendingLimitCall {
        keyId: access_key_addr,
        token: DEFAULT_FEE_TOKEN,
        newLimit: U256::ZERO, // Set to 0, making all pending transfers fail
    };

    // Use a 2D nonce (different nonce_key) so this tx can be mined independently
    let mut update_tx = create_basic_aa_tx(
        chain_id,
        0, // nonce 0 for this new nonce_key
        vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: update_limit_call.abi_encode().into(),
        }],
        2_000_000,
    );
    update_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    update_tx.nonce_key = U256::from(1); // Use a different nonce key so it's independent

    let update_sig = sign_aa_tx_secp256k1(&update_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, update_tx, update_sig).await?;

    println!("Spending limit reduced to 0");

    // The maintenance task monitors for SpendingLimitUpdated events and evicts transactions
    // signed with keys whose spending limits have changed.
    // Advance another block to trigger the commit notification
    setup.node.advance_block().await?;

    wait_until_pool_not_contains(
        &setup.node.inner.pool,
        &delayed_tx_hash,
        "spending limit eviction",
    )
    .await?;

    // ========================================
    // STEP 4: Verify transaction is evicted from the pool
    // ========================================
    println!("\n=== STEP 4: Verify transaction is evicted from pool ===");

    // Check pool state after spending limit update
    let tx_still_in_pool = setup.node.inner.pool.contains(&delayed_tx_hash);

    // Check if transaction was mined (should not be, since it had valid_after in future)
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [delayed_tx_hash])
        .await?;

    // Check the transfer recipient balance
    let recipient_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient)
        .call()
        .await?;

    println!("\n=== RESULTS ===");
    println!("Transaction still in pool: {tx_still_in_pool}");
    println!("Transaction mined: {}", receipt.is_some());
    println!("Recipient balance: {recipient_balance}");
    println!("Expected transfer amount: {transfer_amount}");

    assert!(
        !tx_still_in_pool,
        "DoS via AA keychain spending limit TOCTOU: \
         Transaction from key with reduced spending limit should be evicted from the mempool"
    );
    assert!(
        receipt.is_none(),
        "Transaction from key with reduced spending limit should be evicted, not mined. \
         If it was mined (even if reverted), the eviction mechanism is not working."
    );
    assert_eq!(
        recipient_balance,
        U256::ZERO,
        "Recipient should have no balance since transaction was evicted"
    );

    println!("\n=== Test passed: Transaction was correctly evicted ===");
    Ok(())
}
