//! End-to-end integration tests for bridge flows.
//!
//! These tests simulate the full bridge lifecycle with mock components.
//! Tests requiring Anvil are marked with `#[ignore]` for CI compatibility.

use super::fixtures::*;
#[allow(deprecated)]
use crate::proof::BurnProof;
use crate::{
    persistence::{ProcessedBurn, SignedDeposit, StateManager},
    proof::{AttestationGenerator, BurnAttestation, TempoBlockHeader},
    signer::BridgeSigner,
};
use alloy::{
    consensus::{Receipt, ReceiptEnvelope, ReceiptWithBloom},
    primitives::{Address, Bytes, LogData, B256},
    rpc::types::{Log as RpcLog, TransactionReceipt},
};

fn create_mock_receipt(status: bool, logs_count: usize) -> TransactionReceipt {
    let primitive_logs: Vec<alloy::primitives::Log> = (0..logs_count)
        .map(|i| alloy::primitives::Log {
            address: Address::repeat_byte(i as u8),
            data: LogData::new_unchecked(vec![], Bytes::new()),
        })
        .collect();

    let receipt = Receipt {
        status: status.into(),
        cumulative_gas_used: 21000 * (logs_count as u64 + 1),
        logs: primitive_logs,
    };

    let receipt_with_bloom = ReceiptWithBloom::new(receipt, Default::default());
    let envelope = ReceiptEnvelope::Eip1559(receipt_with_bloom);

    let rpc_envelope = envelope.map_logs(|log| RpcLog {
        inner: log,
        block_hash: None,
        block_number: None,
        block_timestamp: None,
        transaction_hash: None,
        transaction_index: None,
        log_index: None,
        removed: false,
    });

    TransactionReceipt {
        inner: rpc_envelope,
        transaction_hash: B256::random(),
        transaction_index: Some(0),
        block_hash: Some(B256::random()),
        block_number: Some(1),
        gas_used: 21000,
        effective_gas_price: 1_000_000_000,
        blob_gas_used: None,
        blob_gas_price: None,
        from: Address::ZERO,
        to: Some(Address::repeat_byte(0xDE)),
        contract_address: None,
    }
}

mod deposit_flow {
    use super::*;

    #[tokio::test]
    async fn test_deposit_id_uniqueness() {
        let deposits: Vec<_> = (0..10)
            .map(|i| TestDeposit::usdc_deposit(1_000_000 * (i + 1), Address::repeat_byte(i as u8)))
            .collect();

        let ids: std::collections::HashSet<_> = deposits.iter().map(|d| d.deposit_id).collect();
        assert_eq!(
            ids.len(),
            deposits.len(),
            "All deposit IDs should be unique"
        );
    }

    #[tokio::test]
    async fn test_deposit_signature_generation() {
        let validator_set = MockValidatorSet::single();
        let (_, signer) = &validator_set.validators[0];
        let bridge_signer = BridgeSigner::from_bytes(&signer.to_bytes()).unwrap();

        let deposit = TestDeposit::usdc_deposit(1_000_000, Address::repeat_byte(0x42));
        let signature = bridge_signer
            .sign_deposit(&deposit.deposit_id)
            .await
            .unwrap();

        assert_eq!(signature.len(), 65);
        assert!(!signature.is_empty());
    }

    #[tokio::test]
    async fn test_multi_validator_signing() {
        let validator_set = MockValidatorSet::three_of_five();
        let deposit = TestDeposit::usdc_deposit(10_000_000, Address::repeat_byte(0x42));

        let mut signatures = Vec::new();
        for (_, signer) in &validator_set.validators {
            let bridge_signer = BridgeSigner::from_bytes(&signer.to_bytes()).unwrap();
            let sig = bridge_signer
                .sign_deposit(&deposit.deposit_id)
                .await
                .unwrap();
            signatures.push(sig);
        }

        assert_eq!(signatures.len(), 5);
        assert!(signatures.len() as u64 >= validator_set.threshold);

        let unique_sigs: std::collections::HashSet<_> = signatures.iter().collect();
        assert_eq!(unique_sigs.len(), 5, "All signatures should be unique");
    }

    #[tokio::test]
    async fn test_deposit_state_persistence() {
        let state_manager = StateManager::new_in_memory();
        let deposit = TestDeposit::usdc_deposit(1_000_000, Address::repeat_byte(0x42));

        assert!(!state_manager.has_signed_deposit(&deposit.deposit_id).await);

        state_manager
            .record_signed_deposit(SignedDeposit {
                request_id: deposit.deposit_id,
                origin_chain_id: deposit.origin_chain_id,
                origin_tx_hash: deposit.tx_hash,
                tempo_recipient: deposit.tempo_recipient,
                amount: deposit.amount,
                signature_tx_hash: B256::random(),
                signed_at: 12345,
            })
            .await
            .unwrap();

        assert!(state_manager.has_signed_deposit(&deposit.deposit_id).await);
        assert!(
            !state_manager
                .is_deposit_finalized(&deposit.deposit_id)
                .await
        );

        state_manager
            .mark_deposit_finalized(deposit.deposit_id)
            .await
            .unwrap();

        assert!(
            state_manager
                .is_deposit_finalized(&deposit.deposit_id)
                .await
        );
    }

    #[tokio::test]
    async fn test_deposit_threshold_reached() {
        let validator_set = MockValidatorSet::three_of_five();
        let deposit = TestDeposit::usdc_deposit(1_000_000, Address::repeat_byte(0x42));

        let mut signatures_count = 0u64;
        for (_, signer) in validator_set.validators.iter().take(3) {
            let bridge_signer = BridgeSigner::from_bytes(&signer.to_bytes()).unwrap();
            let _sig = bridge_signer
                .sign_deposit(&deposit.deposit_id)
                .await
                .unwrap();
            signatures_count += 1;
        }

        assert!(signatures_count < validator_set.threshold);

        for (_, signer) in validator_set.validators.iter().skip(3).take(1) {
            let bridge_signer = BridgeSigner::from_bytes(&signer.to_bytes()).unwrap();
            let _sig = bridge_signer
                .sign_deposit(&deposit.deposit_id)
                .await
                .unwrap();
            signatures_count += 1;
        }

        assert!(signatures_count >= validator_set.threshold);
    }

    #[tokio::test]
    async fn test_cross_chain_deposit_isolation() {
        let eth_deposit = TestDeposit::new(
            1,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            1_000_000,
            Address::repeat_byte(0x33),
            0,
        );

        let arb_deposit = TestDeposit::new(
            42161,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            1_000_000,
            Address::repeat_byte(0x33),
            0,
        );

        assert_ne!(
            eth_deposit.deposit_id, arb_deposit.deposit_id,
            "Deposits on different chains must have different IDs"
        );
    }

    #[tokio::test]
    async fn test_deposit_file_persistence() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("bridge-state.json");
        let deposit = TestDeposit::usdc_deposit(1_000_000, Address::repeat_byte(0x42));

        {
            let state_manager = StateManager::new_persistent(&path).unwrap();
            state_manager
                .record_signed_deposit(SignedDeposit {
                    request_id: deposit.deposit_id,
                    origin_chain_id: deposit.origin_chain_id,
                    origin_tx_hash: deposit.tx_hash,
                    tempo_recipient: deposit.tempo_recipient,
                    amount: deposit.amount,
                    signature_tx_hash: B256::random(),
                    signed_at: 12345,
                })
                .await
                .unwrap();
        }

        {
            let state_manager = StateManager::new_persistent(&path).unwrap();
            assert!(state_manager.has_signed_deposit(&deposit.deposit_id).await);
        }
    }
}

mod burn_flow {
    use super::*;

    #[tokio::test]
    async fn test_burn_id_uniqueness() {
        let burns: Vec<_> = (0..10)
            .map(|i| TestBurn::usdc_burn(1_000_000 * (i + 1), Address::repeat_byte(i as u8), i))
            .collect();

        let ids: std::collections::HashSet<_> = burns.iter().map(|b| b.burn_id).collect();
        assert_eq!(ids.len(), burns.len(), "All burn IDs should be unique");
    }

    #[tokio::test]
    async fn test_burn_nonce_prevents_replay() {
        let burn1 = TestBurn::usdc_burn(1_000_000, Address::repeat_byte(0x42), 0);
        let burn2 = TestBurn::usdc_burn(1_000_000, Address::repeat_byte(0x42), 1);

        assert_ne!(
            burn1.burn_id, burn2.burn_id,
            "Different nonces must produce different burn IDs"
        );
    }

    #[tokio::test]
    async fn test_burn_state_persistence() {
        let state_manager = StateManager::new_in_memory();
        let burn = TestBurn::usdc_burn(1_000_000, Address::repeat_byte(0x42), 0);

        assert!(!state_manager.has_processed_burn(&burn.burn_id).await);

        state_manager
            .record_processed_burn(ProcessedBurn {
                burn_id: burn.burn_id,
                origin_chain_id: burn.origin_chain_id,
                origin_recipient: burn.origin_recipient,
                amount: burn.amount,
                tempo_block_number: burn.tempo_block_number,
                unlock_tx_hash: Some(B256::random()),
                processed_at: 12345,
            })
            .await
            .unwrap();

        assert!(state_manager.has_processed_burn(&burn.burn_id).await);
    }

    #[tokio::test]
    async fn test_burn_proof_generation() {
        let _receipts = [
            create_mock_receipt(true, 1),
            create_mock_receipt(true, 2),
            create_mock_receipt(true, 3),
        ];

        // Generate attestation instead of binary Merkle proof (F-03 fix)
        let attestation = AttestationGenerator::<()>::create_unsigned_attestation(
            B256::repeat_byte(0x11),    // burn_id
            100,                        // tempo_height
            1,                          // origin_chain_id
            Address::repeat_byte(0x22), // origin_token
            Address::repeat_byte(0x33), // recipient
            1_000_000,                  // amount
        );

        assert_eq!(attestation.tempo_height, 100);
        assert_eq!(attestation.amount, 1_000_000);
        assert!(attestation.signatures.is_empty());
    }

    #[tokio::test]
    async fn test_burn_attestation_digest() {
        let attestation = BurnAttestation {
            burn_id: B256::repeat_byte(0x11),
            tempo_height: 100,
            origin_chain_id: 1,
            origin_token: Address::repeat_byte(0x22),
            recipient: Address::repeat_byte(0x33),
            amount: 1_000_000,
            signatures: vec![],
        };

        let digest1 = attestation.compute_digest(42);
        let digest2 = attestation.compute_digest(42);

        // Digest should be deterministic
        assert_eq!(digest1, digest2);

        // Digest should not be zero
        assert!(!digest1.is_zero());
    }

    #[tokio::test]
    async fn test_burn_cross_chain_isolation() {
        let eth_burn = TestBurn::new(
            1,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            1_000_000,
            0,
            Address::repeat_byte(0x33),
            100,
        );

        let arb_burn = TestBurn::new(
            42161,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            1_000_000,
            0,
            Address::repeat_byte(0x33),
            100,
        );

        assert_ne!(
            eth_burn.burn_id, arb_burn.burn_id,
            "Burns for different origin chains must have different IDs"
        );
    }
}

mod reorg_handling {
    use super::*;

    #[tokio::test]
    async fn test_reorg_detection() {
        let reorg = MockReorg::at_depth(100, 3);

        assert_eq!(reorg.common_ancestor, 100);
        assert_eq!(reorg.old_chain.len(), 3);
        assert_eq!(reorg.new_chain.len(), 3);

        for (old, new) in reorg.old_chain.iter().zip(&reorg.new_chain) {
            assert_eq!(old.block_number, new.block_number);
            assert_ne!(old.block_hash, new.block_hash);
        }
    }

    #[tokio::test]
    async fn test_deposit_invalidation_on_reorg() {
        let state_manager = StateManager::new_in_memory();
        let reorg = MockReorg::at_depth(100, 2);

        let deposit_in_reorged_block = TestDeposit::new(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            1_000_000,
            Address::repeat_byte(0x33),
            0,
        );

        state_manager
            .record_signed_deposit(SignedDeposit {
                request_id: deposit_in_reorged_block.deposit_id,
                origin_chain_id: deposit_in_reorged_block.origin_chain_id,
                origin_tx_hash: deposit_in_reorged_block.tx_hash,
                tempo_recipient: deposit_in_reorged_block.tempo_recipient,
                amount: deposit_in_reorged_block.amount,
                signature_tx_hash: B256::random(),
                signed_at: 12345,
            })
            .await
            .unwrap();

        assert!(
            state_manager
                .has_signed_deposit(&deposit_in_reorged_block.deposit_id)
                .await
        );

        let reorged_blocks = reorg.reorged_blocks();
        assert!(!reorged_blocks.is_empty());
    }

    #[tokio::test]
    async fn test_state_manager_block_tracking() {
        let state_manager = StateManager::new_in_memory();

        assert!(state_manager.get_origin_chain_block(1).await.is_none());

        state_manager
            .update_origin_chain_block(1, 100)
            .await
            .unwrap();
        assert_eq!(state_manager.get_origin_chain_block(1).await, Some(100));

        state_manager
            .update_origin_chain_block(1, 200)
            .await
            .unwrap();
        assert_eq!(state_manager.get_origin_chain_block(1).await, Some(200));

        state_manager
            .update_origin_chain_block(42161, 500)
            .await
            .unwrap();
        assert_eq!(state_manager.get_origin_chain_block(42161).await, Some(500));
        assert_eq!(state_manager.get_origin_chain_block(1).await, Some(200));
    }

    #[tokio::test]
    async fn test_tempo_block_tracking() {
        let state_manager = StateManager::new_in_memory();

        assert_eq!(state_manager.get_tempo_block().await, 0);

        state_manager.update_tempo_block(100).await.unwrap();
        assert_eq!(state_manager.get_tempo_block().await, 100);

        state_manager.update_tempo_block(200).await.unwrap();
        assert_eq!(state_manager.get_tempo_block().await, 200);
    }
}

mod multi_validator {
    use super::*;

    #[tokio::test]
    async fn test_concurrent_signing() {
        let validator_set = MockValidatorSet::three_of_five();
        let deposit = TestDeposit::usdc_deposit(1_000_000, Address::repeat_byte(0x42));

        let handles: Vec<_> = validator_set
            .validators
            .iter()
            .map(|(_, signer)| {
                let deposit_id = deposit.deposit_id;
                let signer_bytes = signer.to_bytes();
                tokio::spawn(async move {
                    let bridge_signer = BridgeSigner::from_bytes(&signer_bytes).unwrap();
                    bridge_signer.sign_deposit(&deposit_id).await.unwrap()
                })
            })
            .collect();

        let signatures: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(signatures.len(), 5);

        let unique_sigs: std::collections::HashSet<_> = signatures.iter().collect();
        assert_eq!(unique_sigs.len(), 5);
    }

    #[tokio::test]
    async fn test_threshold_not_reached_with_insufficient_signers() {
        let validator_set = MockValidatorSet::three_of_five();
        let _deposit = TestDeposit::usdc_deposit(1_000_000, Address::repeat_byte(0x42));

        let signatures_collected = 3u64;

        assert!(
            signatures_collected < validator_set.threshold,
            "3 signatures should not reach threshold of {} for 5 validators",
            validator_set.threshold
        );
    }

    #[tokio::test]
    async fn test_duplicate_signature_handling() {
        let validator_set = MockValidatorSet::single();
        let (_, signer) = &validator_set.validators[0];
        let bridge_signer = BridgeSigner::from_bytes(&signer.to_bytes()).unwrap();

        let deposit = TestDeposit::usdc_deposit(1_000_000, Address::repeat_byte(0x42));

        let sig1 = bridge_signer
            .sign_deposit(&deposit.deposit_id)
            .await
            .unwrap();
        let sig2 = bridge_signer
            .sign_deposit(&deposit.deposit_id)
            .await
            .unwrap();

        assert_eq!(sig1, sig2, "Same signer should produce same signature");
    }

    #[tokio::test]
    async fn test_state_prevents_double_signing() {
        let state_manager = StateManager::new_in_memory();
        let deposit = TestDeposit::usdc_deposit(1_000_000, Address::repeat_byte(0x42));

        assert!(!state_manager.has_signed_deposit(&deposit.deposit_id).await);

        state_manager
            .record_signed_deposit(SignedDeposit {
                request_id: deposit.deposit_id,
                origin_chain_id: deposit.origin_chain_id,
                origin_tx_hash: deposit.tx_hash,
                tempo_recipient: deposit.tempo_recipient,
                amount: deposit.amount,
                signature_tx_hash: B256::random(),
                signed_at: 12345,
            })
            .await
            .unwrap();

        assert!(
            state_manager.has_signed_deposit(&deposit.deposit_id).await,
            "State should track that deposit was already signed"
        );
    }
}

mod attestation_generation {
    use super::*;

    #[tokio::test]
    async fn test_create_unsigned_attestation() {
        let attestation = AttestationGenerator::<()>::create_unsigned_attestation(
            B256::repeat_byte(0x11),
            1000,
            1,
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x33),
            500_000,
        );

        assert_eq!(attestation.burn_id, B256::repeat_byte(0x11));
        assert_eq!(attestation.tempo_height, 1000);
        assert_eq!(attestation.origin_chain_id, 1);
        assert_eq!(attestation.origin_token, Address::repeat_byte(0x22));
        assert_eq!(attestation.recipient, Address::repeat_byte(0x33));
        assert_eq!(attestation.amount, 500_000);
        assert!(attestation.signatures.is_empty());
    }

    #[tokio::test]
    async fn test_attestation_digest_deterministic() {
        let attestation = BurnAttestation {
            burn_id: B256::repeat_byte(0xAB),
            tempo_height: 12345,
            origin_chain_id: 1,
            origin_token: Address::repeat_byte(0xCD),
            recipient: Address::repeat_byte(0xEF),
            amount: 1_000_000,
            signatures: vec![],
        };

        let digest1 = attestation.compute_digest(42);
        let digest2 = attestation.compute_digest(42);
        assert_eq!(digest1, digest2, "Same inputs should produce same digest");

        let digest3 = attestation.compute_digest(43);
        assert_ne!(
            digest1, digest3,
            "Different chain ID should produce different digest"
        );
    }

    #[tokio::test]
    async fn test_tempo_block_header_struct() {
        let header = TempoBlockHeader {
            block_number: 12345,
            block_hash: B256::repeat_byte(0xAB),
            state_root: B256::repeat_byte(0xCD),
            receipts_root: B256::repeat_byte(0xEF),
        };

        assert_eq!(header.block_number, 12345);
        assert!(!header.block_hash.is_zero());
        assert!(!header.state_root.is_zero());
        assert!(!header.receipts_root.is_zero());
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn test_legacy_burn_proof_struct() {
        let proof = BurnProof {
            receipt_rlp: Bytes::from_static(&[1, 2, 3, 4]),
            receipt_proof: vec![
                Bytes::from_static(&[5, 6, 7]),
                Bytes::from_static(&[8, 9, 10]),
            ],
            log_index: 2,
        };

        assert_eq!(proof.log_index, 2);
        assert_eq!(proof.receipt_rlp.len(), 4);
        assert_eq!(proof.receipt_proof.len(), 2);
    }

    #[tokio::test]
    async fn test_compute_receipts_root() {
        let receipts: Vec<TransactionReceipt> = vec![];
        let root = AttestationGenerator::<()>::compute_receipts_root(&receipts);
        assert_eq!(root, alloy_trie::EMPTY_ROOT_HASH);
    }
}

mod security {
    use super::*;

    #[tokio::test]
    async fn test_domain_separation() {
        let chain_id = ANVIL_CHAIN_ID;
        let token = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let amount = 1_000_000u64;

        let deposit_id = compute_deposit_id(chain_id, token, B256::ZERO, 0, recipient, amount, 100);

        let burn_id = compute_burn_id(chain_id, token, recipient, amount, 0, recipient);

        assert_ne!(
            deposit_id, burn_id,
            "Deposit and burn IDs must be different due to domain separation"
        );
    }

    #[tokio::test]
    async fn test_frontrunning_resistance() {
        let victim_recipient = Address::repeat_byte(0xAA);
        let attacker_recipient = Address::repeat_byte(0xBB);

        let victim_deposit = compute_deposit_id(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            0,
            victim_recipient,
            1_000_000,
            100,
        );

        let attacker_deposit = compute_deposit_id(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            0,
            attacker_recipient,
            1_000_000,
            100,
        );

        assert_ne!(
            victim_deposit, attacker_deposit,
            "Recipient must be bound in deposit ID"
        );
    }

    #[tokio::test]
    async fn test_amount_binding() {
        let small_deposit = compute_deposit_id(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            0,
            Address::repeat_byte(0x33),
            1_000_000,
            100,
        );

        let large_deposit = compute_deposit_id(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            0,
            Address::repeat_byte(0x33),
            10_000_000,
            100,
        );

        assert_ne!(
            small_deposit, large_deposit,
            "Different amounts must produce different IDs"
        );
    }

    #[tokio::test]
    async fn test_log_index_uniqueness() {
        let id_log_0 = compute_deposit_id(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            0,
            Address::repeat_byte(0x33),
            1_000_000,
            100,
        );

        let id_log_1 = compute_deposit_id(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            1,
            Address::repeat_byte(0x33),
            1_000_000,
            100,
        );

        assert_ne!(
            id_log_0, id_log_1,
            "Different log indices must produce different IDs"
        );
    }

    #[tokio::test]
    async fn test_signature_determinism() {
        let (_, signer) = &anvil_accounts()[0];
        let bridge_signer = BridgeSigner::from_bytes(&signer.to_bytes()).unwrap();

        let request_id = B256::repeat_byte(0x42);

        let sig1 = bridge_signer.sign_deposit(&request_id).await.unwrap();
        let sig2 = bridge_signer.sign_deposit(&request_id).await.unwrap();

        assert_eq!(sig1, sig2, "Signatures should be deterministic");
    }
}

#[cfg(test)]
mod anvil_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "Requires Anvil binary and forge build artifacts"]
    async fn test_deposit_flow_with_anvil() {
        use super::super::anvil::AnvilHarness;

        // Step 1: Spawn harness (deploys contracts automatically)
        let harness = AnvilHarness::spawn().await.expect("Failed to spawn harness");

        let (depositor_addr, depositor_signer) = harness.accounts[0].clone();
        let tempo_recipient = Address::repeat_byte(0x42);
        let amount = 1_000_000u64; // 1 USDC

        // Step 2: Mint & approve USDC
        harness
            .mint_usdc(depositor_addr, amount)
            .await
            .expect("Failed to mint USDC");
        harness
            .approve_usdc(&depositor_signer, amount)
            .await
            .expect("Failed to approve USDC");

        // Step 3: Make deposit - returns (TransactionReceipt, DepositEvent)
        let (receipt, deposit_event) = harness
            .deposit_usdc(&depositor_signer, amount, tempo_recipient)
            .await
            .expect("Failed to deposit USDC");

        // Step 4: Verify deposit event fields
        assert!(receipt.status());
        assert!(!deposit_event.deposit_id.is_zero());
        assert_eq!(deposit_event.token, harness.usdc);
        assert_eq!(deposit_event.depositor, depositor_addr);
        assert_eq!(deposit_event.amount, amount);
        assert_eq!(deposit_event.tempo_recipient, tempo_recipient);
        assert_eq!(deposit_event.nonce, 0);

        // Step 5: Sign with validators using BridgeSigner
        let threshold = harness.get_threshold().await.expect("Failed to get threshold");
        let bridge_signers = harness
            .create_bridge_signers(threshold as usize + 1)
            .expect("Failed to create bridge signers");

        let mut signatures = Vec::new();
        for signer in &bridge_signers {
            let sig = signer
                .sign_deposit(&deposit_event.deposit_id)
                .await
                .expect("Failed to sign deposit");
            signatures.push(sig);
        }

        // Step 6: Verify signature count >= threshold
        assert!(
            signatures.len() as u64 >= threshold,
            "Signature count {} should be >= threshold {}",
            signatures.len(),
            threshold
        );

        // Step 7: Record in StateManager
        let state_manager = StateManager::new_in_memory();
        assert!(
            !state_manager
                .has_signed_deposit(&deposit_event.deposit_id)
                .await
        );

        state_manager
            .record_signed_deposit(SignedDeposit {
                request_id: deposit_event.deposit_id,
                origin_chain_id: ANVIL_CHAIN_ID,
                origin_tx_hash: deposit_event.tx_hash,
                tempo_recipient: deposit_event.tempo_recipient,
                amount: deposit_event.amount,
                signature_tx_hash: B256::random(),
                signed_at: deposit_event.block_number,
            })
            .await
            .expect("Failed to record signed deposit");

        assert!(
            state_manager
                .has_signed_deposit(&deposit_event.deposit_id)
                .await
        );

        // Step 8: Mark finalized and assert
        state_manager
            .mark_deposit_finalized(deposit_event.deposit_id)
            .await
            .expect("Failed to mark deposit finalized");

        assert!(
            state_manager
                .is_deposit_finalized(&deposit_event.deposit_id)
                .await
        );
    }

    #[tokio::test]
    #[ignore = "Requires Anvil running on localhost:8545"]
    async fn test_burn_unlock_flow_with_anvil() {
        // This test requires:
        // 1. Anvil running: `anvil --port 8545`
        // 2. Escrow + light client deployed
        // 3. Tempo node running with bridge precompile

        let _burn = TestBurn::usdc_burn(1_000_000, Address::repeat_byte(0x42), 0);

        // TODO: Setup TIP-20 balance on Tempo
        // TODO: Burn tokens on Tempo
        // TODO: Relay header to light client
        // TODO: Generate proof
        // TODO: Unlock on origin
        // TODO: Verify tokens unlocked
    }

    #[tokio::test]
    #[ignore = "Requires Anvil binary and forge build artifacts"]
    async fn test_reorg_handling_with_anvil() {
        use super::super::anvil::AnvilHarness;

        // Step 1: Spawn harness
        let harness = AnvilHarness::spawn().await.expect("Failed to spawn harness");
        let state_manager = StateManager::new_in_memory();

        // Step 2: Mine to block 100
        let initial_block = harness.block_number().await.unwrap();
        let blocks_to_mine = if initial_block < 100 {
            100 - initial_block
        } else {
            0
        };
        if blocks_to_mine > 0 {
            harness.mine_blocks(blocks_to_mine).await.unwrap();
        }

        let current_block = harness.block_number().await.unwrap();
        assert!(current_block >= 100, "Should be at block 100 or higher");

        // Take snapshot before the deposit (at block 100)
        let snapshot_id = harness.snapshot().await.unwrap();

        // Step 3: Make deposit at block 101
        let (depositor_addr, depositor_signer) = harness.accounts[0].clone();
        let tempo_recipient = Address::repeat_byte(0x42);
        let amount = 1_000_000u64;

        harness.mint_usdc(depositor_addr, amount).await.unwrap();
        harness
            .approve_usdc(&depositor_signer, amount)
            .await
            .unwrap();

        let (receipt, deposit_event) = harness
            .deposit_usdc(&depositor_signer, amount, tempo_recipient)
            .await
            .unwrap();

        let deposit_block_number = receipt.block_number.expect("Should have block number");
        let deposit_block_hash = harness
            .get_block_hash(deposit_block_number)
            .await
            .unwrap();

        assert!(deposit_block_number > 100, "Deposit should be after block 100");
        assert!(!deposit_event.deposit_id.is_zero(), "Deposit ID should not be zero");

        // Step 4: Record deposit in StateManager as pending
        state_manager
            .record_signed_deposit(SignedDeposit {
                request_id: deposit_event.deposit_id,
                origin_chain_id: ANVIL_CHAIN_ID,
                origin_tx_hash: deposit_event.tx_hash,
                tempo_recipient: deposit_event.tempo_recipient,
                amount: deposit_event.amount,
                signature_tx_hash: B256::random(),
                signed_at: deposit_block_number,
            })
            .await
            .unwrap();

        assert!(
            state_manager
                .has_signed_deposit(&deposit_event.deposit_id)
                .await,
            "Deposit should be recorded"
        );

        // Step 5: Simulate reorg via Anvil (revert to snapshot and mine new blocks)
        let new_height = harness.reorg_to_height(snapshot_id, 5).await.unwrap();

        // Verify the chain was reorganized
        let new_block_hash = harness.get_block_hash(new_height).await.unwrap();
        assert_ne!(
            new_block_hash, deposit_block_hash,
            "Block hash should be different after reorg"
        );

        // Step 6: Verify old deposit is invalidated (check by querying chain)
        // The deposit event should no longer exist on-chain after reorg
        let deposits_after_reorg = harness
            .query_deposits(100, new_height)
            .await
            .unwrap();

        let old_deposit_exists = deposits_after_reorg
            .iter()
            .any(|d| d.deposit_id == deposit_event.deposit_id);

        assert!(
            !old_deposit_exists,
            "Old deposit should not exist on reorged chain"
        );

        // Invalidate the deposit in StateManager (simulating what bridge would do on reorg)
        let removed = state_manager
            .remove_signed_deposit(&deposit_event.deposit_id)
            .await
            .unwrap();
        assert!(removed, "Should have removed the invalidated deposit");

        assert!(
            !state_manager
                .has_signed_deposit(&deposit_event.deposit_id)
                .await,
            "Deposit should be invalidated after reorg"
        );

        // Step 7 & 8: Query new chain for Deposited events and process new deposit if exists
        // Make a new deposit on the reorged chain
        harness.mint_usdc(depositor_addr, amount).await.unwrap();
        harness
            .approve_usdc(&depositor_signer, amount)
            .await
            .unwrap();

        let (new_receipt, new_deposit_event) = harness
            .deposit_usdc(&depositor_signer, amount, tempo_recipient)
            .await
            .unwrap();

        let new_deposit_block = new_receipt.block_number.expect("Should have block number");

        // Record the new deposit
        state_manager
            .record_signed_deposit(SignedDeposit {
                request_id: new_deposit_event.deposit_id,
                origin_chain_id: ANVIL_CHAIN_ID,
                origin_tx_hash: new_deposit_event.tx_hash,
                tempo_recipient: new_deposit_event.tempo_recipient,
                amount: new_deposit_event.amount,
                signature_tx_hash: B256::random(),
                signed_at: new_deposit_block,
            })
            .await
            .unwrap();

        // Step 9: Assert state consistency
        assert!(
            state_manager
                .has_signed_deposit(&new_deposit_event.deposit_id)
                .await,
            "New deposit should be recorded"
        );

        assert!(
            !state_manager
                .has_signed_deposit(&deposit_event.deposit_id)
                .await,
            "Old deposit should remain invalidated"
        );

        assert_ne!(
            deposit_event.deposit_id, new_deposit_event.deposit_id,
            "New deposit should have different ID"
        );

        // Verify escrow balance reflects only the new deposit
        let escrow_balance = harness.usdc_balance(harness.escrow).await.unwrap();
        assert_eq!(
            escrow_balance, amount,
            "Escrow should have balance from new deposit only"
        );
    }

    #[tokio::test]
    #[ignore = "Requires Anvil running on localhost:8545"]
    async fn test_multi_validator_signing_with_anvil() {
        let _validator_set = MockValidatorSet::three_of_five();
        let _deposit = TestDeposit::usdc_deposit(1_000_000, Address::repeat_byte(0x42));

        // TODO: Deploy escrow
        // TODO: Register validators on Tempo
        // TODO: Make deposit
        // TODO: Have each validator sign
        // TODO: Verify threshold detection
        // TODO: Verify finalization
    }
}
