//! Security-focused tests for the bridge.

use super::utils::*;
use alloy::primitives::{Address, B256};

#[test]
fn test_replay_prevention_deposit_ids() {
    let id1 = compute_deposit_id(
        31337,
        Address::repeat_byte(1),
        B256::repeat_byte(2),
        0,
        Address::repeat_byte(3),
        1_000_000,
        100,
    );
    let id2 = compute_deposit_id(
        31337,
        Address::repeat_byte(1),
        B256::repeat_byte(2),
        0,
        Address::repeat_byte(3),
        1_000_000,
        100,
    );
    assert_eq!(id1, id2, "Same deposit params should produce same ID");
}

#[test]
fn test_cross_chain_replay_prevention() {
    let eth_deposit = compute_deposit_id(
        1,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );

    let arb_deposit = compute_deposit_id(
        42161,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );

    assert_ne!(
        eth_deposit, arb_deposit,
        "Chain ID must differentiate deposits"
    );
}

#[test]
fn test_frontrunning_resistance() {
    let victim_recipient = Address::repeat_byte(0xAA);
    let attacker_recipient = Address::repeat_byte(0xBB);

    let victim_id = compute_deposit_id(
        31337,
        Address::repeat_byte(1),
        B256::repeat_byte(2),
        0,
        victim_recipient,
        1_000_000,
        100,
    );

    let attacker_id = compute_deposit_id(
        31337,
        Address::repeat_byte(1),
        B256::repeat_byte(2),
        0,
        attacker_recipient,
        1_000_000,
        100,
    );

    assert_ne!(
        victim_id, attacker_id,
        "Recipient must be bound in request ID"
    );
}

#[test]
fn test_domain_separation() {
    let chain_id = 31337u64;
    let token = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x22);
    let amount = 1_000_000u64;

    let deposit_id = compute_deposit_id(chain_id, token, B256::ZERO, 0, recipient, amount, 100);

    let burn_id = compute_burn_id(chain_id, token, recipient, amount, 0, recipient);

    assert_ne!(
        deposit_id, burn_id,
        "Different operations must have different IDs"
    );
}

#[test]
fn test_threshold_calculation() {
    assert_eq!(compute_threshold(3), 2);
    assert_eq!(compute_threshold(4), 3);
    assert_eq!(compute_threshold(6), 4);
    assert_eq!(compute_threshold(10), 7);
    assert_eq!(compute_threshold(100), 67);
}

#[test]
fn test_threshold_always_majority() {
    for n in 1..=100 {
        let threshold = compute_threshold(n);
        assert!(
            threshold as f64 > n as f64 * 2.0 / 3.0 - 1.0,
            "Threshold {threshold} for {n} validators must be > 2/3"
        );
        assert!(
            threshold <= n,
            "Threshold {threshold} must not exceed validator count {n}"
        );
    }
}

#[test]
fn test_log_index_uniqueness() {
    let id_log_0 = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );

    let id_log_1 = compute_deposit_id(
        31337,
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

#[test]
fn test_tx_hash_uniqueness() {
    let id_tx_a = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0xAA),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );

    let id_tx_b = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0xBB),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );

    assert_ne!(
        id_tx_a, id_tx_b,
        "Different tx hashes must produce different IDs"
    );
}

#[test]
fn test_nonce_sequential_uniqueness() {
    let mut ids = Vec::new();
    for nonce in 0..100 {
        let id = compute_burn_id(
            31337,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            1_000_000,
            nonce,
            Address::repeat_byte(0x33),
        );
        assert!(!ids.contains(&id), "Nonce {nonce} produced duplicate ID");
        ids.push(id);
    }
}

#[test]
fn test_anvil_accounts_are_valid() {
    let accounts = anvil_accounts();
    assert_eq!(accounts.len(), 3);

    for (address, signer) in &accounts {
        assert_eq!(*address, signer.address());
        assert!(!address.is_zero());
    }

    let addresses: Vec<_> = accounts.iter().map(|(a, _)| a).collect();
    for i in 0..addresses.len() {
        for j in (i + 1)..addresses.len() {
            assert_ne!(addresses[i], addresses[j], "Duplicate address found");
        }
    }
}

#[test]
fn test_precompile_addresses_are_correct() {
    assert_eq!(
        BRIDGE_ADDRESS,
        "0xBBBB000000000000000000000000000000000000"
            .parse::<Address>()
            .unwrap()
    );
    assert_eq!(
        VALIDATOR_CONFIG_ADDRESS,
        "0xCCCCCCCC00000000000000000000000000000000"
            .parse::<Address>()
            .unwrap()
    );
}
