//! Tests for the burn (Tempo -> origin unlock) flow.

use super::utils::*;
use alloy::primitives::Address;

#[test]
fn test_burn_id_computation() {
    let origin_chain_id = 31337u64;
    let origin_token = Address::repeat_byte(0x11);
    let origin_recipient = Address::repeat_byte(0x22);
    let amount = 1_000_000u64;
    let nonce = 0u64;
    let burner = Address::repeat_byte(0x33);

    let id = compute_burn_id(
        origin_chain_id,
        origin_token,
        origin_recipient,
        amount,
        nonce,
        burner,
    );

    assert!(!id.is_zero());

    let id2 = compute_burn_id(
        origin_chain_id,
        origin_token,
        origin_recipient,
        amount,
        nonce,
        burner,
    );

    assert_eq!(id, id2);
}

#[test]
fn test_burn_id_nonce_prevents_replay() {
    let id1 = compute_burn_id(
        31337,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        1_000_000,
        0,
        Address::repeat_byte(0x33),
    );

    let id2 = compute_burn_id(
        31337,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        1_000_000,
        1,
        Address::repeat_byte(0x33),
    );

    assert_ne!(id1, id2, "Different nonces must produce different IDs");
}

#[test]
fn test_burn_id_burner_binding() {
    let burner1 = Address::repeat_byte(0x33);
    let burner2 = Address::repeat_byte(0x44);

    let id1 = compute_burn_id(
        31337,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        1_000_000,
        0,
        burner1,
    );
    let id2 = compute_burn_id(
        31337,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        1_000_000,
        0,
        burner2,
    );

    assert_ne!(id1, id2, "Different burners must produce different IDs");
}

#[test]
fn test_burn_id_chain_binding() {
    let eth_id = compute_burn_id(
        1,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        1_000_000,
        0,
        Address::repeat_byte(0x33),
    );

    let arb_id = compute_burn_id(
        42161,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        1_000_000,
        0,
        Address::repeat_byte(0x33),
    );

    assert_ne!(
        eth_id, arb_id,
        "Different chains must produce different IDs"
    );
}

#[test]
fn test_burn_id_recipient_binding() {
    let alice_id = compute_burn_id(
        31337,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0xAA),
        1_000_000,
        0,
        Address::repeat_byte(0x33),
    );

    let bob_id = compute_burn_id(
        31337,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0xBB),
        1_000_000,
        0,
        Address::repeat_byte(0x33),
    );

    assert_ne!(
        alice_id, bob_id,
        "Different recipients must produce different IDs"
    );
}

#[test]
fn test_burn_id_amount_binding() {
    let small_id = compute_burn_id(
        31337,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        1_000_000,
        0,
        Address::repeat_byte(0x33),
    );

    let large_id = compute_burn_id(
        31337,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        10_000_000,
        0,
        Address::repeat_byte(0x33),
    );

    assert_ne!(
        small_id, large_id,
        "Different amounts must produce different IDs"
    );
}
