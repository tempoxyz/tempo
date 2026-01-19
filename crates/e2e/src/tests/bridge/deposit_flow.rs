//! Tests for the deposit (origin -> Tempo) flow.

use super::utils::*;
use alloy::primitives::{Address, B256};

#[test]
fn test_deposit_id_computation() {
    let origin_chain_id = 31337u64;
    let origin_token = Address::repeat_byte(0x11);
    let origin_tx_hash = B256::repeat_byte(0x22);
    let origin_log_index = 0u32;
    let tempo_recipient = Address::repeat_byte(0x33);
    let amount = 1_000_000u64;
    let origin_block_number = 100u64;

    let id = compute_deposit_id(
        origin_chain_id,
        origin_token,
        origin_tx_hash,
        origin_log_index,
        tempo_recipient,
        amount,
        origin_block_number,
    );

    assert!(!id.is_zero());

    let id2 = compute_deposit_id(
        origin_chain_id,
        origin_token,
        origin_tx_hash,
        origin_log_index,
        tempo_recipient,
        amount,
        origin_block_number,
    );

    assert_eq!(id, id2);
}

#[test]
fn test_deposit_id_no_collision() {
    let base_id = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );

    let id1 = compute_deposit_id(
        1,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );
    assert_ne!(base_id, id1);

    let id2 = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0x33),
        2_000_000,
        100,
    );
    assert_ne!(base_id, id2);

    let id3 = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        1,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );
    assert_ne!(base_id, id3);
}

#[test]
fn test_deposit_id_different_tokens() {
    let usdc_id = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );

    let usdt_id = compute_deposit_id(
        31337,
        Address::repeat_byte(0x44),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );

    assert_ne!(usdc_id, usdt_id);
}

#[test]
fn test_deposit_id_different_recipients() {
    let alice_id = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0xAA),
        1_000_000,
        100,
    );

    let bob_id = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0xBB),
        1_000_000,
        100,
    );

    assert_ne!(alice_id, bob_id);
}

#[test]
fn test_deposit_id_different_block_numbers() {
    let id_block_100 = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        100,
    );

    let id_block_101 = compute_deposit_id(
        31337,
        Address::repeat_byte(0x11),
        B256::repeat_byte(0x22),
        0,
        Address::repeat_byte(0x33),
        1_000_000,
        101,
    );

    assert_ne!(id_block_100, id_block_101);
}
