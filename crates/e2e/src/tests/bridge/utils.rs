//! Test utilities for bridge e2e tests.

use alloy::{
    primitives::{Address, B256, address, keccak256},
    signers::local::PrivateKeySigner,
};

pub(super) const BRIDGE_ADDRESS: Address = address!("BBBB000000000000000000000000000000000000");

pub(super) const VALIDATOR_CONFIG_ADDRESS: Address =
    address!("CCCCCCCC00000000000000000000000000000000");

#[allow(dead_code)]
pub(super) const TEST_TIP20: Address = address!("20C0000000000000000000000001000000000000");

const DEPOSIT_DOMAIN: &[u8] = b"TEMPO_BRIDGE_DEPOSIT_V1";

const BURN_DOMAIN: &[u8] = b"TEMPO_BRIDGE_BURN_V1";

pub(super) fn anvil_accounts() -> Vec<(Address, PrivateKeySigner)> {
    let keys = [
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    ];

    keys.iter()
        .map(|k| {
            let signer: PrivateKeySigner = k.parse().unwrap();
            (signer.address(), signer)
        })
        .collect()
}

pub(super) fn compute_deposit_id(
    origin_chain_id: u64,
    origin_token: Address,
    origin_tx_hash: B256,
    origin_log_index: u32,
    tempo_recipient: Address,
    amount: u64,
    origin_block_number: u64,
) -> B256 {
    let mut buf = Vec::with_capacity(DEPOSIT_DOMAIN.len() + 8 + 20 + 32 + 4 + 20 + 8 + 8);
    buf.extend_from_slice(DEPOSIT_DOMAIN);
    buf.extend_from_slice(&origin_chain_id.to_be_bytes());
    buf.extend_from_slice(origin_token.as_slice());
    buf.extend_from_slice(origin_tx_hash.as_slice());
    buf.extend_from_slice(&origin_log_index.to_be_bytes());
    buf.extend_from_slice(tempo_recipient.as_slice());
    buf.extend_from_slice(&amount.to_be_bytes());
    buf.extend_from_slice(&origin_block_number.to_be_bytes());
    keccak256(&buf)
}

pub(super) fn compute_burn_id(
    origin_chain_id: u64,
    origin_token: Address,
    origin_recipient: Address,
    amount: u64,
    nonce: u64,
    sender: Address,
) -> B256 {
    let mut buf = Vec::with_capacity(BURN_DOMAIN.len() + 8 + 20 + 20 + 8 + 8 + 20);
    buf.extend_from_slice(BURN_DOMAIN);
    buf.extend_from_slice(&origin_chain_id.to_be_bytes());
    buf.extend_from_slice(origin_token.as_slice());
    buf.extend_from_slice(origin_recipient.as_slice());
    buf.extend_from_slice(&amount.to_be_bytes());
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf.extend_from_slice(sender.as_slice());
    keccak256(&buf)
}

pub(super) fn compute_threshold(validator_count: u64) -> u64 {
    (validator_count * 2).div_ceil(3)
}
