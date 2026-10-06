//! Single-leaf account/storage proof fixtures shared by state-proof consumers' tests.

use alloc::{vec, vec::Vec};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_rpc_types_eth::{EIP1186AccountProofResponse, EIP1186StorageProof};
use alloy_trie::{Nibbles, TrieAccount, nodes::LeafNode};

use crate::ProofTargets;

pub fn leaf(key: B256, value: Vec<u8>) -> Bytes {
    alloy_rlp::encode(LeafNode::new(Nibbles::unpack(key), value)).into()
}

/// Replace the account proof with a single leaf for the response's metadata.
pub fn account_root(response: &mut EIP1186AccountProofResponse) -> (B256, TrieAccount) {
    let account = TrieAccount {
        nonce: response.nonce,
        balance: response.balance,
        storage_root: response.storage_hash,
        code_hash: response.code_hash,
    };
    let node = leaf(keccak256(response.address), alloy_rlp::encode(account));
    let root = keccak256(&node);
    response.account_proof = vec![node];
    (root, account)
}

/// One account with one nonzero slot `0x0a = value`, proved against the returned state root.
pub fn fixture(nonce: u64, value: u64) -> (B256, ProofTargets, EIP1186AccountProofResponse) {
    let address = Address::repeat_byte(0x20);
    let slot = B256::with_last_byte(10);
    let storage = leaf(keccak256(slot), alloy_rlp::encode(U256::from(value)));
    let mut response = EIP1186AccountProofResponse {
        address,
        nonce,
        balance: U256::from(7),
        code_hash: keccak256([0]),
        storage_hash: keccak256(&storage),
        storage_proof: vec![EIP1186StorageProof {
            key: slot.into(),
            value: U256::from(value),
            proof: vec![storage],
        }],
        ..Default::default()
    };
    let (root, _) = account_root(&mut response);
    (
        root,
        ProofTargets::from([(address, [slot].into())]),
        response,
    )
}
