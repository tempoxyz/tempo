//! Fixed-size messages that travel on the spine's queues.
//!
//! Every message is `Copy + repr(C)` so it fits in a seqlock slot. Variable
//! length data (transaction bytes, block bodies) rides in the queue's dcache
//! and is only referenced by the message.

use serde::{Deserialize, Serialize};
use type_hash_derive::TypeHash;

pub type Hash = [u8; 32];
pub type Address = [u8; 20];

/// Raw transaction bytes arrived from the network, RPC or load generator.
/// Payload: EIP-2718 encoded transaction.
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, TypeHash)]
#[repr(C)]
pub struct RawTx {
    /// Wall-clock nanos when the bytes entered the node.
    pub ingress_ns: u64,
}

/// A transaction that decoded and passed signature recovery and stateless
/// checks. Payload: EIP-2718 encoded transaction.
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, TypeHash)]
#[repr(C)]
pub struct ValidTx {
    pub hash: Hash,
    pub sender: Address,
    pub nonce: u64,
    pub priority_fee: u64,
    pub ingress_ns: u64,
}

/// Consensus asks the builder for a block on top of `parent`.
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, TypeHash)]
#[repr(C)]
pub struct BuildRequest {
    pub height: u64,
    pub parent: Hash,
    pub timestamp_ms: u64,
    pub max_txs: u32,
}

/// A proposed block. Payload: body, see [`body`].
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, TypeHash)]
#[repr(C)]
pub struct Block {
    pub height: u64,
    pub parent: Hash,
    pub hash: Hash,
    pub timestamp_ms: u64,
    pub tx_count: u32,
    /// Oldest ingress time of the block's transactions, 0 for an empty block.
    pub oldest_ingress_ns: u64,
}

/// The executor's verdict on a block.
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, TypeHash)]
#[repr(C)]
pub struct Executed {
    pub height: u64,
    pub hash: Hash,
    pub state_root: Hash,
    pub gas_used: u64,
    pub valid: bool,
    /// Hash of the transaction that made the block invalid; zero when unknown.
    pub bad_tx: Hash,
}

/// Execution's state changes for one block. Payload: `accounts` account
/// records then `slots` storage records, see [`diff`].
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, TypeHash)]
#[repr(C)]
pub struct StateDiff {
    pub height: u64,
    pub hash: Hash,
    pub gas_used: u64,
    pub accounts: u32,
    pub slots: u32,
    pub valid: bool,
    /// Hash of the transaction that made the block invalid; zero when unknown.
    pub bad_tx: Hash,
}

pub mod diff {
    use crate::Address;

    pub const ACCOUNT_LEN: usize = 20 + 8 + 32 + 32 + 1;
    pub const SLOT_LEN: usize = 20 + 32 + 32;

    pub struct AccountRec {
        pub address: Address,
        pub nonce: u64,
        pub balance: [u8; 32],
        pub code_hash: [u8; 32],
        pub deleted: bool,
    }

    pub struct SlotRec {
        pub address: Address,
        pub key: [u8; 32],
        pub value: [u8; 32],
    }

    pub fn push_account(
        buf: &mut Vec<u8>,
        address: Address,
        nonce: u64,
        balance: [u8; 32],
        code_hash: [u8; 32],
        deleted: bool,
    ) {
        buf.extend_from_slice(&address);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&balance);
        buf.extend_from_slice(&code_hash);
        buf.push(u8::from(deleted));
    }

    pub fn push_slot(buf: &mut Vec<u8>, address: Address, key: [u8; 32], value: [u8; 32]) {
        buf.extend_from_slice(&address);
        buf.extend_from_slice(&key);
        buf.extend_from_slice(&value);
    }

    pub fn split(buf: &[u8], accounts: usize) -> (&[u8], &[u8]) {
        buf.split_at((accounts * ACCOUNT_LEN).min(buf.len()))
    }

    pub fn accounts(buf: &[u8], n: usize) -> impl Iterator<Item = AccountRec> + '_ {
        buf.chunks_exact(ACCOUNT_LEN).take(n).map(|r| AccountRec {
            address: r[0..20].try_into().unwrap(),
            nonce: u64::from_le_bytes(r[20..28].try_into().unwrap()),
            balance: r[28..60].try_into().unwrap(),
            code_hash: r[60..92].try_into().unwrap(),
            deleted: r[92] != 0,
        })
    }

    pub fn slots(buf: &[u8], n: usize) -> impl Iterator<Item = SlotRec> + '_ {
        buf.chunks_exact(SLOT_LEN).take(n).map(|r| SlotRec {
            address: r[0..20].try_into().unwrap(),
            key: r[20..52].try_into().unwrap(),
            value: r[52..84].try_into().unwrap(),
        })
    }
}

/// Consensus finalized a block.
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, TypeHash)]
#[repr(C)]
pub struct Finalized {
    pub height: u64,
    pub hash: Hash,
    pub state_root: Hash,
    pub tx_count: u32,
    pub oldest_ingress_ns: u64,
}

/// Storage made a finalized block durable.
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, TypeHash)]
#[repr(C)]
pub struct Persisted {
    pub height: u64,
}

/// Block body layout in the dcache, per transaction: `u32` LE length, the
/// 20-byte sender the verifiers recovered, then the EIP-2718 encoded tx.
pub mod body {
    use crate::Address;

    pub fn encoded_len<'a>(txs: impl Iterator<Item = (&'a Address, &'a [u8])>) -> usize {
        txs.map(|(_, t)| 24 + t.len()).sum()
    }

    pub fn write<'a>(buf: &mut [u8], txs: impl Iterator<Item = (&'a Address, &'a [u8])>) {
        let mut at = 0;
        for (sender, tx) in txs {
            buf[at..at + 4].copy_from_slice(&(tx.len() as u32).to_le_bytes());
            buf[at + 4..at + 24].copy_from_slice(sender);
            at += 24;
            buf[at..at + tx.len()].copy_from_slice(tx);
            at += tx.len();
        }
    }

    pub fn iter(buf: &[u8]) -> impl Iterator<Item = (Address, &[u8])> {
        let mut at = 0;
        std::iter::from_fn(move || {
            let len = u32::from_le_bytes(buf.get(at..at + 4)?.try_into().ok()?) as usize;
            let sender: Address = buf.get(at + 4..at + 24)?.try_into().ok()?;
            let tx = buf.get(at + 24..at + 24 + len)?;
            at += 24 + len;
            Some((sender, tx))
        })
    }
}
