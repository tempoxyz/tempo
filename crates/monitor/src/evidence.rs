//! Evidence references and serializable evidence values.

use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};

use crate::facts::BlockNumHash;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceRef {
    Block(BlockNumHash),
    Tx {
        block: BlockNumHash,
        tx_hash: B256,
        tx_index: u64,
    },
    Log {
        block: BlockNumHash,
        tx_hash: B256,
        log_index: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceValue {
    Bool(bool),
    String(String),
    Address(Address),
    Hash(B256),
    Uint(U256),
    Int(i128),
    Bytes(Bytes),
    Json(serde_json::Value),
}
