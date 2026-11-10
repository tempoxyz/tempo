//! The reth-proofs server's answer to a proof request, shared with its test commands. The checks
//! of its proofs live in the commands binary (src/bin/reth-proofs-commands), so their assertions
//! register only there.

use alloy_primitives::Bytes;
use reth_trie_common::AccountProof;
use serde::{Deserialize, Serialize};

/// The server's answer to one proof request.
#[derive(Debug, Serialize, Deserialize)]
pub struct Proved {
    /// `eth_getMultiProof`'s proofs, one per target.
    pub proofs: Vec<AccountProof>,
    /// The execution witness of a block reading the same targets.
    pub witness: Vec<Bytes>,
}
