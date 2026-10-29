//! Expected verifier measurements reported by the serving node, not observed batch proofs.

use alloy_primitives::{B256, FixedBytes};
use serde::{Deserialize, Serialize};

/// Response for `tempo_getVerifierPcrPolicy`.
///
/// This is the serving node's configured policy, not a cryptographic proof of chain state.
/// It includes development overrides and does not depend on a successful Nitro submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierPcrPolicy {
    /// Chain ID of the serving node.
    pub chain_id: u64,
    /// Head block used to determine which hardforks have activated.
    pub block_number: u64,
    /// Hash of that head block.
    pub block_hash: B256,
    /// Timestamp of that head block, in seconds.
    pub block_timestamp: u64,
    /// Latest active Tempo hardfork at that head.
    pub active_hardfork: String,
    /// Expected measurements for the requested fork (the active fork when omitted).
    pub selected: VerifierPcrPolicyEntry,
    /// Per-fork policy through the selected fork, in protocol order, including null policies.
    /// This is policy history, not a log of accepted attestations or past node configurations.
    pub history: Vec<VerifierPcrPolicyEntry>,
}

/// Expected Nitro PCR0/1/2 at one configured, activated Tempo hardfork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierPcrPolicyEntry {
    /// Tempo hardfork name.
    pub hardfork: String,
    /// Configured activation timestamp in seconds; null for Genesis.
    pub activation_time: Option<u64>,
    /// Approved PCR0, PCR1 and PCR2, in that order. Null means no approved Nitro measurements,
    /// including before the verifier's introduction in T13; it never means zero-valued PCRs.
    pub pcrs: Option<[FixedBytes<48>; 3]>,
}
