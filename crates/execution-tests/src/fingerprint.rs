//! Fingerprint generation for execution results.
//!
//! Combines transaction execution results with post-execution state
//! to produce a deterministic fingerprint for comparison across implementations.

use crate::{
    executor::{Log, TxExecutionResult},
    state_capture::PostExecutionState,
};
use alloy_primitives::{Address, B256, Bytes, keccak256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Serializable transaction execution result for fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxResult {
    pub success: bool,
    pub gas_used: u64,
    pub cumulative_gas_used: Option<u64>,
    pub return_data: Bytes,
    pub logs: Vec<LogEntry>,
    pub revert_reason: Option<String>,
}

/// Serializable log entry for fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

impl From<Log> for LogEntry {
    fn from(log: Log) -> Self {
        Self {
            address: log.address,
            topics: log.topics,
            data: log.data,
        }
    }
}

impl From<&Log> for LogEntry {
    fn from(log: &Log) -> Self {
        Self {
            address: log.address,
            topics: log.topics.clone(),
            data: log.data.clone(),
        }
    }
}

impl From<&TxExecutionResult> for TxResult {
    fn from(result: &TxExecutionResult) -> Self {
        Self {
            success: result.success,
            gas_used: result.gas_used,
            cumulative_gas_used: Some(result.cumulative_gas_used),
            return_data: result.return_data.clone(),
            logs: result.logs.iter().map(LogEntry::from).collect(),
            revert_reason: result.revert_reason.clone(),
        }
    }
}

/// Type alias for backward compatibility
pub type LogFingerprint = LogEntry;

/// Fingerprint of a single transaction execution result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxFingerprint {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Bytes,
    pub logs: Vec<LogFingerprint>,
    pub revert_reason: Option<String>,
}

impl From<TxExecutionResult> for TxFingerprint {
    fn from(result: TxExecutionResult) -> Self {
        Self {
            success: result.success,
            gas_used: result.gas_used,
            return_data: result.return_data,
            logs: result.logs.into_iter().map(LogFingerprint::from).collect(),
            revert_reason: result.revert_reason,
        }
    }
}

impl From<&TxExecutionResult> for TxFingerprint {
    fn from(result: &TxExecutionResult) -> Self {
        Self {
            success: result.success,
            gas_used: result.gas_used,
            return_data: result.return_data.clone(),
            logs: result.logs.iter().map(LogFingerprint::from).collect(),
            revert_reason: result.revert_reason.clone(),
        }
    }
}

/// Execution metadata for fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FingerprintMetadata {
    pub vector_name: String,
    pub hardfork: String,
    pub block_number: u64,
}

/// Complete execution fingerprint.
///
/// Combines transaction results, post-execution state, and metadata
/// into a deterministic fingerprint for cross-implementation comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fingerprint {
    pub metadata: FingerprintMetadata,
    pub tx_results: BTreeMap<usize, TxResult>,
    pub post_state: PostExecutionState,
}

impl Fingerprint {
    /// Create a fingerprint from execution results.
    pub fn from_execution(
        vector_name: impl Into<String>,
        hardfork: impl Into<String>,
        block_number: u64,
        tx_results: Vec<TxExecutionResult>,
        post_state: PostExecutionState,
    ) -> Self {
        let metadata = FingerprintMetadata {
            vector_name: vector_name.into(),
            hardfork: hardfork.into(),
            block_number,
        };

        let tx_results = tx_results
            .iter()
            .enumerate()
            .map(|(i, r)| (i, TxResult::from(r)))
            .collect();

        Self {
            metadata,
            tx_results,
            post_state,
        }
    }

    /// Serialize to canonical JSON with sorted keys.
    ///
    /// BTreeMap ensures deterministic key ordering.
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string(self).expect("fingerprint serialization should not fail")
    }

    /// Compute keccak256 hash of the canonical JSON representation.
    ///
    /// Useful for quick comparison of fingerprints.
    pub fn hash(&self) -> B256 {
        keccak256(self.to_canonical_json().as_bytes())
    }
}

/// Builder for constructing fingerprints.
#[derive(Debug, Default)]
pub struct FingerprintBuilder {
    vector_name: Option<String>,
    hardfork: Option<String>,
    block_number: Option<u64>,
    tx_results: Vec<TxExecutionResult>,
    post_state: Option<PostExecutionState>,
}

impl FingerprintBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn vector_name(mut self, name: impl Into<String>) -> Self {
        self.vector_name = Some(name.into());
        self
    }

    pub fn hardfork(mut self, hardfork: impl Into<String>) -> Self {
        self.hardfork = Some(hardfork.into());
        self
    }

    pub fn block_number(mut self, number: u64) -> Self {
        self.block_number = Some(number);
        self
    }

    pub fn tx_results(mut self, results: Vec<TxExecutionResult>) -> Self {
        self.tx_results = results;
        self
    }

    pub fn post_state(mut self, state: PostExecutionState) -> Self {
        self.post_state = Some(state);
        self
    }

    pub fn build(self) -> eyre::Result<Fingerprint> {
        let vector_name = self
            .vector_name
            .ok_or_else(|| eyre::eyre!("vector_name is required"))?;
        let hardfork = self
            .hardfork
            .ok_or_else(|| eyre::eyre!("hardfork is required"))?;
        let block_number = self
            .block_number
            .ok_or_else(|| eyre::eyre!("block_number is required"))?;
        let post_state = self.post_state.unwrap_or_else(PostExecutionState::empty);

        Ok(Fingerprint::from_execution(
            vector_name,
            hardfork,
            block_number,
            self.tx_results,
            post_state,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_capture::{FieldValue, PrecompileFieldValues};
    use alloy_primitives::{U256, address, b256};
    use std::collections::BTreeMap;

    fn make_test_log() -> Log {
        Log {
            address: address!("1111111111111111111111111111111111111111"),
            topics: vec![
                b256!("0000000000000000000000000000000000000000000000000000000000000001"),
                b256!("0000000000000000000000000000000000000000000000000000000000000002"),
            ],
            data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
        }
    }

    fn make_test_tx_result() -> TxExecutionResult {
        TxExecutionResult {
            success: true,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            return_data: Bytes::from(vec![0x01, 0x02, 0x03]),
            logs: vec![make_test_log()],
            revert_reason: None,
        }
    }

    fn make_test_post_state() -> PostExecutionState {
        let mut storage = BTreeMap::new();
        let mut addr_storage = BTreeMap::new();
        addr_storage.insert(U256::from(0), U256::from(42));
        storage.insert(
            address!("1111111111111111111111111111111111111111"),
            addr_storage,
        );

        let mut nonces = BTreeMap::new();
        nonces.insert(address!("3333333333333333333333333333333333333333"), 5u64);

        PostExecutionState {
            storage,
            nonces,
            precompiles: BTreeMap::new(),
        }
    }

    #[test]
    fn test_fingerprint_from_execution() {
        let tx_results = vec![make_test_tx_result()];
        let post_state = make_test_post_state();

        let fp = Fingerprint::from_execution(
            "test_vector",
            "cancun",
            1000,
            tx_results,
            post_state.clone(),
        );

        assert_eq!(fp.metadata.vector_name, "test_vector");
        assert_eq!(fp.metadata.hardfork, "cancun");
        assert_eq!(fp.metadata.block_number, 1000);
        assert_eq!(fp.tx_results.len(), 1);
        assert_eq!(fp.post_state, post_state);
    }

    #[test]
    fn test_fingerprint_builder() {
        let tx_results = vec![make_test_tx_result()];
        let post_state = make_test_post_state();

        let fp = FingerprintBuilder::new()
            .vector_name("test_vector")
            .hardfork("cancun")
            .block_number(1000)
            .tx_results(tx_results)
            .post_state(post_state.clone())
            .build()
            .unwrap();

        assert_eq!(fp.metadata.vector_name, "test_vector");
        assert_eq!(fp.metadata.hardfork, "cancun");
        assert_eq!(fp.metadata.block_number, 1000);
        assert_eq!(fp.post_state, post_state);
    }

    #[test]
    fn test_fingerprint_builder_missing_fields() {
        let result = FingerprintBuilder::new().build();
        assert!(result.is_err());

        let result = FingerprintBuilder::new().vector_name("test").build();
        assert!(result.is_err());

        let result = FingerprintBuilder::new()
            .vector_name("test")
            .hardfork("cancun")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let tx_results = vec![make_test_tx_result()];
        let post_state = make_test_post_state();

        let fp = Fingerprint::from_execution("test_vector", "cancun", 1000, tx_results, post_state);

        let json = fp.to_canonical_json();
        let parsed: Fingerprint = serde_json::from_str(&json).unwrap();

        assert_eq!(fp, parsed);
    }

    #[test]
    fn test_canonical_json_deterministic() {
        let tx_results = vec![make_test_tx_result()];
        let post_state = make_test_post_state();

        let fp1 = Fingerprint::from_execution(
            "test_vector",
            "cancun",
            1000,
            tx_results.clone(),
            post_state.clone(),
        );
        let fp2 =
            Fingerprint::from_execution("test_vector", "cancun", 1000, tx_results, post_state);

        assert_eq!(fp1.to_canonical_json(), fp2.to_canonical_json());
    }

    #[test]
    fn test_hash_stability() {
        let tx_results = vec![make_test_tx_result()];
        let post_state = make_test_post_state();

        let fp = Fingerprint::from_execution("test_vector", "cancun", 1000, tx_results, post_state);

        let hash1 = fp.hash();
        let hash2 = fp.hash();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, B256::ZERO);
    }

    #[test]
    fn test_hash_changes_with_data() {
        let tx_results = vec![make_test_tx_result()];
        let post_state = make_test_post_state();

        let fp1 = Fingerprint::from_execution(
            "test_vector",
            "cancun",
            1000,
            tx_results.clone(),
            post_state.clone(),
        );
        let fp2 =
            Fingerprint::from_execution("different_vector", "cancun", 1000, tx_results, post_state);

        assert_ne!(fp1.hash(), fp2.hash());
    }

    #[test]
    fn test_tx_result_from_execution_result() {
        let exec_result = make_test_tx_result();
        let tx_result = TxResult::from(&exec_result);

        assert_eq!(tx_result.success, exec_result.success);
        assert_eq!(tx_result.gas_used, exec_result.gas_used);
        assert_eq!(
            tx_result.cumulative_gas_used,
            Some(exec_result.cumulative_gas_used)
        );
        assert_eq!(tx_result.return_data, exec_result.return_data);
        assert_eq!(tx_result.logs.len(), 1);
    }

    #[test]
    fn test_log_entry_from_log() {
        let log = make_test_log();
        let entry = LogEntry::from(&log);

        assert_eq!(entry.address, log.address);
        assert_eq!(entry.topics, log.topics);
        assert_eq!(entry.data, log.data);
    }

    #[test]
    fn test_empty_fingerprint() {
        let fp =
            Fingerprint::from_execution("empty", "cancun", 0, vec![], PostExecutionState::empty());

        assert!(fp.tx_results.is_empty());
        assert!(fp.post_state.is_empty());

        let json = fp.to_canonical_json();
        let parsed: Fingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, parsed);
    }

    #[test]
    fn test_multiple_tx_results() {
        let mut result1 = make_test_tx_result();
        result1.gas_used = 21000;
        result1.cumulative_gas_used = 21000;

        let mut result2 = make_test_tx_result();
        result2.gas_used = 50000;
        result2.cumulative_gas_used = 71000;

        let fp = Fingerprint::from_execution(
            "multi_tx",
            "cancun",
            100,
            vec![result1, result2],
            PostExecutionState::empty(),
        );

        assert_eq!(fp.tx_results.len(), 2);
        assert_eq!(fp.tx_results.get(&0).unwrap().gas_used, 21000);
        assert_eq!(fp.tx_results.get(&1).unwrap().gas_used, 50000);
    }

    #[test]
    fn test_failed_tx_with_revert_reason() {
        let result = TxExecutionResult {
            success: false,
            gas_used: 30000,
            cumulative_gas_used: 30000,
            return_data: Bytes::new(),
            logs: vec![],
            revert_reason: Some("execution reverted: insufficient balance".to_string()),
        };

        let fp = Fingerprint::from_execution(
            "revert_test",
            "cancun",
            1,
            vec![result],
            PostExecutionState::empty(),
        );

        let tx_result = fp.tx_results.get(&0).unwrap();
        assert!(!tx_result.success);
        assert_eq!(
            tx_result.revert_reason,
            Some("execution reverted: insufficient balance".to_string())
        );

        let json = fp.to_canonical_json();
        let parsed: Fingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, parsed);
    }

    #[test]
    fn test_log_fingerprint_from_log() {
        let log = make_test_log();
        let fingerprint = LogFingerprint::from(log.clone());

        assert_eq!(fingerprint.address, log.address);
        assert_eq!(fingerprint.topics, log.topics);
        assert_eq!(fingerprint.data, log.data);
    }

    #[test]
    fn test_log_fingerprint_from_log_ref() {
        let log = make_test_log();
        let fingerprint = LogFingerprint::from(&log);

        assert_eq!(fingerprint.address, log.address);
        assert_eq!(fingerprint.topics, log.topics);
        assert_eq!(fingerprint.data, log.data);
    }

    #[test]
    fn test_tx_fingerprint_from_execution_result() {
        let exec_result = make_test_tx_result();
        let fingerprint = TxFingerprint::from(exec_result.clone());

        assert_eq!(fingerprint.success, exec_result.success);
        assert_eq!(fingerprint.gas_used, exec_result.gas_used);
        assert_eq!(fingerprint.return_data, exec_result.return_data);
        assert_eq!(fingerprint.logs.len(), exec_result.logs.len());
        assert_eq!(fingerprint.revert_reason, exec_result.revert_reason);
    }

    #[test]
    fn test_tx_fingerprint_from_execution_result_ref() {
        let exec_result = make_test_tx_result();
        let fingerprint = TxFingerprint::from(&exec_result);

        assert_eq!(fingerprint.success, exec_result.success);
        assert_eq!(fingerprint.gas_used, exec_result.gas_used);
        assert_eq!(fingerprint.return_data, exec_result.return_data);
        assert_eq!(fingerprint.logs.len(), exec_result.logs.len());
        assert_eq!(fingerprint.revert_reason, exec_result.revert_reason);
    }

    #[test]
    fn test_tx_fingerprint_with_logs() {
        let exec_result = make_test_tx_result();
        let fingerprint = TxFingerprint::from(&exec_result);

        assert_eq!(fingerprint.logs.len(), 1);
        let log_fp = &fingerprint.logs[0];
        assert_eq!(log_fp.address, exec_result.logs[0].address);
        assert_eq!(log_fp.topics, exec_result.logs[0].topics);
        assert_eq!(log_fp.data, exec_result.logs[0].data);
    }

    #[test]
    fn test_tx_fingerprint_with_revert() {
        let result = TxExecutionResult {
            success: false,
            gas_used: 25000,
            cumulative_gas_used: 25000,
            return_data: Bytes::new(),
            logs: vec![],
            revert_reason: Some("out of gas".to_string()),
        };

        let fingerprint = TxFingerprint::from(result);

        assert!(!fingerprint.success);
        assert_eq!(fingerprint.gas_used, 25000);
        assert!(fingerprint.logs.is_empty());
        assert_eq!(fingerprint.revert_reason, Some("out of gas".to_string()));
    }

    #[test]
    fn test_tx_fingerprint_serialization_roundtrip() {
        let exec_result = make_test_tx_result();
        let fingerprint = TxFingerprint::from(exec_result);

        let json = serde_json::to_string(&fingerprint).unwrap();
        let parsed: TxFingerprint = serde_json::from_str(&json).unwrap();

        assert_eq!(fingerprint, parsed);
    }

    #[test]
    fn test_log_fingerprint_serialization_roundtrip() {
        let log = make_test_log();
        let fingerprint = LogFingerprint::from(log);

        let json = serde_json::to_string(&fingerprint).unwrap();
        let parsed: LogFingerprint = serde_json::from_str(&json).unwrap();

        assert_eq!(fingerprint, parsed);
    }

    #[test]
    fn test_fingerprint_with_precompiles() {
        let mut precompiles = BTreeMap::new();
        let mut fields = BTreeMap::new();
        fields.insert(
            "total_supply".to_string(),
            FieldValue::Simple(U256::from(1000000)),
        );
        fields.insert(
            "balances".to_string(),
            FieldValue::Mapping({
                let mut m = BTreeMap::new();
                m.insert(
                    "0x1111111111111111111111111111111111111111".to_string(),
                    U256::from(500),
                );
                m
            }),
        );
        precompiles.insert(
            address!("20C0000000000000000000000000000000000001"),
            PrecompileFieldValues {
                name: "TIP20Token".to_string(),
                fields,
            },
        );

        let post_state = PostExecutionState {
            storage: BTreeMap::new(),
            nonces: BTreeMap::new(),
            precompiles,
        };

        let fp =
            Fingerprint::from_execution("test_with_precompiles", "T1", 100, vec![], post_state);

        // Verify serialization works
        let json = fp.to_canonical_json();
        assert!(json.contains("precompiles"));
        assert!(json.contains("TIP20Token"));

        // Verify deserialization works
        let parsed: Fingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, parsed);

        // Verify hash is stable
        let hash1 = fp.hash();
        let hash2 = fp.hash();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, B256::ZERO);
    }
}
