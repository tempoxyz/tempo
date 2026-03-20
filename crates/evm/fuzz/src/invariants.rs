use alloy_primitives::B256;

/// Outcome from either the oracle or the SUT for one block.
#[derive(Debug, Clone)]
pub struct BlockOutcome {
    /// Hashes of accepted transactions (in order)
    pub accepted_tx_hashes: Vec<B256>,
    /// Rejected transactions with error class
    pub rejected: Vec<(u16, ErrClass)>,
    /// Digest of nonce precompile state after this block
    pub nonce_state_digest: B256,
    /// Digest of the section trace
    pub section_trace_digest: B256,
}

/// Normalized error classification for oracle/SUT comparison.
///
/// We don't compare exact error messages — we classify errors into buckets
/// so the oracle and SUT can use different internal types but still be compared.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrClass {
    // Nonce errors
    InvalidNonce,
    InvalidNonceKey,
    ExpiringReplay,
    InvalidExpiry,
    ExpiringSetFull,
    NonceOverflow,

    // Section errors
    SectionViolation,
    RegularAfterSystem,
    DuplicateSystemTx,
    ProposerSubblockAlreadyProcessed,

    // Gas errors
    SharedGasViolation,
    GasLimitExceeded,
    IncentiveGasExceeded,

    // Subblock errors
    InvalidSubblockSignature,
    InvalidSubblockValidator,
    DuplicateValidatorMetadata,
    UnknownValidatorMetadata,
    SubblockGasExceedsBudget,
    SubblockTooLarge,

    // System tx errors
    InvalidSystemTx,
    InvalidSystemTxMetadata,

    // Execution errors
    InsufficientBalance,
    ExecutionReverted,

    // Catch-all
    Other(String),
}

/// Result of invariant checking for one block.
#[derive(Debug)]
pub struct InvariantResult {
    pub passed: bool,
    pub violations: Vec<InvariantViolation>,
}

/// A specific invariant violation.
#[derive(Debug)]
pub struct InvariantViolation {
    pub invariant: &'static str,
    pub details: String,
}

impl InvariantResult {
    pub fn new() -> Self {
        Self {
            passed: true,
            violations: Vec::new(),
        }
    }

    fn fail(&mut self, invariant: &'static str, details: String) {
        self.passed = false;
        self.violations.push(InvariantViolation { invariant, details });
    }
}

impl Default for InvariantResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Check all invariants between oracle and SUT outcomes for a single block.
pub fn check_block_invariants(
    oracle: &BlockOutcome,
    sut: &BlockOutcome,
    block_idx: usize,
) -> InvariantResult {
    let mut result = InvariantResult::new();

    // 1. Same number of accepted transactions
    if oracle.accepted_tx_hashes.len() != sut.accepted_tx_hashes.len() {
        result.fail(
            "accepted_tx_count",
            format!(
                "block {block_idx}: oracle accepted {} txs, SUT accepted {} txs",
                oracle.accepted_tx_hashes.len(),
                sut.accepted_tx_hashes.len()
            ),
        );
    }

    // 2. Same accepted tx hash sequence
    if oracle.accepted_tx_hashes != sut.accepted_tx_hashes {
        result.fail(
            "accepted_tx_sequence",
            format!(
                "block {block_idx}: accepted tx hash sequences differ. Oracle: {:?}, SUT: {:?}",
                oracle.accepted_tx_hashes, sut.accepted_tx_hashes
            ),
        );
    }

    // 3. Same rejection classes (order-insensitive comparison)
    let oracle_rejections: std::collections::HashSet<_> = oracle.rejected.iter().cloned().collect();
    let sut_rejections: std::collections::HashSet<_> = sut.rejected.iter().cloned().collect();

    // Check for rejections in oracle but not in SUT (tx accepted when it shouldn't be)
    for (idx, err) in &oracle.rejected {
        if !sut_rejections.contains(&(*idx, err.clone())) {
            result.fail(
                "rejection_class_missing_in_sut",
                format!(
                    "block {block_idx}: oracle rejected tx {idx} with {err:?}, but SUT did not",
                ),
            );
        }
    }

    // Check for rejections in SUT but not in oracle (tx rejected when it shouldn't be)
    for (idx, err) in &sut.rejected {
        if !oracle_rejections.contains(&(*idx, err.clone())) {
            result.fail(
                "rejection_class_missing_in_oracle",
                format!(
                    "block {block_idx}: SUT rejected tx {idx} with {err:?}, but oracle did not",
                ),
            );
        }
    }

    // 4. Same nonce state digest
    if oracle.nonce_state_digest != sut.nonce_state_digest {
        result.fail(
            "nonce_state_digest",
            format!(
                "block {block_idx}: nonce state digests differ. Oracle: {:?}, SUT: {:?}",
                oracle.nonce_state_digest, sut.nonce_state_digest
            ),
        );
    }

    // 5. Same section trace digest
    if oracle.section_trace_digest != sut.section_trace_digest {
        result.fail(
            "section_trace_digest",
            format!(
                "block {block_idx}: section trace digests differ. Oracle: {:?}, SUT: {:?}",
                oracle.section_trace_digest, sut.section_trace_digest
            ),
        );
    }

    result
}

/// Nonce-specific invariants to check after each block.
pub fn check_nonce_invariants(
    nonce_changes: &[(alloy_primitives::Address, alloy_primitives::U256, u64, u64)],
    // (account, nonce_key, old_value, new_value)
    block_idx: usize,
) -> InvariantResult {
    let mut result = InvariantResult::new();

    for (addr, key, old, new) in nonce_changes {
        // User nonce must never decrease
        if new < old {
            result.fail(
                "nonce_monotonicity",
                format!(
                    "block {block_idx}: nonce for ({addr:?}, {key:?}) decreased from {old} to {new}",
                ),
            );
        }

        // Successful increment should be exactly +1
        if *new != 0 && *new != *old && *new != old + 1 {
            result.fail(
                "nonce_increment_exactness",
                format!(
                    "block {block_idx}: nonce for ({addr:?}, {key:?}) jumped from {old} to {new} (expected +1)",
                ),
            );
        }
    }

    result
}

/// Gas invariants to check after each block.
pub fn check_gas_invariants(
    block_gas_limit: u64,
    total_gas_used: u64,
    non_shared_gas_used: u64,
    non_shared_gas_limit: u64,
    non_payment_gas_used: u64,
    general_gas_limit: u64,
    per_validator_gas: &[(u8, u64)], // (validator_idx, gas_used)
    per_validator_budget: u64,
    incentive_gas_used: u64,
    incentive_gas_available: u64,
    block_idx: usize,
) -> InvariantResult {
    let mut result = InvariantResult::new();

    // Total gas must not exceed block gas limit
    if total_gas_used > block_gas_limit {
        result.fail(
            "total_gas_limit",
            format!(
                "block {block_idx}: total gas {total_gas_used} exceeds block limit {block_gas_limit}",
            ),
        );
    }

    // Non-shared gas must not exceed its limit
    if non_shared_gas_used > non_shared_gas_limit {
        result.fail(
            "non_shared_gas_limit",
            format!(
                "block {block_idx}: non-shared gas {non_shared_gas_used} exceeds limit {non_shared_gas_limit}",
            ),
        );
    }

    // Non-payment gas must not exceed general gas limit
    if non_payment_gas_used > general_gas_limit {
        result.fail(
            "general_gas_limit",
            format!(
                "block {block_idx}: non-payment gas {non_payment_gas_used} exceeds general limit {general_gas_limit}",
            ),
        );
    }

    // Each validator's subblock gas must not exceed per-validator budget
    for (validator_idx, gas) in per_validator_gas {
        if *gas > per_validator_budget {
            result.fail(
                "per_validator_gas_budget",
                format!(
                    "block {block_idx}: validator {validator_idx} used {gas} gas, exceeds budget {per_validator_budget}",
                ),
            );
        }
    }

    // Incentive gas must not exceed available incentive gas
    if incentive_gas_used > incentive_gas_available {
        result.fail(
            "incentive_gas_limit",
            format!(
                "block {block_idx}: incentive gas {incentive_gas_used} exceeds available {incentive_gas_available}",
            ),
        );
    }

    result
}

/// Cache coherence invariants — compare outcomes from cached vs uncached execution.
pub fn check_cache_invariants(
    cached_outcome: &BlockOutcome,
    uncached_outcome: &BlockOutcome,
    block_idx: usize,
) -> InvariantResult {
    let mut result = InvariantResult::new();

    if cached_outcome.accepted_tx_hashes != uncached_outcome.accepted_tx_hashes {
        result.fail(
            "cache_coherence_accepted_txs",
            format!(
                "block {block_idx}: cached and uncached execution accepted different transactions",
            ),
        );
    }

    if cached_outcome.nonce_state_digest != uncached_outcome.nonce_state_digest {
        result.fail(
            "cache_coherence_nonce_state",
            format!(
                "block {block_idx}: cached and uncached execution produced different nonce states",
            ),
        );
    }

    if cached_outcome.section_trace_digest != uncached_outcome.section_trace_digest {
        result.fail(
            "cache_coherence_section_trace",
            format!(
                "block {block_idx}: cached and uncached execution produced different section traces",
            ),
        );
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matching_outcomes_pass() {
        let outcome = BlockOutcome {
            accepted_tx_hashes: vec![B256::repeat_byte(1), B256::repeat_byte(2)],
            rejected: vec![(3, ErrClass::InvalidNonce)],
            nonce_state_digest: B256::repeat_byte(0xaa),
            section_trace_digest: B256::repeat_byte(0xbb),
        };

        let result = check_block_invariants(&outcome, &outcome.clone(), 0);
        assert!(result.passed, "identical outcomes should pass: {:?}", result.violations);
    }

    #[test]
    fn test_different_accepted_txs_fail() {
        let oracle = BlockOutcome {
            accepted_tx_hashes: vec![B256::repeat_byte(1)],
            rejected: vec![],
            nonce_state_digest: B256::ZERO,
            section_trace_digest: B256::ZERO,
        };
        let sut = BlockOutcome {
            accepted_tx_hashes: vec![B256::repeat_byte(2)],
            rejected: vec![],
            nonce_state_digest: B256::ZERO,
            section_trace_digest: B256::ZERO,
        };

        let result = check_block_invariants(&oracle, &sut, 0);
        assert!(!result.passed);
    }

    #[test]
    fn test_nonce_monotonicity_violation() {
        let changes = vec![
            (alloy_primitives::Address::ZERO, alloy_primitives::U256::from(1), 5u64, 3u64),
        ];

        let result = check_nonce_invariants(&changes, 0);
        assert!(!result.passed);
        assert!(result.violations.iter().any(|v| v.invariant == "nonce_monotonicity"));
    }

    #[test]
    fn test_gas_invariants_pass() {
        let result = check_gas_invariants(
            30_000_000,  // block limit
            21_000,      // total used
            21_000,      // non-shared used
            20_000_000,  // non-shared limit
            21_000,      // non-payment used
            10_000_000,  // general limit
            &[(0, 0)],   // per-validator
            5_000_000,   // per-validator budget
            0,           // incentive used
            5_000_000,   // incentive available
            0,
        );
        assert!(result.passed);
    }

    #[test]
    fn test_gas_invariants_fail_total_exceeded() {
        let result = check_gas_invariants(
            30_000_000,
            30_000_001, // exceeds!
            21_000,
            20_000_000,
            21_000,
            10_000_000,
            &[],
            5_000_000,
            0,
            5_000_000,
            0,
        );
        assert!(!result.passed);
        assert!(result.violations.iter().any(|v| v.invariant == "total_gas_limit"));
    }
}
