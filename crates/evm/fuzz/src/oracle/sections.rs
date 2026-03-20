/// Normalized error classes for oracle/SUT comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrClass {
    InvalidNonce,
    InvalidNonceKey,
    ExpiringReplay,
    InvalidExpiry,
    ExpiringSetFull,
    SectionViolation,
    SharedGasViolation,
    InvalidSystemTx,
    InvalidSubblockSignature,
    InvalidSubblockValidator,
    DuplicateSystemTx,
    DuplicateValidatorMetadata,
    UnknownValidatorMetadata,
    GasLimitExceeded,
    RegularAfterSystem,
    ProposerSubblockAlreadyProcessed,
    Other(String),
}

/// Simplified model of BlockSection state transitions.
///
/// Models the section state machine from TempoBlockExecutor::validate_tx.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionState {
    StartOfBlock,
    NonShared,
    SubBlock { proposer_idx: u8 },
    GasIncentive,
    System { seen_subblocks_signatures: bool },
}

/// Tracks section transitions and gas accounting for one block.
#[derive(Debug)]
pub struct SectionOracle {
    state: SectionState,
    /// Proposer indices that have completed their subblock section
    closed_proposers: Vec<u8>,
    /// Non-shared gas remaining
    non_shared_gas_left: u64,
    /// Non-payment gas remaining
    non_payment_gas_left: u64,
    /// Incentive gas used
    incentive_gas_used: u64,
    /// Per-validator shared gas budget
    per_validator_shared_gas: u64,
    /// Shared gas limit
    shared_gas_limit: u64,
    /// Section trace for digest comparison
    trace: Vec<SectionState>,
}

impl SectionOracle {
    pub fn new(
        block_gas_limit: u64,
        shared_gas_limit: u64,
        general_gas_limit: u64,
        num_validators: usize,
    ) -> Self {
        let per_validator = if num_validators > 0 {
            shared_gas_limit / num_validators as u64
        } else {
            0
        };

        Self {
            state: SectionState::StartOfBlock,
            closed_proposers: Vec::new(),
            non_shared_gas_left: block_gas_limit - shared_gas_limit,
            non_payment_gas_left: general_gas_limit,
            incentive_gas_used: 0,
            per_validator_shared_gas: per_validator,
            shared_gas_limit,
            trace: vec![SectionState::StartOfBlock],
        }
    }

    /// Get current section state.
    pub fn state(&self) -> SectionState {
        self.state
    }

    /// Validate a transaction's section transition.
    ///
    /// Returns the new section state or an error class.
    pub fn validate_tx(
        &mut self,
        is_system: bool,
        is_subblock: bool,
        subblock_proposer_idx: Option<u8>,
        gas_used: u64,
        is_payment: bool,
    ) -> Result<SectionState, ErrClass> {
        if is_system {
            return self.validate_system_tx();
        }

        if is_subblock {
            let proposer = subblock_proposer_idx.unwrap_or(0);
            return self.validate_subblock_tx(proposer);
        }

        // Regular transaction
        self.validate_regular_tx(gas_used, is_payment)
    }

    fn validate_system_tx(&mut self) -> Result<SectionState, ErrClass> {
        let seen = match self.state {
            SectionState::System {
                seen_subblocks_signatures,
            } => {
                if seen_subblocks_signatures {
                    return Err(ErrClass::DuplicateSystemTx);
                }
                true
            }
            _ => true,
        };

        let new_state = SectionState::System {
            seen_subblocks_signatures: seen,
        };
        self.state = new_state;
        self.trace.push(new_state);
        Ok(new_state)
    }

    fn validate_subblock_tx(&mut self, proposer_idx: u8) -> Result<SectionState, ErrClass> {
        match self.state {
            SectionState::GasIncentive | SectionState::System { .. } => {
                Err(ErrClass::SectionViolation)
            }
            SectionState::StartOfBlock | SectionState::NonShared => {
                let new_state = SectionState::SubBlock { proposer_idx };
                self.state = new_state;
                self.trace.push(new_state);
                Ok(new_state)
            }
            SectionState::SubBlock {
                proposer_idx: current,
            } => {
                if current == proposer_idx || !self.closed_proposers.contains(&proposer_idx) {
                    let new_state = SectionState::SubBlock { proposer_idx };
                    if current != proposer_idx {
                        self.closed_proposers.push(current);
                    }
                    self.state = new_state;
                    self.trace.push(new_state);
                    Ok(new_state)
                } else {
                    Err(ErrClass::ProposerSubblockAlreadyProcessed)
                }
            }
        }
    }

    fn validate_regular_tx(
        &mut self,
        gas_used: u64,
        is_payment: bool,
    ) -> Result<SectionState, ErrClass> {
        match self.state {
            SectionState::System { .. } => Err(ErrClass::RegularAfterSystem),
            SectionState::StartOfBlock | SectionState::NonShared => {
                if gas_used > self.non_shared_gas_left
                    || (!is_payment && gas_used > self.non_payment_gas_left)
                {
                    // Flip to GasIncentive
                    let new_state = SectionState::GasIncentive;
                    self.state = new_state;
                    self.incentive_gas_used += gas_used;
                    self.trace.push(new_state);
                    Ok(new_state)
                } else {
                    let new_state = SectionState::NonShared;
                    self.state = new_state;
                    self.non_shared_gas_left -= gas_used;
                    if !is_payment {
                        self.non_payment_gas_left -= gas_used;
                    }
                    self.trace.push(new_state);
                    Ok(new_state)
                }
            }
            SectionState::SubBlock { .. } => {
                // After subblock, assume GasIncentive
                let new_state = SectionState::GasIncentive;
                self.state = new_state;
                self.incentive_gas_used += gas_used;
                self.trace.push(new_state);
                Ok(new_state)
            }
            SectionState::GasIncentive => {
                self.incentive_gas_used += gas_used;
                self.trace.push(SectionState::GasIncentive);
                Ok(SectionState::GasIncentive)
            }
        }
    }

    /// Compute a digest of the section trace.
    pub fn trace_digest(&self) -> alloy_primitives::B256 {
        use alloy_primitives::keccak256;

        let mut data = Vec::new();
        for state in &self.trace {
            let byte = match state {
                SectionState::StartOfBlock => 0u8,
                SectionState::NonShared => 1,
                SectionState::SubBlock { proposer_idx } => 2 + proposer_idx,
                SectionState::GasIncentive => 100,
                SectionState::System {
                    seen_subblocks_signatures,
                } => {
                    if *seen_subblocks_signatures {
                        201
                    } else {
                        200
                    }
                }
            };
            data.push(byte);
        }
        keccak256(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_section_order() {
        let mut oracle = SectionOracle::new(30_000_000, 10_000_000, 10_000_000, 2);

        // Regular tx → NonShared
        assert_eq!(
            oracle.validate_tx(false, false, None, 21_000, false),
            Ok(SectionState::NonShared)
        );

        // Subblock tx → SubBlock
        assert_eq!(
            oracle.validate_tx(false, true, Some(0), 0, false),
            Ok(SectionState::SubBlock { proposer_idx: 0 })
        );

        // Regular tx after subblock → GasIncentive
        assert_eq!(
            oracle.validate_tx(false, false, None, 21_000, false),
            Ok(SectionState::GasIncentive)
        );

        // System tx → System
        assert!(oracle.validate_tx(true, false, None, 0, false).is_ok());
    }

    #[test]
    fn test_regular_after_system_rejected() {
        let mut oracle = SectionOracle::new(30_000_000, 10_000_000, 10_000_000, 1);

        // System tx
        oracle.validate_tx(true, false, None, 0, false).unwrap();

        // Regular tx after system → error
        assert_eq!(
            oracle.validate_tx(false, false, None, 21_000, false),
            Err(ErrClass::RegularAfterSystem)
        );
    }

    #[test]
    fn test_duplicate_system_tx_rejected() {
        let mut oracle = SectionOracle::new(30_000_000, 10_000_000, 10_000_000, 1);

        // First system tx → ok
        oracle.validate_tx(true, false, None, 0, false).unwrap();

        // Duplicate → error
        assert_eq!(
            oracle.validate_tx(true, false, None, 0, false),
            Err(ErrClass::DuplicateSystemTx)
        );
    }

    #[test]
    fn test_gas_boundary_flip() {
        // Set up with very little non-shared gas
        let mut oracle = SectionOracle::new(30_000_000, 29_000_000, 10_000_000, 1);
        // non_shared_gas_left = 30M - 29M = 1M

        // First tx fits in non-shared
        assert_eq!(
            oracle.validate_tx(false, false, None, 500_000, false),
            Ok(SectionState::NonShared)
        );

        // Second tx exceeds non-shared → flips to GasIncentive
        assert_eq!(
            oracle.validate_tx(false, false, None, 600_000, false),
            Ok(SectionState::GasIncentive)
        );
    }
}
