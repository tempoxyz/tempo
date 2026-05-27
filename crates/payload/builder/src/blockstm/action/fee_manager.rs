//! Fee-manager semantic actions.

use crate::blockstm::{
    action::slots::fee_manager_collected_fees_key,
    rw_set::{BlockStmAccessKey, BlockStmWriteSet},
};
use alloy_primitives::{Address, U256};
use std::collections::BTreeMap;

/// Ordered validator/proposer fee accumulator delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectedFeesDelta {
    pub beneficiary: Address,
    pub validator_token: Address,
    pub amount: U256,
}

impl CollectedFeesDelta {
    /// Returns the fee-manager accumulator slot covered by this action.
    pub fn covered_storage_slots(&self) -> Vec<BlockStmAccessKey> {
        vec![fee_manager_collected_fees_key(
            self.beneficiary,
            self.validator_token,
        )]
    }
}

/// In-memory collected-fee accumulator values.
pub type CollectedFeesMap = BTreeMap<(Address, Address), U256>;

/// Ordered collected-fee resolver error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectedFeesResolutionError {
    Overflow {
        beneficiary: Address,
        validator_token: Address,
    },
}

/// Output of ordered collected-fee resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedFeesResolution {
    pub collected_fees: CollectedFeesMap,
    pub writes: BlockStmWriteSet,
}

/// Resolves validator/proposer fee credits in serial transaction order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectedFeesResolver {
    collected_fees: CollectedFeesMap,
}

impl CollectedFeesResolver {
    /// Creates a resolver with base collected-fee balances.
    pub fn new(collected_fees: CollectedFeesMap) -> Self {
        Self { collected_fees }
    }

    /// Applies all deltas in order.
    pub fn resolve(
        mut self,
        actions: &[CollectedFeesDelta],
    ) -> Result<CollectedFeesResolution, CollectedFeesResolutionError> {
        for action in actions {
            let key = (action.beneficiary, action.validator_token);
            let current = self.collected_fees.get(&key).copied().unwrap_or_default();
            let next = current.checked_add(action.amount).ok_or(
                CollectedFeesResolutionError::Overflow {
                    beneficiary: action.beneficiary,
                    validator_token: action.validator_token,
                },
            )?;
            self.collected_fees.insert(key, next);
        }

        let mut writes = BlockStmWriteSet::default();
        for ((beneficiary, validator_token), amount) in &self.collected_fees {
            writes.record(
                fee_manager_collected_fees_key(*beneficiary, *validator_token),
                *amount,
            );
        }

        Ok(CollectedFeesResolution {
            collected_fees: self.collected_fees,
            writes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstm::BlockStmValue;
    use alloy_primitives::address;

    #[test]
    fn blockstm_actions_collected_fees_accumulates_by_validator_and_token() {
        let validator = address!("0x00000000000000000000000000000000000000aa");
        let token = address!("0x20c0000000000000000000000000000000000001");
        let mut base = CollectedFeesMap::new();
        base.insert((validator, token), U256::from(5));

        let resolution = CollectedFeesResolver::new(base)
            .resolve(&[
                CollectedFeesDelta {
                    beneficiary: validator,
                    validator_token: token,
                    amount: U256::from(7),
                },
                CollectedFeesDelta {
                    beneficiary: validator,
                    validator_token: token,
                    amount: U256::from(11),
                },
            ])
            .unwrap();

        assert_eq!(
            resolution
                .writes
                .get(&fee_manager_collected_fees_key(validator, token)),
            Some(BlockStmValue::from(U256::from(23)))
        );
    }

    #[test]
    fn blockstm_actions_collected_fees_reports_overflow() {
        let validator = address!("0x00000000000000000000000000000000000000aa");
        let token = address!("0x20c0000000000000000000000000000000000001");
        let mut base = CollectedFeesMap::new();
        base.insert((validator, token), U256::MAX);

        assert_eq!(
            CollectedFeesResolver::new(base)
                .resolve(&[CollectedFeesDelta {
                    beneficiary: validator,
                    validator_token: token,
                    amount: U256::ONE,
                }])
                .unwrap_err(),
            CollectedFeesResolutionError::Overflow {
                beneficiary: validator,
                validator_token: token,
            }
        );
    }
}
