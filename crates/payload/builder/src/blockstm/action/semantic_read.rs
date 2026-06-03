//! Semantic prefix read actions.

use crate::blockstm::{action::BlockStmResource, rw_set::BlockStmValue};
use alloy_primitives::U256;

/// Covered read that must be validated against the serial prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticPrefixRead {
    /// Prefix balance must be at least the requested amount.
    MinBalance {
        resource: BlockStmResource,
        amount: U256,
        op_index: u32,
    },
    /// Exact prefix value is user-visible and must not be stale.
    ExactValue {
        resource: BlockStmResource,
        op_index: u32,
    },
}

/// Error returned when a semantic prefix read is stale or insufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticPrefixReadError {
    InsufficientBalance {
        resource: BlockStmResource,
        required: U256,
        actual: U256,
    },
    ExactValueMismatch {
        resource: BlockStmResource,
        expected: BlockStmValue,
        actual: BlockStmValue,
    },
}

impl SemanticPrefixRead {
    /// Validates a semantic read against the serial prefix value.
    pub fn validate(
        self,
        attempted_value: BlockStmValue,
        prefix_value: BlockStmValue,
    ) -> Result<(), SemanticPrefixReadError> {
        match self {
            Self::MinBalance {
                resource, amount, ..
            } => {
                let actual = U256::from_be_bytes(prefix_value.0.0);
                if actual < amount {
                    Err(SemanticPrefixReadError::InsufficientBalance {
                        resource,
                        required: amount,
                        actual,
                    })
                } else {
                    Ok(())
                }
            }
            Self::ExactValue { resource, .. } => {
                if attempted_value != prefix_value {
                    Err(SemanticPrefixReadError::ExactValueMismatch {
                        resource,
                        expected: attempted_value,
                        actual: prefix_value,
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blockstm_actions_semantic_read_accepts_sufficient_prefix_balance() {
        let read = SemanticPrefixRead::MinBalance {
            resource: BlockStmResource::Tip20Balance,
            amount: U256::from(10),
            op_index: 0,
        };

        assert_eq!(
            read.validate(
                BlockStmValue::from(U256::from(100)),
                BlockStmValue::from(U256::from(10))
            ),
            Ok(())
        );
    }

    #[test]
    fn blockstm_actions_semantic_read_rejects_stale_exact_value() {
        let read = SemanticPrefixRead::ExactValue {
            resource: BlockStmResource::SemanticRead,
            op_index: 0,
        };

        assert!(matches!(
            read.validate(
                BlockStmValue::from(U256::from(1)),
                BlockStmValue::from(U256::from(2))
            ),
            Err(SemanticPrefixReadError::ExactValueMismatch { .. })
        ));
    }
}
