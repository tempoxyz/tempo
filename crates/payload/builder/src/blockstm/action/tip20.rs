//! TIP20 semantic actions.

use crate::blockstm::{action::slots::tip20_balance_key, rw_set::BlockStmWriteSet};
use alloy_primitives::{Address, U256};
use std::collections::BTreeMap;

/// Ordered fee precharge/refund delta for a TIP20 fee token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip20FeeEscrowDelta {
    pub token: Address,
    pub fee_payer: Address,
    pub fee_manager: Address,
    pub max_fee_precharge: U256,
    pub actual_spending: U256,
    pub refund_amount: U256,
}

impl Tip20FeeEscrowDelta {
    /// Returns TIP20 balance slots covered by this action.
    pub fn covered_storage_slots(&self) -> Vec<crate::blockstm::rw_set::BlockStmAccessKey> {
        vec![
            tip20_balance_key(self.token, self.fee_payer),
            tip20_balance_key(self.token, self.fee_manager),
        ]
    }
}

/// Ordered simple TIP20 transfer delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip20TransferDelta {
    pub token: Address,
    pub sender: Address,
    pub recipient: Address,
    pub amount: U256,
}

impl Tip20TransferDelta {
    /// Returns TIP20 balance slots covered by this action.
    pub fn covered_storage_slots(&self) -> Vec<crate::blockstm::rw_set::BlockStmAccessKey> {
        vec![
            tip20_balance_key(self.token, self.sender),
            tip20_balance_key(self.token, self.recipient),
        ]
    }
}

/// In-memory balances used by ordered TIP20 resolvers.
pub type Tip20BalanceMap = BTreeMap<(Address, Address), U256>;

/// Ordered TIP20 resolver error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tip20ResolutionError {
    InsufficientBalance {
        token: Address,
        account: Address,
        available: U256,
        required: U256,
    },
    FeeEscrowInvariant {
        token: Address,
        fee_payer: Address,
        max_fee_precharge: U256,
        actual_spending: U256,
        refund_amount: U256,
    },
    Overflow {
        token: Address,
        account: Address,
    },
}

/// Resolves ordered TIP20 balance actions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tip20BalanceResolver {
    balances: Tip20BalanceMap,
}

impl Tip20BalanceResolver {
    /// Creates a resolver with the provided base balances.
    pub fn new(balances: Tip20BalanceMap) -> Self {
        Self { balances }
    }

    /// Applies a simple TIP20 transfer in serial order.
    pub fn apply_transfer(
        &mut self,
        action: Tip20TransferDelta,
    ) -> Result<(), Tip20ResolutionError> {
        self.sub_balance(action.token, action.sender, action.amount)?;
        self.add_balance(action.token, action.recipient, action.amount)
    }

    /// Applies a fee precharge/refund action in serial operation order.
    pub fn apply_fee_escrow(
        &mut self,
        action: Tip20FeeEscrowDelta,
    ) -> Result<(), Tip20ResolutionError> {
        if action
            .actual_spending
            .checked_add(action.refund_amount)
            .map_or(true, |spent_plus_refund| {
                spent_plus_refund != action.max_fee_precharge
            })
        {
            return Err(Tip20ResolutionError::FeeEscrowInvariant {
                token: action.token,
                fee_payer: action.fee_payer,
                max_fee_precharge: action.max_fee_precharge,
                actual_spending: action.actual_spending,
                refund_amount: action.refund_amount,
            });
        }

        self.sub_balance(action.token, action.fee_payer, action.max_fee_precharge)?;
        self.add_balance(action.token, action.fee_manager, action.max_fee_precharge)?;
        self.sub_balance(action.token, action.fee_manager, action.refund_amount)?;
        self.add_balance(action.token, action.fee_payer, action.refund_amount)
    }

    /// Applies all transfers in order.
    pub fn resolve_transfers(
        mut self,
        actions: &[Tip20TransferDelta],
    ) -> Result<Tip20BalanceResolution, Tip20ResolutionError> {
        for action in actions {
            self.apply_transfer(*action)?;
        }
        Ok(self.finish())
    }

    /// Applies all fee escrow actions in order.
    pub fn resolve_fee_escrows(
        mut self,
        actions: &[Tip20FeeEscrowDelta],
    ) -> Result<Tip20BalanceResolution, Tip20ResolutionError> {
        for action in actions {
            self.apply_fee_escrow(*action)?;
        }
        Ok(self.finish())
    }

    /// Returns the current balance for `(token, account)`.
    pub fn balance(&self, token: Address, account: Address) -> U256 {
        self.balances
            .get(&(token, account))
            .copied()
            .unwrap_or_default()
    }

    fn finish(self) -> Tip20BalanceResolution {
        let mut writes = BlockStmWriteSet::default();
        for ((token, account), balance) in &self.balances {
            writes.record(tip20_balance_key(*token, *account), *balance);
        }
        Tip20BalanceResolution {
            balances: self.balances,
            writes,
        }
    }

    fn sub_balance(
        &mut self,
        token: Address,
        account: Address,
        amount: U256,
    ) -> Result<(), Tip20ResolutionError> {
        let balance = self.balance(token, account);
        let new_balance =
            balance
                .checked_sub(amount)
                .ok_or(Tip20ResolutionError::InsufficientBalance {
                    token,
                    account,
                    available: balance,
                    required: amount,
                })?;
        self.balances.insert((token, account), new_balance);
        Ok(())
    }

    fn add_balance(
        &mut self,
        token: Address,
        account: Address,
        amount: U256,
    ) -> Result<(), Tip20ResolutionError> {
        let balance = self.balance(token, account);
        let new_balance = balance
            .checked_add(amount)
            .ok_or(Tip20ResolutionError::Overflow { token, account })?;
        self.balances.insert((token, account), new_balance);
        Ok(())
    }
}

/// Output of ordered TIP20 balance resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tip20BalanceResolution {
    pub balances: Tip20BalanceMap,
    pub writes: BlockStmWriteSet,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstm::BlockStmValue;
    use alloy_primitives::address;

    fn token() -> Address {
        address!("0x20c0000000000000000000000000000000000001")
    }

    #[test]
    fn blockstm_actions_tip20_transfer_preserves_serial_balance_order() {
        let alice = address!("0x00000000000000000000000000000000000000a1");
        let bob = address!("0x00000000000000000000000000000000000000b2");
        let carol = address!("0x00000000000000000000000000000000000000c3");
        let mut base = Tip20BalanceMap::new();
        base.insert((token(), alice), U256::from(10));

        let resolution = Tip20BalanceResolver::new(base)
            .resolve_transfers(&[
                Tip20TransferDelta {
                    token: token(),
                    sender: alice,
                    recipient: bob,
                    amount: U256::from(7),
                },
                Tip20TransferDelta {
                    token: token(),
                    sender: bob,
                    recipient: carol,
                    amount: U256::from(4),
                },
            ])
            .unwrap();

        assert_eq!(
            resolution.balances.get(&(token(), alice)),
            Some(&U256::from(3))
        );
        assert_eq!(
            resolution.balances.get(&(token(), bob)),
            Some(&U256::from(3))
        );
        assert_eq!(
            resolution.writes.get(&tip20_balance_key(token(), carol)),
            Some(BlockStmValue::from(U256::from(4)))
        );
    }

    #[test]
    fn blockstm_actions_tip20_transfer_rejects_insufficient_sender_balance() {
        let alice = address!("0x00000000000000000000000000000000000000a1");
        let bob = address!("0x00000000000000000000000000000000000000b2");

        assert_eq!(
            Tip20BalanceResolver::default()
                .resolve_transfers(&[Tip20TransferDelta {
                    token: token(),
                    sender: alice,
                    recipient: bob,
                    amount: U256::from(1),
                }])
                .unwrap_err(),
            Tip20ResolutionError::InsufficientBalance {
                token: token(),
                account: alice,
                available: U256::ZERO,
                required: U256::from(1),
            }
        );
    }

    #[test]
    fn blockstm_actions_tip20_fee_escrow_applies_precharge_then_refund() {
        let payer = address!("0x00000000000000000000000000000000000000a1");
        let manager = address!("0x00000000000000000000000000000000000000f0");
        let mut base = Tip20BalanceMap::new();
        base.insert((token(), payer), U256::from(100));

        let resolution = Tip20BalanceResolver::new(base)
            .resolve_fee_escrows(&[Tip20FeeEscrowDelta {
                token: token(),
                fee_payer: payer,
                fee_manager: manager,
                max_fee_precharge: U256::from(30),
                actual_spending: U256::from(12),
                refund_amount: U256::from(18),
            }])
            .unwrap();

        assert_eq!(
            resolution.balances.get(&(token(), payer)),
            Some(&U256::from(88))
        );
        assert_eq!(
            resolution.balances.get(&(token(), manager)),
            Some(&U256::from(12))
        );
    }

    #[test]
    fn blockstm_actions_tip20_fee_escrow_rejects_bad_refund_math() {
        let payer = address!("0x00000000000000000000000000000000000000a1");
        let manager = address!("0x00000000000000000000000000000000000000f0");

        assert!(matches!(
            Tip20BalanceResolver::default()
                .resolve_fee_escrows(&[Tip20FeeEscrowDelta {
                    token: token(),
                    fee_payer: payer,
                    fee_manager: manager,
                    max_fee_precharge: U256::from(30),
                    actual_spending: U256::from(11),
                    refund_amount: U256::from(18),
                }])
                .unwrap_err(),
            Tip20ResolutionError::FeeEscrowInvariant { .. }
        ));
    }
}
