//! What a pending transaction's pre-execution checks read, recorded at admission.
//!
//! Validation runs the handler's pre-execution checks with storage actions recording on. The
//! actions say which slots the checks read and what they saw, and, for the checks with an
//! affordability predicate, what had to hold. [`Preconditions`] keeps what a later write can
//! falsify: a write that changes a slot so that its condition fails sends the transaction back to
//! validation. Reads no later write can turn into a failure are dropped, and the hot slots whose
//! value changes with every transaction (fee payer balances, spending limits, 2D nonce lanes)
//! keep only the threshold their check needs.

use crate::transaction::TempoPooledTransaction;
use alloy_consensus::Transaction;
use alloy_primitives::{Address, U256, map::HashSet};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    storage::StorageAction,
    tip20::{TIP20Token, is_tip20_prefix},
};

/// What a slot must still satisfy for a pending transaction to pass its pre-execution checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Condition {
    /// The slot still holds the value validation read.
    Equals(U256),
    /// The slot holds at least this value.
    AtLeast(U256),
    /// The slot holds less than this value.
    Below(U256),
    /// A spending limit's remaining amount covers this value. From T7 a periodic limit spent to
    /// exactly zero stores `U256::MAX`, which no real remaining amount reaches.
    RemainingAtLeast(U256),
    /// A 2D nonce lane has not moved past this nonce.
    LaneAtMost(u64),
}

impl Condition {
    /// Returns whether a slot holding `value` satisfies the condition.
    pub(crate) fn holds(self, value: U256) -> bool {
        match self {
            Self::Equals(expected) => value == expected,
            Self::AtLeast(min) => value >= min,
            Self::Below(max) => value < max,
            Self::RemainingAtLeast(min) => value != U256::MAX && value >= min,
            Self::LaneAtMost(nonce) => value <= U256::from(nonce),
        }
    }
}

/// A slot a pending transaction's pre-execution checks depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Precondition {
    pub(crate) address: Address,
    pub(crate) slot: U256,
    pub(crate) condition: Condition,
}

/// The slots a pending transaction's pre-execution checks depend on, recorded at admission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preconditions(Box<[Precondition]>);

impl Preconditions {
    /// Builds the preconditions of `tx` from the storage actions its validation recorded.
    pub(crate) fn from_actions(tx: &TempoPooledTransaction, actions: Vec<StorageAction>) -> Self {
        let fee = tx.fee_token_cost();
        let fee_payer_slot = tx.fee_balance_slot().map(|(_, slot)| slot);
        // Every TIP-20 token stores balances in the same mapping.
        let fee_manager_slot = TIP20Token::from_address_unchecked(DEFAULT_FEE_TOKEN).balances
            [TIP_FEE_MANAGER_ADDRESS]
            .slot();
        let spending_limit_slot = tx
            .keychain_subject()
            .filter(|_| tx.is_sender_paid_fee())
            .map(|subject| {
                AccountKeychain::new().spending_limits
                    [AccountKeychain::spending_limit_key(subject.account, subject.key_id)]
                    [subject.fee_token]
                    .remaining
                    .slot()
            });
        let lane = tx
            .nonce_key_slot()
            .filter(|_| !tx.is_expiring_nonce())
            .map(|slot| (slot, tx.nonce()));
        let expiring_seen = tx
            .is_expiring_nonce()
            .then(|| tx.expiring_nonce_slot())
            .flatten();

        let mut written = HashSet::<(Address, U256)>::default();
        let mut read = HashSet::<(Address, U256)>::default();
        let mut preconditions = Vec::new();
        let mut push = |address, slot, condition| {
            preconditions.push(Precondition {
                address,
                slot,
                condition,
            })
        };
        for action in actions {
            match action {
                // Increments can only fail on overflow.
                StorageAction::Sinc(address, slot, ..)
                | StorageAction::Sstore(address, slot, ..) => {
                    written.insert((address, slot));
                }
                StorageAction::Sdec(address, slot, _, delta) => {
                    if !written.contains(&(address, slot)) {
                        push(address, slot, Condition::AtLeast(delta));
                    }
                    written.insert((address, slot));
                }
                StorageAction::FeeTokenBalanceCheck(address, slot, _, required, sufficient) => {
                    if !written.contains(&(address, slot)) {
                        push(
                            address,
                            slot,
                            if sufficient {
                                Condition::AtLeast(required)
                            } else {
                                Condition::Below(required)
                            },
                        );
                    }
                }
                // Fee AMM routes depend on the block's validator token: the payload builder
                // checks them itself.
                StorageAction::FeeAmmSwap(..) | StorageAction::FeeAmmLiquidityCheck(..) => {}
                StorageAction::Sload(address, slot, value) => {
                    let key = (address, slot);
                    if written.contains(&key) || !read.insert(key) {
                        continue;
                    }
                    let condition = if is_tip20_prefix(address) {
                        if slot == fee_manager_slot {
                            // The fee manager's balance only receives fees.
                            continue;
                        } else if Some(slot) == fee_payer_slot {
                            // Only a decrease below what the fee needs can fail the checks.
                            Condition::AtLeast(value.min(fee))
                        } else {
                            Condition::Equals(value)
                        }
                    } else if address == ACCOUNT_KEYCHAIN_ADDRESS
                        && Some(slot) == spending_limit_slot
                    {
                        let remaining = if value == U256::MAX {
                            U256::ZERO
                        } else {
                            value
                        };
                        Condition::RemainingAtLeast(remaining.min(fee))
                    } else if address == NONCE_PRECOMPILE_ADDRESS {
                        if let Some((lane_slot, nonce)) = lane
                            && slot == lane_slot
                        {
                            Condition::LaneAtMost(nonce)
                        } else if expiring_seen.is_some_and(|seen| seen != slot) {
                            // The expiring nonce ring moves with every expiring transaction;
                            // only this transaction's replay entry is its own.
                            continue;
                        } else {
                            Condition::Equals(value)
                        }
                    } else {
                        Condition::Equals(value)
                    };
                    push(address, slot, condition);
                }
            }
        }
        Self(preconditions.into_boxed_slice())
    }

    /// Returns the recorded preconditions.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Precondition> {
        self.0.iter()
    }

    /// Returns the number of recorded preconditions.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no precondition was recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Returns preconditions holding `conditions` on `(address, slot)` pairs.
    #[cfg(test)]
    pub(crate) fn from_conditions(
        conditions: impl IntoIterator<Item = (Address, U256, Condition)>,
    ) -> Self {
        Self(
            conditions
                .into_iter()
                .map(|(address, slot, condition)| Precondition {
                    address,
                    slot,
                    condition,
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TxBuilder;
    use alloy_primitives::address;
    use tempo_precompiles::{PATH_USD_ADDRESS, TIP403_REGISTRY_ADDRESS};

    fn conditions(tx: &TempoPooledTransaction, actions: Vec<StorageAction>) -> Vec<Precondition> {
        Preconditions::from_actions(tx, actions).0.into_vec()
    }

    #[test]
    fn keeps_what_a_later_write_can_falsify() {
        let tx = TxBuilder::aa(Address::random())
            .fee_token(PATH_USD_ADDRESS)
            .build();
        let fee = tx.fee_token_cost();
        let (_, balance_slot) = tx.fee_balance_slot().unwrap();
        let fee_manager_slot = TIP20Token::from_address_unchecked(DEFAULT_FEE_TOKEN).balances
            [TIP_FEE_MANAGER_ADDRESS]
            .slot();
        let policy = TIP403_REGISTRY_ADDRESS;
        let other = address!("0x20c0000000000000000000000000000000000001");
        let got = conditions(
            &tx,
            vec![
                // Exact reads, deduplicated.
                StorageAction::Sload(policy, U256::from(1), U256::from(7)),
                StorageAction::Sload(policy, U256::from(1), U256::from(7)),
                // The fee payer's balance keeps the fee as its threshold.
                StorageAction::Sload(PATH_USD_ADDRESS, balance_slot, fee * U256::from(3)),
                // The fee manager's balance only receives fees.
                StorageAction::Sload(PATH_USD_ADDRESS, fee_manager_slot, U256::ZERO),
                // An insufficient fallback candidate must stay insufficient.
                StorageAction::FeeTokenBalanceCheck(other, balance_slot, U256::ONE, fee, false),
                // A decrement needs its delta.
                StorageAction::Sdec(PATH_USD_ADDRESS, balance_slot, fee * U256::from(3), fee),
                // A read of the transaction's own write says nothing about the parent state.
                StorageAction::Sstore(policy, U256::from(2), U256::ZERO, U256::ONE),
                StorageAction::Sload(policy, U256::from(2), U256::ONE),
                StorageAction::Sinc(policy, U256::from(3), U256::ZERO, U256::ONE),
            ],
        );
        assert_eq!(
            got,
            vec![
                Precondition {
                    address: policy,
                    slot: U256::from(1),
                    condition: Condition::Equals(U256::from(7)),
                },
                Precondition {
                    address: PATH_USD_ADDRESS,
                    slot: balance_slot,
                    condition: Condition::AtLeast(fee),
                },
                Precondition {
                    address: other,
                    slot: balance_slot,
                    condition: Condition::Below(fee),
                },
                Precondition {
                    address: PATH_USD_ADDRESS,
                    slot: balance_slot,
                    condition: Condition::AtLeast(fee),
                },
            ]
        );
    }

    #[test]
    fn nonce_lanes_keep_only_how_far_they_may_move() {
        let lane_tx = TxBuilder::aa(Address::random())
            .nonce_key(U256::from(5))
            .nonce(3)
            .build();
        let lane = lane_tx.nonce_key_slot().unwrap();
        assert_eq!(
            conditions(
                &lane_tx,
                vec![StorageAction::Sload(
                    NONCE_PRECOMPILE_ADDRESS,
                    lane,
                    U256::from(3)
                )]
            ),
            vec![Precondition {
                address: NONCE_PRECOMPILE_ADDRESS,
                slot: lane,
                condition: Condition::LaneAtMost(3),
            }]
        );
    }

    #[test]
    fn spending_limits_decode_the_zero_sentinel() {
        for (stored, expected) in [(U256::MAX, U256::ZERO), (U256::from(5), U256::from(5))] {
            assert!(!Condition::RemainingAtLeast(U256::ONE).holds(U256::MAX));
            let remaining = if stored == U256::MAX {
                U256::ZERO
            } else {
                stored
            };
            assert_eq!(remaining, expected);
        }
    }
}
