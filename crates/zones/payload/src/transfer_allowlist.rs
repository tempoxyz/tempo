//! Sequencer-local allowlist for Zone TIP-20 transfers.
//!
//! The allowlist is sequencer-local policy that consensus does not replicate, so only the leader
//! enforces it; followers and the prover accept any block. Pool admission rejects a transaction
//! whose calls move TIP-20 funds to or from an unlisted account, and the leader's builder checks
//! each pool transaction again against the current list before executing it, which catches list
//! changes after admission.
//!
//! Checking calldata is enough on Zones: contract creation and authorization lists are disabled,
//! and T15, which enables transfers, removes the Multicall3 and Permit2 predeploys. Funds can only
//! move through the TIP-20 and `ReceivePolicyGuard` calls screened here, the outbox, and fees.

use alloy_primitives::{Address, TxKind};
use alloy_sol_types::{SolCall as _, SolInterface as _};
use evm2::registry::HandlerError;
use reth_transaction_pool::{PoolTransaction as _, error::InvalidPoolTransactionError};
use std::fmt;
use tempo_contracts::precompiles::{IReceivePolicyGuard, ITIP20, RECEIVE_POLICY_GUARD_ADDRESS};
use tempo_primitives::TempoAddressExt as _;
use tempo_transaction_pool::transaction::{TempoPoolTransactionError, TempoPooledTransaction};

use crate::abi::{IZoneOutbox, ZONE_OUTBOX_ADDRESS};

/// Zone accounts that may send and receive TIP-20 transfers in blocks this node builds.
pub trait TransferAllowlist: fmt::Debug + Send + Sync + 'static {
    /// Whether every one of `addresses` may send or receive Zone transfers, read from a single
    /// version of the list so a concurrent write cannot approve each party under a different
    /// one. An allowlist that has never been written allows every address.
    fn allows_all(&self, addresses: &[Address]) -> bool;

    /// Whether a TIP-20 transfer from `from` to `to` is allowed.
    ///
    /// Transfers to or from the zero address or the outbox mint, burn, or withdraw, so they are
    /// exempt: an account removed from the list can still withdraw.
    fn allows_transfer(&self, from: Address, to: Address) -> bool {
        let exempt = |address: Address| address.is_zero() || address == ZONE_OUTBOX_ADDRESS;
        exempt(from) || exempt(to) || self.allows_all(&[from, to])
    }

    /// Whether `sender` may request a withdrawal whose L1 bounce-back credits
    /// `fallback_recipient` on the Zone.
    ///
    /// Naming oneself is always allowed, so an unlisted account can still withdraw.
    fn allows_withdrawal_fallback(&self, sender: Address, fallback_recipient: Address) -> bool {
        fallback_recipient == sender || self.allows_all(&[sender, fallback_recipient])
    }
}

/// Reject a transaction whose calls move TIP-20 funds (including `ReceivePolicyGuard` claims) or
/// name a withdrawal fallback recipient outside `allowlist`, or call `transferFrom` from an
/// unlisted account.
///
/// Pool admission calls this on submission, and the leader's builder calls it again before
/// executing each pool transaction.
pub fn validate_transfer_calls(
    allowlist: &dyn TransferAllowlist,
    tx: &TempoPooledTransaction,
) -> Result<(), InvalidPoolTransactionError> {
    let sender = *tx.sender_ref();
    let allowed = tx.inner().calls().all(|(kind, input)| {
        let TxKind::Call(target) = kind else {
            return true;
        };
        if target.is_tip20() {
            return match ITIP20::ITIP20Calls::abi_decode(input) {
                Ok(ITIP20::ITIP20Calls::transfer(ITIP20::transferCall { to, .. }))
                | Ok(ITIP20::ITIP20Calls::transferWithMemo(ITIP20::transferWithMemoCall {
                    to,
                    ..
                })) => allowlist.allows_transfer(sender, to),
                // A listed caller is required, so `transferFrom(a, b, 0)` cannot probe the list.
                Ok(ITIP20::ITIP20Calls::transferFrom(ITIP20::transferFromCall {
                    from,
                    to,
                    ..
                }))
                | Ok(ITIP20::ITIP20Calls::transferFromWithMemo(
                    ITIP20::transferFromWithMemoCall { from, to, .. },
                )) => allowlist.allows_all(&[sender]) && allowlist.allows_transfer(from, to),
                _ => true,
            };
        }
        if target == RECEIVE_POLICY_GUARD_ADDRESS {
            // Only the receipt's recovery authority can claim, and it picks where funds go. Unlike
            // `transfer`, a claim to the outbox is not exempt, since it requests no withdrawal.
            return match IReceivePolicyGuard::claimCall::abi_decode(input) {
                Ok(call) => allowlist.allows_all(&[sender, call.to]),
                Err(_) => true,
            };
        }
        if target != ZONE_OUTBOX_ADDRESS {
            return true;
        }
        match IZoneOutbox::requestWithdrawalCall::abi_decode(input) {
            Ok(call) => allowlist.allows_withdrawal_fallback(sender, call.zoneFallbackRecipient),
            Err(_) => true,
        }
    });
    if allowed {
        Ok(())
    } else {
        Err(unlisted_transfer_error())
    }
}

/// Pool error for a transaction that moves Zone funds to or from an account the allowlist does
/// not allow. It does not say which account failed the check.
fn unlisted_transfer_error() -> InvalidPoolTransactionError {
    InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(HandlerError::External(
        "transfer sender or recipient is not allowlisted".into(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip1559};
    use alloy_primitives::{Bytes, Signature, U256, address};
    use reth_primitives_traits::Recovered;
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{Call, TempoTransaction},
    };

    const ALICE: Address = address!("0x00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0x0000000000000000000000000000000000000b0b");
    const CAROL: Address = address!("0x00000000000000000000000000000000000ca201");

    /// Allows only the listed addresses.
    #[derive(Debug)]
    struct Listed(BTreeSet<Address>);

    impl TransferAllowlist for Listed {
        fn allows_all(&self, addresses: &[Address]) -> bool {
            addresses.iter().all(|address| self.0.contains(address))
        }
    }

    /// Holds only ALICE, then only BOB after every lookup, as if each lookup raced a write that
    /// swapped them.
    #[derive(Debug, Default)]
    struct Swapping(AtomicBool);

    impl TransferAllowlist for Swapping {
        fn allows_all(&self, addresses: &[Address]) -> bool {
            let listed = if self.0.fetch_xor(true, Ordering::SeqCst) {
                BOB
            } else {
                ALICE
            };
            addresses.iter().all(|address| *address == listed)
        }
    }

    #[test]
    fn both_parties_are_checked_against_one_list_version() {
        assert!(!Swapping::default().allows_transfer(ALICE, BOB));
        assert!(!Swapping::default().allows_withdrawal_fallback(ALICE, BOB));
    }

    fn call(to: Address, input: impl Into<Bytes>) -> Call {
        Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: input.into(),
        }
    }

    fn token_transfer(to: Address) -> Call {
        call(
            Address::new_tip20(0),
            ITIP20::transferCall {
                to,
                amount: U256::ONE,
            }
            .abi_encode(),
        )
    }

    fn token_transfer_from(from: Address, to: Address) -> Call {
        call(
            Address::new_tip20(0),
            ITIP20::transferFromWithMemoCall {
                from,
                to,
                amount: U256::ONE,
                memo: Default::default(),
            }
            .abi_encode(),
        )
    }

    fn request_withdrawal(fallback_recipient: Address) -> Call {
        call(
            ZONE_OUTBOX_ADDRESS,
            IZoneOutbox::requestWithdrawalCall {
                token: Address::new_tip20(0),
                to: fallback_recipient,
                amount: 1,
                memo: Default::default(),
                gasLimit: 0,
                zoneFallbackRecipient: fallback_recipient,
                data: Bytes::new(),
                revealTo: Bytes::new(),
            }
            .abi_encode(),
        )
    }

    fn claim(to: Address) -> Call {
        call(
            RECEIVE_POLICY_GUARD_ADDRESS,
            IReceivePolicyGuard::claimCall {
                to,
                receipt: Bytes::new(),
            }
            .abi_encode(),
        )
    }

    fn pooled_transaction(envelope: TempoTxEnvelope, sender: Address) -> TempoPooledTransaction {
        TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender))
    }

    /// Checks an AA transaction from `sender` against a list holding ALICE and BOB.
    fn admits_calls(sender: Address, calls: Vec<Call>) -> bool {
        let transaction = TempoTransaction {
            calls,
            ..Default::default()
        };
        let transaction = pooled_transaction(
            transaction
                .into_signed(Signature::test_signature().into())
                .into(),
            sender,
        );
        match validate_transfer_calls(&Listed(BTreeSet::from([ALICE, BOB])), &transaction) {
            Ok(()) => true,
            Err(err) => {
                assert_eq!(err.to_string(), unlisted_transfer_error().to_string());
                false
            }
        }
    }

    #[test]
    fn transfers_need_both_parties_listed() {
        assert!(admits_calls(ALICE, vec![token_transfer(BOB)]));
        assert!(!admits_calls(ALICE, vec![token_transfer(CAROL)]));
        assert!(!admits_calls(CAROL, vec![token_transfer(ALICE)]));
        // Any unlisted call rejects the whole batch.
        assert!(!admits_calls(
            ALICE,
            vec![token_transfer(BOB), token_transfer(CAROL)]
        ));
        // The spender, owner, and recipient must all be listed.
        assert!(admits_calls(BOB, vec![token_transfer_from(ALICE, BOB)]));
        assert!(!admits_calls(ALICE, vec![token_transfer_from(CAROL, BOB)]));
        assert!(!admits_calls(
            ALICE,
            vec![token_transfer_from(ALICE, CAROL)]
        ));
        // An unlisted spender is rejected whatever parties it names, so it cannot use the result
        // to learn whether they are listed.
        assert!(!admits_calls(CAROL, vec![token_transfer_from(ALICE, BOB)]));
        assert!(!admits_calls(
            CAROL,
            vec![token_transfer_from(ALICE, ALICE)]
        ));
        assert!(!admits_calls(
            CAROL,
            vec![token_transfer_from(CAROL, CAROL)]
        ));
        // Transfer calldata sent to a non-token contract moves no TIP-20 funds.
        assert!(admits_calls(
            ALICE,
            vec![call(
                CAROL,
                ITIP20::transferCall {
                    to: CAROL,
                    amount: U256::ONE
                }
                .abi_encode()
            )]
        ));
    }

    #[test]
    fn unlisted_accounts_can_still_withdraw() {
        assert!(admits_calls(
            CAROL,
            vec![token_transfer(ZONE_OUTBOX_ADDRESS)]
        ));
        assert!(admits_calls(CAROL, vec![request_withdrawal(CAROL)]));
    }

    #[test]
    fn withdrawal_fallback_recipients_need_both_parties_listed_unless_self() {
        assert!(admits_calls(ALICE, vec![request_withdrawal(BOB)]));
        assert!(!admits_calls(CAROL, vec![request_withdrawal(ALICE)]));
        assert!(!admits_calls(ALICE, vec![request_withdrawal(CAROL)]));
    }

    #[test]
    fn receipt_claims_need_the_claimer_and_destination_listed() {
        assert!(admits_calls(ALICE, vec![claim(BOB)]));
        assert!(admits_calls(ALICE, vec![claim(ALICE)]));
        assert!(!admits_calls(ALICE, vec![claim(CAROL)]));
        assert!(!admits_calls(CAROL, vec![claim(ALICE)]));
        assert!(!admits_calls(CAROL, vec![claim(CAROL)]));
        assert!(!admits_calls(CAROL, vec![claim(ZONE_OUTBOX_ADDRESS)]));
    }

    #[test]
    fn non_aa_transfers_are_checked() {
        let envelope = TempoTxEnvelope::Eip1559(Signed::new_unhashed(
            TxEip1559 {
                to: TxKind::Call(Address::new_tip20(0)),
                input: ITIP20::transferCall {
                    to: BOB,
                    amount: U256::ONE,
                }
                .abi_encode()
                .into(),
                ..Default::default()
            },
            Signature::test_signature(),
        ));
        let transaction = pooled_transaction(envelope, ALICE);
        assert!(validate_transfer_calls(&Listed(BTreeSet::from([ALICE])), &transaction).is_err());
        assert!(
            validate_transfer_calls(&Listed(BTreeSet::from([ALICE, BOB])), &transaction).is_ok()
        );
    }
}
