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
//! move through the TIP-20 calls screened here, the outbox, and fees. `ReceivePolicyGuard` claims
//! need no screen: from T15 zone precompiles revert blocked inbounds instead of diverting them to
//! the guard, and earlier the inbox reverts a mint the receive policy blocks, so the guard never
//! holds funds on a zone.

use alloy_primitives::{Address, TxKind};
use alloy_sol_types::SolCall as _;
use evm2::registry::HandlerError;
use reth_transaction_pool::{PoolTransaction as _, error::InvalidPoolTransactionError};
use std::fmt;
use tempo_contracts::precompiles::ITIP20;
use tempo_primitives::TempoAddressExt as _;
use tempo_transaction_pool::transaction::{TempoPoolTransactionError, TempoPooledTransaction};

use crate::abi::{IZoneOutbox, ZONE_OUTBOX_ADDRESS};

/// Zone accounts that may send and receive TIP-20 transfers in blocks this node builds.
pub trait TransferAllowlist: fmt::Debug + Send + Sync + 'static {
    /// Whether every one of `addresses` may send or receive Zone transfers, read from a single
    /// version of the list so a concurrent write cannot approve each party under a different
    /// one. An allowlist that has never been written allows every address.
    fn allows_all(&self, addresses: &[Address]) -> bool;
}

/// Reject a transaction whose calls move TIP-20 funds or name a withdrawal fallback recipient
/// outside `allowlist`, or call `transferFrom` from an unlisted account. Every party of the
/// transaction is checked against one version of the list.
///
/// Pool admission calls this on submission, and the leader's builder calls it again before
/// executing each pool transaction.
pub fn validate_transfer_calls(
    allowlist: &dyn TransferAllowlist,
    tx: &TempoPooledTransaction,
) -> Result<(), InvalidPoolTransactionError> {
    let sender = *tx.sender_ref();
    let mut parties = Vec::new();
    for (kind, input) in tx.inner().calls() {
        if let TxKind::Call(target) = kind {
            push_parties(sender, target, input, &mut parties)?;
        }
    }
    if parties.is_empty() || allowlist.allows_all(&parties) {
        Ok(())
    } else {
        Err(transfer_error(
            "transfer sender or recipient is not allowlisted",
        ))
    }
}

/// Push the accounts that a call from `sender` to `target` moves Zone funds between onto
/// `parties`.
///
/// Fails when `input` has a screened selector but does not decode. The precompile would revert
/// such a call, and admitting it unscreened would rely on both decoders agreeing.
fn push_parties(
    sender: Address,
    target: Address,
    input: &[u8],
    parties: &mut Vec<Address>,
) -> Result<(), InvalidPoolTransactionError> {
    let Some(&selector) = input.first_chunk::<4>() else {
        return Ok(());
    };
    let malformed = |_| transfer_error("malformed transfer calldata");
    if target.is_tip20() {
        // A listed spender is required, so `transferFrom(a, b, 0)` cannot probe the list.
        let (spender, from, to) = match selector {
            ITIP20::transferCall::SELECTOR => {
                ITIP20::transferCall::abi_decode(input).map(|call| (None, sender, call.to))
            }
            ITIP20::transferWithMemoCall::SELECTOR => {
                ITIP20::transferWithMemoCall::abi_decode(input).map(|call| (None, sender, call.to))
            }
            ITIP20::transferFromCall::SELECTOR => ITIP20::transferFromCall::abi_decode(input)
                .map(|call| (Some(sender), call.from, call.to)),
            ITIP20::transferFromWithMemoCall::SELECTOR => {
                ITIP20::transferFromWithMemoCall::abi_decode(input)
                    .map(|call| (Some(sender), call.from, call.to))
            }
            _ => return Ok(()),
        }
        .map_err(malformed)?;
        parties.extend(spender);
        // Moving funds into the outbox withdraws, which an unlisted account may still do.
        if from != ZONE_OUTBOX_ADDRESS && to != ZONE_OUTBOX_ADDRESS {
            parties.extend([from, to]);
        }
    } else if target == ZONE_OUTBOX_ADDRESS
        && selector == IZoneOutbox::requestWithdrawalCall::SELECTOR
    {
        let call = IZoneOutbox::requestWithdrawalCall::abi_decode(input).map_err(malformed)?;
        // The fallback is credited if the withdrawal bounces back from L1. Naming oneself is
        // always allowed, so an unlisted account can still withdraw.
        if call.zoneFallbackRecipient != sender {
            parties.extend([sender, call.zoneFallbackRecipient]);
        }
    }
    Ok(())
}

/// Pool error for a transaction that fails the transfer screen. It does not say which account
/// failed the check.
fn transfer_error(reason: &'static str) -> InvalidPoolTransactionError {
    InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(HandlerError::External(
        reason.into(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip1559};
    use alloy_primitives::{Bytes, Signature, U256, address};
    use reth_primitives_traits::Recovered;
    use std::collections::BTreeSet;
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

    fn pooled_transaction(envelope: TempoTxEnvelope, sender: Address) -> TempoPooledTransaction {
        TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender))
    }

    fn aa_transaction(sender: Address, calls: Vec<Call>) -> TempoPooledTransaction {
        let transaction = TempoTransaction {
            calls,
            ..Default::default()
        };
        pooled_transaction(
            transaction
                .into_signed(Signature::test_signature().into())
                .into(),
            sender,
        )
    }

    /// Checks an AA transaction from `sender` against a list holding ALICE and BOB.
    fn admits_calls(sender: Address, calls: Vec<Call>) -> bool {
        let transaction = aa_transaction(sender, calls);
        match validate_transfer_calls(&Listed(BTreeSet::from([ALICE, BOB])), &transaction) {
            Ok(()) => true,
            Err(err) => {
                assert_eq!(
                    err.to_string(),
                    transfer_error("transfer sender or recipient is not allowlisted").to_string()
                );
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
    fn malformed_screened_calls_are_rejected() {
        let truncated = |call: Call| {
            let mut input = call.input.to_vec();
            input.truncate(input.len() - 1);
            Call {
                input: input.into(),
                ..call
            }
        };
        let screened = [
            token_transfer(BOB),
            token_transfer_from(ALICE, BOB),
            request_withdrawal(BOB),
        ];
        for call in screened {
            let transaction = aa_transaction(ALICE, vec![truncated(call)]);
            let err = validate_transfer_calls(&Listed(BTreeSet::from([ALICE, BOB])), &transaction)
                .unwrap_err();
            assert_eq!(
                err.to_string(),
                transfer_error("malformed transfer calldata").to_string()
            );
        }
        // Calls the screen does not inspect are left to the precompile.
        assert!(admits_calls(
            CAROL,
            vec![truncated(call(
                Address::new_tip20(0),
                ITIP20::approveCall {
                    spender: CAROL,
                    amount: U256::ONE
                }
                .abi_encode()
            ))]
        ));
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
