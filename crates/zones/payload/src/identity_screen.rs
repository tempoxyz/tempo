//! Sequencer enforcement of [`ZoneIdentity`](zone_precompiles::ZoneIdentity) org edges.
//!
//! Until a fork hooks the check into execution, the sequencer leaves out of its blocks every
//! transaction whose top-level calls move a TIP-20 along an edge `ZoneIdentity` does not allow, and
//! rejects them at pool admission. Both read the same storage the later in-EVM check will read:
//! pool admission at the latest state, the builder at the state inside the block it is building, so
//! an admin's change applies from the next transaction.
//!
//! Only top-level calls are screened: a router that moves funds in a nested call is trusted until
//! the check runs in execution.

use alloy_primitives::{Address, TxKind, U256};
use alloy_sol_types::SolCall as _;
use evm2::registry::HandlerError;
use reth_transaction_pool::{PoolTransaction as _, error::InvalidPoolTransactionError};
use tempo_contracts::precompiles::ITIP20;
use tempo_primitives::TempoAddressExt as _;
use tempo_transaction_pool::transaction::{TempoPoolTransactionError, TempoPooledTransaction};
use zone_precompiles::zone_identity::{TransferKind, TransferVerdict, check_transfer};

use crate::abi::{IZoneOutbox, ZONE_OUTBOX_ADDRESS};

/// A movement of funds one top-level call makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundsMove {
    /// TIP-20 moved.
    pub token: Address,
    /// Owner the funds leave.
    pub from: Address,
    /// Recipient on the zone, or on Tempo for a withdrawal.
    pub to: Address,
    /// Whether the move stays on the zone or leaves it.
    pub kind: TransferKind,
}

/// Rejects `tx` unless every movement of funds its top-level calls make is allowed by
/// `ZoneIdentity` storage, read through `sload`.
///
/// The outer error is a state read failure; the inner one rejects the transaction.
pub fn screen_identity<E>(
    mut sload: impl FnMut(U256) -> Result<U256, E>,
    tx: &TempoPooledTransaction,
) -> Result<Result<(), InvalidPoolTransactionError>, E> {
    let moves = match funds_moves(tx) {
        Ok(moves) => moves,
        Err(error) => return Ok(Err(error)),
    };
    for FundsMove {
        token,
        from,
        to,
        kind,
    } in moves
    {
        let verdict = check_transfer(&mut sload, token, from, to, kind)?;
        if verdict == TransferVerdict::NotEnforced {
            return Ok(Ok(()));
        }
        if !verdict.is_allowed() {
            return Ok(Err(identity_error(verdict)));
        }
    }
    Ok(Ok(()))
}

/// Decodes the movements of funds `tx`'s top-level calls make.
///
/// Transfers to or from the outbox are part of a withdrawal, which is screened through its
/// `requestWithdrawal` call. A `transferFrom` is screened from the owner, not the spender.
pub fn funds_moves(
    tx: &TempoPooledTransaction,
) -> Result<Vec<FundsMove>, InvalidPoolTransactionError> {
    let sender = *tx.sender_ref();
    let mut moves = Vec::new();
    for (kind, input) in tx.inner().calls() {
        if let TxKind::Call(target) = kind {
            push_moves(sender, target, input, &mut moves)?;
        }
    }
    Ok(moves)
}

fn push_moves(
    sender: Address,
    target: Address,
    input: &[u8],
    moves: &mut Vec<FundsMove>,
) -> Result<(), InvalidPoolTransactionError> {
    let Some(&selector) = input.first_chunk::<4>() else {
        return Ok(());
    };
    let malformed = |_| transfer_error("malformed transfer calldata");
    if target.is_tip20() {
        let (from, to) = match selector {
            ITIP20::transferCall::SELECTOR => {
                ITIP20::transferCall::abi_decode(input).map(|call| (sender, call.to))
            }
            ITIP20::transferWithMemoCall::SELECTOR => {
                ITIP20::transferWithMemoCall::abi_decode(input).map(|call| (sender, call.to))
            }
            ITIP20::transferFromCall::SELECTOR => {
                ITIP20::transferFromCall::abi_decode(input).map(|call| (call.from, call.to))
            }
            ITIP20::transferFromWithMemoCall::SELECTOR => {
                ITIP20::transferFromWithMemoCall::abi_decode(input).map(|call| (call.from, call.to))
            }
            _ => return Ok(()),
        }
        .map_err(malformed)?;
        if from != ZONE_OUTBOX_ADDRESS && to != ZONE_OUTBOX_ADDRESS {
            moves.push(FundsMove {
                token: target,
                from,
                to,
                kind: TransferKind::InZone,
            });
        }
    } else if target == ZONE_OUTBOX_ADDRESS
        && selector == IZoneOutbox::requestWithdrawalCall::SELECTOR
    {
        let call = IZoneOutbox::requestWithdrawalCall::abi_decode(input).map_err(malformed)?;
        moves.push(FundsMove {
            token: call.token,
            from: sender,
            to: call.to,
            kind: TransferKind::Withdrawal,
        });
        // A bounced withdrawal lands on the fallback recipient, so it must be reachable in-zone.
        if call.zoneFallbackRecipient != sender {
            moves.push(FundsMove {
                token: call.token,
                from: sender,
                to: call.zoneFallbackRecipient,
                kind: TransferKind::InZone,
            });
        }
    }
    Ok(())
}

fn identity_error(verdict: TransferVerdict) -> InvalidPoolTransactionError {
    transfer_error(match verdict {
        TransferVerdict::Frozen => "transfer party is frozen",
        TransferVerdict::L1OnlyInZone => "in-zone transfer names an L1-only address",
        TransferVerdict::UnregisteredToken => "token is not registered for org transfers",
        _ => "org policy forbids this transfer",
    })
}

fn transfer_error(reason: &'static str) -> InvalidPoolTransactionError {
    InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(HandlerError::External(
        reason.into(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip1559};
    use alloy_primitives::{Bytes, Signature, address};
    use reth_primitives_traits::Recovered;
    use std::collections::HashMap;
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{Call, TempoTransaction},
    };
    use zone_precompiles::zone_identity::{Member, ZoneIdentity};

    const ALICE: Address = address!("0x00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0x0000000000000000000000000000000000000b0b");
    const CAROL: Address = address!("0x00000000000000000000000000000000000ca201");
    const OFFRAMP: Address = address!("0x000000000000000000000000000000000000f00d");

    fn usd() -> Address {
        Address::new_tip20(1)
    }

    /// Raw `ZoneIdentity` storage: Alice and Bob in org 1, Carol in org 2, the off-ramp L1-only in
    /// org 3. Org 1 may send USD to itself and to org 3; org 2 has no edges.
    fn storage() -> HashMap<U256, U256> {
        let identity = ZoneIdentity::new();
        let mut slots = HashMap::new();
        let shift = identity.enforced.offset().unwrap_or_default() * 8;
        slots.insert(identity.enforced.slot(), U256::ONE << shift);
        let member = |org, l1_only| {
            Member {
                org,
                l1_only,
                frozen: false,
            }
            .encode()
        };
        slots.insert(identity.members[ALICE].slot(), member(1, false));
        slots.insert(identity.members[BOB].slot(), member(1, false));
        slots.insert(identity.members[CAROL].slot(), member(2, false));
        slots.insert(identity.members[OFFRAMP].slot(), member(3, true));
        slots.insert(identity.token_bits[usd()].slot(), U256::ONE);
        slots.insert(identity.edges[1][1].slot(), U256::ONE);
        slots.insert(identity.edges[1][3].slot(), U256::ONE);
        slots
    }

    fn call(to: Address, input: impl Into<Bytes>) -> Call {
        Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: input.into(),
        }
    }

    fn transfer(to: Address) -> Call {
        call(
            usd(),
            ITIP20::transferCall {
                to,
                amount: U256::ONE,
            }
            .abi_encode(),
        )
    }

    fn transfer_from(from: Address, to: Address) -> Call {
        call(
            usd(),
            ITIP20::transferFromCall {
                from,
                to,
                amount: U256::ONE,
            }
            .abi_encode(),
        )
    }

    fn withdraw(to: Address, fallback: Address) -> Call {
        call(
            ZONE_OUTBOX_ADDRESS,
            IZoneOutbox::requestWithdrawalCall {
                token: usd(),
                to,
                amount: 1,
                memo: Default::default(),
                gasLimit: 0,
                zoneFallbackRecipient: fallback,
                data: Bytes::new(),
                revealTo: Bytes::new(),
            }
            .abi_encode(),
        )
    }

    fn tx(sender: Address, calls: Vec<Call>) -> TempoPooledTransaction {
        let transaction = TempoTransaction {
            calls,
            ..Default::default()
        };
        TempoPooledTransaction::new(Recovered::new_unchecked(
            transaction
                .into_signed(Signature::test_signature().into())
                .into(),
            sender,
        ))
    }

    fn admits(slots: &HashMap<U256, U256>, sender: Address, calls: Vec<Call>) -> bool {
        screen_identity(
            |slot| Ok::<_, ()>(slots.get(&slot).copied().unwrap_or_default()),
            &tx(sender, calls),
        )
        .unwrap()
        .is_ok()
    }

    #[test]
    fn transfers_follow_org_edges() {
        let slots = storage();
        assert!(admits(&slots, ALICE, vec![transfer(BOB)]));
        assert!(!admits(&slots, ALICE, vec![transfer(CAROL)]));
        assert!(!admits(&slots, CAROL, vec![transfer(ALICE)]));
        assert!(!admits(&slots, ALICE, vec![transfer(BOB), transfer(CAROL)]));
        // transferFrom is screened from the owner, whoever the spender is.
        assert!(admits(&slots, CAROL, vec![transfer_from(ALICE, BOB)]));
        assert!(!admits(&slots, ALICE, vec![transfer_from(CAROL, BOB)]));
    }

    #[test]
    fn l1_only_addresses_take_withdrawals_not_transfers() {
        let slots = storage();
        assert!(admits(&slots, ALICE, vec![withdraw(OFFRAMP, ALICE)]));
        assert!(!admits(&slots, ALICE, vec![transfer(OFFRAMP)]));
        assert!(!admits(&slots, CAROL, vec![withdraw(OFFRAMP, CAROL)]));
    }

    #[test]
    fn withdrawal_fallback_must_be_reachable() {
        let slots = storage();
        assert!(admits(&slots, ALICE, vec![withdraw(OFFRAMP, BOB)]));
        assert!(!admits(&slots, ALICE, vec![withdraw(OFFRAMP, CAROL)]));
    }

    #[test]
    fn unaffiliated_accounts_can_only_withdraw_to_themselves() {
        let slots = storage();
        let stray = address!("0x0000000000000000000000000000000000005a1e");
        assert!(admits(&slots, stray, vec![withdraw(stray, stray)]));
        assert!(!admits(&slots, stray, vec![withdraw(OFFRAMP, stray)]));
        assert!(!admits(&slots, stray, vec![transfer(ALICE)]));
    }

    #[test]
    fn nothing_is_screened_when_not_enforced() {
        let slots = HashMap::new();
        assert!(admits(&slots, CAROL, vec![transfer(ALICE)]));
    }

    #[test]
    fn legacy_transactions_are_screened() {
        let slots = storage();
        let legacy = |to| {
            let tx = TxEip1559 {
                to: TxKind::Call(usd()),
                input: ITIP20::transferCall {
                    to,
                    amount: U256::ONE,
                }
                .abi_encode()
                .into(),
                ..Default::default()
            };
            let envelope =
                TempoTxEnvelope::Eip1559(Signed::new_unhashed(tx, Signature::test_signature()));
            TempoPooledTransaction::new(Recovered::new_unchecked(envelope, ALICE))
        };
        let screen = |tx: &TempoPooledTransaction| {
            screen_identity(
                |slot| Ok::<_, ()>(slots.get(&slot).copied().unwrap_or_default()),
                tx,
            )
            .unwrap()
            .is_ok()
        };
        assert!(screen(&legacy(BOB)));
        assert!(!screen(&legacy(CAROL)));
    }
}
