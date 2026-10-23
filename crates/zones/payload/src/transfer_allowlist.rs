//! Leader-side allowlist for Zone TIP-20 transfers.
//!
//! The allowlist is sequencer-local policy that consensus does not replicate, so the leader
//! enforces it while building blocks; followers and the prover accept any block. After executing
//! a pool transaction, the builder leaves it out of the block if any of its TIP-20 `Transfer`
//! events moves funds between accounts that are not both allowed, or if it requests a withdrawal
//! whose Zone fallback recipient is another account and the two are not both allowed. Checking
//! executed events rather than calldata covers AA batches and transfers made by predeploys.

use alloy_primitives::{Address, B256};
use alloy_sol_types::SolEvent;
use reth_evm::block::TxResult;
use reth_transaction_pool::error::InvalidPoolTransactionError;
use std::fmt;
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::TempoInvalidTransaction;
use tempo_primitives::TempoAddressExt as _;
use tempo_transaction_pool::transaction::TempoPoolTransactionError;
use zone_precompiles::ZoneOutbox;

use crate::abi::{IZoneOutbox, ZONE_OUTBOX_ADDRESS};

/// Zone accounts that may send and receive TIP-20 transfers in blocks this node builds.
pub trait TransferAllowlist: fmt::Debug + Send + Sync + 'static {
    /// Whether `address` may send or receive Zone transfers. An allowlist that has never been
    /// written allows every address.
    fn allows(&self, address: Address) -> bool;

    /// Whether a TIP-20 transfer from `from` to `to` may be included in a block whose fee
    /// recipient is `fee_recipient`.
    ///
    /// Transfers to the fee recipient settle fees, and transfers to or from the zero address or
    /// the outbox mint, burn, or withdraw, so they are exempt: an account removed from the list
    /// can still pay fees and withdraw.
    fn allows_transfer(&self, fee_recipient: Address, from: Address, to: Address) -> bool {
        let exempt = |address: Address| address.is_zero() || address == ZONE_OUTBOX_ADDRESS;
        exempt(from) || exempt(to) || to == fee_recipient || (self.allows(from) && self.allows(to))
    }

    /// Whether `sender` may request a withdrawal whose L1 bounce-back credits
    /// `fallback_recipient` on the Zone.
    ///
    /// Naming oneself is always allowed, so an unlisted account can still withdraw.
    fn allows_withdrawal_fallback(&self, sender: Address, fallback_recipient: Address) -> bool {
        fallback_recipient == sender || (self.allows(sender) && self.allows(fallback_recipient))
    }
}

/// Pool error for a transaction that moves Zone funds to or from an account the allowlist does
/// not allow. It does not say which account, so it does not reveal list membership.
pub fn unlisted_transfer_error() -> InvalidPoolTransactionError {
    InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(
        TempoInvalidTransaction::EthInvalidTransaction(
            "transfer sender or recipient is not allowlisted".into(),
        ),
    ))
}

/// Whether every TIP-20 transfer and withdrawal fallback recipient in the executed transaction
/// is allowed in a block whose fee recipient is `beneficiary`.
pub(crate) fn allows_executed(
    allowlist: &dyn TransferAllowlist,
    beneficiary: Address,
    result: &impl TxResult,
) -> bool {
    let result = result.result();
    result.result.logs().iter().all(|log| {
        // An event that matches but fails to decode is treated as a violation.
        if log.address.is_tip20() && log.topics().first() == Some(&ITIP20::Transfer::SIGNATURE_HASH)
        {
            let Ok(ITIP20::Transfer { from, to, .. }) =
                ITIP20::Transfer::decode_log_data(&log.data)
            else {
                return false;
            };
            return allowlist.allows_transfer(beneficiary, from, to);
        }
        if log.address != ZONE_OUTBOX_ADDRESS
            || log.topics().first() != Some(&IZoneOutbox::WithdrawalRequested::SIGNATURE_HASH)
        {
            return true;
        }
        let Ok(withdrawal) = IZoneOutbox::WithdrawalRequested::decode_log_data(&log.data) else {
            return false;
        };
        // Deposit bounce-backs carry no sender or fallback recipient.
        if withdrawal.sender.is_zero() {
            return true;
        }
        // `requestWithdrawal` writes the recipient in the same transaction. A missing slot reads
        // as the zero address, which is never allowed, so the transaction is left out.
        let slot = ZoneOutbox::new().fallback_recipient_slot(withdrawal.fallbackNonce);
        let fallback_recipient = result
            .state
            .get(&ZONE_OUTBOX_ADDRESS)
            .and_then(|outbox| outbox.storage.get(&slot))
            .map_or(Address::ZERO, |value| {
                Address::from_word(B256::from(value.present_value))
            });
        allowlist.allows_withdrawal_fallback(withdrawal.sender, fallback_recipient)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, IntoLogData, Log, LogData, U256, address};
    use reth_revm::revm::{
        context::result::{ExecutionResult, HaltReason, ResultAndState},
        state::{Account, EvmState, EvmStorageSlot, TransactionId},
    };
    use std::collections::BTreeSet;

    const ALICE: Address = address!("0x00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0x0000000000000000000000000000000000000b0b");
    const CAROL: Address = address!("0x00000000000000000000000000000000000ca201");
    const SEQUENCER: Address = address!("0x0000000000000000000000000000000000005e01");

    /// Allows only the listed addresses.
    #[derive(Debug)]
    struct Listed(BTreeSet<Address>);

    impl TransferAllowlist for Listed {
        fn allows(&self, address: Address) -> bool {
            self.0.contains(&address)
        }
    }

    struct Executed(ResultAndState<HaltReason>);

    impl TxResult for Executed {
        type HaltReason = HaltReason;

        fn result(&self) -> &ResultAndState<HaltReason> {
            &self.0
        }

        fn into_result(self) -> ResultAndState<HaltReason> {
            self.0
        }
    }

    fn alice_and_bob() -> Listed {
        Listed(BTreeSet::from([ALICE, BOB]))
    }

    fn transfer(from: Address, to: Address) -> Log {
        Log {
            address: Address::new_tip20(0),
            data: ITIP20::Transfer {
                from,
                to,
                amount: U256::from(1),
            }
            .into_log_data(),
        }
    }

    fn withdrawal(sender: Address, fallback_nonce: u64) -> Log {
        Log {
            address: ZONE_OUTBOX_ADDRESS,
            data: IZoneOutbox::WithdrawalRequested {
                withdrawalIndex: 0,
                sender,
                token: Address::new_tip20(0),
                to: sender,
                amount: 1,
                fee: 0,
                memo: B256::ZERO,
                gasLimit: 0,
                fallbackNonce: fallback_nonce,
                data: Bytes::new(),
                revealTo: Bytes::new(),
            }
            .into_log_data(),
        }
    }

    /// Outbox state after `requestWithdrawal` stored `recipient` under `fallback_nonce`.
    fn fallback_recipient(fallback_nonce: u64, recipient: Address) -> EvmState {
        let mut outbox = Account::default();
        outbox.storage.insert(
            ZoneOutbox::new().fallback_recipient_slot(fallback_nonce),
            EvmStorageSlot::new_changed(
                U256::ZERO,
                U256::from_be_slice(recipient.as_slice()),
                TransactionId::ZERO,
            ),
        );
        EvmState::from_iter([(ZONE_OUTBOX_ADDRESS, outbox)])
    }

    fn allows(logs: Vec<Log>, state: EvmState) -> bool {
        let result = Executed(ResultAndState::new(
            ExecutionResult::Revert {
                gas: Default::default(),
                logs,
                output: Bytes::new(),
            },
            state,
        ));
        allows_executed(&alice_and_bob(), SEQUENCER, &result)
    }

    #[test]
    fn transfers_need_both_parties_listed() {
        assert!(allows(vec![transfer(ALICE, BOB)], EvmState::default()));
        assert!(!allows(vec![transfer(ALICE, CAROL)], EvmState::default()));
        assert!(!allows(vec![transfer(CAROL, ALICE)], EvmState::default()));
        // One unlisted transfer leaves out the whole transaction, e.g. an AA batch.
        assert!(!allows(
            vec![transfer(ALICE, BOB), transfer(BOB, CAROL)],
            EvmState::default()
        ));
    }

    #[test]
    fn fees_burns_and_withdrawals_are_exempt() {
        for log in [
            transfer(CAROL, SEQUENCER),
            transfer(CAROL, ZONE_OUTBOX_ADDRESS),
            transfer(ZONE_OUTBOX_ADDRESS, Address::ZERO),
            transfer(Address::ZERO, CAROL),
        ] {
            assert!(allows(vec![log], EvmState::default()));
        }
    }

    #[test]
    fn transfer_events_from_other_contracts_are_ignored() {
        let mut log = transfer(ALICE, CAROL);
        log.address = CAROL;
        assert!(allows(vec![log], EvmState::default()));
    }

    #[test]
    fn malformed_transfer_events_are_left_out() {
        let mut log = transfer(ALICE, BOB);
        log.data = LogData::new_unchecked(vec![ITIP20::Transfer::SIGNATURE_HASH], Bytes::new());
        assert!(!allows(vec![log], EvmState::default()));
    }

    #[test]
    fn withdrawal_fallback_recipients_need_both_parties_listed_unless_self() {
        assert!(allows(
            vec![withdrawal(ALICE, 1)],
            fallback_recipient(1, BOB)
        ));
        assert!(!allows(
            vec![withdrawal(ALICE, 1)],
            fallback_recipient(1, CAROL)
        ));
        assert!(!allows(
            vec![withdrawal(CAROL, 1)],
            fallback_recipient(1, ALICE)
        ));
        // An unlisted account can still withdraw with itself as the fallback recipient.
        assert!(allows(
            vec![withdrawal(CAROL, 1)],
            fallback_recipient(1, CAROL)
        ));
        // The slot is read for this withdrawal's nonce, not another one.
        assert!(!allows(
            vec![withdrawal(ALICE, 2)],
            fallback_recipient(1, BOB)
        ));
        // Deposit bounce-backs have no sender.
        assert!(allows(
            vec![withdrawal(Address::ZERO, 0)],
            EvmState::default()
        ));
    }
}
