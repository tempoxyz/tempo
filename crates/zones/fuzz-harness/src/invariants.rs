//! The properties every zone case must keep.
//!
//! * **Proves**: the batch proves. Only a user transaction the zone refuses to include may stop
//!   it, and the harness drops those before checking.
//! * **Ledger**: every pathUSD balance an invariant reads equals its starting balance plus the
//!   pathUSD `Transfer` logs into it, minus those out of it, after every block.
//! * **TIP-1160 gate**: before T15, or while the portal has not opted in, or while pathUSD is
//!   paused on Tempo, every user transfer reverts.
//! * **TIP-1160 transfers**: from T15, with the opt-in and pathUSD not paused, a transfer between
//!   signers that the sender can pay succeeds.
//! * **TIP-1179 resolution**: from T15, with transfers open, a transfer to a virtual address of a
//!   registered master succeeds and credits the master; one to a virtual address of an
//!   unregistered master reverts.
//! * **TIP-1179 forwarding**: a virtual address never holds a balance.

use std::{collections::BTreeMap, fmt};

use alloy_consensus::TxReceipt as _;
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolEvent as _;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::{ITIP20, PATH_USD_ADDRESS};
use tempo_primitives::{MasterId, TempoAddressExt as _};
use zone_spf::{BatchOutput, Error as SpfError};

use crate::{
    BlockRecord,
    input::{Call, Fork, ZoneCase},
    witness::{Fixture, SentCall, TX_GAS},
};

/// A broken invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The invariant's name.
    pub invariant: &'static str,
    /// What broke.
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.invariant, self.detail)
    }
}

/// Checks every invariant against one run.
pub fn check(
    case: &ZoneCase,
    fixture: &Fixture,
    result: &Result<BatchOutput, SpfError>,
    blocks: &[BlockRecord],
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut violate = |invariant, detail: String| violations.push(Violation { invariant, detail });

    match result {
        Ok(_) => {}
        // A refused transaction the harness ran out of retries for.
        Err(SpfError::TransactionExecution { .. }) => {}
        Err(error) => violate("proves", format!("the batch did not prove: {error:?}")),
    }

    let open = case.fork == Fork::T15 && case.l1.transfers_enabled && !case.l1.path_usd_paused;
    let tracked = fixture.tracked_accounts();
    let mut ledger: BTreeMap<Address, U256> = tracked
        .iter()
        .map(|account| (*account, fixture.starting_balance(*account)))
        .collect();
    let mut actual = ledger.clone();
    let max_fee = U256::from(TX_GAS) * U256::from(TEMPO_T0_BASE_FEE);

    for (block_index, block) in blocks.iter().enumerate() {
        let sent = fixture
            .sent()
            .get(block_index)
            .map_or(&[][..], Vec::as_slice);
        for (receipt_index, receipt) in block.receipts.iter().enumerate() {
            // Receipts are the advanceTempo system transaction, the user transactions and, in the
            // last block, finalizeWithdrawalBatch.
            let call = receipt_index
                .checked_sub(1)
                .and_then(|index| sent.get(index));
            if let Some(call) = call {
                check_call(
                    case,
                    fixture,
                    call,
                    receipt.status(),
                    &ledger,
                    open,
                    max_fee,
                    &mut violate,
                );
            }
            for log in &receipt.logs {
                if log.address != PATH_USD_ADDRESS {
                    continue;
                }
                let Ok(transfer) = ITIP20::Transfer::decode_log_data(&log.data) else {
                    continue;
                };
                if let Some(balance) = ledger.get_mut(&transfer.from) {
                    *balance = balance.wrapping_sub(transfer.amount);
                }
                if let Some(balance) = ledger.get_mut(&transfer.to) {
                    *balance = balance.wrapping_add(transfer.amount);
                }
            }
        }

        for (account, balance) in &block.balances {
            actual.insert(*account, *balance);
        }
        for account in &tracked {
            if ledger[account] != actual[account] {
                violate(
                    "ledger",
                    format!(
                        "block {block_index}: {account} holds {} but its Transfer logs give {}",
                        actual[account], ledger[account]
                    ),
                );
            }
            if account.is_virtual() && !actual[account].is_zero() {
                violate(
                    "tip1179-forwarding",
                    format!(
                        "block {block_index}: virtual address {account} holds {}",
                        actual[account]
                    ),
                );
            }
        }
        // Keep checking later blocks against what the state says, not a diverged ledger.
        ledger.clone_from(&actual);
    }

    violations
}

#[expect(clippy::too_many_arguments)]
fn check_call(
    case: &ZoneCase,
    fixture: &Fixture,
    sent: &SentCall,
    succeeded: bool,
    ledger: &BTreeMap<Address, U256>,
    open: bool,
    max_fee: U256,
    violate: &mut impl FnMut(&'static str, String),
) {
    let (amount, is_transfer_from) = match &sent.call {
        Call::Transfer { amount, .. } => (U256::from(amount.0), false),
        Call::TransferFrom { amount, .. } => (U256::from(amount.0), true),
        Call::Approve { .. } | Call::Raw { .. } => return,
    };
    let recipient = sent.recipient.expect("transfers have a recipient");
    let at = format!("block {} call {}", sent.position.0, sent.position.1);

    if !open {
        if succeeded {
            violate(
                "tip1160-gate",
                format!(
                    "{at}: a transfer succeeded on {:?} with transfers_enabled={} paused={}",
                    case.fork, case.l1.transfers_enabled, case.l1.path_usd_paused
                ),
            );
        }
        return;
    }
    // A transferFrom also needs an allowance, which the harness does not model.
    if is_transfer_from {
        return;
    }
    let affordable = ledger
        .get(&sent.sender)
        .is_some_and(|balance| amount.saturating_add(max_fee) <= *balance);

    if recipient.is_virtual() {
        let (id, _) = recipient.decode_virtual().expect("virtual address");
        let master = fixture.masters().get(&MasterId::from(id));
        match master {
            Some(_) if affordable && !succeeded => violate(
                "tip1179-resolution",
                format!(
                    "{at}: a transfer of {amount} to {recipient}, a registered master's virtual address, reverted"
                ),
            ),
            None if succeeded => violate(
                "tip1179-resolution",
                format!(
                    "{at}: a transfer to {recipient}, whose master is not registered, succeeded"
                ),
            ),
            _ => {}
        }
        return;
    }
    if fixture.signers().contains(&recipient) && affordable && !succeeded {
        violate(
            "tip1160-transfers",
            format!(
                "{at}: an affordable transfer of {amount} from {} to {recipient} reverted",
                sent.sender
            ),
        );
    }
}
