//! Collection of protocol evidence from canonical L2 blocks.

mod events;
mod state;

use std::collections::{BTreeMap, BTreeSet};

use alloy_consensus::{Transaction, TxReceipt, transaction::TxHashRef};
use alloy_eips::BlockNumHash;
use alloy_primitives::{Address, Log, keccak256};
use alloy_sol_types::{SolCall, SolEvent};
use tempo_zone_contracts::{IZoneInbox, TEMPO_STATE_ADDRESS, TempoState, ZONE_INBOX_ADDRESS};

use events::EventCollector;

pub(crate) use events::{
    DepositResult, L1Anchor, L2BridgeAction, TokenTransfer, WithdrawalBounceBackStatus,
    WithdrawalOrigin,
};
pub(crate) use state::{AccountingStateError, read_accounting_state, read_zone_genesis};

/// Authenticated anchor, transfers, and bridge actions from one L2 block.
#[derive(Debug)]
pub(crate) struct L2BlockEvidence {
    anchor: Option<L1Anchor>,
    transfers: Vec<TokenTransfer>,
    actions: Vec<L2BridgeAction>,
}

impl L2BlockEvidence {
    /// Return the full-import anchor, or `None` for a checkpoint-only block with deferred work.
    pub(crate) const fn l1_anchor(&self) -> Option<&L1Anchor> {
        self.anchor.as_ref()
    }

    /// Return accounts named by canonical TIP-20 transfers, grouped by token.
    pub(crate) fn accounting_candidates(&self) -> BTreeMap<Address, BTreeSet<Address>> {
        let mut candidates = BTreeMap::<Address, BTreeSet<Address>>::new();
        for transfer in &self.transfers {
            let accounts = candidates.entry(transfer.token).or_default();
            if !transfer.from.is_zero() {
                accounts.insert(transfer.from);
            }
            if !transfer.to.is_zero() {
                accounts.insert(transfer.to);
            }
        }
        candidates
    }

    /// Return canonical TIP-20 transfers in block-log order.
    pub(crate) fn token_transfers(&self) -> impl Iterator<Item = TokenTransfer> + '_ {
        self.transfers.iter().copied()
    }

    /// Return authenticated bridge actions in block-log order.
    pub(crate) fn bridge_actions(&self) -> impl Iterator<Item = &L2BridgeAction> {
        self.actions.iter()
    }
}

/// Collect recognized events from one canonical L2 block.
pub(crate) fn collect_l2_block_evidence<T, R>(
    transactions: &[T],
    receipts: &[R],
    block: BlockNumHash,
) -> eyre::Result<L2BlockEvidence>
where
    T: TxHashRef + Transaction,
    R: TxReceipt<Log = Log>,
{
    eyre::ensure!(
        transactions.len() == receipts.len(),
        "block {} has {} transactions but {} receipts",
        block.number,
        transactions.len(),
        receipts.len()
    );

    // Only an explicit checkpoint-only system call may omit TempoAdvanced. Canonical Zone
    // execution authenticates its header chain; here we require the exact no-accounting shape.
    if transactions.first().is_some_and(|tx| {
        tx.to() == Some(ZONE_INBOX_ADDRESS)
            && tx
                .input()
                .starts_with(&IZoneInbox::advanceTempoHeadersCall::SELECTOR)
    }) {
        eyre::ensure!(
            transactions.len() == 1,
            "checkpoint-only block must contain one transaction"
        );
        let call =
            IZoneInbox::advanceTempoHeadersCall::abi_decode_validate(transactions[0].input())?;
        eyre::ensure!(
            !call.headers.is_empty()
                && call.headers.len()
                    <= zone_primitives::constants::MAX_TEMPO_HEADERS_PER_ZONE_BLOCK,
            "invalid checkpoint header count"
        );
        let receipt = &receipts[0];
        eyre::ensure!(receipt.status(), "checkpoint-only transaction failed");
        let [log] = receipt.logs() else {
            eyre::bail!("checkpoint-only block must emit only TempoBlockFinalized");
        };
        eyre::ensure!(
            log.address == TEMPO_STATE_ADDRESS
                && log.topics().first() == Some(&TempoState::TempoBlockFinalized::SIGNATURE_HASH),
            "checkpoint-only block must emit TempoBlockFinalized"
        );
        let event = crate::decode_event::<TempoState::TempoBlockFinalized>(
            log,
            "TempoBlockFinalized",
            block.number,
        )?;
        eyre::ensure!(
            event.blockHash == keccak256(call.headers.last().expect("nonempty headers")),
            "checkpoint event does not match the imported header"
        );
        return Ok(L2BlockEvidence {
            anchor: None,
            transfers: Vec::new(),
            actions: Vec::new(),
        });
    }

    let mut collector = EventCollector::default();
    for (transaction, receipt) in transactions.iter().zip(receipts) {
        collector.extract_receipt(transaction, receipt, block.number)?;
    }

    collector.finish(block.number)
}
