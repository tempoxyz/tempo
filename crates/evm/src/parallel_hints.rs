//! Static dependency hints for parallel block execution.
//!
//! Hints only order work in the parallel executor: missing or wrong ones never change a block's
//! result, only cost re-executions or idle workers.

use crate::transaction::{TempoEvmTx, TempoTxEnv};
use alloy_primitives::{Address, TxKind, map::HashMap};
use std::borrow::Borrow;
use tempo_contracts::precompiles::PaymentSlots;
use tempo_primitives::TempoAddressExt;

/// Derives each transaction's dependencies on earlier transactions of the block from what the
/// transaction itself says: its sender, its fee payer, the holders of the TIP-20 payments it makes
/// and the contracts other than TIP-20 tokens it calls.
///
/// Each such address is a key the transaction is expected to write, and a transaction depends on
/// the last earlier transaction that wrote each of its keys. Contracts other than TIP-20 tokens
/// are keyed whole, since every call reads and writes their shared state, such as a vault's
/// totals or a channel reserve's balance.
#[derive(Debug, Default)]
pub(crate) struct StaticHints {
    /// The last transaction that wrote each key.
    writers: HashMap<Address, u32>,
    /// The index of the next transaction.
    next: u32,
}

impl StaticHints {
    /// Returns the dependencies of the block's next transaction, `tx`, and records its keys.
    pub(crate) fn next(&mut self, tx: &TempoTxEnv) -> Vec<u32> {
        let index = self.next;
        self.next += 1;
        let evm_tx: &TempoEvmTx = tx.borrow();
        if evm_tx.is_system_tx() {
            return Vec::new();
        }
        let sender = evm_tx.signer();
        let mut dependencies = Vec::new();
        let mut write = |key: Address| {
            if let Some(writer) = self.writers.insert(key, index)
                && writer != index
            {
                dependencies.push(writer);
            }
        };
        write(sender);
        if let Ok(fee_payer) = tx.fee_payer()
            && fee_payer != sender
        {
            write(fee_payer);
        }
        for (kind, input) in evm_tx.calls() {
            let TxKind::Call(to) = kind else { continue };
            if !to.is_tip20() {
                write(to);
            } else if let Some(payment) = PaymentSlots::classify(input) {
                payment.addresses().iter().copied().for_each(&mut write);
            }
        }
        dependencies.sort_unstable();
        dependencies.dedup();
        dependencies
    }
}
