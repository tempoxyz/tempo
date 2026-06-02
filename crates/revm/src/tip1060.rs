//! TIP-1060 specific implementations.

use crate::evm::TempoEvm;
use alloy_evm::Database;
use revm::context::JournalTr;
use tempo_precompiles::STORAGE_GAS_TOKENS_ADDRESS as GAS_TOKEN;

/// Applies the storage gas-token refund accrued during a transaction.
///
/// During execution, refunds are accumulated in the transient storage of the configured
/// storage gas-token contract (via TLOAD/TSTORE). At the end of the transaction this flushes
/// those transient credits into the contract's persistent storage: for every key written to
/// transient storage at the gas-token contract, the transient value is added on top of the
/// current persistent value under the same key.
///
pub fn apply_refund<DB: Database, I>(evm: &mut TempoEvm<DB, I>) -> Result<(), DB::Error> {
    let journal = &mut evm.inner.ctx.journaled_state;

    // Snapshot the transient (key, credit) pairs at the gas-token contract written during this
    // tx, so we don't borrow `transient_storage` while mutating the journal below.
    let credits: Vec<_> = journal
        .transient_storage
        .iter()
        .filter(|((address, _), _)| *address == GAS_TOKEN)
        .map(|((_, key), credit)| (*key, *credit))
        .collect();

    for (key, credit) in credits {
        if credit.is_zero() {
            continue;
        }

        // SLOAD the current persistent value and add the transient credit on top.
        let current = journal.sload(GAS_TOKEN, key)?.data;

        // SSTORE the accumulated total back into the contract's persistent storage.
        journal.sstore(GAS_TOKEN, key, current.saturating_add(credit))?;
    }

    Ok(())
}
