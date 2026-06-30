//! TIP-1060 specific implementations.

use crate::{
    TempoInvalidTransaction,
    evm::{TempoContext, TempoEvm},
};
use alloy_evm::Database;
use alloy_primitives::{Address, U256};
use revm::{
    context::{Host as _, JournalTr, result::EVMError},
    context_interface::cfg::GasParams,
    interpreter::{
        Gas, InstructionContext, InstructionResult, SStoreResult, StateLoad,
        gas::GasTracker,
        instructions::host::{sstore_default_gas_accounting, sstore_with_gas_accounting},
        interpreter::EthInterpreter,
    },
};
use tempo_chainspec::constants::gas::STORAGE_CREDIT_VALUE;
use tempo_precompiles::{
    STORAGE_CREDITS_ADDRESS,
    storage::{FromWord, StorageAction},
    storage_credits::{StorageCreditsBackend, TransientState, sstore_storage_credits},
};

/// Applies storage-credit settlement at the end of a transaction.
///
/// During execution, each account's transaction-local mode and pending `Refund` creations are
/// stored in one transient word at the same key as its persistent balance. At end-of-transaction,
/// entries with non-zero pending creations are settled against the same account's persistent
/// storage credit balance, consuming up to `min(pending, balance)` credits and refunding one fixed
/// storage credit value per credit. Mode-only transient entries are ignored.
pub fn apply_refund<DB: Database, I>(
    evm: &mut TempoEvm<DB, I>,
    gas: &mut Gas,
) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
    if !evm.cfg.spec.is_t7() {
        return Ok(());
    }

    let journal = &mut evm.inner.ctx.journaled_state;

    // Take the tx-local storage-credit slots so we can settle them while mutating the journal.
    let Some(slots) = journal.transient_storage.remove(&STORAGE_CREDITS_ADDRESS) else {
        return Ok(());
    };

    let mut refunds = 0i64;
    for (key, word) in slots {
        let transient_state =
            TransientState::try_from(word).map_err(|err| EVMError::Custom(err.to_string()))?;
        let pending = transient_state.pending_refunds;
        if pending == 0 {
            continue;
        }

        // SLOAD the current persistent balance and settle pending refund-eligible creations against it.
        let old_word = journal.sload(STORAGE_CREDITS_ADDRESS, key)?.data;
        evm.actions
            .record(StorageAction::Sload(STORAGE_CREDITS_ADDRESS, key, old_word));
        let mut balance =
            u64::from_word(old_word).map_err(|err| EVMError::Custom(err.to_string()))?;
        let settled = pending.min(balance);

        if settled == 0 {
            continue;
        }

        // SSTORE the post-settlement balance back into persistent storage.
        balance -= settled;
        refunds += settled as i64;

        let new_word = U256::from(balance);
        debug_assert_ne!(new_word, old_word);

        journal.sstore(STORAGE_CREDITS_ADDRESS, key, new_word)?;
        evm.actions.record(StorageAction::Sstore(
            STORAGE_CREDITS_ADDRESS,
            key,
            new_word,
        ));
    }

    // Refund storage credit value per settled credit.
    gas.record_refund(refunds.saturating_mul(STORAGE_CREDIT_VALUE as i64));

    Ok(())
}

/// Opcode-level [`StorageCreditsBackend`] adapter over an [`InstructionContext`].
///
/// Bridges the revm host/interpreter to the backend-agnostic [`sstore_storage_credits`] so the
/// SSTORE opcode runs the same TIP-1060 storage credits policy as precompile storage writes.
struct StorageCreditsContext<'a, DB: Database> {
    context: &'a mut TempoContext<DB>,
    gas_tracker: &'a mut GasTracker,
}

impl<DB: Database> StorageCreditsBackend for StorageCreditsContext<'_, DB> {
    type Error = InstructionResult;

    #[inline]
    fn gas_params(&self) -> &GasParams {
        self.context.gas_params()
    }

    #[inline]
    fn gas_tracker(&mut self) -> &mut GasTracker {
        self.gas_tracker
    }

    #[inline]
    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, Self::Error> {
        self.context
            .load_account_info_skip_cold_load(address, false, false)?;
        Ok(self
            .context
            .sload_skip_cold_load(address, key, skip_cold_load)?)
    }

    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, Self::Error> {
        Ok(self
            .context
            .sstore_skip_cold_load(address, key, value, skip_cold_load)?)
    }

    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> U256 {
        self.context.tload(address, key)
    }

    #[inline]
    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        self.context.tstore(address, key, value);
    }
}

/// Tempo SSTORE instruction with TIP-1060 storage-credit accounting.
pub(crate) fn sstore<DB: Database>(
    context: InstructionContext<'_, TempoContext<DB>, EthInterpreter>,
) -> Result<(), InstructionResult> {
    sstore_with_gas_accounting(context, |context, owner, state_load| {
        {
            let InstructionContext { interpreter, host } = context;
            sstore_storage_credits(
                &mut StorageCreditsContext {
                    context: host,
                    gas_tracker: interpreter.gas.tracker_mut(),
                },
                owner,
                None,
                state_load,
            )?;
        }

        // Storage-credit hook only handles TIP-1060 bookkeeping + state gas. Keep default
        // gas/refunds for cold, update, and residual costs. T7 gas table ensures no double-charge.
        sstore_default_gas_accounting(context, owner, state_load)
    })
}
