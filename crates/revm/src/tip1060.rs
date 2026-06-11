//! TIP-1060 specific implementations.

use crate::{
    TempoInvalidTransaction,
    evm::{TempoContext, TempoEvm},
};
use alloy_evm::Database;
use alloy_primitives::{Address, IntoLogData, Log, U256};
use revm::{
    context::{Host as _, JournalTr, result::EVMError},
    context_interface::cfg::GasParams,
    interpreter::{
        Gas, InstructionContext, InstructionResult, SStoreResult, StateLoad,
        gas::GasTracker,
        instruction_context::{GasStateOutcome, GasStateTr},
        interpreter::EthInterpreter,
    },
};
use tempo_contracts::precompiles::TIP1060StorageCreditsEvent;
use tempo_precompiles::{
    STORAGE_CREDITS_ADDRESS,
    storage::FromWord,
    tip1060_storage_credits::{
        CreditMode, STORAGE_CREDIT_VALUE, StorageCreditsBackend, sstore_storage_credits,
    },
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
    // This is safe cause refunds are applied in post-execution.
    let Some(slots) = journal.transient_storage.remove(&STORAGE_CREDITS_ADDRESS) else {
        return Ok(());
    };

    let mut refunds = 0;
    for (key, word) in slots {
        let pending = word.as_limbs()[0];
        if pending == 0 {
            continue;
        }

        // SLOAD the current persistent balance and settle pending refund-eligible creations against it.
        let old_word = journal.sload(STORAGE_CREDITS_ADDRESS, key)?.data;
        let mut balance =
            u64::from_word(old_word).map_err(|err| EVMError::Custom(err.to_string()))?;
        let settled = pending.min(balance);

        if settled == 0 {
            continue;
        }

        // SSTORE the post-settlement balance back into persistent storage.
        balance -= settled;
        refunds += settled;

        let new_word = U256::from(balance);
        debug_assert_ne!(new_word, old_word);

        journal.sstore(STORAGE_CREDITS_ADDRESS, key, new_word)?;
    }

    // Refund storage credit value (230k) per settled credit.
    gas.erase_cost(refunds.saturating_mul(STORAGE_CREDIT_VALUE));

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
    fn out_of_gas() -> Self::Error {
        InstructionResult::OutOfGas
    }

    #[inline]
    fn fatal_external() -> Self::Error {
        InstructionResult::FatalExternalError
    }

    #[inline]
    fn gas_params(&self) -> &GasParams {
        self.context.gas_params()
    }

    #[inline]
    fn gas_tracker(&mut self) -> &mut GasTracker {
        self.gas_tracker
    }

    #[inline]
    fn load_credits(
        &mut self,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, Self::Error> {
        self.context
            .load_account_info_skip_cold_load(STORAGE_CREDITS_ADDRESS, false, false)?;
        Ok(self
            .context
            .sload_skip_cold_load(STORAGE_CREDITS_ADDRESS, key, skip_cold_load)?)
    }

    #[inline]
    fn store_credits(
        &mut self,
        key: U256,
        value: U256,
    ) -> Result<StateLoad<SStoreResult>, Self::Error> {
        Ok(self
            .context
            .sstore_skip_cold_load(STORAGE_CREDITS_ADDRESS, key, value, false)?)
    }

    #[inline]
    fn load_transient_state(&mut self, key: U256) -> U256 {
        self.context.tload(STORAGE_CREDITS_ADDRESS, key)
    }

    #[inline]
    fn store_transient_state(&mut self, key: U256, value: U256) {
        self.context.tstore(STORAGE_CREDITS_ADDRESS, key, value);
    }

    #[inline]
    fn emit_mode_updated(
        &mut self,
        account: Address,
        new_mode: CreditMode,
    ) -> Result<(), Self::Error> {
        self.context.log(Log {
            address: STORAGE_CREDITS_ADDRESS,
            data: TIP1060StorageCreditsEvent::mode_updated(account, new_mode.into())
                .into_log_data(),
        });
        Ok(())
    }
}

/// Tempo SSTORE gas-state policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct TIP1060StorageCreditsState;

impl<DB> GasStateTr<EthInterpreter, TempoContext<DB>> for TIP1060StorageCreditsState
where
    DB: Database,
{
    fn sstore_gas_state(
        context: &mut InstructionContext<'_, TempoContext<DB>, EthInterpreter>,
        owner: Address,
        values: &StateLoad<SStoreResult>,
    ) -> Result<GasStateOutcome, InstructionResult> {
        let InstructionContext { interpreter, host } = context;
        sstore_storage_credits(
            &mut StorageCreditsContext {
                context: host,
                gas_tracker: interpreter.gas.tracker_mut(),
            },
            owner,
            values,
        )
    }
}
