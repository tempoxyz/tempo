//! TIP-1060 specific implementations.

use crate::{
    TempoInvalidTransaction,
    evm::{TempoContext, TempoEvm},
};
use alloy_evm::Database;
use alloy_primitives::{Address, U256};
use revm::{
    context::{Host as _, JournalTr, result::EVMError},
    context_interface::cfg::{GasId, GasParams},
    interpreter::{
        Gas, InstructionContext, InstructionResult, SStoreResult, StateLoad,
        gas::GasTracker,
        instruction_context::{GasStateOutcome, GasStateTr},
        interpreter::EthInterpreter,
    },
};
use tempo_precompiles::{
    STORAGE_CREDITS_ADDRESS,
    tip1060_storage_credits::{AccountState, StorageCreditsBackend, sstore_storage_credits},
};

/// Applies the storage credits refund accrued during a transaction.
///
/// During execution, refunds are accumulated in the transient storage of the configured
/// storage credits contract (via TLOAD/TSTORE). At the end of the transaction this flushes
/// those transient credits into the contract's persistent storage: for every key written to
/// transient storage at the storage credits contract, the transient value is added on top of the
/// current persistent value under the same key.
///
/// Returns number of credits applied.
pub fn apply_refund<DB: Database, I>(
    evm: &mut TempoEvm<DB, I>,
    gas: &mut Gas,
) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
    let journal = &mut evm.inner.ctx.journaled_state;

    // Snapshot the transient (key, sstores) pairs at the storage credits contract written during this
    // tx, so we don't borrow `transient_storage` while mutating the journal below.
    let sstores: Vec<_> = journal
        .transient_storage
        .get(&STORAGE_CREDITS_ADDRESS)
        .map(|slots| slots.iter().map(|(key, credit)| (*key, *credit)).collect())
        .unwrap_or_default();

    let mut refunds = 0;
    for (key, sstores_num) in sstores {
        if sstores_num.is_zero() {
            continue;
        }

        // SLOAD the current persistent value and add the transient credit on top.
        let old_word = journal.sload(STORAGE_CREDITS_ADDRESS, key)?.data;
        let mut state =
            AccountState::from_word(old_word).map_err(|err| EVMError::Custom(err.to_string()))?;

        let pending = sstores_num.as_limbs()[0];
        let settled = pending.min(state.balance);

        if settled == 0 {
            continue;
        }

        // SSTORE the accumulated total back into the contract's persistent storage.
        state.balance -= settled;
        refunds += settled;

        let new_word = state.into_word();
        debug_assert_ne!(new_word, old_word);

        journal.sstore(STORAGE_CREDITS_ADDRESS, key, new_word)?;
    }

    // Refund 230k per storage credit.
    let storage_credit_value = evm
        .inner
        .ctx
        .cfg
        .gas_params
        .get(GasId::sstore_set_state_gas());
    gas.erase_cost(refunds.saturating_mul(storage_credit_value));

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
    fn load_storage_credit_account(&mut self) -> Result<(), Self::Error> {
        self.context
            .load_account_info_skip_cold_load(STORAGE_CREDITS_ADDRESS, false, false)?;
        Ok(())
    }

    #[inline]
    fn load_credits(
        &mut self,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, Self::Error> {
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
    fn credit_tstore_increment(&mut self, key: U256) {
        let pending = self.context.tload(STORAGE_CREDITS_ADDRESS, key);
        self.context.tstore(
            STORAGE_CREDITS_ADDRESS,
            key,
            pending.saturating_add(U256::from(1)),
        );
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
