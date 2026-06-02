//! TIP-1060 specific implementations.

use crate::evm::{TempoContext, TempoEvm};
use alloy_evm::Database;
use alloy_primitives::{Address, U256};
use revm::{
    context::{Host as _, JournalTr},
    context_interface::cfg::GasParams,
    interpreter::{
        InstructionContext, InstructionResult, SStoreResult, StateLoad,
        instruction_context::{GasStateOutcome, GasStateTr},
        interpreter::EthInterpreter,
    },
};
use tempo_precompiles::{
    STORAGE_GAS_TOKENS_ADDRESS as GAS_TOKEN,
    tip1060_storage_gas_token::{GasStateBackend, sstore_gas_state},
};

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

/// Opcode-level [`GasStateBackend`] adapter over an [`InstructionContext`].
///
/// Bridges the revm host/interpreter to the backend-agnostic
/// [`sstore_gas_state`] so the SSTORE opcode runs the same TIP-1060
/// gas-token policy as precompile-driven storage writes.
struct InterpreterGasState<'a, 'b, DB: Database> {
    context: &'a mut InstructionContext<'b, TempoContext<DB>, EthInterpreter>,
}

impl<DB: Database> GasStateBackend for InterpreterGasState<'_, '_, DB> {
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
        self.context.host.gas_params()
    }

    #[inline]
    fn remaining_gas(&self) -> u64 {
        self.context.interpreter.gas.remaining()
    }

    #[inline]
    fn charge_gas(&mut self, cost: u64) -> Result<(), Self::Error> {
        if self.context.interpreter.gas.record_regular_cost(cost) {
            Ok(())
        } else {
            Err(InstructionResult::OutOfGas)
        }
    }

    #[inline]
    fn load_gas_token_account(&mut self) -> Result<(), Self::Error> {
        self.context
            .host
            .load_account_info_skip_cold_load(GAS_TOKEN, false, false)?;
        Ok(())
    }

    #[inline]
    fn gas_token_sload(
        &mut self,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, Self::Error> {
        Ok(self
            .context
            .host
            .sload_skip_cold_load(GAS_TOKEN, key, skip_cold_load)?)
    }

    #[inline]
    fn gas_token_sstore(&mut self, key: U256, value: U256) -> Result<(), Self::Error> {
        self.context
            .host
            .sstore_skip_cold_load(GAS_TOKEN, key, value, false)?;
        Ok(())
    }

    #[inline]
    fn token_tstore_increment(&mut self, key: U256) {
        let pending = self.context.host.tload(GAS_TOKEN, key);
        self.context
            .host
            .tstore(GAS_TOKEN, key, pending.saturating_add(U256::from(1)));
    }
}

/// Tempo SSTORE gas-state policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct TIP1060StorageGasTokenState;

impl<DB> GasStateTr<EthInterpreter, TempoContext<DB>> for TIP1060StorageGasTokenState
where
    DB: Database,
{
    fn sstore_gas_state(
        context: &mut InstructionContext<'_, TempoContext<DB>, EthInterpreter>,
        owner: Address,
        values: &SStoreResult,
    ) -> Result<GasStateOutcome, InstructionResult> {
        sstore_gas_state(&mut InterpreterGasState { context }, owner, values)
    }
}
