//! Backend-agnostic TIP-1060 SSTORE gas-token accounting.
//!
//! [`sstore_gas_state`] implements the storage gas-token policy that runs
//! after a storage slot is written. It is driven through the [`GasStateBackend`]
//! trait so the exact same logic can be reused from two places:
//!
//! - the opcode-level SSTORE hook in `tempo-revm` (`TempoGasState`), and
//! - [`EvmPrecompileStorageProvider`](crate::storage::evm::EvmPrecompileStorageProvider)
//!   so precompile-driven storage writes honor the same accounting.

use super::{AccountState, StorageGasMode, TIP1060StorageGasToken};
use alloy::primitives::{Address, U256};
use revm::{
    context_interface::cfg::GasParams,
    interpreter::{SStoreResult, StateLoad, instruction_context::GasStateOutcome},
};

/// Storage and gas operations required by [`sstore_gas_state`].
///
/// All storage operations target the storage gas-token contract; the concrete
/// address is supplied by the implementor so this trait stays free of revm
/// host details. The associated [`Error`](GasStateBackend::Error) lets each
/// backend surface failures in its own error type (`InstructionResult` for the
/// opcode path, `TempoPrecompileError` for the precompile path).
pub trait GasStateBackend {
    /// Error type returned by the backend.
    type Error;

    /// Constructs the backend's out-of-gas error.
    fn out_of_gas() -> Self::Error;

    /// Constructs the backend's fatal/external error (e.g. malformed state word).
    fn fatal_external() -> Self::Error;

    /// Gas parameters for the active spec.
    fn gas_params(&self) -> &GasParams;

    /// Remaining regular gas.
    fn remaining_gas(&self) -> u64;

    /// Charges `cost` regular gas, returning [`out_of_gas`](Self::out_of_gas) if insufficient.
    fn charge_gas(&mut self, cost: u64) -> Result<(), Self::Error>;

    /// Loads (warms) the storage gas-token contract account.
    fn load_gas_token_account(&mut self) -> Result<(), Self::Error>;

    /// SLOAD a slot of the gas-token contract, optionally skipping the cold load.
    fn gas_token_sload(
        &mut self,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, Self::Error>;

    /// SSTORE a slot of the gas-token contract (cold load is never skipped here).
    fn gas_token_sstore(&mut self, key: U256, value: U256) -> Result<(), Self::Error>;

    /// Increments the pending refund count held in the gas-token contract's
    /// transient storage at `key` (TLOAD the current count, add one, TSTORE).
    fn token_tstore_increment(&mut self, key: U256);
}

/// Applies the TIP-1060 storage gas-token policy for a single SSTORE.
///
/// Called after the storage write has been journaled, with `values` describing
/// the original/present/new slot values for `owner`. Returns a [`GasStateOutcome`]
/// telling the caller whether to skip the normal dynamic/state-gas accounting
/// (`skip_gas`) and/or the refund accounting (`skip_refund`).
pub fn sstore_gas_state<B: GasStateBackend>(
    backend: &mut B,
    owner: Address,
    values: &SStoreResult,
) -> Result<GasStateOutcome, B::Error> {
    let mut outcome = GasStateOutcome::default();

    if values.is_new_eq_present() {
        return Ok(outcome);
    }

    // 0→x: slot create (charged EIP-8037 state gas today).
    let is_create = values.is_original_eq_present() && values.is_original_zero();
    // x→0: slot clear (present non-zero set to zero).
    let is_clear = values.is_new_zero() && !values.is_present_zero();

    // x→y: return from instruction, nothing to be done.
    if !(is_create || is_clear) {
        return Ok(outcome);
    }

    // Load token_state for the contract
    let warm_storage_read_cost = backend.gas_params().warm_storage_read_cost();
    backend.charge_gas(warm_storage_read_cost)?;

    backend.load_gas_token_account()?;

    let account_slot = TIP1060StorageGasToken::slot(owner);
    let additional_cold_cost = backend.gas_params().cold_storage_additional_cost();
    let skip_cold = backend.remaining_gas() < additional_cold_cost;
    let storage = backend.gas_token_sload(account_slot, skip_cold)?;
    if storage.is_cold {
        backend.charge_gas(additional_cold_cost)?;
    }

    let mut gas_token_state =
        AccountState::from_word(storage.data).map_err(|_| B::fatal_external())?;

    let mut was_changed = false;
    if is_clear {
        gas_token_state.balance = gas_token_state.balance.saturating_add(1);
        was_changed = true;
    } else {
        match gas_token_state.mode {
            StorageGasMode::DirectTokens => {
                if gas_token_state.balance > 0 {
                    // Consume the gas token credit and charge 20k for the SSTORE.
                    backend.charge_gas(20_000)?;
                    gas_token_state.balance -= 1;
                    was_changed = true;

                    // only if there is token available, skip refund and gas
                    outcome.skip_refund = true;
                    outcome.skip_gas = true;
                }
                // If no token is available, leave both regular and state gas enabled so
                // revm charges the full zero-to-nonzero creation cost after this hook.
            }
            StorageGasMode::PreserveTokens => {
                // Do nothing, so revm takes care of gas accounting after this hook.
            }
            StorageGasMode::RefundTokens => {
                // Skip refund as it will happen at the end of the transaction.
                outcome.skip_refund = true;
                backend.token_tstore_increment(account_slot);
            }
        }
    }

    if was_changed {
        backend.gas_token_sstore(account_slot, gas_token_state.into_word())?;
    }

    Ok(outcome)
}
