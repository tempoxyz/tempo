//! Backend-agnostic TIP-1060 SSTORE storage credits accounting.
//!
//! [`sstore_storage_credits`] implements the storage credits policy that runs
//! after a storage slot is written. It is driven through the [`StorageCreditsBackend`]
//! trait so the exact same logic can be reused from two places:
//!
//! - the opcode-level SSTORE hook in `tempo-revm` (`TempoGasState`), and
//! - [`EvmPrecompileStorageProvider`](crate::storage::evm::EvmPrecompileStorageProvider)
//!   so precompile-driven storage writes honor the same accounting.

use super::{AccountState, CreditMode, TIP1060StorageCredits};
use alloy::primitives::{Address, U256};
use revm::{
    context_interface::cfg::GasParams,
    interpreter::{SStoreResult, StateLoad, instruction_context::GasStateOutcome},
};
use tempo_contracts::precompiles::STORAGE_CREDITS_ADDRESS;

/// Storage and gas operations required by [`sstore_storage_credits`].
///
/// All storage operations target the storage credits contract; the concrete
/// address is supplied by the implementor so this trait stays free of revm
/// host details. The associated [`Error`](StorageCreditsBackend::Error) lets each
/// backend surface failures in its own error type (`InstructionResult` for the
/// opcode path, `TempoPrecompileError` for the precompile path).
pub trait StorageCreditsBackend {
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

    /// Loads (warms) the storage credits contract account.
    fn load_storage_credit_account(&mut self) -> Result<(), Self::Error>;

    /// SLOAD a slot of the storage credits contract, optionally skipping the cold load.
    fn load_credits(
        &mut self,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, Self::Error>;

    /// SSTORE a slot of the storage credits contract (cold load is never skipped here).
    fn store_credits(
        &mut self,
        key: U256,
        value: U256,
    ) -> Result<StateLoad<SStoreResult>, Self::Error>;

    /// Increments the pending refund count held in the storage credits contract's
    /// transient storage at `key` (TLOAD the current count, add one, TSTORE).
    fn credit_tstore_increment(&mut self, key: U256);
}

/// Applies the TIP-1060 storage credits policy for a single SSTORE.
///
/// Called after the storage write has been journaled, with `values` describing
/// the original/present/new slot values for `owner`. Returns a [`GasStateOutcome`]
/// telling the caller whether to skip the normal dynamic/state-gas accounting
/// (`skip_gas`) and/or the refund accounting (`skip_refund`).
pub fn sstore_storage_credits<B: StorageCreditsBackend>(
    backend: &mut B,
    owner: Address,
    caller_state_load: &StateLoad<SStoreResult>,
) -> Result<GasStateOutcome, B::Error> {
    let (values, is_cold) = (&caller_state_load.data, caller_state_load.is_cold);

    // TIP-1060 removes the legacy storage-clearing gas refunds.
    let mut outcome = GasStateOutcome {
        skip_gas: false,
        skip_refund: true,
    };

    // if new and present value are equal or if both present value are not zero, skip storage credits accounting.
    if values.is_new_eq_present() || (!values.is_present_zero() && !values.is_new_zero()) {
        return Ok(outcome);
    }

    // Storage-credit precompile state is used for protocol bookkeeping. Because of that,
    // always skips TIP-1000 + TIP-1060 self-accounting and charge only update gas.
    if owner == STORAGE_CREDITS_ADDRESS {
        if is_cold {
            backend.charge_gas(backend.gas_params().cold_storage_cost())?;
        }
        if values.new_values_changes_present() && values.is_original_eq_present() {
            backend.charge_gas(backend.gas_params().sstore_reset_without_cold_load_cost())?;
        }

        return Ok(GasStateOutcome {
            skip_gas: true,
            skip_refund: true,
        });
    }

    // Load token_state for the contract
    let warm_storage_read_cost = backend.gas_params().warm_storage_read_cost();
    backend.charge_gas(warm_storage_read_cost)?;

    backend.load_storage_credit_account()?;

    let account_slot = TIP1060StorageCredits::slot(owner);
    let additional_cold_cost = backend.gas_params().cold_storage_additional_cost();
    let skip_cold = backend.remaining_gas() < additional_cold_cost;
    let storage_credit_state_load = backend.load_credits(account_slot, skip_cold)?;
    if storage_credit_state_load.is_cold {
        backend.charge_gas(additional_cold_cost)?;
    }

    let mut storage_credits =
        AccountState::from_word(storage_credit_state_load.data).map_err(|_| B::fatal_external())?;

    let mut was_changed = false;
    if values.is_new_zero() {
        // x→0: slot clear (present non-zero set to zero).
        storage_credits.balance = storage_credits.balance.saturating_add(1);
        was_changed = true;
    } else {
        // 0→x: slot create (charged EIP-8037 state gas today).
        match storage_credits.mode {
            CreditMode::Direct => {
                // Only if there is a credit available, skip gas
                if storage_credits.balance > 0 {
                    // Consume the storage credit and charge 20k for the SSTORE + cold access cost.
                    if caller_state_load.is_cold {
                        backend.charge_gas(backend.gas_params().cold_storage_cost())?;
                    }
                    backend.charge_gas(20_000)?;
                    storage_credits.balance -= 1;
                    was_changed = true;
                    outcome.skip_gas = true;
                }
                // Otherwise, leave gas enabled so revm charges full creation costs.
            }
            CreditMode::Preserve => {
                // Do nothing, so revm takes care of gas accounting after this hook.
            }
            CreditMode::Refund => {
                backend.credit_tstore_increment(account_slot);
            }
        }
    }

    if was_changed {
        // cold load is already checked above when we loaded the storage credits account.
        let result = backend
            .store_credits(account_slot, storage_credits.into_word())?
            .data;

        // Only when change happens charge additional gas.
        // Creation of credit slot is compensated by creation of the contract creation.
        // And creation and deletion of credit is compensated by EIP-1060, so no additional gas is charged.
        if result.new_values_changes_present() && result.is_original_eq_present() {
            backend.charge_gas(backend.gas_params().sstore_reset_without_cold_load_cost())?;
        };
    }

    Ok(outcome)
}
