//! Backend-agnostic TIP-1060 SSTORE storage credits accounting.
//!
//! [`sstore_storage_credits`] implements the storage credits policy that runs
//! after a storage slot is written. It is driven through the [`StorageCreditsBackend`]
//! trait so the exact same logic can be reused from two places:
//!
//! - the opcode-level SSTORE hook in `tempo-revm` (`TempoGasState`), and
//! - [`EvmPrecompileStorageProvider`](crate::storage::evm::EvmPrecompileStorageProvider)
//!   so precompile-driven storage writes honor the same accounting.

use super::{CreditMode, TIP1060StorageCredits, TransientState};
use crate::storage::FromWord;
use alloy::primitives::{Address, IntoLogData, LogData, U256};
use revm::{
    context_interface::cfg::GasParams,
    interpreter::{InstructionResult, SStoreResult, StateLoad, gas::GasTracker},
};
use tempo_chainspec::constants::gas::STORAGE_CREDIT_VALUE;
use tempo_contracts::precompiles::{STORAGE_CREDITS_ADDRESS, TIP1060StorageCreditsEvent};

/// Error mapping required by storage credit accounting.
pub trait StorageCreditsError: Sized {
    fn out_of_gas() -> Self;
    fn fatal_external() -> Self;
}

impl StorageCreditsError for InstructionResult {
    fn out_of_gas() -> Self {
        Self::OutOfGas
    }

    fn fatal_external() -> Self {
        Self::FatalExternalError
    }
}

/// Minimal journal/gas operations required by storage credit accounting.
pub trait StorageCreditsBackend {
    type Error: StorageCreditsError;

    /// Gas parameters for the active spec.
    fn gas_params(&self) -> &GasParams;

    /// Gas tracker for the active execution context.
    fn gas_tracker(&mut self) -> &mut GasTracker;

    /// Charges `cost` regular gas, returning [`out_of_gas`](StorageCreditsError::out_of_gas) if insufficient.
    #[inline]
    fn charge_gas(&mut self, cost: u64) -> Result<(), Self::Error> {
        self.gas_tracker()
            .record_regular_cost(cost)
            .then_some(())
            .ok_or_else(Self::Error::out_of_gas)
    }

    /// SLOAD `address[key]`, optionally skipping the cold load.
    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, Self::Error>;

    /// SSTORE `address[key]`.
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, Self::Error>;

    /// TLOAD `address[key]`.
    fn tload(&mut self, address: Address, key: U256) -> U256;

    /// TSTORE `address[key] = value`.
    fn tstore(&mut self, address: Address, key: U256, value: U256);

    /// Emits `event` from `address`.
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), Self::Error>;
}

#[inline]
fn emit_mode_updated<B: StorageCreditsBackend>(
    backend: &mut B,
    account: Address,
    new_mode: CreditMode,
) -> Result<(), B::Error> {
    let event = TIP1060StorageCreditsEvent::mode_updated(account, new_mode.into());
    backend.emit_event(STORAGE_CREDITS_ADDRESS, event.into_log_data())
}

#[inline]
fn store_credit_state<B: StorageCreditsBackend>(
    backend: &mut B,
    key: U256,
    state: TransientState,
) -> Result<(), B::Error> {
    backend.tstore(STORAGE_CREDITS_ADDRESS, key, state.into());
    Ok(())
}

/// Applies TIP-1060 storage credits after a single SSTORE has been journaled.
///
/// Returns whether to skip normal dynamic/state gas and/or refund accounting.
pub fn sstore_storage_credits<B: StorageCreditsBackend>(
    backend: &mut B,
    owner: Address,
    caller_state_load: &StateLoad<SStoreResult>,
) -> Result<(), B::Error> {
    let values = &caller_state_load.data;

    // Only account for storage credits when the slot crosses the zero boundary (x→0 or 0→x).
    // If both values are zero or non-zero, slot occupancy is unchanged, so skip credits accounting.
    if values.is_present_zero() == values.is_new_zero() {
        return Ok(());
    }

    // Storage-credit precompile state is used for protocol bookkeeping. Because of that,
    // always skips TIP-1000 + TIP-1060 self-accounting and charge only update gas.
    if owner == STORAGE_CREDITS_ADDRESS {
        return Ok(());
    }

    // Load the persistent storage credit balance for the storage-owning account.
    let warm_storage_read_cost = backend.gas_params().warm_storage_read_cost();
    backend.charge_gas(warm_storage_read_cost)?;

    let account_slot = TIP1060StorageCredits::slot(owner);
    let additional_cold_cost = backend.gas_params().cold_storage_additional_cost();
    let skip_cold = backend.gas_tracker().remaining() < additional_cold_cost;
    let storage_credit_state_load =
        backend.sload(STORAGE_CREDITS_ADDRESS, account_slot, skip_cold)?;
    if storage_credit_state_load.is_cold {
        backend.charge_gas(additional_cold_cost)?;
    }

    let mut credit =
        u64::from_word(storage_credit_state_load.data).map_err(|_| B::Error::fatal_external())?;

    let mut was_changed = false;
    if values.is_new_zero() {
        // x→0: storage deletion always mints a new credit.
        credit = credit.saturating_add(1);
        was_changed = true;
    } else {
        // 0→x: storage creation.
        // This hook manages the 245k creditable gas, independent of the original value.
        // revm's SSTORE function adds the 5k residual for clean writes (`original == present == 0`).
        let mut transient_state: TransientState = backend
            .tload(STORAGE_CREDITS_ADDRESS, account_slot)
            .try_into()
            .map_err(|_| B::Error::fatal_external())?;

        match transient_state.mode {
            CreditMode::Direct if credit > 0 && transient_state.budget > 0 => {
                // Consume one credit to cover the 245k creditable portion.
                credit -= 1;
                was_changed = true;

                // An unlimited budget is never decremented.
                if transient_state.budget != u64::MAX {
                    transient_state.budget -= 1;
                    if transient_state.budget == 0 {
                        // When budget is exhausted, switch to `Preserve` mode.
                        transient_state.mode = CreditMode::Preserve;
                        emit_mode_updated(backend, owner, CreditMode::Preserve)?;
                    }
                    store_credit_state(backend, account_slot, transient_state)?;
                }
            }
            CreditMode::Direct => {
                // If no credit available, charge the 245k creditable portion as gas.
                if transient_state.budget == 0 {
                    // When budget is exhausted, switch to `Preserve` mode.
                    transient_state.mode = CreditMode::Preserve;
                    store_credit_state(backend, account_slot, transient_state)?;
                    emit_mode_updated(backend, owner, CreditMode::Preserve)?;
                }
                backend.charge_gas(STORAGE_CREDIT_VALUE)?;
            }
            CreditMode::Preserve => {
                // Always charge the 245k creditable portion as gas without consuming credits.
                backend.charge_gas(STORAGE_CREDIT_VALUE)?;
            }
            CreditMode::Refund => {
                // Charge the 245k creditable portion upfront and record a pending refund-eligible
                // creation, settled at end-of-transaction.
                backend.charge_gas(STORAGE_CREDIT_VALUE)?;
                transient_state.pending_refunds = transient_state.pending_refunds.saturating_add(1);
                store_credit_state(backend, account_slot, transient_state)?;
            }
        }
    }

    if was_changed {
        // Cold load is already checked above when we loaded the storage credits account.
        let result = backend
            .sstore(
                STORAGE_CREDITS_ADDRESS,
                account_slot,
                U256::from(credit),
                false,
            )?
            .data;

        // Only when change happens charge additional gas.
        if result.new_values_changes_present() && result.is_original_eq_present() {
            backend.charge_gas(backend.gas_params().sstore_reset_without_cold_load_cost())?;
        };
    }

    Ok(())
}
