//! Backend-agnostic TIP-1060 SSTORE storage credits accounting.
//!
//! [`sstore_storage_credits`] implements the storage credits policy that runs
//! after a storage slot is written. It is driven through the [`StorageCreditsBackend`]
//! trait so the exact same logic can be reused from two places:
//!
//! - the opcode-level SSTORE hook in `tempo-revm` (`TempoGasState`), and
//! - [`EvmPrecompileStorageProvider`](crate::storage::evm::EvmPrecompileStorageProvider)
//!   so precompile-driven storage writes honor the same accounting.

use super::{
    ACCOUNT_SPACE, CreditMode, DEFERRED_SLOT_SPACE, DEFERRED_STATUS_SPACE, DeferredClear,
    StorageCredits, TransientState,
};
use crate::{ACCOUNT_KEYCHAIN_ADDRESS, TIP_FEE_MANAGER_ADDRESS, storage::FromWord};
use alloy::primitives::{Address, U256};
use revm::{
    context_interface::cfg::GasParams,
    interpreter::{InstructionResult, SStoreResult, StateLoad, gas::GasTracker},
};
use tempo_chainspec::constants::gas::STORAGE_CREDIT_VALUE;
use tempo_contracts::precompiles::STORAGE_CREDITS_ADDRESS;
use tempo_primitives::TempoAddressExt;

/// Error mapping required by storage credit accounting.
pub trait StorageCreditsErr: Sized {
    fn out_of_gas() -> Self;
    fn fatal_external() -> Self;
}

impl StorageCreditsErr for InstructionResult {
    fn out_of_gas() -> Self {
        Self::OutOfGas
    }

    fn fatal_external() -> Self {
        Self::FatalExternalError
    }
}

/// Minimal journal/gas operations required by storage credit accounting.
pub trait StorageCreditsBackend {
    type Error: StorageCreditsErr;

    /// Gas parameters for the active spec.
    fn gas_params(&self) -> &GasParams;

    /// Gas tracker for the active execution context.
    fn gas_tracker(&mut self) -> &mut GasTracker;

    /// Charges `cost` regular gas, returning [`out_of_gas`](StorageCreditsErr::out_of_gas) if insufficient.
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
/// When provided, `key` identifies slots post-tx fee bookkeeping may restore with accounting off:
/// - watched `x→0`: mark a pending clear instead of minting a credit during execution.
/// - watched `0→x` with pending clear: net churn instead of charging creation/spending credits.
///
/// Pending clears finalize after post-tx fees and mint only if the slot still ends zero.
pub fn sstore_storage_credits<B: StorageCreditsBackend>(
    backend: &mut B,
    owner: Address,
    key: Option<U256>,
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

    let account_slot = StorageCredits::slot(ACCOUNT_SPACE, owner);
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
        // x→0: storage deletion doesn't mint on watched slots.
        if let Some(key) = key
            && (owner.is_tip20()
                || owner == ACCOUNT_KEYCHAIN_ADDRESS
                || owner == TIP_FEE_MANAGER_ADDRESS)
        {
            let deferred_status_slot = StorageCredits::slot(DEFERRED_STATUS_SPACE, owner);
            let deferred_slot = StorageCredits::slot(DEFERRED_SLOT_SPACE, owner);

            let status: DeferredClear = backend
                .tload(STORAGE_CREDITS_ADDRESS, deferred_status_slot)
                .try_into()
                .map_err(|_| B::Error::fatal_external())?;

            let is_watched = status != DeferredClear::None
                && backend.tload(STORAGE_CREDITS_ADDRESS, deferred_slot) == key;

            let new_status = match (is_watched, values.is_new_zero(), status) {
                // x→0 on a watched slot: defer the clear action.
                (true, true, _) => Some(DeferredClear::Pending),
                // x→0→x churn on a watched slot: cancel the pending clear.
                (true, false, DeferredClear::Pending) => Some(DeferredClear::Watched),
                // Otherwise, proceed normally.
                _ => None,
            };

            if let Some(status_to_write) = new_status {
                backend.tstore(
                    STORAGE_CREDITS_ADDRESS,
                    deferred_status_slot,
                    status_to_write.into(),
                );
                return Ok(());
            }
        }

        // x→0: storage deletion always mints a new credit on regular slots.
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
                // Use one to cover the 245k creditable portion.
                credit -= 1;
                was_changed = true;

                // An unlimited budget is never decremented.
                if transient_state.budget != u64::MAX {
                    transient_state.budget -= 1;
                    store_credit_state(backend, account_slot, transient_state)?;
                }
            }
            CreditMode::Direct | CreditMode::Preserve => {
                // Direct without spendable credits, or Preserve, pays the creditable portion as gas.
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

#[cfg(test)]
mod tests {
    use super::{ACCOUNT_SPACE, CreditMode, DeferredClear, StorageCredits};
    use crate::{
        PATH_USD_ADDRESS, STORAGE_CREDITS_ADDRESS,
        error::TempoPrecompileError,
        storage::{
            Handler, PrecompileStorageProvider, StorageCtx, hashmap::HashMapStorageProvider,
        },
        storage_credits::DEFERRED_STATUS_SPACE,
    };
    use alloy::primitives::{Address, U256};
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn watched_clear_is_not_persistent_or_direct_spendable_before_finalization() -> eyre::Result<()>
    {
        let owner = PATH_USD_ADDRESS;
        let watched_slot = U256::from(0x22);
        let fresh_slot = U256::from(0x33);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.sstore(owner, watched_slot, U256::ONE)?;
        storage.set_spec(TempoHardfork::T7);

        StorageCtx::enter(&mut storage, || {
            StorageCredits::new().watch_deferred_clear_slot(owner, watched_slot)
        })?;
        storage.sstore(owner, watched_slot, U256::ZERO)?;

        StorageCtx::enter(&mut storage, || {
            let mut credits = StorageCredits::new();
            assert_eq!(credits.balance_of(owner)?, 0);
            assert_eq!(
                credits
                    .handler::<DeferredClear>(DEFERRED_STATUS_SPACE, owner)
                    .t_read()?,
                DeferredClear::Pending
            );

            let mut state = credits.credit_state_of(owner)?;
            state.mode = CreditMode::Direct;
            state.budget = u64::MAX;
            credits.write_credit_state_of(owner, state)
        })?;

        storage.sstore(owner, fresh_slot, U256::ONE)?;

        StorageCtx::enter(&mut storage, || {
            let credits = StorageCredits::new();
            assert_eq!(credits.balance_of(owner)?, 0);
            assert_eq!(credits.credit_state_of(owner)?.budget, u64::MAX);
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn watched_clear_recreation_nets_without_consuming_credit_or_pending_refund() -> eyre::Result<()>
    {
        let owner = PATH_USD_ADDRESS;
        let watched_slot = U256::from(0x55);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.sstore(owner, watched_slot, U256::ONE)?;
        storage.sstore(
            STORAGE_CREDITS_ADDRESS,
            StorageCredits::slot(ACCOUNT_SPACE, owner),
            U256::ONE,
        )?;
        storage.set_spec(TempoHardfork::T7);

        StorageCtx::enter(&mut storage, || {
            StorageCredits::new().watch_deferred_clear_slot(owner, watched_slot)
        })?;
        storage.sstore(owner, watched_slot, U256::ZERO)?;
        storage.sstore(owner, watched_slot, U256::ONE)?;

        StorageCtx::enter(&mut storage, || {
            let credits = StorageCredits::new();
            assert_eq!(credits.balance_of(owner)?, 1);
            assert_eq!(credits.credit_state_of(owner)?.pending_refunds, 0);
            assert_eq!(
                credits
                    .handler::<DeferredClear>(DEFERRED_STATUS_SPACE, owner)
                    .t_read()?,
                DeferredClear::Watched
            );
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn unregistered_zero_key_clear_mints_persistent_credit() -> eyre::Result<()> {
        let owner = Address::repeat_byte(0x66);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.sstore(owner, U256::ZERO, U256::ONE)?;
        storage.set_spec(TempoHardfork::T7);

        storage.sstore(owner, U256::ZERO, U256::ZERO)?;

        StorageCtx::enter(&mut storage, || {
            assert_eq!(StorageCredits::new().balance_of(owner)?, 1);
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }
}
