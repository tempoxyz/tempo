//! Backend-agnostic TIP-1060 SSTORE storage credits accounting.
//!
//! [`sstore_storage_credits`] implements the storage credits policy that runs
//! after a storage slot is written. It is driven through the [`StorageCreditsBackend`]
//! trait so the exact same logic can be reused from two places:
//!
//! - the opcode-level SSTORE hook in `tempo-revm` (`TempoGasState`), and
//! - [`EvmPrecompileStorageProvider`](crate::storage::evm::EvmPrecompileStorageProvider)
//!   so precompile-driven storage writes honor the same accounting.

use super::{CreditMode, StorageCredits, TransientState};
use crate::storage::{FromWord, SstoreTransitionFlags};
use alloy::primitives::{Address, U256};
use revm::{
    context_interface::cfg::GasParams,
    interpreter::{InstructionResult, SStoreResult, StateLoad, gas::GasTracker},
};
use tempo_chainspec::constants::gas::STORAGE_CREDIT_VALUE;
use tempo_contracts::precompiles::STORAGE_CREDITS_ADDRESS;

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
    ) -> Result<SstoreTransitionFlags, Self::Error>;

    /// TLOAD `address[key]`.
    fn tload(&mut self, address: Address, key: U256) -> U256;

    /// TSTORE `address[key] = value`.
    fn tstore(&mut self, address: Address, key: U256, value: U256);

    /// Returns true when `owner[key]` is a tx-local slot whose clear must not mint a credit.
    fn is_non_creditable_slot(&mut self, _owner: Address, _key: U256) -> bool {
        false
    }

    /// Returns whether x→0 storage clears should mint a persistent storage credit.
    #[inline]
    fn tip1060_storage_credit_minting_enabled(&self) -> bool {
        true
    }
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
/// When provided, `key` lets the hook skip minting a credit for the single transaction-local slot
/// whose clear must not mint a credit for the storage-owning account.
pub fn sstore_storage_credits<B: StorageCreditsBackend>(
    backend: &mut B,
    owner: Address,
    key: Option<U256>,
    caller_state_load: &StateLoad<SStoreResult>,
) -> Result<(), B::Error> {
    let sstore_flags = SstoreTransitionFlags::from(caller_state_load);

    // Only account for storage credits when the slot crosses the zero boundary (x→0 or 0→x).
    // If both values are zero or non-zero, slot occupancy is unchanged, so skip credits accounting.
    if !sstore_flags.crosses_zero_boundary() {
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

    let account_slot = StorageCredits::slot(owner);
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
    if sstore_flags.is_nonzero_to_zero() {
        // x→0: storage deletion doesn't mint on protocol fee/keychain bookkeeping slots.
        if let Some(key) = key
            && backend.is_non_creditable_slot(owner, key)
        {
            return Ok(());
        }

        // x→0: storage deletion mints a new credit on regular slots.
        if backend.tip1060_storage_credit_minting_enabled() {
            credit = credit.saturating_add(1);
            was_changed = true;
        }
    } else if sstore_flags.is_zero_to_nonzero() {
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
        let flags = backend.sstore(
            STORAGE_CREDITS_ADDRESS,
            account_slot,
            U256::from(credit),
            false,
        )?;

        // Only when change happens charge additional gas.
        if flags.charges_clean_update() {
            backend.charge_gas(backend.gas_params().sstore_reset_without_cold_load_cost())?;
        };
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CreditMode, StorageCredits};
    use crate::{
        PATH_USD_ADDRESS, STORAGE_CREDITS_ADDRESS,
        error::TempoPrecompileError,
        storage::{PrecompileStorageProvider, StorageCtx, hashmap::HashMapStorageProvider},
        storage_credits::NonCreditableSlots,
        tip20::TIP20Token,
    };
    use alloy::primitives::{Address, U256};
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn non_creditable_slot_is_not_persistent_or_direct_spendable_credit() -> eyre::Result<()> {
        let owner = PATH_USD_ADDRESS;
        let fee_payer = Address::repeat_byte(0x22);
        let no_credit_slot = TIP20Token::from_address_unchecked(owner).balances[fee_payer].slot();
        let fresh_slot = U256::from(0x33);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.sstore(owner, no_credit_slot, U256::ONE)?;
        storage.set_spec(TempoHardfork::T7);

        let mut non_creditable_slots = NonCreditableSlots::empty();
        non_creditable_slots.initialize(fee_payer, owner, None);
        storage.set_non_creditable_slots(non_creditable_slots);
        storage.sstore(owner, no_credit_slot, U256::ZERO)?;

        StorageCtx::enter(&mut storage, || {
            let mut credits = StorageCredits::new();
            assert_eq!(credits.balance_of(owner)?, 0);

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
    fn non_creditable_slot_recreation_is_accounted_as_normal_creation() -> eyre::Result<()> {
        let owner = PATH_USD_ADDRESS;
        let fee_payer = Address::repeat_byte(0x55);
        let no_credit_slot = TIP20Token::from_address_unchecked(owner).balances[fee_payer].slot();
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.sstore(owner, no_credit_slot, U256::ONE)?;
        storage.sstore(
            STORAGE_CREDITS_ADDRESS,
            StorageCredits::slot(owner),
            U256::ONE,
        )?;
        storage.set_spec(TempoHardfork::T7);

        let mut non_creditable_slots = NonCreditableSlots::empty();
        non_creditable_slots.initialize(fee_payer, owner, None);
        storage.set_non_creditable_slots(non_creditable_slots);
        storage.sstore(owner, no_credit_slot, U256::ZERO)?;
        storage.sstore(owner, no_credit_slot, U256::ONE)?;

        StorageCtx::enter(&mut storage, || {
            let credits = StorageCredits::new();
            let state = credits.credit_state_of(owner)?;
            assert_eq!(credits.balance_of(owner)?, 1);
            assert_eq!(state.pending_refunds, 1);
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
