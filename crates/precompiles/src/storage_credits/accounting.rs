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
use crate::storage::FromWord;
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
/// Returns whether to skip normal dynamic/state gas and/or refund accounting.
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
    if values.is_new_zero() {
        let is_pending_clear = key.is_some_and(|key| {
            backend.tload(
                STORAGE_CREDITS_ADDRESS,
                StorageCredits::pending_slot(owner, key),
            ) == U256::ONE
        });

        if is_pending_clear {
            let mut transient_state: TransientState = backend
                .tload(STORAGE_CREDITS_ADDRESS, account_slot)
                .try_into()
                .map_err(|_| B::Error::fatal_external())?;
            // Fee bookkeeping watches one restorable slot per owner.
            transient_state.pending_credits = 1;
            store_credit_state(backend, account_slot, transient_state)?;
        } else {
            // x→0: storage deletion always mints a new credit.
            credit = credit.saturating_add(1);
            was_changed = true;
        }
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
    use super::*;
    use revm::interpreter::gas::GasTracker;
    use std::collections::HashMap;

    struct TestBackend {
        gas_params: GasParams,
        gas_tracker: GasTracker,
        storage: HashMap<(Address, U256), U256>,
        transient: HashMap<(Address, U256), U256>,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                gas_params: GasParams::default(),
                gas_tracker: GasTracker::new(10_000_000, 10_000_000, 0),
                storage: HashMap::new(),
                transient: HashMap::new(),
            }
        }

        fn persistent_credit(&self, owner: Address) -> U256 {
            self.storage
                .get(&(STORAGE_CREDITS_ADDRESS, StorageCredits::slot(owner)))
                .copied()
                .unwrap_or(U256::ZERO)
        }

        fn transient_state(&self, owner: Address) -> TransientState {
            self.transient
                .get(&(STORAGE_CREDITS_ADDRESS, StorageCredits::slot(owner)))
                .copied()
                .unwrap_or_default()
                .try_into()
                .unwrap()
        }
    }

    impl StorageCreditsBackend for TestBackend {
        type Error = InstructionResult;

        fn gas_params(&self) -> &GasParams {
            &self.gas_params
        }

        fn gas_tracker(&mut self) -> &mut GasTracker {
            &mut self.gas_tracker
        }

        fn sload(
            &mut self,
            address: Address,
            key: U256,
            _skip_cold_load: bool,
        ) -> Result<StateLoad<U256>, Self::Error> {
            Ok(StateLoad::new(
                self.storage
                    .get(&(address, key))
                    .copied()
                    .unwrap_or(U256::ZERO),
                false,
            ))
        }

        fn sstore(
            &mut self,
            address: Address,
            key: U256,
            value: U256,
            _skip_cold_load: bool,
        ) -> Result<StateLoad<SStoreResult>, Self::Error> {
            let present_value = self
                .storage
                .insert((address, key), value)
                .unwrap_or(U256::ZERO);
            Ok(StateLoad::new(
                SStoreResult {
                    original_value: present_value,
                    present_value,
                    new_value: value,
                },
                false,
            ))
        }

        fn tload(&mut self, address: Address, key: U256) -> U256 {
            self.transient
                .get(&(address, key))
                .copied()
                .unwrap_or(U256::ZERO)
        }

        fn tstore(&mut self, address: Address, key: U256, value: U256) {
            self.transient.insert((address, key), value);
        }
    }

    fn sstore_result(present_value: U256, new_value: U256) -> StateLoad<SStoreResult> {
        StateLoad::new(
            SStoreResult {
                original_value: present_value,
                present_value,
                new_value,
            },
            false,
        )
    }

    #[test]
    fn pending_clear_is_not_spendable_before_finalization() {
        let owner = Address::repeat_byte(0x11);
        let watched_slot = U256::from(0x22);
        let mut backend = TestBackend::new();

        backend.tstore(
            STORAGE_CREDITS_ADDRESS,
            StorageCredits::pending_slot(owner, watched_slot),
            U256::ONE,
        );
        sstore_storage_credits(
            &mut backend,
            owner,
            Some(watched_slot),
            &sstore_result(U256::ONE, U256::ZERO),
        )
        .unwrap();

        let mut state = backend.transient_state(owner);
        assert_eq!(state.pending_credits, 1);
        assert_eq!(backend.persistent_credit(owner), U256::ZERO);

        state.mode = CreditMode::Direct;
        state.budget = u64::MAX;
        backend.tstore(
            STORAGE_CREDITS_ADDRESS,
            StorageCredits::slot(owner),
            state.into(),
        );
        let gas_before = backend.gas_tracker.remaining();

        sstore_storage_credits(
            &mut backend,
            owner,
            Some(U256::from(0x33)),
            &sstore_result(U256::ZERO, U256::ONE),
        )
        .unwrap();

        let state = backend.transient_state(owner);
        assert_eq!(state.pending_credits, 1);
        assert_eq!(state.budget, u64::MAX);
        assert_eq!(backend.persistent_credit(owner), U256::ZERO);
        assert!(backend.gas_tracker.remaining() < gas_before);
    }

    #[test]
    fn unregistered_zero_key_clear_mints_persistent_credit() {
        let owner = Address::repeat_byte(0x44);
        let mut backend = TestBackend::new();

        sstore_storage_credits(
            &mut backend,
            owner,
            Some(U256::ZERO),
            &sstore_result(U256::ONE, U256::ZERO),
        )
        .unwrap();

        assert_eq!(backend.transient_state(owner).pending_credits, 0);
        assert_eq!(backend.persistent_credit(owner), U256::ONE);
    }
}
