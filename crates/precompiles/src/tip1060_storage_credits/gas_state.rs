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
use alloy::primitives::{Address, U256};
use revm::{
    context_interface::cfg::GasParams,
    interpreter::{SStoreResult, StateLoad, gas::GasTracker, instruction_context::GasStateOutcome},
};
use tempo_contracts::precompiles::STORAGE_CREDITS_ADDRESS;

pub const STORAGE_CREDIT_VALUE: u64 = 230_000;
const SSTORE_SET_WITHOUT_EXPANSION_COST: u64 = 20_000;

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

    /// Gas tracker for the active execution context.
    fn gas_tracker(&mut self) -> &mut GasTracker;

    /// Charges `cost` regular gas, returning [`out_of_gas`](Self::out_of_gas) if insufficient.
    #[inline]
    fn charge_gas(&mut self, cost: u64) -> Result<(), Self::Error> {
        self.gas_tracker()
            .record_regular_cost(cost)
            .then_some(())
            .ok_or_else(Self::out_of_gas)
    }

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

    /// Loads the transaction-local storage credit state for `account`.
    fn load_transient_state(&mut self, account: Address) -> Result<TransientState, Self::Error>;

    /// Stores the transaction-local storage credit state for `account`.
    fn store_transient_state(
        &mut self,
        account: Address,
        state: TransientState,
    ) -> Result<(), Self::Error>;
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

    // Only account for storage credits when the slot crosses the zero boundary
    // (zero -> non-zero or non-zero -> zero). If both values are zero or both are
    // non-zero, slot occupancy is unchanged, so skip storage credits accounting.
    if values.is_present_zero() == values.is_new_zero() {
        return Ok(outcome);
    }

    // Storage-credit precompile state is used for protocol bookkeeping. Because of that,
    // always skips TIP-1000 + TIP-1060 self-accounting and charge only update gas.
    if owner == STORAGE_CREDITS_ADDRESS {
        if is_cold {
            backend.charge_gas(backend.gas_params().cold_storage_cost())?;
        }
        if values.is_original_eq_present() {
            backend.charge_gas(backend.gas_params().sstore_reset_without_cold_load_cost())?;
        }

        return Ok(GasStateOutcome {
            skip_gas: true,
            skip_refund: true,
        });
    }

    // Load the persistent storage credit balance for the storage-owning account.
    let warm_storage_read_cost = backend.gas_params().warm_storage_read_cost();
    backend.charge_gas(warm_storage_read_cost)?;

    backend.load_storage_credit_account()?;

    let account_slot = TIP1060StorageCredits::slot(owner);
    let additional_cold_cost = backend.gas_params().cold_storage_additional_cost();
    let skip_cold = backend.gas_tracker().remaining() < additional_cold_cost;
    let storage_credit_state_load = backend.load_credits(account_slot, skip_cold)?;
    if storage_credit_state_load.is_cold {
        backend.charge_gas(additional_cold_cost)?;
    }

    let mut balance =
        u64::from_word(storage_credit_state_load.data).map_err(|_| B::fatal_external())?;

    let mut was_changed = false;
    if values.is_new_zero() {
        // x→0: slot clear (present non-zero set to zero).
        balance = balance.saturating_add(1);
        was_changed = true;
    } else {
        // 0→x: slot create. The selected storage creation mode is transient.
        let mut transient_state = backend.load_transient_state(owner)?;

        match transient_state.mode {
            CreditMode::Direct => {
                // Only if there is a credit available, skip gas
                if balance > 0 {
                    // Consume the storage credit and charge 20k for the SSTORE + cold access cost.
                    if caller_state_load.is_cold {
                        backend.charge_gas(backend.gas_params().cold_storage_cost())?;
                    }
                    backend.charge_gas(SSTORE_SET_WITHOUT_EXPANSION_COST)?;
                    balance -= 1;
                    was_changed = true;
                    outcome.skip_gas = true;
                }
                // Otherwise, leave gas enabled so revm charges full creation costs.
            }
            CreditMode::Preserve => {
                // Do nothing, so revm takes care of gas accounting after this hook.
            }
            CreditMode::Refund => {
                transient_state.pending_refunds = transient_state.pending_refunds.saturating_add(1);
                backend.store_transient_state(owner, transient_state)?;
            }
        }
    }

    if was_changed {
        // cold load is already checked above when we loaded the storage credits account.
        let result = backend
            .store_credits(account_slot, U256::from(balance))?
            .data;

        // Only when change happens charge additional gas.
        // Creating or updating the protocol credit-balance slot is TIP-1060 bookkeeping and
        // does not incur the extra TIP-1000 storage creation component.
        if result.new_values_changes_present() && result.is_original_eq_present() {
            backend.charge_gas(backend.gas_params().sstore_reset_without_cold_load_cost())?;
        };
    }

    Ok(outcome)
}
