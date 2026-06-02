//! TIP-1060 storage gas-token accounting shared by EVM and precompile SSTORE paths.

use alloy::primitives::Address;

use crate::{STORAGE_GAS_TOKENS_ADDRESS, state_gas_token::{AccountState, StorageGasMode}};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorageGasTokenOutcome {
    pub skip_refund: bool,
    pub skip_state_gas: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorageWriteTransition {
    pub is_noop: bool,
    pub is_create: bool,
    pub is_clear: bool,
}

pub trait StorageGasTokenBackend {
    type Error;

    fn load_state(&mut self, owner: Address) -> Result<AccountState, Self::Error>;
    fn store_state(&mut self, owner: Address, state: AccountState) -> Result<(), Self::Error>;
    fn load_pending_refund_creations(&mut self, owner: Address) -> Result<u64, Self::Error>;
    fn store_pending_refund_creations(
        &mut self,
        owner: Address,
        pending: u64,
    ) -> Result<(), Self::Error>;
}

pub fn apply_storage_gas_token_transition<B: StorageGasTokenBackend>(
    backend: &mut B,
    owner: Address,
    transition: StorageWriteTransition,
) -> Result<StorageGasTokenOutcome, B::Error> {
    let mut outcome = StorageGasTokenOutcome::default();

    if owner == STORAGE_GAS_TOKENS_ADDRESS || transition.is_noop {
        return Ok(outcome);
    }

    if !(transition.is_create || transition.is_clear) {
        return Ok(outcome);
    }

    let mut state = backend.load_state(owner)?;

    if transition.is_clear {
        outcome.skip_refund = true;
        state.balance = state.balance.saturating_add(1);
        backend.store_state(owner, state)?;
        return Ok(outcome);
    }

    match state.mode {
        StorageGasMode::DirectTokens if state.balance > 0 => {
            state.balance -= 1;
            outcome.skip_state_gas = true;
            backend.store_state(owner, state)?;
        }
        StorageGasMode::DirectTokens | StorageGasMode::PreserveTokens => {}
        StorageGasMode::RefundTokens => {
            outcome.skip_refund = true;
            let pending = backend.load_pending_refund_creations(owner)?;
            backend.store_pending_refund_creations(owner, pending.saturating_add(1))?;
        }
    }

    Ok(outcome)
}
