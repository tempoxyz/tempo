use std::{cell::RefCell, rc::Rc};

use alloy_primitives::{Address, U256};

use crate::error::{Result, TempoPrecompileError};
use tempo_contracts::precompiles::TIPFeeAMMError;

#[derive(Debug, Clone, PartialEq)]
pub enum StorageAction {
    /// Records an SLOAD opcode.
    Sload(Address, U256, U256),
    /// Records an SSTORE opcode.
    Sstore(Address, U256, U256),
    /// Records an increment of a storage slot by delta.
    ///
    /// If the slot **was** zero before incrementing,
    /// [`Self::Sload`] and [`Self::Sstore`] are recorded instead.
    Sinc(Address, U256, U256),
    /// Records a decrement of a storage slot by delta.
    ///
    /// If the slot **became** zero as a result of decrementing,
    /// [`Self::Sload`] and [`Self::Sstore`] are recorded instead.
    Sdec(Address, U256, U256),
    /// Records a FeeAMM pool fee swap over a packed pool slot.
    ///
    /// Replay checks `amount_out <= reserve_validator_token`, increments
    /// `reserve_user_token` by `amount_in`, and decrements `reserve_validator_token`
    /// by `amount_out`.
    FeeAmmSwap(Address, U256, U256, U256),
}

/// Applies a FeeAMM swap to a packed `Pool` storage word.
///
/// FeeAMM packs `reserve_user_token` into the low 128 bits and
/// `reserve_validator_token` into the high 128 bits.
pub fn apply_fee_amm_swap_to_pool_slot(
    slot_value: U256,
    amount_in: U256,
    amount_out: U256,
) -> Result<U256> {
    let mask = U256::from(u128::MAX);
    let reserve_user_token = slot_value & mask;
    let reserve_validator_token: U256 = slot_value >> 128usize;

    // Check if there's enough validatorToken available
    if amount_out > reserve_validator_token {
        return Err(TIPFeeAMMError::insufficient_liquidity().into());
    }

    let amount_in: u128 = amount_in
        .try_into()
        .map_err(|_| TempoPrecompileError::under_overflow())?;
    let amount_out: u128 = amount_out
        .try_into()
        .map_err(|_| TempoPrecompileError::under_overflow())?;
    let reserve_user_token: u128 = reserve_user_token
        .try_into()
        .map_err(|_| TempoPrecompileError::under_overflow())?;
    let reserve_validator_token: u128 = reserve_validator_token
        .try_into()
        .map_err(|_| TempoPrecompileError::under_overflow())?;

    // Update reserves
    let reserve_user_token = reserve_user_token
        .checked_add(amount_in)
        .ok_or_else(TempoPrecompileError::under_overflow)?;
    let reserve_validator_token = reserve_validator_token
        .checked_sub(amount_out)
        .ok_or_else(TempoPrecompileError::under_overflow)?;

    Ok(U256::from(reserve_user_token) | (U256::from(reserve_validator_token) << 128))
}

/// Buffer for recording EVM [storage actions](StorageAction).
#[derive(Debug, Clone)]
pub enum StorageActions {
    Disabled,
    Enabled(Rc<RefCell<Vec<StorageAction>>>),
}

impl StorageActions {
    /// Returns an [`StorageActions`] instance with actions recording disabled.
    pub fn disabled() -> Self {
        Self::Disabled
    }

    /// Returns an [`StorageActions`] instance with actions recording enabled.
    pub fn enabled() -> Self {
        Self::Enabled(Rc::default())
    }

    /// Enables actions recording.
    pub fn enable(&mut self) {
        match self {
            Self::Disabled => *self = Self::enabled(),
            Self::Enabled(actions) => actions.borrow_mut().clear(),
        }
    }

    /// Returns true if actions recording is enabled.
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }

    /// Replaces the recorded storage actions with an empty buffer, returning the previous actions.
    pub fn take(&self) -> Option<Vec<StorageAction>> {
        self.replace(Vec::new())
    }

    /// Replaces the recorded storage actions with the given ones, returning the previous actions.
    pub fn replace(&self, actions: Vec<StorageAction>) -> Option<Vec<StorageAction>> {
        match self {
            Self::Disabled => None,
            Self::Enabled(recorded) => {
                Some(std::mem::replace(&mut *recorded.borrow_mut(), actions))
            }
        }
    }

    /// Records an action if recording is enabled.
    pub fn record(&self, action: StorageAction) {
        if let Self::Enabled(actions) = self {
            actions.borrow_mut().push(action);
        }
    }
}
