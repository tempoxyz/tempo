use std::{cell::RefCell, rc::Rc};

use alloy_primitives::{Address, U256};

#[derive(Debug, Clone, PartialEq)]
pub enum StorageAction {
    /// Records an SLOAD opcode.
    Sload {
        address: Address,
        key: U256,
        value: U256,
    },
    /// Records an SSTORE opcode.
    Sstore {
        address: Address,
        key: U256,
        value: U256,
    },
    /// Records an increment of a storage slot by delta.
    ///
    /// If the slot **was** zero before incrementing,
    /// [`Self::Sload`] and [`Self::Sstore`] are recorded instead.
    Sinc {
        address: Address,
        key: U256,
        delta: U256,
    },
    /// Records a decrement of a storage slot by delta.
    ///
    /// If the slot **became** zero as a result of decrementing,
    /// [`Self::Sload`] and [`Self::Sstore`] are recorded instead.
    Sdec {
        address: Address,
        key: U256,
        delta: U256,
    },
    /// Records a FeeAMM pool fee swap over a packed pool slot.
    FeeAmmSwap {
        address: Address,
        key: U256,
        amount_in: U256,
        amount_out: U256,
    },
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
