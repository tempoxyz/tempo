use std::{cell::RefCell, rc::Rc};

use alloy_primitives::{Address, U256};

#[derive(Debug, Clone, PartialEq)]
pub enum StorageAction {
    /// Records an SLOAD opcode.
    Sload(Address, U256, U256),
    /// Records an SSTORE opcode.
    Sstore(Address, U256, U256),
}

/// Buffer for recording EVM [storage actions](StorageAction).
#[derive(Debug, Clone)]
pub enum StorageActions {
    Disabled,
    Enabled(Rc<RefCell<Vec<StorageAction>>>),
}

impl StorageActions {
    /// Returns an [`StorageActions`] instance with actions recording disabled.
    #[inline]
    pub fn disabled() -> Self {
        Self::Disabled
    }

    /// Returns an [`StorageActions`] instance with actions recording enabled.
    #[inline]
    pub fn enabled() -> Self {
        Self::Enabled(Rc::default())
    }

    /// Enables actions recording.
    #[inline]
    pub fn enable(&self) {
        if let Self::Enabled(actions) = self {
            actions.borrow_mut().clear();
        }
    }

    /// Replaces the recorded storage actions with an empty buffer, returning the previous actions.
    #[inline]
    pub fn take(&self) -> Option<Vec<StorageAction>> {
        self.replace(Vec::new())
    }

    /// Replaces the recorded storage actions with the given ones, returning the previous actions.
    #[inline]
    pub fn replace(&self, actions: Vec<StorageAction>) -> Option<Vec<StorageAction>> {
        match self {
            Self::Disabled => None,
            Self::Enabled(current) => Some(std::mem::replace(&mut *current.borrow_mut(), actions)),
        }
    }

    /// Records an action if recording is enabled.
    #[inline]
    pub fn record(&self, action: StorageAction) {
        if let Self::Enabled(actions) = self {
            actions.borrow_mut().push(action);
        }
    }
}
