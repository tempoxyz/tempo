use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use alloy_primitives::{Address, U256};

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
}

/// Buffer for recording EVM [storage actions](StorageAction).
#[derive(Debug, Clone)]
pub struct StorageActions {
    enabled: Rc<Cell<bool>>,
    actions: Rc<RefCell<Vec<StorageAction>>>,
}

impl StorageActions {
    /// Returns an [`StorageActions`] instance with actions recording disabled.
    pub fn disabled() -> Self {
        Self {
            enabled: Rc::new(Cell::new(false)),
            actions: Rc::default(),
        }
    }

    /// Returns an [`StorageActions`] instance with actions recording enabled.
    pub fn enabled() -> Self {
        Self {
            enabled: Rc::new(Cell::new(true)),
            actions: Rc::default(),
        }
    }

    /// Enables actions recording.
    pub fn enable(&self) {
        self.enabled.set(true);
        self.actions.borrow_mut().clear();
    }

    /// Replaces the recorded storage actions with an empty buffer, returning the previous actions.
    pub fn take(&self) -> Option<Vec<StorageAction>> {
        self.replace(Vec::new())
    }

    /// Replaces the recorded storage actions with the given ones, returning the previous actions.
    pub fn replace(&self, actions: Vec<StorageAction>) -> Option<Vec<StorageAction>> {
        if !self.enabled.get() {
            return None;
        }

        Some(std::mem::replace(&mut *self.actions.borrow_mut(), actions))
    }

    /// Records an action if recording is enabled.
    pub fn record(&self, action: StorageAction) {
        if !self.enabled.get() {
            return;
        }

        self.actions.borrow_mut().push(action);
    }
}
