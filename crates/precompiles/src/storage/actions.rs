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
}

/// Buffer for recording EVM [storage actions](StorageAction).
#[derive(Debug, Clone)]
pub struct StorageActions {
    inner: Rc<StorageActionsInner>,
}

#[derive(Debug, Default)]
struct StorageActionsInner {
    enabled: Cell<bool>,
    actions: RefCell<Vec<StorageAction>>,
}

impl StorageActions {
    /// Returns an [`StorageActions`] instance with actions recording disabled.
    pub fn disabled() -> Self {
        Self {
            inner: Rc::default(),
        }
    }

    /// Returns an [`StorageActions`] instance with actions recording enabled.
    pub fn enabled() -> Self {
        Self {
            inner: Rc::new(StorageActionsInner {
                enabled: Cell::new(true),
                actions: RefCell::default(),
            }),
        }
    }

    /// Enables actions recording.
    pub fn enable(&self) {
        self.inner.enabled.set(true);
        self.inner.actions.borrow_mut().clear();
    }

    /// Replaces the recorded storage actions with an empty buffer, returning the previous actions.
    pub fn take(&self) -> Option<Vec<StorageAction>> {
        self.replace(Vec::new())
    }

    /// Replaces the recorded storage actions with the given ones, returning the previous actions.
    pub fn replace(&self, actions: Vec<StorageAction>) -> Option<Vec<StorageAction>> {
        if !self.inner.enabled.get() {
            return None;
        }

        Some(std::mem::replace(
            &mut *self.inner.actions.borrow_mut(),
            actions,
        ))
    }

    /// Records an action if recording is enabled.
    pub fn record(&self, action: StorageAction) {
        if !self.inner.enabled.get() {
            return;
        }

        self.inner.actions.borrow_mut().push(action);
    }
}
