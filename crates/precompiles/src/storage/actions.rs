use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

use alloy_primitives::{Address, U256};

#[derive(Debug, Clone, PartialEq)]
pub enum StorageAction {
    /// Records an SLOAD opcode.
    Sload(Address, U256, U256),
    /// Records an SSTORE opcode.
    Sstore(Address, U256, U256),
}

/// Records the actions performed by the EVM.
#[derive(Debug, Clone)]
pub struct StorageActions {
    enabled: Rc<AtomicBool>,
    actions: Rc<RefCell<Vec<StorageAction>>>,
}

impl StorageActions {
    /// Returns an [`StorageActions`] instance with actions recording disabled.
    pub fn disabled() -> Self {
        Self {
            enabled: Rc::new(AtomicBool::new(false)),
            actions: Rc::default(),
        }
    }

    /// Returns an [`StorageActions`] instance with actions recording enabled.
    pub fn enabled() -> Self {
        Self {
            enabled: Rc::new(AtomicBool::new(true)),
            actions: Rc::default(),
        }
    }

    /// Enables actions recording.
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
        self.actions.borrow_mut().clear();
    }

    /// Returns recorded storage actions, if recording is enabled.
    pub fn take(&self) -> Option<Vec<StorageAction>> {
        if !self.enabled.load(Ordering::Relaxed) {
            return None;
        }

        Some(std::mem::take(&mut *self.actions.borrow_mut()))
    }

    /// Replaces the recorded actions with the given ones, if recording is enabled.
    pub fn replace(&self, actions: Vec<StorageAction>) -> Option<Vec<StorageAction>> {
        if !self.enabled.load(Ordering::Relaxed) {
            return None;
        }

        Some(std::mem::replace(&mut *self.actions.borrow_mut(), actions))
    }

    /// Records an action if recording is enabled.
    pub fn record(&self, action: StorageAction) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        self.actions.borrow_mut().push(action);
    }
}
