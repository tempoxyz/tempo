use std::{cell::RefCell, rc::Rc};

pub use tempo_primitives::{FeeHook, StorageAction};

/// Buffer for recording EVM [storage actions](StorageAction).
#[derive(Debug, Clone)]
pub enum StorageActions {
    Disabled,
    Enabled(Rc<RefCell<StorageActionsState>>),
}

/// Shared mutable state for [`StorageActions`] clones.
#[derive(Debug, Default)]
pub struct StorageActionsState {
    actions: Vec<StorageAction>,
    /// The depth of the current unrecorded actions scope.
    ///
    /// Incremented on each [`StorageActions::unrecorded`] call,
    /// and decremented on exit from it.
    ///
    /// Allows for nesting multiple unrecorded scopes, while [`StorageActions::recorded`]
    /// can temporarily reset the depth to resume normal recording inside such a scope.
    unrecorded_depth: usize,
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
            Self::Enabled(state) => {
                state.borrow_mut().actions.clear();
            }
        }
    }

    /// Returns true if actions recording is enabled.
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }

    /// Clears recorded storage actions without releasing the backing allocation.
    pub fn clear(&self) {
        match self {
            Self::Disabled => {}
            Self::Enabled(actions) => actions.borrow_mut().actions.clear(),
        }
    }

    /// Replaces the recorded storage actions with an empty buffer, returning the previous actions.
    pub fn take(&self) -> Option<Vec<StorageAction>> {
        self.replace(Vec::new())
    }

    /// Replaces the recorded storage actions with the given ones, returning the previous actions.
    pub fn replace(&self, actions: Vec<StorageAction>) -> Option<Vec<StorageAction>> {
        match self {
            Self::Disabled => None,
            Self::Enabled(state) => {
                Some(std::mem::replace(&mut state.borrow_mut().actions, actions))
            }
        }
    }

    /// Runs a closure where [`Self::record`] calls are suppressed.
    pub fn unrecorded<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self.unrecorded_guard();
        f()
    }

    /// Runs a closure where [`Self::record`] calls are recorded even inside an unrecorded scope.
    pub fn recorded<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self.recorded_guard();
        f()
    }

    /// Enters a scope where [`Self::record`] calls are suppressed.
    fn unrecorded_guard(&self) -> Option<UnrecordedStorageActionsGuard> {
        if let Self::Enabled(state) = self {
            state.borrow_mut().unrecorded_depth += 1;
            Some(UnrecordedStorageActionsGuard(self.clone()))
        } else {
            None
        }
    }

    /// Enters a scope where [`Self::record`] calls are recorded.
    fn recorded_guard(&self) -> Option<RecordedStorageActionsGuard> {
        if let Self::Enabled(state) = self {
            let mut state = state.borrow_mut();
            let previous_unrecorded_depth = state.unrecorded_depth;
            state.unrecorded_depth = 0;
            Some(RecordedStorageActionsGuard {
                actions: self.clone(),
                previous_unrecorded_depth,
            })
        } else {
            None
        }
    }

    /// Records an action if recording is enabled and the current scope is recorded.
    pub fn record(&self, action: StorageAction) {
        if let Self::Enabled(state) = self {
            let mut state = state.borrow_mut();
            if state.unrecorded_depth == 0 {
                state.actions.push(action);
            }
        }
    }

    /// Records an action if recording is enabled, even inside an unrecorded scope.
    pub fn record_always(&self, action: StorageAction) {
        if let Self::Enabled(state) = self {
            state.borrow_mut().actions.push(action);
        }
    }
}

/// Unrecorded storage-actions scope guard.
#[derive(Debug)]
struct UnrecordedStorageActionsGuard(StorageActions);

impl Drop for UnrecordedStorageActionsGuard {
    fn drop(&mut self) {
        if let StorageActions::Enabled(state) = &self.0 {
            let mut state = state.borrow_mut();
            state.unrecorded_depth = state
                .unrecorded_depth
                .checked_sub(1)
                .expect("unrecorded storage action scope underflow");
        }
    }
}

/// Recorded storage-actions scope guard.
#[derive(Debug)]
struct RecordedStorageActionsGuard {
    actions: StorageActions,
    previous_unrecorded_depth: usize,
}

impl Drop for RecordedStorageActionsGuard {
    fn drop(&mut self) {
        if let StorageActions::Enabled(state) = &self.actions {
            state.borrow_mut().unrecorded_depth = self.previous_unrecorded_depth;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};

    #[test]
    fn test_unrecorded_record_always() {
        let actions = StorageActions::enabled();
        let address = Address::repeat_byte(0x42);
        let key = U256::from(7);

        actions.record(StorageAction::Sload(address, key, U256::ONE));

        actions.unrecorded(|| {
            actions.record(StorageAction::Sstore(
                address,
                key,
                U256::ONE,
                U256::from(2),
            ));

            actions.unrecorded(|| {
                actions.record(StorageAction::Sinc(
                    address,
                    key,
                    U256::from(2),
                    U256::from(3),
                ));
                actions.record_always(StorageAction::FeeAmmSwap(key, U256::from(3), U256::from(4)));
            });

            actions.record(StorageAction::Sdec(
                address,
                key,
                U256::from(5),
                U256::from(6),
            ));
        });

        actions.record(StorageAction::Sstore(
            address,
            key,
            U256::ONE,
            U256::from(8),
        ));

        assert_eq!(
            actions.take(),
            Some(vec![
                StorageAction::Sload(address, key, U256::ONE),
                StorageAction::FeeAmmSwap(key, U256::from(3), U256::from(4)),
                StorageAction::Sstore(address, key, U256::ONE, U256::from(8)),
            ])
        );
    }

    #[test]
    fn test_recorded_scope_resumes_recording() {
        let actions = StorageActions::enabled();
        let address = Address::repeat_byte(0x42);
        let key = U256::from(7);

        actions.unrecorded(|| {
            actions.record(StorageAction::Sload(address, key, U256::ONE));

            actions.recorded(|| {
                actions.record(StorageAction::Sstore(
                    address,
                    key,
                    U256::ONE,
                    U256::from(2),
                ));

                actions.unrecorded(|| {
                    actions.record(StorageAction::Sinc(
                        address,
                        key,
                        U256::from(2),
                        U256::from(3),
                    ));
                });

                actions.record(StorageAction::Sdec(
                    address,
                    key,
                    U256::from(5),
                    U256::from(6),
                ));
            });

            actions.record(StorageAction::Sload(address, key, U256::from(7)));
        });

        actions.record(StorageAction::Sstore(
            address,
            key,
            U256::ONE,
            U256::from(8),
        ));

        assert_eq!(
            actions.take(),
            Some(vec![
                StorageAction::Sstore(address, key, U256::ONE, U256::from(2)),
                StorageAction::Sdec(address, key, U256::from(5), U256::from(6)),
                StorageAction::Sstore(address, key, U256::ONE, U256::from(8)),
            ])
        );
    }
}
