use std::{cell::RefCell, rc::Rc};

use alloy_primitives::{Address, U256};

#[derive(Debug, Clone, Copy, PartialEq)]
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
    /// `address` - FeeAMM contract address.
    /// `key` - Storage slot key.
    /// `amount_in` - Amount of tokens to swap in.
    ///
    /// `amount_out` can be calculated using [`compute_amount_out`](crate::tip_fee_manager::amm::compute_amount_out).
    FeeAmmSwap(Address, U256, U256),
}

impl StorageAction {
    /// Returns the address of the storage action.
    pub fn address(&self) -> Address {
        match self {
            Self::Sload(address, ..)
            | Self::Sstore(address, ..)
            | Self::Sinc(address, ..)
            | Self::Sdec(address, ..)
            | Self::FeeAmmSwap(address, ..) => *address,
        }
    }
}

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
    /// Allows for nesting multiple unrecorded scopes, making sure that
    /// only when all scopes are exited, [`StorageActions::record`] records actions again.
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

    /// Enters a scope where [`Self::record`] calls are suppressed.
    fn unrecorded_guard(&self) -> Option<UnrecordedStorageActionsGuard> {
        if let Self::Enabled(state) = self {
            state.borrow_mut().unrecorded_depth += 1;
            Some(UnrecordedStorageActionsGuard(self.clone()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unrecorded_record_always() {
        let actions = StorageActions::enabled();
        let address = Address::repeat_byte(0x42);
        let key = U256::from(7);

        actions.record(StorageAction::Sload(address, key, U256::from(1)));

        actions.unrecorded(|| {
            actions.record(StorageAction::Sstore(address, key, U256::from(2)));

            actions.unrecorded(|| {
                actions.record(StorageAction::Sinc(address, key, U256::from(3)));
                actions.record_always(StorageAction::FeeAmmSwap(address, key, U256::from(4)));
            });

            actions.record(StorageAction::Sdec(address, key, U256::from(6)));
        });

        actions.record(StorageAction::Sstore(address, key, U256::from(8)));

        assert_eq!(
            actions.take(),
            Some(vec![
                StorageAction::Sload(address, key, U256::from(1)),
                StorageAction::FeeAmmSwap(address, key, U256::from(4)),
                StorageAction::Sstore(address, key, U256::from(8)),
            ])
        );
    }
}
