//! Batching of execution state updates sent to the state root task.

use alloy_primitives::{Address, U256, map::HashMap};
use reth_evm::{OnStateHook, StateUpdate};
use reth_execution_types::AccountUpdate;

/// Number of state updates merged into one message to the state root task.
///
/// Every update is a channel send that wakes the state root task's hashing thread. Merging
/// transactions' updates turns per-transaction wakeups into one per batch, and accounts that
/// every transaction touches (fee manager, nonce manager, tokens) are hashed once per batch.
pub(crate) const STATE_UPDATE_BATCH_SIZE: usize = 64;

/// [`OnStateHook`] that merges state updates and forwards them in batches.
///
/// A merged account keeps the original of its first update and the current value, created flag
/// and storage values of its latest one, so every batch has the same net effect as the updates
/// it replaces. Remaining updates are flushed when the hook is dropped, before the inner hook
/// signals the end of the stream.
pub(crate) struct BatchedStateHook<H: OnStateHook> {
    inner: H,
    batch_size: usize,
    /// Updates merged into the pending batch.
    updates: usize,
    pending: Vec<AccountUpdate>,
    /// Index of each account in `pending`.
    accounts: HashMap<Address, usize>,
    /// Index of each storage slot in its account's `storage`.
    slots: HashMap<(Address, U256), usize>,
}

impl<H: OnStateHook> BatchedStateHook<H> {
    pub(crate) fn new(inner: H, batch_size: usize) -> Self {
        Self {
            inner,
            batch_size,
            updates: 0,
            pending: Vec::new(),
            accounts: HashMap::default(),
            slots: HashMap::default(),
        }
    }

    fn merge(&mut self, account: AccountUpdate) {
        let Some(&index) = self.accounts.get(&account.address) else {
            self.push(account);
            return;
        };
        if account.wiped {
            // A wipe drops the account's earlier storage. Keep it as a separate update so the
            // state root task sees the same sequence it would without batching.
            self.flush();
            self.push(account);
            return;
        }
        let pending = &mut self.pending[index];
        pending.current = account.current;
        pending.created |= account.created;
        for (key, slot) in account.storage {
            match self.slots.get(&(account.address, key)) {
                Some(&slot_index) => {
                    pending.storage[slot_index].1.present_value = slot.present_value
                }
                None => {
                    self.slots
                        .insert((account.address, key), pending.storage.len());
                    pending.storage.push((key, slot));
                }
            }
        }
    }

    fn push(&mut self, account: AccountUpdate) {
        let address = account.address;
        for (slot_index, (key, _)) in account.storage.iter().enumerate() {
            self.slots.insert((address, *key), slot_index);
        }
        self.accounts.insert(address, self.pending.len());
        self.pending.push(account);
    }

    /// Sends the pending batch, if any.
    pub(crate) fn flush(&mut self) {
        if self.updates == 0 && self.pending.is_empty() {
            return;
        }
        self.updates = 0;
        self.accounts.clear();
        self.slots.clear();
        let accounts = core::mem::take(&mut self.pending);
        self.inner.on_state(StateUpdate { accounts });
    }
}

impl<H: OnStateHook> OnStateHook for BatchedStateHook<H> {
    fn on_state(&mut self, state: StateUpdate) {
        for account in state.accounts {
            self.merge(account);
        }
        self.updates += 1;
        if self.updates >= self.batch_size {
            self.flush();
        }
    }
}

impl<H: OnStateHook> Drop for BatchedStateHook<H> {
    fn drop(&mut self) {
        // Match the inner hook: a drop during a panic leaves the stream unfinished.
        if std::thread::panicking() {
            return;
        }
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, keccak256};
    use evm2::evm::AccountInfo;
    use reth_execution_types::state_update_to_hashed_post_state;
    use reth_trie_common::{HashedPostState, bundle_state::StorageSlot};
    use std::sync::{Arc, Mutex};

    type Sent = Arc<Mutex<Vec<StateUpdate>>>;

    fn recording_hook(sent: &Sent) -> impl OnStateHook + use<> {
        let sent = sent.clone();
        move |state| sent.lock().unwrap().push(state)
    }

    fn slot(original: u64, current: u64) -> StorageSlot {
        StorageSlot::new_changed(U256::from(original), U256::from(current))
    }

    fn info(balance: u64) -> Option<AccountInfo> {
        Some(AccountInfo::default().with_balance(U256::from(balance)))
    }

    fn update(
        address: Address,
        original: u64,
        current: u64,
        storage: &[(u64, u64, u64)],
    ) -> AccountUpdate {
        AccountUpdate {
            address,
            original: info(original),
            current: info(current),
            created: false,
            wiped: false,
            storage: storage
                .iter()
                .map(|&(key, original, current)| (U256::from(key), slot(original, current)))
                .collect(),
        }
    }

    /// State after applying hashed updates in order, as the state root task does, on top of the
    /// values the stream started from.
    fn apply(stream: &[StateUpdate], updates: &[StateUpdate]) -> HashedPostState {
        let mut state = HashedPostState::default();
        for account in stream.iter().flat_map(|update| &update.accounts).rev() {
            // Seed with the value before the first update to each account and slot.
            let hashed = keccak256(account.address);
            state
                .accounts
                .insert(hashed, account.original.as_ref().map(Into::into));
            let storage = state.storages.entry(hashed).or_default();
            for (key, slot) in &account.storage {
                storage
                    .storage
                    .insert(keccak256(B256::from(*key)), slot.previous_or_original_value);
            }
        }
        for update in updates {
            state.extend(state_update_to_hashed_post_state(update));
        }
        state
    }

    fn stream() -> Vec<StateUpdate> {
        let a = Address::repeat_byte(0xaa);
        let b = Address::repeat_byte(0xbb);
        vec![
            StateUpdate {
                accounts: vec![update(a, 1, 2, &[(1, 0, 5)]), update(b, 7, 8, &[])],
            },
            StateUpdate {
                accounts: vec![update(a, 2, 3, &[(1, 5, 6), (2, 0, 9)])],
            },
            // Changes `b` back to its value before the batch.
            StateUpdate {
                accounts: vec![update(b, 8, 7, &[(3, 4, 4)])],
            },
            StateUpdate {
                accounts: vec![update(a, 3, 4, &[(2, 9, 0)])],
            },
        ]
    }

    #[test]
    fn batches_have_the_same_net_effect_as_single_updates() {
        let updates = stream();
        for batch_size in [1, 2, 3, 4, 64] {
            let sent = Sent::default();
            {
                let mut hook = BatchedStateHook::new(recording_hook(&sent), batch_size);
                for update in updates.clone() {
                    hook.on_state(update);
                }
            }
            let sent = sent.lock().unwrap();
            assert_eq!(
                sent.len(),
                updates.len().div_ceil(batch_size),
                "batch size {batch_size}"
            );
            assert_eq!(
                apply(&updates, &sent),
                apply(&updates, &updates),
                "batch size {batch_size}"
            );
        }
    }

    #[test]
    fn merged_accounts_keep_first_original_and_latest_values() {
        let sent = Sent::default();
        {
            let mut hook = BatchedStateHook::new(recording_hook(&sent), 64);
            for update in stream() {
                hook.on_state(update);
            }
        }
        let sent = sent.lock().unwrap();
        let [batch] = sent.as_slice() else {
            panic!("expected one batch")
        };
        let a = batch.account(&Address::repeat_byte(0xaa)).unwrap();
        assert_eq!(a.original, info(1));
        assert_eq!(a.current, info(4));
        assert_eq!(
            a.storage,
            [(U256::from(1), slot(0, 6)), (U256::from(2), slot(0, 0))]
        );
    }

    #[test]
    fn wiped_account_starts_a_new_batch() {
        let a = Address::repeat_byte(0xaa);
        let sent = Sent::default();
        {
            let mut hook = BatchedStateHook::new(recording_hook(&sent), 64);
            hook.on_state(StateUpdate {
                accounts: vec![update(a, 1, 2, &[(1, 0, 5)])],
            });
            let mut wiped = update(a, 2, 3, &[(2, 0, 1)]);
            wiped.wiped = true;
            hook.on_state(StateUpdate {
                accounts: vec![wiped],
            });
        }
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(sent[1].accounts[0].wiped);
        assert_eq!(sent[1].accounts[0].storage.len(), 1);
    }
}
