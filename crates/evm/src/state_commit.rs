//! Commit repeated storage updates without rebuilding unchanged account transitions.

use alloy_primitives::{Address, map::hash_map::Entry};
use reth_revm::{
    Database, DatabaseCommit, State,
    db::states::{AccountStatus, StorageSlot},
    state::{Account, AccountInfo, EvmState},
};
use std::borrow::Cow;

// AccountInfo equality omits account_id and inline code. Retaining either cached
// copy is safe only when those fields also agree. Pointer identity here refers to
// the immutable BytecodeInner, not to potentially shared raw byte buffers.
fn same_info(a: &AccountInfo, b: &AccountInfo) -> bool {
    a == b
        && a.account_id == b.account_id
        && match (&a.code, &b.code) {
            (None, None) => true,
            (Some(a), Some(b)) => std::ptr::eq(a.bytecode(), b.bytecode()),
            _ => false,
        }
}

fn update<P: Database>(db: &mut State<P>, address: Address, account: &Account) -> bool {
    if account.is_created() || account.is_selfdestructed() || account.is_empty() {
        return false;
    }
    let Some(cached) = db.cache.accounts.get_mut(&address) else {
        return false;
    };
    if cached.status != AccountStatus::Changed {
        return false;
    }
    let Some(current) = cached.account.as_mut() else {
        return false;
    };
    if !same_info(&current.info, &account.info) {
        return false;
    }
    let Some(transition) = db
        .transition_state
        .as_mut()
        .and_then(|s| s.transitions.get_mut(&address))
    else {
        return false;
    };
    if transition.status != AccountStatus::Changed
        || !transition
            .info
            .as_ref()
            .is_some_and(|info| same_info(info, &account.info))
    {
        return false;
    }

    // Changed is a fixed point of CacheAccount::change. Keep both account infos
    // and the transition's original metadata/destruction history. Merge storage
    // using revm's TransitionAccount::update rules, including returning a slot to
    // its block-original value. Unchanged observations belong only to BAL/hooks.
    for (key, slot) in &account.storage {
        if !slot.is_changed() {
            continue;
        }
        current.storage.insert(*key, slot.present_value);
        match transition.storage.entry(*key) {
            Entry::Vacant(entry) => {
                entry.insert(StorageSlot::new_changed(
                    slot.original_value,
                    slot.present_value,
                ));
            }
            Entry::Occupied(mut entry) => {
                if entry.get().original_value() == slot.present_value {
                    entry.remove();
                } else {
                    entry.get_mut().present_value = slot.present_value;
                }
            }
        }
    }
    true
}

pub(crate) fn commit<P: Database>(db: &mut State<P>, changes: EvmState) {
    // The owned path already avoids borrowed account clones. Specialize only
    // the node's observed commit path with accumulated block transitions.
    if db.state_hook.is_none() || db.transition_state.is_none() {
        db.commit(changes);
        return;
    }
    db.bal_state.commit(&changes);
    for (address, account) in &changes {
        if !account.is_touched() || update(db, *address, account) {
            continue;
        }
        // Existing nonempty accounts can retain borrowed storage even when their
        // metadata or status changed. revm still builds/merges their transition.
        if !account.is_created()
            && !account.is_selfdestructed()
            && !account.is_empty()
            && let Some(cached) = db.cache.accounts.get_mut(address)
        {
            let transition = cached.change(Cow::Borrowed(account));
            db.transition_state
                .as_mut()
                .unwrap()
                .add_transition(*address, transition);
            continue;
        }
        // Delegate all lifecycle and metadata changes to revm. Its public API
        // consumes accounts, so clone only these fallbacks to preserve hook data.
        let transitions = db
            .cache
            .apply_evm_state(std::iter::once((*address, account.clone())), |_, _| {});
        db.transition_state
            .as_mut()
            .unwrap()
            .add_transitions(transitions);
    }
    db.state_hook.as_mut().unwrap().on_state(changes);
}

#[cfg(test)]
mod tests;
