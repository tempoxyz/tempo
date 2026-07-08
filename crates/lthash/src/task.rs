//! The worker that folds a block's state changes into the parent accumulator.

use crate::{
    accumulator::{
        LTHASH_ACCOUNT_ELEMENT_LEN, LTHASH_STORAGE_ELEMENT_LEN, LthashAccumulator,
        lthash_account_element, lthash_storage_element,
    },
    error::LthashError,
};
use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_eip7928::{AccountChanges, BlockAccessList, bal::DecodedBal};
use alloy_primitives::{Address, B256, StorageKey, StorageValue, U256, keccak256};
use crossbeam_channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use reth_primitives_traits::Account;
use reth_revm::state::EvmState;
use reth_storage_api::StateProviderBox;
use std::{collections::HashMap, sync::Arc};

#[derive(Debug)]
pub(crate) enum LthashMessage {
    AccountTouched {
        address: Address,
        hashed_address: B256,
        new_account: Option<Account>,
    },
    StorageTouched {
        address: Address,
        hashed_address: B256,
        slot: StorageKey,
        hashed_slot: B256,
        new_value: StorageValue,
    },
    FinishedUpdates,
}

/// Input feeding the lthash task.
pub(crate) enum LthashInput {
    /// A complete block access list, known before execution starts.
    Bal(Arc<DecodedBal>),
    /// Per-transaction updates streamed from the execution hook.
    Stream(CrossbeamReceiver<LthashMessage>),
}

#[derive(Debug, Clone)]
pub(crate) struct LthashOutcome {
    pub(crate) root: B256,
    pub(crate) accumulator: LthashAccumulator,
    pub(crate) account_updates: usize,
    pub(crate) storage_updates: usize,
}

pub(crate) struct LthashTask {
    provider: StateProviderBox,
    state: LthashState,
}

impl LthashTask {
    pub(crate) fn new(provider: StateProviderBox, parent_accumulator: LthashAccumulator) -> Self {
        Self {
            provider,
            state: LthashState::new(parent_accumulator),
        }
    }

    pub(crate) fn run(mut self, input: LthashInput) -> Result<LthashOutcome, LthashError> {
        match input {
            LthashInput::Bal(decoded) => {
                let bal: BlockAccessList = decoded.as_bal().clone().into();
                self.apply_bal(&bal)?;
            }
            LthashInput::Stream(updates_rx) => loop {
                match updates_rx.recv() {
                    Ok(LthashMessage::AccountTouched {
                        address,
                        hashed_address,
                        new_account,
                    }) => {
                        self.touch_account(address, hashed_address, new_account)?;
                    }
                    Ok(LthashMessage::StorageTouched {
                        address,
                        hashed_address,
                        slot,
                        hashed_slot,
                        new_value,
                    }) => {
                        self.touch_storage(address, hashed_address, slot, hashed_slot, new_value)?;
                    }
                    Ok(LthashMessage::FinishedUpdates) => break,
                    Err(_) => return Err(LthashError::UpdatesClosed),
                }
            },
        }

        Ok(self.state.finish())
    }

    fn apply_bal(&mut self, bal: &BlockAccessList) -> Result<(), LthashError> {
        for account_changes in bal {
            self.apply_bal_account(account_changes)?;
        }
        Ok(())
    }

    fn apply_bal_account(&mut self, account_changes: &AccountChanges) -> Result<(), LthashError> {
        let address = account_changes.address;
        let hashed_address = keccak256(address);

        for slot_changes in &account_changes.storage_changes {
            let Some(last_change) = slot_changes.changes.last() else {
                continue;
            };
            let slot = StorageKey::from(slot_changes.slot);
            let hashed_slot = keccak256(slot_changes.slot.to_be_bytes::<32>());
            self.touch_storage(
                address,
                hashed_address,
                slot,
                hashed_slot,
                last_change.new_value,
            )?;
        }

        let account_fields = BalAccountStateFields::from_changes(account_changes);
        if account_fields.is_empty() {
            return Ok(());
        }

        let existing_account = if account_fields.needs_parent_account() {
            self.provider
                .basic_account(&address)
                .map_err(|source| LthashError::AccountRead {
                    hashed_address,
                    source,
                })?
        } else {
            None
        };

        self.touch_account(
            address,
            hashed_address,
            Some(account_fields.into_account(existing_account)),
        )
    }

    fn touch_account(
        &mut self,
        address: Address,
        hashed_address: B256,
        new_account: Option<Account>,
    ) -> Result<(), LthashError> {
        if !self.state.accounts.contains_key(&hashed_address) {
            let old = self.provider.basic_account(&address).map_err(|source| {
                LthashError::AccountRead {
                    hashed_address,
                    source,
                }
            })?;
            self.state.subtract_old_account(hashed_address, old);
        }

        self.state.touch_account(hashed_address, new_account);
        Ok(())
    }

    fn touch_storage(
        &mut self,
        address: Address,
        hashed_address: B256,
        slot: StorageKey,
        hashed_slot: B256,
        new_value: StorageValue,
    ) -> Result<(), LthashError> {
        let key = (hashed_address, hashed_slot);
        if !self.state.storages.contains_key(&key) {
            let old = self
                .provider
                .storage(address, slot)
                .map_err(|source| LthashError::StorageRead {
                    hashed_address,
                    hashed_slot,
                    source,
                })?
                .unwrap_or_default();
            self.state
                .subtract_old_storage(hashed_address, hashed_slot, old);
        }

        self.state
            .touch_storage(hashed_address, hashed_slot, new_value);
        Ok(())
    }
}

#[derive(Debug)]
struct LthashState {
    accumulator: LthashAccumulator,
    accounts: HashMap<B256, AccountEntry>,
    storages: HashMap<(B256, B256), StorageEntry>,
    account_updates: usize,
    storage_updates: usize,
}

impl LthashState {
    fn new(accumulator: LthashAccumulator) -> Self {
        Self {
            accumulator,
            accounts: HashMap::new(),
            storages: HashMap::new(),
            account_updates: 0,
            storage_updates: 0,
        }
    }

    fn subtract_old_account(&mut self, hashed_address: B256, old: Option<Account>) {
        if let Some(old) = old.and_then(|account| lthash_account_element(hashed_address, account)) {
            self.accumulator.subtract(old);
        }
        self.account_updates += 1;
    }

    fn subtract_old_storage(&mut self, hashed_address: B256, hashed_slot: B256, old: StorageValue) {
        if let Some(old) = lthash_storage_element(hashed_address, hashed_slot, old) {
            self.accumulator.subtract(old);
        }
        self.storage_updates += 1;
    }

    fn touch_account(&mut self, hashed_address: B256, new_account: Option<Account>) {
        let entry = self.accounts.entry(hashed_address).or_default();
        if let Some(element) = entry.added_new.take() {
            self.accumulator.subtract(element);
        }

        let element =
            new_account.and_then(|account| lthash_account_element(hashed_address, account));
        if let Some(element) = element {
            self.accumulator.add(element);
        }
        entry.added_new = element;
    }

    fn touch_storage(&mut self, hashed_address: B256, hashed_slot: B256, new_value: StorageValue) {
        let entry = self
            .storages
            .entry((hashed_address, hashed_slot))
            .or_default();
        if let Some(element) = entry.added_new.take() {
            self.accumulator.subtract(element);
        }

        let element = lthash_storage_element(hashed_address, hashed_slot, new_value);
        if let Some(element) = element {
            self.accumulator.add(element);
        }
        entry.added_new = element;
    }

    fn finish(self) -> LthashOutcome {
        LthashOutcome {
            root: self.accumulator.checksum(),
            accumulator: self.accumulator,
            account_updates: self.account_updates,
            storage_updates: self.storage_updates,
        }
    }
}

#[derive(Debug, Default)]
struct AccountEntry {
    added_new: Option<[u8; LTHASH_ACCOUNT_ELEMENT_LEN]>,
}

#[derive(Debug, Default)]
struct StorageEntry {
    added_new: Option<[u8; LTHASH_STORAGE_ELEMENT_LEN]>,
}

pub(crate) fn send_evm_state_to_lthash(
    update: &EvmState,
    to_lthash_task: &CrossbeamSender<LthashMessage>,
) {
    for (address, account) in update {
        if !account.is_touched() {
            continue;
        }

        let hashed_address = keccak256(address);
        if account.info != account.original_info() {
            let new_account =
                (!account.is_selfdestructed()).then(|| Account::from_revm_account(account));
            let _ = to_lthash_task.send(LthashMessage::AccountTouched {
                address: *address,
                hashed_address,
                new_account,
            });
        }

        if account.is_selfdestructed() {
            continue;
        }

        for (slot, value) in account.changed_storage_slots() {
            let slot = *slot;
            let hashed_slot = keccak256(slot.to_be_bytes::<32>());
            let _ = to_lthash_task.send(LthashMessage::StorageTouched {
                address: *address,
                hashed_address,
                slot: slot.into(),
                hashed_slot,
                new_value: value.present_value,
            });
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BalAccountStateFields {
    balance: Option<U256>,
    nonce: Option<u64>,
    code_hash: Option<B256>,
}

impl BalAccountStateFields {
    fn from_changes(account_changes: &AccountChanges) -> Self {
        Self {
            balance: account_changes
                .balance_changes
                .last()
                .map(|change| change.post_balance),
            nonce: account_changes
                .nonce_changes
                .last()
                .map(|change| change.new_nonce),
            code_hash: account_changes.code_changes.last().map(|code_change| {
                if code_change.new_code.is_empty() {
                    KECCAK_EMPTY
                } else {
                    keccak256(&code_change.new_code)
                }
            }),
        }
    }

    const fn is_empty(self) -> bool {
        self.balance.is_none() && self.nonce.is_none() && self.code_hash.is_none()
    }

    const fn needs_parent_account(self) -> bool {
        self.balance.is_none() || self.nonce.is_none() || self.code_hash.is_none()
    }

    fn into_account(self, existing_account: Option<Account>) -> Account {
        let existing_account = existing_account.as_ref();
        Account {
            balance: self.balance.unwrap_or_else(|| {
                existing_account
                    .map(|account| account.balance)
                    .unwrap_or_default()
            }),
            nonce: self
                .nonce
                .unwrap_or_else(|| existing_account.map(|account| account.nonce).unwrap_or(0)),
            bytecode_hash: self.code_hash.or_else(|| {
                existing_account
                    .and_then(|account| account.bytecode_hash)
                    .or(Some(KECCAK_EMPTY))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::account;

    #[test]
    fn replacement_uses_only_old_and_latest_new_values() {
        let hashed_address = B256::repeat_byte(0x11);
        let old = account(1, 10);
        let mid = account(2, 20);
        let new = account(3, 30);

        let mut parent = LthashAccumulator::zero();
        parent.add(lthash_account_element(hashed_address, old).unwrap());

        let mut state = LthashState::new(parent);
        state.subtract_old_account(hashed_address, Some(old));
        state.touch_account(hashed_address, Some(mid));
        state.touch_account(hashed_address, Some(new));

        let outcome = state.finish();
        let mut expected = LthashAccumulator::zero();
        expected.add(lthash_account_element(hashed_address, new).unwrap());

        assert_eq!(outcome.root, expected.checksum());
        assert_eq!(outcome.account_updates, 1);
        assert_eq!(outcome.storage_updates, 0);
    }

    #[test]
    fn zero_storage_removes_latest_element() {
        let hashed_address = B256::repeat_byte(0x11);
        let hashed_slot = B256::repeat_byte(0x22);
        let old = U256::from(7);

        let mut parent = LthashAccumulator::zero();
        parent.add(lthash_storage_element(hashed_address, hashed_slot, old).unwrap());

        let mut state = LthashState::new(parent);
        state.subtract_old_storage(hashed_address, hashed_slot, old);
        state.touch_storage(hashed_address, hashed_slot, U256::ZERO);

        assert_eq!(state.finish().root, LthashAccumulator::zero().checksum());
    }

    #[test]
    fn seeded_root_chains_from_parent() {
        let hashed_address = B256::repeat_byte(0x55);
        let parent_update = account(1, 10);
        let child_update = account(2, 20);

        // Parent block: touch the account from empty state.
        let mut parent_state = LthashState::new(LthashAccumulator::zero());
        parent_state.touch_account(hashed_address, Some(parent_update));
        let parent = parent_state.finish();

        // Child block seeded with the parent accumulator replaces the account element.
        let mut child_state = LthashState::new(parent.accumulator.clone());
        child_state.subtract_old_account(hashed_address, Some(parent_update));
        child_state.touch_account(hashed_address, Some(child_update));
        let child = child_state.finish();

        // The chained result equals writing the final value directly from empty state.
        let mut expected = LthashAccumulator::zero();
        expected.add(lthash_account_element(hashed_address, child_update).unwrap());
        assert_eq!(child.root, expected.checksum());
        assert_ne!(child.root, parent.root);
    }
}
