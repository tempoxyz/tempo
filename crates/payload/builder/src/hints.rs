//! Parent-state storage values that prewarming read, handed to the builder.
//!
//! Prewarming executes each transaction on top of the parent state without committing, so the
//! original value of every slot it touched is the slot's parent-state value. The builder only
//! asks its database for slots the block has not loaded yet, which still hold their
//! parent-state value, so a hint is always the value the database would return. Answering from
//! the transaction's own small hint list skips the shared execution cache lookups on the
//! builder thread.

use std::{
    cell::RefCell,
    sync::{Arc, OnceLock},
};

use alloy_primitives::{Address, B256, StorageKey, StorageValue, U256};
use evm2::evm::{StateChangeSink, StorageChange};
use reth_primitives_traits::{Account, Bytecode};
use reth_storage_api::{EvmStateProvider, errors::provider::ProviderResult};

/// Storage hints of one transaction, filled by prewarming once it executed the transaction.
pub(crate) type StorageHintSlot = Arc<OnceLock<StorageHints>>;

/// Storage slots a prewarmed transaction touched, with their parent-state values.
#[derive(Debug, Default)]
pub(crate) struct StorageHints(Vec<(Address, B256, U256)>);

impl StorageHints {
    /// Collects the slots touched by a transaction executed on top of the parent state.
    pub(crate) fn from_pending_state(state: &evm2::evm::PendingState) -> Self {
        let mut hints = Self::default();
        let _ = evm2::evm::StateChangeSource::visit(state, &mut hints);
        hints
    }

    fn get(&self, address: Address, key: B256) -> Option<U256> {
        self.0
            .iter()
            .find(|(hint_address, hint_key, _)| *hint_key == key && *hint_address == address)
            .map(|(_, _, value)| *value)
    }
}

impl StateChangeSink for StorageHints {
    type Error = core::convert::Infallible;

    fn storage(&mut self, change: StorageChange) -> Result<(), Self::Error> {
        self.0
            .push((change.address, B256::from(change.key), change.original));
        Ok(())
    }

    fn storage_read(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), Self::Error> {
        self.0.push((address, B256::from(key), value));
        Ok(())
    }
}

/// State provider that answers storage reads from the current transaction's hints.
pub(crate) struct HintedStateProvider<'a> {
    inner: &'a dyn EvmStateProvider,
    current: RefCell<Option<StorageHintSlot>>,
}

impl<'a> HintedStateProvider<'a> {
    pub(crate) fn new(inner: &'a dyn EvmStateProvider) -> Self {
        Self {
            inner,
            current: RefCell::default(),
        }
    }

    /// Sets the hints of the transaction about to execute.
    pub(crate) fn set_hints(&self, hints: Option<StorageHintSlot>) {
        *self.current.borrow_mut() = hints;
    }
}

impl EvmStateProvider for HintedStateProvider<'_> {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.inner.basic_account(address)
    }

    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }

    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.inner.bytecode_by_hash(code_hash)
    }

    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        let hint = self
            .current
            .borrow()
            .as_ref()
            .and_then(|slot| slot.get())
            .and_then(|hints| hints.get(account, storage_key));
        if let Some(value) = hint {
            debug_assert_eq!(
                self.inner
                    .storage(account, storage_key)
                    .ok()
                    .map(Option::unwrap_or_default),
                Some(value),
                "prewarm storage hint differs from the parent state"
            );
            return Ok(Some(value));
        }
        self.inner.storage(account, storage_key)
    }
}
