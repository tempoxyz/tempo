//! Shared L1 reader fixtures for precompile and EVM integration tests.
use crate::{L1StateError, L1StorageReader};
use alloy_primitives::{Address, B256, U256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tempo_precompiles::{
    storage::{
        Handler, PrecompileStorageProvider, Slot, Storable, StorageCtx,
        hashmap::HashMapStorageProvider,
    },
    tip403_registry::{CompoundPolicyData, PolicyData, TIP403Registry},
    zone_factory::ZonePortalStorage,
};

pub type L1Slot = (Address, B256, u64);
type Shared<T> = Arc<Mutex<T>>;

/// In-memory exact-block L1 reader shared by EVM and precompile tests.
#[derive(Clone)]
pub struct MockL1Reader {
    storage: Shared<HashMap<u64, HashMapStorageProvider>>,
    storage_requests: Shared<Vec<L1Slot>>,
    fallback: B256,
    fail_storage: bool,
}

impl Default for MockL1Reader {
    fn default() -> Self {
        Self {
            storage: Default::default(),
            storage_requests: Default::default(),
            fallback: B256::ZERO,
            fail_storage: false,
        }
    }
}

impl MockL1Reader {
    pub(crate) fn with_storage<T>(
        &self,
        block_number: u64,
        f: impl FnOnce() -> tempo_precompiles::Result<T>,
    ) -> tempo_precompiles::Result<T> {
        let mut storage_by_block = self.storage.lock().unwrap();
        let storage = storage_by_block
            .entry(block_number)
            .or_insert_with(|| HashMapStorageProvider::new(1));
        StorageCtx::enter(storage, f)
    }

    pub fn insert(&self, address: Address, slot: U256, block_number: u64, value: U256) {
        self.with_storage(block_number, || {
            StorageCtx::default().sstore(address, slot, value)
        })
        .unwrap();
    }

    pub fn returning(value: B256) -> Self {
        Self {
            fallback: value,
            ..Default::default()
        }
    }

    pub fn failing_storage() -> Self {
        Self {
            fail_storage: true,
            ..Default::default()
        }
    }

    pub fn storage_requests(&self) -> Vec<L1Slot> {
        self.storage_requests.lock().unwrap().clone()
    }

    pub fn request_count<T: Storable>(&self, block_number: u64, slot: &Slot<T>) -> usize {
        let expected = (slot.address(), B256::from(slot.slot()), block_number);
        self.storage_requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| **request == expected)
            .count()
    }

    pub fn requested<T: Storable>(&self, block_number: u64, slot: &Slot<T>) -> bool {
        self.request_count(block_number, slot) != 0
    }

    pub fn seed_active_sequencer(
        &self,
        portal_address: Address,
        block_number: u64,
        account: Address,
    ) {
        self.with_storage(block_number, || {
            ZonePortalStorage::new(portal_address).role[account]
                .write(u8::from(tempo_contracts::zones::ZonePortal::Role::Sequencer))
        })
        .unwrap();
    }

    pub fn seed_simple_policy(
        &self,
        block_number: u64,
        policy_id: u64,
        policy_type: tempo_contracts::precompiles::ITIP403Registry::PolicyType,
        accounts: &[Address],
    ) -> tempo_precompiles::Result<()> {
        self.with_storage(block_number, || {
            let mut registry = TIP403Registry::new();
            let next_policy_id = registry.policy_id_counter()?.max(policy_id + 1);
            registry.policy_id_counter.write(next_policy_id)?;
            registry.policy_records[policy_id].base.write(PolicyData {
                policy_type: policy_type as u8,
                admin: Address::ZERO,
            })?;
            for account in accounts {
                registry.policy_set[policy_id][*account].write(true)?;
            }
            Ok(())
        })
    }

    pub fn seed_blacklist_policy(
        &self,
        block_number: u64,
        policy_id: u64,
        accounts: &[Address],
    ) -> tempo_precompiles::Result<()> {
        self.seed_simple_policy(
            block_number,
            policy_id,
            tempo_contracts::precompiles::ITIP403Registry::PolicyType::BLACKLIST,
            accounts,
        )
    }

    pub fn seed_compound_policy(
        &self,
        block_number: u64,
        policy_id: u64,
        sender_policy_id: u64,
        recipient_policy_id: u64,
        mint_recipient_policy_id: u64,
    ) -> tempo_precompiles::Result<()> {
        self.with_storage(block_number, || {
            let mut registry = TIP403Registry::new();
            let next_policy_id = registry.policy_id_counter()?.max(policy_id + 1);
            registry.policy_id_counter.write(next_policy_id)?;
            registry.policy_records[policy_id].base.write(PolicyData {
                policy_type: tempo_contracts::precompiles::ITIP403Registry::PolicyType::COMPOUND
                    as u8,
                admin: Address::ZERO,
            })?;
            registry.policy_records[policy_id]
                .compound
                .write(CompoundPolicyData {
                    sender_policy_id,
                    recipient_policy_id,
                    mint_recipient_policy_id,
                })?;
            Ok(())
        })
    }
}

impl L1StorageReader for MockL1Reader {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        self.storage_requests
            .lock()
            .unwrap()
            .push((account, slot, block_number));
        if self.fail_storage {
            return Err(L1StateError::StorageUnavailable {
                account,
                slot,
                block_number,
                reason: "RPC unavailable".into(),
            });
        }

        let value = match self.storage.lock().unwrap().get_mut(&block_number) {
            Some(storage) => storage.sload(account, slot.into()).map_err(|err| {
                L1StateError::StorageUnavailable {
                    account,
                    slot,
                    block_number,
                    reason: err.to_string(),
                }
            })?,
            None => U256::ZERO,
        };
        if value.is_zero() {
            Ok(self.fallback)
        } else {
            Ok(value.into())
        }
    }
}
