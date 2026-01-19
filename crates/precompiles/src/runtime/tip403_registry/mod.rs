//! TIP403 transfer policy registry implementation module.

use crate::{
    TIP403_REGISTRY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, U256};
use tempo_precompiles_macros::{Storable, contract};

pub use crate::abi::{ITIP403Registry, ITIP403Registry::PolicyType};

#[derive(Debug, Clone, Storable)]
pub struct PolicyData {
    pub policy_type: PolicyType,
    pub admin: Address,
}

#[contract(addr = TIP403_REGISTRY_ADDRESS, abi = ITIP403Registry, dispatch)]
pub struct TIP403Registry {
    policy_id_counter: u64,
    policy_data: Mapping<u64, PolicyData>,
    policy_set: Mapping<u64, Mapping<Address, bool>>,
}

// NOTE(rusowsky): can be removed once revm uses precompiles rather than directly
// interacting with storage slots.
impl PolicyData {
    pub fn decode_from_slot(slot_value: U256) -> Self {
        use crate::storage::{LayoutCtx, Storable, packing::PackedSlot};

        // NOTE: fine to expect, as `StorageOps` on `PackedSlot` are infallible
        Self::load(&PackedSlot(slot_value), U256::ZERO, LayoutCtx::FULL)
            .expect("unable to decode PoliciData from slot")
    }

    pub fn encode_to_slot(&self) -> U256 {
        use crate::storage::packing::insert_into_word;
        use __packing_policy_data::{ADMIN_LOC as A_LOC, POLICY_TYPE_LOC as PT_LOC};

        let encoded = insert_into_word(
            U256::ZERO,
            &self.policy_type,
            PT_LOC.offset_bytes,
            PT_LOC.size,
        )
        .expect("unable to insert 'policy_type'");

        insert_into_word(encoded, &self.admin, A_LOC.offset_bytes, A_LOC.size)
            .expect("unable to insert 'admin'")
    }
}

impl TIP403Registry {
    /// Initializes the registry contract.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    // Internal helper functions
    fn get_policy_data(&self, policy_id: u64) -> Result<PolicyData> {
        self.policy_data[policy_id].read()
    }

    fn set_policy_data(&mut self, policy_id: u64, data: PolicyData) -> Result<()> {
        self.policy_data[policy_id].write(data)
    }

    fn set_policy_set(&mut self, policy_id: u64, account: Address, value: bool) -> Result<()> {
        self.policy_set[policy_id][account].write(value)
    }

    fn is_authorized_internal(&self, policy_id: u64, user: Address) -> Result<bool> {
        // Special case for always-allow and always-reject policies
        if policy_id < 2 {
            return Ok(policy_id == 1);
        }

        let data = self.get_policy_data(policy_id)?;
        let is_in_set = self.policy_set[policy_id][user].read()?;

        let auth = match data.policy_type {
            PolicyType::WHITELIST => is_in_set,
            PolicyType::BLACKLIST => !is_in_set,
        };

        Ok(auth)
    }

    fn policy_id_counter_internal(&self) -> Result<u64> {
        self.policy_id_counter.read().map(|counter| counter.max(2))
    }

    fn policy_exists_internal(&self, policy_id: u64) -> Result<bool> {
        if policy_id < 2 {
            return Ok(true);
        }
        let counter = self.policy_id_counter_internal()?;
        Ok(policy_id < counter)
    }
}

impl ITIP403Registry::IRegistry for TIP403Registry {
    fn policy_id_counter(&self) -> Result<u64> {
        self.policy_id_counter_internal()
    }

    fn policy_exists(&self, policy_id: u64) -> Result<bool> {
        self.policy_exists_internal(policy_id)
    }

    fn policy_data(&self, policy_id: u64) -> Result<(PolicyType, Address)> {
        if !self.policy_exists_internal(policy_id)? {
            return Err(TIP403RegistryError::policy_not_found().into());
        }

        let data = self.get_policy_data(policy_id)?;
        Ok((data.policy_type, data.admin))
    }

    fn is_authorized(&self, policy_id: u64, user: Address) -> Result<bool> {
        self.is_authorized_internal(policy_id, user)
    }

    fn create_policy(
        &mut self,
        msg_sender: Address,
        admin: Address,
        policy_type: PolicyType,
    ) -> Result<u64> {
        let new_policy_id = self.policy_id_counter_internal()?;

        self.policy_id_counter.write(
            new_policy_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        self.policy_data[new_policy_id].write(PolicyData { policy_type, admin })?;

        self.emit_event(TIP403RegistryEvent::policy_created(
            new_policy_id,
            msg_sender,
            policy_type,
        ))?;

        self.emit_event(TIP403RegistryEvent::policy_admin_updated(
            new_policy_id,
            msg_sender,
            admin,
        ))?;

        Ok(new_policy_id)
    }

    fn create_policy_with_accounts(
        &mut self,
        msg_sender: Address,
        admin: Address,
        policy_type: PolicyType,
        accounts: Vec<Address>,
    ) -> Result<u64> {
        let new_policy_id = self.policy_id_counter_internal()?;

        self.policy_id_counter.write(
            new_policy_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        self.set_policy_data(new_policy_id, PolicyData { policy_type, admin })?;

        for account in accounts.iter() {
            self.set_policy_set(new_policy_id, *account, true)?;

            match policy_type {
                PolicyType::WHITELIST => {
                    self.emit_event(TIP403RegistryEvent::whitelist_updated(
                        new_policy_id,
                        msg_sender,
                        *account,
                        true,
                    ))?;
                }
                PolicyType::BLACKLIST => {
                    self.emit_event(TIP403RegistryEvent::blacklist_updated(
                        new_policy_id,
                        msg_sender,
                        *account,
                        true,
                    ))?;
                }
            }
        }

        self.emit_event(TIP403RegistryEvent::policy_created(
            new_policy_id,
            msg_sender,
            policy_type,
        ))?;

        self.emit_event(TIP403RegistryEvent::policy_admin_updated(
            new_policy_id,
            msg_sender,
            admin,
        ))?;

        Ok(new_policy_id)
    }

    fn set_policy_admin(
        &mut self,
        msg_sender: Address,
        policy_id: u64,
        admin: Address,
    ) -> Result<()> {
        let data = self.get_policy_data(policy_id)?;

        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }

        self.set_policy_data(policy_id, PolicyData { admin, ..data })?;

        self.emit_event(TIP403RegistryEvent::policy_admin_updated(
            policy_id, msg_sender, admin,
        ))
    }

    fn modify_policy_whitelist(
        &mut self,
        msg_sender: Address,
        policy_id: u64,
        account: Address,
        allowed: bool,
    ) -> Result<()> {
        let data = self.get_policy_data(policy_id)?;

        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }

        if data.policy_type != PolicyType::WHITELIST {
            return Err(TIP403RegistryError::incompatible_policy_type().into());
        }

        self.set_policy_set(policy_id, account, allowed)?;

        self.emit_event(TIP403RegistryEvent::whitelist_updated(
            policy_id, msg_sender, account, allowed,
        ))
    }

    fn modify_policy_blacklist(
        &mut self,
        msg_sender: Address,
        policy_id: u64,
        account: Address,
        restricted: bool,
    ) -> Result<()> {
        let data = self.get_policy_data(policy_id)?;

        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }

        if data.policy_type != PolicyType::BLACKLIST {
            return Err(TIP403RegistryError::incompatible_policy_type().into());
        }

        self.set_policy_set(policy_id, account, restricted)?;

        self.emit_event(TIP403RegistryEvent::blacklist_updated(
            policy_id, msg_sender, account, restricted,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::primitives::Address;
    use rand::Rng;

    #[test]
    fn test_create_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            assert_eq!(ITIP403Registry::IRegistry::policy_id_counter(&registry)?, 2);

            let result = ITIP403Registry::IRegistry::create_policy(
                &mut registry,
                admin,
                admin,
                PolicyType::WHITELIST,
            );
            assert!(result.is_ok());
            assert_eq!(result?, 2);

            assert_eq!(ITIP403Registry::IRegistry::policy_id_counter(&registry)?, 3);

            let data = ITIP403Registry::IRegistry::policy_data(&registry, 2)?;
            assert_eq!(data.0, PolicyType::WHITELIST);
            assert_eq!(data.1, admin);
            Ok(())
        })
    }

    #[test]
    fn test_is_authorized_special_policies() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();

            assert!(!ITIP403Registry::IRegistry::is_authorized(
                &registry, 0, user
            )?);
            assert!(ITIP403Registry::IRegistry::is_authorized(
                &registry, 1, user
            )?);
            Ok(())
        })
    }

    #[test]
    fn test_whitelist_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let policy_id = ITIP403Registry::IRegistry::create_policy(
                &mut registry,
                admin,
                admin,
                PolicyType::WHITELIST,
            )?;

            assert!(!ITIP403Registry::IRegistry::is_authorized(
                &registry, policy_id, user
            )?);

            ITIP403Registry::IRegistry::modify_policy_whitelist(
                &mut registry,
                admin,
                policy_id,
                user,
                true,
            )?;

            assert!(ITIP403Registry::IRegistry::is_authorized(
                &registry, policy_id, user
            )?);

            Ok(())
        })
    }

    #[test]
    fn test_blacklist_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let policy_id = ITIP403Registry::IRegistry::create_policy(
                &mut registry,
                admin,
                admin,
                PolicyType::BLACKLIST,
            )?;

            assert!(ITIP403Registry::IRegistry::is_authorized(
                &registry, policy_id, user
            )?);

            ITIP403Registry::IRegistry::modify_policy_blacklist(
                &mut registry,
                admin,
                policy_id,
                user,
                true,
            )?;

            assert!(!ITIP403Registry::IRegistry::is_authorized(
                &registry, policy_id, user
            )?);

            Ok(())
        })
    }

    #[test]
    fn test_policy_data_reverts_for_non_existent_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();

            let result = ITIP403Registry::IRegistry::policy_data(&registry, 100);
            assert!(result.is_err());

            let err = result.unwrap_err();
            assert!(matches!(
                err,
                crate::error::TempoPrecompileError::TIP403Registry(
                    TIP403RegistryError::PolicyNotFound(_)
                )
            ));

            Ok(())
        })
    }

    #[test]
    fn test_policy_exists() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            assert!(ITIP403Registry::IRegistry::policy_exists(&registry, 0)?);
            assert!(ITIP403Registry::IRegistry::policy_exists(&registry, 1)?);

            let mut rng = rand::thread_rng();
            for _ in 0..100 {
                let random_policy_id = rng.gen_range(2..u64::MAX);
                assert!(!ITIP403Registry::IRegistry::policy_exists(
                    &registry,
                    random_policy_id
                )?);
            }

            let mut created_policy_ids = Vec::new();
            for i in 0..50 {
                let policy_id = ITIP403Registry::IRegistry::create_policy(
                    &mut registry,
                    admin,
                    admin,
                    if i % 2 == 0 {
                        PolicyType::WHITELIST
                    } else {
                        PolicyType::BLACKLIST
                    },
                )?;
                created_policy_ids.push(policy_id);
            }

            for policy_id in &created_policy_ids {
                assert!(ITIP403Registry::IRegistry::policy_exists(
                    &registry, *policy_id
                )?);
            }

            Ok(())
        })
    }
}
