pub mod dispatch;

use tempo_contracts::precompiles::FEATURE_REGISTRY_ADDRESS;
pub use tempo_contracts::precompiles::{FeatureRegistryError, IFeatureRegistry};
use tempo_precompiles_macros::contract;

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, U256};

/// Feature Registry precompile.
///
/// Stores a bitmap of active features and supports:
/// - Immediate activation/deactivation by the admin (owner)
/// - Timestamp-scheduled activation with admin killswitch
///
/// Storage layout:
/// - Slot 0: admin config (owner address)
/// - Slot 1: feature bitmap (mapping from word_index → u256)
/// - Slot 2: scheduled activations (mapping from feature_id → timestamp)
#[contract(addr = FEATURE_REGISTRY_ADDRESS)]
pub struct FeatureRegistry {
    owner: Address,
    features: Mapping<u64, U256>,
    scheduled: Mapping<u32, u64>,
}

impl FeatureRegistry {
    /// Initialize the feature registry with the given admin owner.
    pub fn initialize(&mut self, admin: Address) -> Result<()> {
        self.__initialize()?;
        self.owner.write(admin)
    }

    // =========================================================================
    // View functions
    // =========================================================================

    /// Get the admin owner address.
    pub fn owner(&self) -> Result<Address> {
        self.owner.read()
    }

    /// Get a single 256-bit word of the feature bitmap.
    pub fn feature_word(&self, index: u64) -> Result<U256> {
        self.features[index].read()
    }

    /// Check whether a specific feature is active.
    ///
    /// A feature is active if its bit is set in the bitmap, OR if it has a
    /// scheduled activation timestamp that has passed.
    pub fn is_active(&self, feature_id: u32) -> Result<bool> {
        // Check the bitmap first
        let word_index = (feature_id / 256) as u64;
        let bit_index = feature_id % 256;
        let word = self.features[word_index].read()?;
        if word & (U256::from(1) << bit_index) != U256::ZERO {
            return Ok(true);
        }

        // Check scheduled activation
        let scheduled_at = self.scheduled[feature_id].read()?;
        if scheduled_at != 0 {
            let now: u64 = self.storage.timestamp().saturating_to();
            if now >= scheduled_at {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get the scheduled activation timestamp for a feature (0 if not scheduled).
    pub fn scheduled_activation(&self, feature_id: u32) -> Result<u64> {
        self.scheduled[feature_id].read()
    }

    // =========================================================================
    // Mutate functions (owner only)
    // =========================================================================

    fn require_owner(&self, caller: Address) -> Result<()> {
        let admin = self.owner.read()?;
        if caller != admin {
            Err(FeatureRegistryError::unauthorized())?
        }
        Ok(())
    }

    /// Immediately activate a feature by setting its bit in the bitmap.
    pub fn activate(&mut self, caller: Address, feature_id: u32) -> Result<()> {
        self.require_owner(caller)?;

        let word_index = (feature_id / 256) as u64;
        let bit_index = feature_id % 256;
        let word = self.features[word_index].read()?;
        let bit = U256::from(1) << bit_index;

        if word & bit != U256::ZERO {
            Err(FeatureRegistryError::feature_already_active(feature_id))?
        }

        self.features[word_index].write(word | bit)?;

        // Clear any scheduled activation since the feature is now active
        let scheduled_at = self.scheduled[feature_id].read()?;
        if scheduled_at != 0 {
            self.scheduled[feature_id].write(0)?;
        }

        Ok(())
    }

    /// Immediately deactivate a feature (killswitch).
    ///
    /// This clears the bit in the bitmap AND cancels any scheduled activation.
    pub fn deactivate(&mut self, caller: Address, feature_id: u32) -> Result<()> {
        self.require_owner(caller)?;

        let word_index = (feature_id / 256) as u64;
        let bit_index = feature_id % 256;
        let word = self.features[word_index].read()?;
        let bit = U256::from(1) << bit_index;

        let was_active = word & bit != U256::ZERO;
        let scheduled_at = self.scheduled[feature_id].read()?;

        if !was_active && scheduled_at == 0 {
            Err(FeatureRegistryError::feature_not_active(feature_id))?
        }

        // Clear the bit
        if was_active {
            self.features[word_index].write(word & !bit)?;
        }

        // Also cancel any scheduled activation
        if scheduled_at != 0 {
            self.scheduled[feature_id].write(0)?;
        }

        Ok(())
    }

    /// Schedule a feature to activate at a future timestamp.
    pub fn schedule_activation(
        &mut self,
        caller: Address,
        feature_id: u32,
        activate_at: u64,
    ) -> Result<()> {
        self.require_owner(caller)?;

        // Must be in the future
        let now: u64 = self.storage.timestamp().saturating_to();
        if activate_at <= now {
            Err(FeatureRegistryError::invalid_activation_time())?
        }

        // Must not already be active
        let word_index = (feature_id / 256) as u64;
        let bit_index = feature_id % 256;
        let word = self.features[word_index].read()?;
        if word & (U256::from(1) << bit_index) != U256::ZERO {
            Err(FeatureRegistryError::feature_already_active(feature_id))?
        }

        // Must not already be scheduled
        let existing = self.scheduled[feature_id].read()?;
        if existing != 0 {
            Err(FeatureRegistryError::feature_already_scheduled(feature_id))?
        }

        self.scheduled[feature_id].write(activate_at)
    }

    /// Cancel a scheduled activation (killswitch for scheduled features).
    pub fn cancel_scheduled_activation(
        &mut self,
        caller: Address,
        feature_id: u32,
    ) -> Result<()> {
        self.require_owner(caller)?;

        let scheduled_at = self.scheduled[feature_id].read()?;
        if scheduled_at == 0 {
            Err(FeatureRegistryError::feature_not_scheduled(feature_id))?
        }

        self.scheduled[feature_id].write(0)
    }

    /// Transfer admin ownership.
    pub fn transfer_ownership(&mut self, caller: Address, new_owner: Address) -> Result<()> {
        self.require_owner(caller)?;

        if new_owner == Address::ZERO {
            Err(FeatureRegistryError::invalid_owner())?
        }

        self.owner.write(new_owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider};

    #[test]
    fn test_initialize_and_owner() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            assert!(reg.is_initialized()?);
            assert_eq!(reg.owner()?, admin);
            Ok(())
        })
    }

    #[test]
    fn test_activate_and_deactivate() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            assert!(!reg.is_active(0)?);

            reg.activate(admin, 0)?;
            assert!(reg.is_active(0)?);

            reg.deactivate(admin, 0)?;
            assert!(!reg.is_active(0)?);

            Ok(())
        })
    }

    #[test]
    fn test_activate_rejects_non_owner() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let non_owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            let result = reg.activate(non_owner, 0);
            assert_eq!(
                result,
                Err(FeatureRegistryError::unauthorized().into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_activate_already_active() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            reg.activate(admin, 5)?;
            let result = reg.activate(admin, 5);
            assert_eq!(
                result,
                Err(FeatureRegistryError::feature_already_active(5).into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_deactivate_not_active() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            let result = reg.deactivate(admin, 42);
            assert_eq!(
                result,
                Err(FeatureRegistryError::feature_not_active(42).into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_schedule_activation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1000u64));
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            // Schedule for timestamp 2000
            reg.schedule_activation(admin, 7, 2000)?;
            assert_eq!(reg.scheduled_activation(7)?, 2000);

            // Not active yet (current time is 1000)
            assert!(!reg.is_active(7)?);

            Ok::<_, eyre::Report>(())
        })?;

        // After the scheduled time, feature should be active
        storage.set_timestamp(U256::from(2000u64));
        StorageCtx::enter(&mut storage, || {
            let reg = FeatureRegistry::new();
            assert!(reg.is_active(7)?);
            Ok(())
        })
    }

    #[test]
    fn test_schedule_past_timestamp_fails() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1000u64));
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            let result = reg.schedule_activation(admin, 7, 500);
            assert_eq!(
                result,
                Err(FeatureRegistryError::invalid_activation_time().into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_cancel_scheduled_activation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1000u64));
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            reg.schedule_activation(admin, 3, 2000)?;
            assert_eq!(reg.scheduled_activation(3)?, 2000);

            // Killswitch: cancel the scheduled activation
            reg.cancel_scheduled_activation(admin, 3)?;
            assert_eq!(reg.scheduled_activation(3)?, 0);
            assert!(!reg.is_active(3)?);

            Ok(())
        })
    }

    #[test]
    fn test_cancel_not_scheduled() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            let result = reg.cancel_scheduled_activation(admin, 99);
            assert_eq!(
                result,
                Err(FeatureRegistryError::feature_not_scheduled(99).into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_deactivate_killswitches_scheduled_feature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1000u64));
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            // Schedule feature
            reg.schedule_activation(admin, 10, 2000)?;
            assert_eq!(reg.scheduled_activation(10)?, 2000);

            // Deactivate also cancels scheduled (even though bit isn't set)
            reg.deactivate(admin, 10)?;
            assert_eq!(reg.scheduled_activation(10)?, 0);
            assert!(!reg.is_active(10)?);

            Ok(())
        })
    }

    #[test]
    fn test_activate_clears_schedule() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1000u64));
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            reg.schedule_activation(admin, 4, 2000)?;
            assert_eq!(reg.scheduled_activation(4)?, 2000);

            // Immediately activate should clear the schedule
            reg.activate(admin, 4)?;
            assert!(reg.is_active(4)?);
            assert_eq!(reg.scheduled_activation(4)?, 0);

            Ok(())
        })
    }

    #[test]
    fn test_multiple_features_independent() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            reg.activate(admin, 0)?;
            reg.activate(admin, 5)?;
            reg.activate(admin, 11)?;

            assert!(reg.is_active(0)?);
            assert!(!reg.is_active(1)?);
            assert!(reg.is_active(5)?);
            assert!(reg.is_active(11)?);

            reg.deactivate(admin, 5)?;
            assert!(reg.is_active(0)?);
            assert!(!reg.is_active(5)?);
            assert!(reg.is_active(11)?);

            Ok(())
        })
    }

    #[test]
    fn test_high_feature_ids() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            // Feature ID 300 (word index 1, bit 44)
            reg.activate(admin, 300)?;
            assert!(reg.is_active(300)?);
            assert!(!reg.is_active(299)?);

            // Feature ID 1000 (word index 3, bit 232)
            reg.activate(admin, 1000)?;
            assert!(reg.is_active(1000)?);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_ownership() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let new_admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            reg.transfer_ownership(admin, new_admin)?;
            assert_eq!(reg.owner()?, new_admin);

            // Old admin can no longer activate
            let result = reg.activate(admin, 0);
            assert_eq!(
                result,
                Err(FeatureRegistryError::unauthorized().into())
            );

            // New admin can
            reg.activate(new_admin, 0)?;
            assert!(reg.is_active(0)?);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_ownership_to_zero_fails() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            let result = reg.transfer_ownership(admin, Address::ZERO);
            assert_eq!(
                result,
                Err(FeatureRegistryError::invalid_owner().into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_feature_word_returns_bitmap() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            reg.activate(admin, 0)?;
            reg.activate(admin, 3)?;

            let word = reg.feature_word(0)?;
            // Bits 0 and 3 set: 0b1001 = 9
            assert_eq!(word, U256::from(9));

            // Second word should be empty
            let word1 = reg.feature_word(1)?;
            assert_eq!(word1, U256::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_schedule_already_active_fails() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1000u64));
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            reg.activate(admin, 1)?;
            let result = reg.schedule_activation(admin, 1, 2000);
            assert_eq!(
                result,
                Err(FeatureRegistryError::feature_already_active(1).into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_schedule_already_scheduled_fails() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1000u64));
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            reg.schedule_activation(admin, 2, 2000)?;
            let result = reg.schedule_activation(admin, 2, 3000);
            assert_eq!(
                result,
                Err(FeatureRegistryError::feature_already_scheduled(2).into())
            );
            Ok(())
        })
    }
}
