//! Block-bucket replay protection for expiring nonce transactions.
use crate::{
    EXPIRING_NONCE_PRECOMPILE_ADDRESS, Precompile, charge_input_cost, dispatch,
    error::Result,
    mutate_void,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256};
use tempo_contracts::precompiles::{IExpiringNonce, NonceError};
use tempo_precompiles_macros::contract;

/// Five minutes at the minimum one-millisecond block interval.
pub const MAX_EXPIRY_NUM_BLOCKS: u64 = 300_000;

#[contract(addr = EXPIRING_NONCE_PRECOMPILE_ADDRESS)]
pub struct ExpiringNonceManager {
    seen: Mapping<B256, u64>,
    bucket: Mapping<u64, Mapping<u64, B256>>,
    bucket_count: Mapping<u64, u64>,
}

impl ExpiringNonceManager {
    /// Checks replay protection and appends the hash to this block's bucket.
    pub fn check_and_mark_expiring_nonce(&mut self, hash: B256, valid_before: u64) -> Result<()> {
        let now = self.storage.timestamp().saturating_to::<u64>();
        if valid_before <= now
            || valid_before
                > now.saturating_add(self.storage.spec().expiring_nonce_max_expiry_secs())
        {
            return Err(NonceError::invalid_expiring_nonce_expiry().into());
        }
        if self.seen[hash].read()? > now {
            return Err(NonceError::expiring_nonce_replay().into());
        }
        let block = self.storage.block_number();
        let count = self.bucket_count[block].read()?;
        let next = count
            .checked_add(1)
            .ok_or_else(NonceError::nonce_overflow)?;
        self.seen[hash].write(valid_before)?;
        self.bucket[block][count].write(hash)?;
        self.bucket_count[block].write(next)?;
        Ok(())
    }

    /// Clears the retired block's hashes, bucket entries, and count at block end.
    pub fn prune(&mut self, sender: Address) -> Result<()> {
        if sender != Address::ZERO {
            return Err(tempo_contracts::precompiles::CurrentCommitteeError::unauthorized().into());
        }
        let Some(block) = self
            .storage
            .block_number()
            .checked_sub(MAX_EXPIRY_NUM_BLOCKS)
        else {
            return Ok(());
        };
        let count = self.bucket_count[block].read()?;
        for i in 0..count {
            let hash = self.bucket[block][i].read()?;
            // Fail closed if a chain configuration allows blocks faster than the
            // retention bound (for example, equal timestamps in development).
            if self.seen[hash].read()? > self.storage.timestamp().saturating_to::<u64>() {
                return Err(crate::error::TempoPrecompileError::Fatal(
                    "expiring nonce bucket contains an unexpired hash".into(),
                ));
            }
            self.seen[hash].write(0)?;
            self.bucket[block][i].write(B256::ZERO)?;
        }
        if count != 0 {
            self.bucket_count[block].write(0)?;
        }
        Ok(())
    }
}

impl Precompile for ExpiringNonceManager {
    fn call(&mut self, calldata: &[u8], sender: Address) -> revm::precompile::PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }
        dispatch!(calldata, |call| match call {
            IExpiringNonce::IExpiringNonceCalls {
                prune(call) => mutate_void(call, sender, |s, _| self.prune(s))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::U256;
    use tempo_chainspec::hardfork::TempoHardfork;
    #[test]
    fn test_expiring_nonce_basic_flow() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();

            let tx_hash = B256::repeat_byte(0x11);
            let valid_before = now + 20; // 20s in future, within 30s window

            // First tx should succeed
            mgr.check_and_mark_expiring_nonce(tx_hash, valid_before)?;

            // Same tx hash should fail (replay)
            let result = mgr.check_and_mark_expiring_nonce(tx_hash, valid_before);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_replay())
            );

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_expiry_validation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();

            let tx_hash = B256::repeat_byte(0x22);

            // valid_before in the past should fail
            let result = mgr.check_and_mark_expiring_nonce(tx_hash, now - 1);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );

            // valid_before exactly at now should fail
            let result = mgr.check_and_mark_expiring_nonce(tx_hash, now);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );

            // valid_before too far in future should fail before T11.
            let result = mgr.check_and_mark_expiring_nonce(tx_hash, now + 31);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );

            // valid_before at exactly the pre-T11 maximum should succeed
            mgr.check_and_mark_expiring_nonce(tx_hash, now + 30)?;

            Ok(())
        })
    }

    #[test]
    fn test_t11_expiring_nonce_expiry_validation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();

            mgr.check_and_mark_expiring_nonce(B256::repeat_byte(0x22), now + 300)?;
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(B256::repeat_byte(0x23), now + 301)
                    .unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );

            Ok(())
        })
    }
    #[test]
    fn expiring_nonce_prunes_only_retired_bucket() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        storage.set_timestamp(U256::from(1000));
        storage.set_block_number(7);
        let first = B256::repeat_byte(1);
        let second = B256::repeat_byte(2);
        let later = B256::repeat_byte(3);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            mgr.check_and_mark_expiring_nonce(first, 1300)?;
            mgr.check_and_mark_expiring_nonce(second, 1300)?;
            assert_eq!(mgr.bucket_count[7].read()?, 2);
            assert_eq!(mgr.bucket[7][0].read()?, first);
            assert_eq!(mgr.bucket[7][1].read()?, second);
            Ok::<_, eyre::Report>(())
        })?;
        storage.set_block_number(8);
        storage.set_timestamp(U256::from(1001));
        StorageCtx::enter(&mut storage, || {
            ExpiringNonceManager::new().check_and_mark_expiring_nonce(later, 1301)
        })?;
        storage.set_block_number(7 + MAX_EXPIRY_NUM_BLOCKS - 1);
        storage.set_timestamp(U256::from(1300));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            mgr.prune(Address::ZERO)?;
            assert_eq!(mgr.seen[first].read()?, 1300);
            Ok::<_, eyre::Report>(())
        })?;
        storage.set_block_number(7 + MAX_EXPIRY_NUM_BLOCKS);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            mgr.prune(Address::ZERO)?;
            assert_eq!(mgr.seen[first].read()?, 0);
            assert_eq!(mgr.seen[second].read()?, 0);
            assert_eq!(mgr.bucket[7][0].read()?, B256::ZERO);
            assert_eq!(mgr.bucket[7][1].read()?, B256::ZERO);
            assert_eq!(mgr.bucket_count[7].read()?, 0);
            assert_eq!(mgr.seen[later].read()?, 1301);
            assert_eq!(mgr.bucket_count[8].read()?, 1);
            mgr.prune(Address::ZERO)?;
            Ok(())
        })
    }

    #[test]
    fn expiring_nonce_pruning_rejects_live_entries_and_unauthorized_calls() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1000));
        storage.set_block_number(0);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            mgr.check_and_mark_expiring_nonce(B256::ZERO, 1030)?;
            assert!(mgr.prune(Address::repeat_byte(1)).is_err());
            mgr.prune(Address::ZERO)?;
            Ok::<_, eyre::Report>(())
        })?;
        storage.set_block_number(MAX_EXPIRY_NUM_BLOCKS);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            assert!(mgr.prune(Address::ZERO).is_err());
            assert_eq!(mgr.seen[B256::ZERO].read()?, 1030);
            Ok(())
        })
    }
}
