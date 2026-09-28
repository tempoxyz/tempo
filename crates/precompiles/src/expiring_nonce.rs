//! Block-bucket replay protection for expiring nonce transactions.
use crate::{
    EXPIRING_NONCE_PRECOMPILE_ADDRESS, Precompile, charge_input_cost, dispatch,
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256};
use tempo_contracts::precompiles::NonceError;
use tempo_precompiles_macros::contract;

#[contract(addr = EXPIRING_NONCE_PRECOMPILE_ADDRESS)]
pub struct ExpiringNonceManager {
    seen: Mapping<B256, u64>,
    bucket: Mapping<u64, Mapping<u64, B256>>,
    bucket_count: Mapping<u64, u64>,
    bucket_max_expiry: Mapping<u64, u64>,
    oldest_unpruned_block: u64,
}

/// Progress through a prune operation against a fixed parent state.
#[derive(Debug, Default)]
pub struct PruneCursor {
    block: Option<u64>,
    index: u64,
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
        let mut seen = self.seen.at_owned(&hash);
        if seen.read()? > now {
            return Err(NonceError::expiring_nonce_replay().into());
        }
        let block = self.storage.block_number();
        let mut bucket_count = self.bucket_count.at_owned(&block);
        let count = bucket_count.read()?;
        let next = count
            .checked_add(1)
            .ok_or_else(NonceError::nonce_overflow)?;
        seen.write(valid_before)?;
        self.bucket.at_owned(&block).at_owned(&count).write(hash)?;
        bucket_count.write(next)?;
        let mut max_expiry = self.bucket_max_expiry.at_owned(&block);
        if valid_before > max_expiry.read()? {
            max_expiry.write(valid_before)?;
        }
        Ok(())
    }

    /// Prunes whole buckets in block order, stopping at the first potentially live bucket.
    pub fn prune(&mut self) -> Result<()> {
        self.prune_chunk(&mut PruneCursor::default(), u64::MAX)
            .map(|_| ())
    }

    /// Deletes at most `limit` entries, returning whether pruning is complete.
    ///
    /// The caller must finish every chunk before publishing the block. The storage cursor
    /// advances only in the final chunk; intermediate progress lives in `cursor`.
    pub fn prune_chunk(&mut self, cursor: &mut PruneCursor, mut limit: u64) -> Result<bool> {
        assert!(limit > 0);
        let current_block = self.storage.block_number();
        let now = self.storage.timestamp().saturating_to::<u64>();
        if cursor.block.is_none() {
            cursor.block = Some(self.oldest_unpruned_block.read()?);
        }
        let block = cursor.block.as_mut().expect("initialized above");
        while *block < current_block {
            let mut max_expiry = self.bucket_max_expiry.at_owned(block);
            if max_expiry.read()? > now {
                break;
            }
            let mut bucket_count = self.bucket_count.at_owned(block);
            let count = bucket_count.read()?;
            let bucket = self.bucket.at_owned(block);
            let end = count.min(cursor.index.saturating_add(limit));
            for i in cursor.index..end {
                let mut entry = bucket.at_owned(&i);
                let hash = entry.read()?;
                self.seen.at_owned(&hash).write(0)?;
                entry.write(B256::ZERO)?;
            }
            limit -= end - cursor.index;
            cursor.index = end;
            if end < count {
                return Ok(false);
            }
            if count != 0 {
                bucket_count.write(0)?;
                max_expiry.write(0)?;
            }
            *block += 1;
            cursor.index = 0;
            if limit == 0 {
                return Ok(false);
            }
        }
        if *block != self.oldest_unpruned_block.read()? {
            self.oldest_unpruned_block.write(*block)?;
        }
        Ok(true)
    }
}

impl Precompile for ExpiringNonceManager {
    fn call(&mut self, calldata: &[u8], _sender: Address) -> revm::precompile::PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }
        // This precompile exposes storage only; mutations come from the EVM.
        if calldata.len() >= 4 {
            dispatch::unknown_selector_result(calldata)
        } else {
            dispatch::missing_selector_result()
        }
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
    fn expiring_nonce_prunes_in_block_order_at_latest_expiry() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        storage.set_timestamp(U256::from(1000));
        storage.set_block_number(7);
        let first = B256::repeat_byte(1);
        let second = B256::repeat_byte(2);
        let third = B256::repeat_byte(3);
        let later = B256::repeat_byte(4);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            mgr.check_and_mark_expiring_nonce(first, 1100)?;
            mgr.check_and_mark_expiring_nonce(second, 1300)?;
            mgr.check_and_mark_expiring_nonce(third, 1200)?;
            assert_eq!(mgr.bucket_max_expiry[7].read()?, 1300);
            assert_eq!(mgr.bucket_count[7].read()?, 3);
            assert_eq!(mgr.bucket[7][0].read()?, first);
            assert_eq!(mgr.bucket[7][1].read()?, second);
            Ok::<_, eyre::Report>(())
        })?;
        // Block 8 is empty; block 9 expires before block 7.
        storage.set_block_number(9);
        StorageCtx::enter(&mut storage, || {
            ExpiringNonceManager::new().check_and_mark_expiring_nonce(later, 1200)
        })?;
        storage.set_block_number(10);
        storage.set_timestamp(U256::from(1299));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            mgr.prune()?;
            assert_eq!(mgr.oldest_unpruned_block.read()?, 7);
            assert_eq!(mgr.seen[first].read()?, 1100);
            assert_eq!(mgr.seen[later].read()?, 1200);
            Ok::<_, eyre::Report>(())
        })?;
        storage.set_block_number(11);
        storage.set_timestamp(U256::from(1300));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            // The current block's bucket must remain untouched.
            let current = B256::repeat_byte(5);
            mgr.check_and_mark_expiring_nonce(current, 1301)?;
            let mut cursor = PruneCursor::default();
            assert!(!mgr.prune_chunk(&mut cursor, 2)?);
            assert_eq!(mgr.oldest_unpruned_block.read()?, 7);
            assert_eq!(mgr.bucket_count[7].read()?, 3);
            assert_eq!(mgr.seen[first].read()?, 0);
            assert_eq!(mgr.seen[second].read()?, 0);
            assert_eq!(mgr.seen[third].read()?, 1200);
            while !mgr.prune_chunk(&mut cursor, 2)? {}
            assert_eq!(mgr.oldest_unpruned_block.read()?, 11);
            for hash in [first, second, third, later] {
                assert_eq!(mgr.seen[hash].read()?, 0);
            }
            for block in [7, 8, 9, 10] {
                assert_eq!(mgr.bucket_count[block].read()?, 0);
                assert_eq!(mgr.bucket_max_expiry[block].read()?, 0);
            }
            for i in 0..3 {
                assert_eq!(mgr.bucket[7][i].read()?, B256::ZERO);
            }
            assert_eq!(mgr.bucket[9][0].read()?, B256::ZERO);
            assert_eq!(mgr.seen[current].read()?, 1301);
            assert_eq!(mgr.bucket_count[11].read()?, 1);
            mgr.prune()?;
            Ok(())
        })
    }

    #[test]
    fn expiring_nonce_pruning_waits_for_time_even_after_many_blocks() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1000));
        storage.set_block_number(0);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            mgr.check_and_mark_expiring_nonce(B256::ZERO, 1030)?;
            mgr.prune()?;
            Ok::<_, eyre::Report>(())
        })?;
        storage.set_block_number(1_000_000);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            mgr.prune()?;
            assert_eq!(mgr.oldest_unpruned_block.read()?, 0);
            assert_eq!(mgr.seen[B256::ZERO].read()?, 1030);
            Ok(())
        })
    }
    #[test]
    fn expiring_nonce_has_no_external_prune_method() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1000));
        storage.set_block_number(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = ExpiringNonceManager::new();
            let hash = B256::repeat_byte(1);
            mgr.seen[hash].write(999)?;
            mgr.bucket[0][0].write(hash)?;
            mgr.bucket_count[0].write(1)?;
            mgr.bucket_max_expiry[0].write(999)?;
            let selector = alloy::primitives::keccak256("prune()");
            let output = mgr.call(&selector[..4], Address::ZERO)?;
            assert!(matches!(
                output.status,
                revm::precompile::PrecompileStatus::Revert
            ));
            assert_eq!(mgr.seen[hash].read()?, 999);
            assert_eq!(mgr.bucket_count[0].read()?, 1);
            Ok(())
        })
    }
}
