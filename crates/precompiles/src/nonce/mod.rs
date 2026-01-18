pub mod dispatch;

pub use tempo_contracts::precompiles::INonce;
use tempo_contracts::precompiles::{NonceError, NonceEvent};
use tempo_precompiles_macros::contract;

use crate::{
    NONCE_PRECOMPILE_ADDRESS,
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256, U256};

/// Maximum number of cascading head cleanups per write.
/// When checking the head for expiry, if expired, also check the next entries.
/// This allows the buffer to shrink quickly during low-traffic periods.
pub const MAX_CASCADE_CLEANUP: u32 = 10;

/// NonceManager contract for managing 2D nonces as per the AA spec
///
/// Storage Layout (similar to Solidity contract):
/// ```solidity
/// contract Nonce {
///     mapping(address => mapping(uint256 => uint64)) public nonces;      // slot 0
///     
///     // Expiring nonce storage (for hash-based replay protection)
///     mapping(bytes32 => uint64) public expiringNonceSeen;               // slot 1: txHash => expiry
///     mapping(uint64 => bytes32) public expiringNonceBuffer;             // slot 2: unbounded buffer of tx hashes
///     uint64 public expiringNonceHead;                                   // slot 3: head pointer (oldest entry)
///     uint64 public expiringNonceTail;                                   // slot 4: tail pointer (next write position)
/// }
/// ```
///
/// - Slot 0: 2D nonce mapping - keccak256(abi.encode(nonce_key, keccak256(abi.encode(account, 0))))
/// - Slot 1: Expiring nonce seen set - txHash => expiry timestamp
/// - Slot 2: Unbounded buffer - index => txHash (grows/shrinks dynamically)
/// - Slot 3: Head pointer - points to oldest entry (for cleanup)
/// - Slot 4: Tail pointer - points to next write position
///
/// Note: Protocol nonce (key 0) is stored directly in account state, not here.
/// Only user nonce keys (1-N) are managed by this precompile.
#[contract(addr = NONCE_PRECOMPILE_ADDRESS)]
pub struct NonceManager {
    nonces: Mapping<Address, Mapping<U256, u64>>,
    expiring_nonce_seen: Mapping<B256, u64>,
    expiring_nonce_buffer: Mapping<u64, B256>,
    expiring_nonce_head: u64,
    expiring_nonce_tail: u64,
}

impl NonceManager {
    /// Initializes the nonce manager contract.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Get the nonce for a specific account and nonce key
    pub fn get_nonce(&self, call: INonce::getNonceCall) -> Result<u64> {
        // Protocol nonce (key 0) is stored in account state, not in this precompile
        // Users should query account nonce directly, not through this precompile
        if call.nonceKey == 0 {
            return Err(NonceError::protocol_nonce_not_supported().into());
        }

        // For user nonce keys, read from precompile storage
        self.nonces[call.account][call.nonceKey].read()
    }

    /// Internal: Increment nonce for a specific account and nonce key
    pub fn increment_nonce(&mut self, account: Address, nonce_key: U256) -> Result<u64> {
        if nonce_key == 0 {
            return Err(NonceError::invalid_nonce_key().into());
        }

        let current = self.nonces[account][nonce_key].read()?;

        let new_nonce = current
            .checked_add(1)
            .ok_or_else(NonceError::nonce_overflow)?;

        self.nonces[account][nonce_key].write(new_nonce)?;

        self.emit_event(NonceEvent::NonceIncremented(INonce::NonceIncremented {
            account,
            nonceKey: nonce_key,
            newNonce: new_nonce,
        }))?;

        Ok(new_nonce)
    }

    // ========== Expiring Nonce Methods ==========

    /// Returns the storage slot for a given tx hash in the expiring nonce seen set.
    /// This can be used by the transaction pool to check if a tx hash has been seen.
    pub fn expiring_seen_slot(&self, tx_hash: B256) -> U256 {
        self.expiring_nonce_seen[tx_hash].slot()
    }

    /// Checks if a tx hash has been seen and is still valid (not expired).
    pub fn is_expiring_nonce_seen(&self, tx_hash: B256, now: u64) -> Result<bool> {
        let expiry = self.expiring_nonce_seen[tx_hash].read()?;
        Ok(expiry != 0 && expiry > now)
    }

    /// Checks and marks an expiring nonce transaction.
    ///
    /// Uses an unbounded buffer with head/tail pointers that grows and shrinks dynamically.
    /// Every write to the tail also cleans up expired entries at the head (with cascading cleanup).
    ///
    /// This is called during transaction execution to:
    /// 1. Validate the expiry is within the allowed window
    /// 2. Check for replay (tx hash already seen and not expired)
    /// 3. Clean up expired entries at the head (cascading up to MAX_CASCADE_CLEANUP)
    /// 4. Mark the tx hash as seen at the tail
    ///
    /// Returns an error if:
    /// - The expiry is not within (now, now + max_skew]
    /// - The tx hash has already been seen and not expired
    pub fn check_and_mark_expiring_nonce(
        &mut self,
        tx_hash: B256,
        valid_before: u64,
        now: u64,
        max_skew_secs: u64,
    ) -> Result<()> {
        // 1. Validate expiry window: must be in (now, now + max_skew]
        if valid_before <= now || valid_before > now.saturating_add(max_skew_secs) {
            return Err(NonceError::invalid_expiring_nonce_expiry().into());
        }

        // 2. Replay check: reject if tx hash is already seen and not expired
        let seen_expiry = self.expiring_nonce_seen[tx_hash].read()?;
        if seen_expiry != 0 && seen_expiry > now {
            return Err(NonceError::expiring_nonce_replay().into());
        }

        // 3. Clean up expired entries at the head (cascading cleanup)
        self.cleanup_expired_head(now)?;

        // 4. Insert new entry at tail
        let tail = self.expiring_nonce_tail.read()?;
        self.expiring_nonce_buffer[tail].write(tx_hash)?;
        self.expiring_nonce_seen[tx_hash].write(valid_before)?;
        self.expiring_nonce_tail.write(tail.wrapping_add(1))?;

        Ok(())
    }

    /// Cleans up expired entries at the head of the buffer.
    ///
    /// Uses cascading cleanup: if an entry is expired, check the next one too.
    /// This allows the buffer to shrink quickly during low-traffic periods.
    /// Cleans up to MAX_CASCADE_CLEANUP entries per call.
    fn cleanup_expired_head(&mut self, now: u64) -> Result<()> {
        let mut head = self.expiring_nonce_head.read()?;
        let tail = self.expiring_nonce_tail.read()?;

        let mut cleaned = 0u32;
        while head < tail && cleaned < MAX_CASCADE_CLEANUP {
            let old_hash = self.expiring_nonce_buffer[head].read()?;
            if old_hash == B256::ZERO {
                // Empty slot, skip
                head = head.wrapping_add(1);
                cleaned += 1;
                continue;
            }

            let old_expiry = self.expiring_nonce_seen[old_hash].read()?;
            if old_expiry != 0 && old_expiry > now {
                // Entry is still valid, stop cleanup
                break;
            }

            // Entry is expired, clear it and advance head
            self.expiring_nonce_seen[old_hash].write(0)?;
            self.expiring_nonce_buffer[head].write(B256::ZERO)?;
            head = head.wrapping_add(1);
            cleaned += 1;
        }

        // Update head pointer if we cleaned anything
        if cleaned > 0 {
            self.expiring_nonce_head.write(head)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };

    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_get_nonce_returns_zero_for_new_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mgr = NonceManager::new();

            let account = address!("0x1111111111111111111111111111111111111111");
            let nonce = mgr.get_nonce(INonce::getNonceCall {
                account,
                nonceKey: U256::from(5),
            })?;

            assert_eq!(nonce, 0);
            Ok(())
        })
    }

    #[test]
    fn test_get_nonce_rejects_protocol_nonce() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mgr = NonceManager::new();

            let account = address!("0x1111111111111111111111111111111111111111");
            let result = mgr.get_nonce(INonce::getNonceCall {
                account,
                nonceKey: U256::ZERO,
            });

            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::protocol_nonce_not_supported())
            );
            Ok(())
        })
    }

    #[test]
    fn test_increment_nonce() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let account = address!("0x1111111111111111111111111111111111111111");
            let nonce_key = U256::from(5);

            let new_nonce = mgr.increment_nonce(account, nonce_key)?;
            assert_eq!(new_nonce, 1);
            assert_eq!(mgr.emitted_events().len(), 1);

            let new_nonce = mgr.increment_nonce(account, nonce_key)?;
            assert_eq!(new_nonce, 2);
            mgr.assert_emitted_events(vec![
                INonce::NonceIncremented {
                    account,
                    nonceKey: nonce_key,
                    newNonce: 1,
                },
                INonce::NonceIncremented {
                    account,
                    nonceKey: nonce_key,
                    newNonce: 2,
                },
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_different_accounts_independent() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let account1 = address!("0x1111111111111111111111111111111111111111");
            let account2 = address!("0x2222222222222222222222222222222222222222");
            let nonce_key = U256::from(5);

            for _ in 0..10 {
                mgr.increment_nonce(account1, nonce_key)?;
            }
            for _ in 0..20 {
                mgr.increment_nonce(account2, nonce_key)?;
            }

            let nonce1 = mgr.get_nonce(INonce::getNonceCall {
                account: account1,
                nonceKey: nonce_key,
            })?;
            let nonce2 = mgr.get_nonce(INonce::getNonceCall {
                account: account2,
                nonceKey: nonce_key,
            })?;

            assert_eq!(nonce1, 10);
            assert_eq!(nonce2, 20);
            Ok(())
        })
    }

    // ========== Expiring Nonce Tests ==========

    #[test]
    fn test_expiring_nonce_basic_flow() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let tx_hash = B256::repeat_byte(0x11);
            let now = 1000;
            let valid_before = now + 20; // 20s in future, within 30s window
            let max_skew = 30;

            // First tx should succeed
            mgr.check_and_mark_expiring_nonce(tx_hash, valid_before, now, max_skew)?;

            // Same tx hash should fail (replay)
            let result = mgr.check_and_mark_expiring_nonce(tx_hash, valid_before, now, max_skew);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_replay())
            );

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_expiry_validation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let tx_hash = B256::repeat_byte(0x22);
            let now = 1000;
            let max_skew = 30;

            // valid_before in the past should fail
            let result = mgr.check_and_mark_expiring_nonce(tx_hash, now - 1, now, max_skew);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );

            // valid_before exactly at now should fail
            let result = mgr.check_and_mark_expiring_nonce(tx_hash, now, now, max_skew);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );

            // valid_before too far in future should fail
            let result = mgr.check_and_mark_expiring_nonce(tx_hash, now + 31, now, max_skew);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );

            // valid_before at exactly max_skew should succeed
            mgr.check_and_mark_expiring_nonce(tx_hash, now + 30, now, max_skew)?;

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_expired_entry_eviction() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let tx_hash1 = B256::repeat_byte(0x33);
            let tx_hash2 = B256::repeat_byte(0x44);
            let now = 1000;
            let valid_before = now + 20;
            let max_skew = 30;

            // Insert first tx
            mgr.check_and_mark_expiring_nonce(tx_hash1, valid_before, now, max_skew)?;

            // Verify it's seen
            assert!(mgr.is_expiring_nonce_seen(tx_hash1, now)?);

            // After expiry, it should no longer be "seen" (expired)
            assert!(!mgr.is_expiring_nonce_seen(tx_hash1, valid_before + 1)?);

            // Insert second tx after first has expired - should clean up first at head
            let new_now = valid_before + 1;
            let new_valid_before = new_now + 20;
            mgr.check_and_mark_expiring_nonce(tx_hash2, new_valid_before, new_now, max_skew)?;

            // tx_hash1 should now be fully evicted (cleaned up at head)
            // tx_hash2 is now in the buffer
            assert!(mgr.is_expiring_nonce_seen(tx_hash2, new_now)?);

            // Verify head/tail pointers advanced correctly
            assert_eq!(mgr.expiring_nonce_head.read()?, 1); // head advanced past tx_hash1
            assert_eq!(mgr.expiring_nonce_tail.read()?, 2); // tail at position 2

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_cascading_cleanup() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let now = 1000;
            let valid_before = now + 20;
            let max_skew = 30;

            // Insert multiple txs that will all expire at the same time
            for i in 0..5u8 {
                let tx_hash = B256::repeat_byte(i);
                mgr.check_and_mark_expiring_nonce(tx_hash, valid_before, now, max_skew)?;
            }

            // Verify tail advanced
            assert_eq!(mgr.expiring_nonce_tail.read()?, 5);
            assert_eq!(mgr.expiring_nonce_head.read()?, 0);

            // Now insert a new tx after all previous ones expired
            // Cascading cleanup should clean up multiple entries
            let new_now = valid_before + 1;
            let new_valid_before = new_now + 20;
            let new_tx_hash = B256::repeat_byte(0x99);
            mgr.check_and_mark_expiring_nonce(new_tx_hash, new_valid_before, new_now, max_skew)?;

            // Head should have advanced (cleaned up expired entries)
            assert!(mgr.expiring_nonce_head.read()? >= 5);
            assert!(mgr.is_expiring_nonce_seen(new_tx_hash, new_now)?);

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_unbounded_growth() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let mut now = 1000u64;
            let max_skew = 30;

            // Insert many txs - buffer should grow without limit
            for i in 0..1000u64 {
                let tx_hash = B256::from(U256::from(i));
                let valid_before = now + 20;
                mgr.check_and_mark_expiring_nonce(tx_hash, valid_before, now, max_skew)?;
                now += 1; // Small time increments so entries don't expire
            }

            // All entries should be in the buffer (none expired yet)
            assert_eq!(mgr.expiring_nonce_tail.read()?, 1000);
            // Head might have advanced slightly due to cascading cleanup
            // but most entries should still be there

            Ok(())
        })
    }

    #[test]
    fn test_expiring_seen_slot() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mgr = NonceManager::new();

            let tx_hash = B256::repeat_byte(0x55);
            let slot = mgr.expiring_seen_slot(tx_hash);

            // Slot should be deterministic
            assert_eq!(slot, mgr.expiring_seen_slot(tx_hash));

            // Different hashes should have different slots
            let other_hash = B256::repeat_byte(0x66);
            assert_ne!(slot, mgr.expiring_seen_slot(other_hash));

            Ok(())
        })
    }
}
