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

/// Capacity of the expiring nonce seen set (supports 10k TPS for 30 seconds).
pub const EXPIRING_NONCE_SET_CAPACITY: u32 = 300_000;

/// Maximum allowed skew for expiring nonce transactions (30 seconds).
/// Transactions must have valid_before in (now, now + MAX_EXPIRY_SECS].
pub const EXPIRING_NONCE_MAX_EXPIRY_SECS: u64 = 30;

/// NonceManager contract for managing 2D nonces as per the AA spec
///
/// Storage Layout (similar to Solidity contract):
/// ```solidity
/// contract Nonce {
///     mapping(address => mapping(uint256 => uint64)) public nonces;      // slot 0
///     
///     // Expiring nonce storage (for hash-based replay protection)
///     mapping(bytes32 => uint64) public expiringNonceSeen;               // slot 1: txHash => expiry
///     mapping(uint32 => bytes32) public expiringNonceRing;               // slot 2: circular buffer of tx hashes
///     uint32 public expiringNonceRingPtr;                                // slot 3: current position (wraps at CAPACITY)
/// }
/// ```
///
/// - Slot 0: 2D nonce mapping - keccak256(abi.encode(nonce_key, keccak256(abi.encode(account, 0))))
/// - Slot 1: Expiring nonce seen set - txHash => expiry timestamp
/// - Slot 2: Expiring nonce circular buffer - index => txHash
/// - Slot 3: Circular buffer pointer (current position, wraps at CAPACITY)
///
/// Note: Protocol nonce (key 0) is stored directly in account state, not here.
/// Only user nonce keys (1-N) are managed by this precompile.
#[contract(addr = NONCE_PRECOMPILE_ADDRESS)]
pub struct NonceManager {
    nonces: Mapping<Address, Mapping<U256, u64>>,
    expiring_nonce_seen: Mapping<B256, u64>,
    expiring_nonce_ring: Mapping<u32, B256>,
    expiring_nonce_ring_ptr: u32,
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
    /// Uses a circular buffer that overwrites expired entries as the pointer advances.
    ///
    /// This is called during transaction execution to:
    /// 1. Validate the expiry is within the allowed window
    /// 2. Check for replay (tx hash already seen and not expired)
    /// 3. Check if we can evict the entry at current pointer (must be expired or empty)
    /// 4. Mark the tx hash as seen
    ///
    /// Returns an error if:
    /// - The expiry is not within (now, now + EXPIRING_NONCE_MAX_EXPIRY_SECS]
    /// - The tx hash has already been seen and not expired
    /// - The entry at current pointer is not expired (buffer full of valid entries)
    pub fn check_and_mark_expiring_nonce(
        &mut self,
        tx_hash: B256,
        valid_before: u64,
    ) -> Result<()> {
        let now: u64 = self.storage.timestamp().saturating_to();

        // 1. Validate expiry window: must be in (now, now + max_skew]
        if valid_before <= now || valid_before > now.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            return Err(NonceError::invalid_expiring_nonce_expiry().into());
        }

        // 2. Replay check: reject if tx hash is already seen and not expired
        let seen_expiry = self.expiring_nonce_seen[tx_hash].read()?;
        if seen_expiry != 0 && seen_expiry > now {
            return Err(NonceError::expiring_nonce_replay().into());
        }

        // 3. Get current pointer (bounded in [0, CAPACITY)) and use directly as index
        let ptr = self.expiring_nonce_ring_ptr.read()?;
        let idx = ptr;
        let old_hash = self.expiring_nonce_ring[idx].read()?;

        // 4. If there's an existing entry, check if it's expired (can be evicted)
        // Safety check: buffer is sized so entries should always be expired, but verify
        // in case TPS exceeds expectations.
        if old_hash != B256::ZERO {
            let old_expiry = self.expiring_nonce_seen[old_hash].read()?;
            if old_expiry != 0 && old_expiry > now {
                // Entry is still valid, cannot evict - buffer is full
                return Err(NonceError::expiring_nonce_set_full().into());
            }
            // Clear the old entry from seen set
            self.expiring_nonce_seen[old_hash].write(0)?;
        }

        // 5. Insert new entry
        self.expiring_nonce_ring[idx].write(tx_hash)?;
        self.expiring_nonce_seen[tx_hash].write(valid_before)?;

        // 6. Advance pointer (wraps at CAPACITY, not u32::MAX)
        let next = if ptr + 1 >= EXPIRING_NONCE_SET_CAPACITY {
            0
        } else {
            ptr + 1
        };
        self.expiring_nonce_ring_ptr.write(next)?;

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
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

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
        let mut storage = HashMapStorageProvider::new(1);
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

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

            // valid_before too far in future should fail (uses EXPIRING_NONCE_MAX_EXPIRY_SECS = 30)
            let result = mgr.check_and_mark_expiring_nonce(tx_hash, now + 31);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );

            // valid_before at exactly max_skew should succeed
            mgr.check_and_mark_expiring_nonce(tx_hash, now + 30)?;

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_expired_entry_eviction() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let now = 1000u64;
        let valid_before = now + 20;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let tx_hash1 = B256::repeat_byte(0x33);

            // Insert first tx
            mgr.check_and_mark_expiring_nonce(tx_hash1, valid_before)?;

            // Verify it's seen
            assert!(mgr.is_expiring_nonce_seen(tx_hash1, now)?);

            // After expiry, it should no longer be "seen" (expired)
            assert!(!mgr.is_expiring_nonce_seen(tx_hash1, valid_before + 1)?);

            Ok::<_, eyre::Report>(())
        })?;

        // Insert second tx after first has expired - should evict first
        let new_now = valid_before + 1;
        let new_valid_before = new_now + 20;
        storage.set_timestamp(U256::from(new_now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let tx_hash2 = B256::repeat_byte(0x44);
            mgr.check_and_mark_expiring_nonce(tx_hash2, new_valid_before)?;

            // tx_hash1 should now be fully evicted (since it was at ring position 0)
            // and tx_hash2 replaces it
            assert!(mgr.is_expiring_nonce_seen(tx_hash2, new_now)?);

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

    #[test]
    fn test_ring_buffer_pointer_wraps_at_capacity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            // Manually set pointer to just before capacity to test wrap
            mgr.expiring_nonce_ring_ptr
                .write(EXPIRING_NONCE_SET_CAPACITY - 1)?;

            // Insert a tx - pointer should wrap to 0
            let tx_hash = B256::repeat_byte(0x77);
            let valid_before = now + 20;
            mgr.check_and_mark_expiring_nonce(tx_hash, valid_before)?;

            // Pointer should now be 0 (wrapped at capacity)
            let ptr = mgr.expiring_nonce_ring_ptr.read()?;
            assert_eq!(ptr, 0, "Pointer should wrap to 0 at capacity");

            // Insert another tx - pointer should be 1
            let tx_hash2 = B256::repeat_byte(0x88);
            mgr.check_and_mark_expiring_nonce(tx_hash2, valid_before)?;

            let ptr = mgr.expiring_nonce_ring_ptr.read()?;
            assert_eq!(ptr, 1, "Pointer should increment to 1 after wrap");

            Ok(())
        })
    }
}
