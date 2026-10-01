//! 2D nonce management precompile and expiring nonce replay protection,
//! enabling concurrent transaction execution as part of [Tempo Transactions].
//!
//! [Tempo Transactions]: <https://docs.tempo.xyz/protocol/transactions>

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

/// Number of replay-hash bits supplied by the primary table's slot index.
pub const EXPIRING_NONCE_PRIMARY_BITS: u32 = 22;

/// Fixed number of primary replay-protection slots. Collisions use the existing ring.
pub const EXPIRING_NONCE_PRIMARY_CAPACITY: u32 = 1 << EXPIRING_NONCE_PRIMARY_BITS;

const PRIMARY_MASK: u64 = EXPIRING_NONCE_PRIMARY_CAPACITY as u64 - 1;

/// Selects the primary slot from the low bits of the complete replay hash.
pub fn primary_index(hash: B256) -> u32 {
    (U256::from_be_bytes(hash.0) & U256::from(PRIMARY_MASK)).to::<u32>()
}

/// Packs the remaining replay-hash bits and a modular expiry into one storage word.
/// Only hashes accepted by [`primary_eligible`] may occupy a primary slot.
pub fn encode_primary(hash: B256, valid_before: u64) -> U256 {
    (U256::from_be_bytes(hash.0) & !U256::from(PRIMARY_MASK))
        | U256::from(valid_before & PRIMARY_MASK)
}

/// Routes a zero hash quotient permanently to the ring so an expiry guard can
/// never erase an occupied primary cell when its modular timestamp becomes zero.
pub fn primary_eligible(hash: B256) -> bool {
    !(U256::from_be_bytes(hash.0) & !U256::from(PRIMARY_MASK)).is_zero()
}

/// Reconstructs the complete replay hash from an occupied primary slot and its index.
pub fn decode_primary(index: u32, value: U256) -> B256 {
    B256::from(((value & !U256::from(PRIMARY_MASK)) | U256::from(index)).to_be_bytes::<32>())
}

/// Checks a primary value at `primary_index(hash)` for an exact replay-hash match.
pub fn primary_matches(hash: B256, value: U256) -> bool {
    !value.is_zero()
        && (value & !U256::from(PRIMARY_MASK))
            == (U256::from_be_bytes(hash.0) & !U256::from(PRIMARY_MASK))
}

/// Returns whether a primary cell and all its fallback entries have expired.
///
/// The maximum expiry window must be shorter than the timestamp modulus. An ancient
/// entry can appear live after a wrap, but this only sends new transactions to the
/// fallback ring; a genuinely live entry can never appear expired.
pub fn primary_available(value: U256, now: u64, max_expiry_secs: u64) -> bool {
    let expiry = (value & U256::from(PRIMARY_MASK)).to::<u64>();
    let delta = expiry.wrapping_sub(now) & PRIMARY_MASK;
    value.is_zero() || delta == 0 || delta > max_expiry_secs
}

/// Extends an occupied bucket's expiry guard to cover a successful fallback insert.
///
/// `value` must be an unavailable primary cell with a nonzero hash quotient, and
/// `valid_before` must have passed the active fork's absolute expiry validation.
/// Compare remaining lifetimes, not encoded timestamps, to handle modular wrap.
pub fn extend_primary_guard(value: U256, now: u64, valid_before: u64) -> U256 {
    let expiry = (value & U256::from(PRIMARY_MASK)).to::<u64>();
    let remaining = expiry.wrapping_sub(now) & PRIMARY_MASK;
    if valid_before - now > remaining {
        (value & !U256::from(PRIMARY_MASK)) | U256::from(valid_before & PRIMARY_MASK)
    } else {
        value
    }
}

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
///     mapping(uint32 => uint256) public expiringNoncePrimary;              // slot 4: packed replay hash quotient and bucket expiry guard
/// }
/// ```
///
/// - Slot 0: 2D nonce mapping - keccak256(abi.encode(nonce_key, keccak256(abi.encode(account, 0))))
/// - Slot 1: Expiring nonce seen set - txHash => expiry timestamp
/// - Slot 2: Expiring nonce circular buffer - index => txHash
/// - Slot 3: Circular buffer pointer (current position, wraps at CAPACITY)
/// - Slot 4: T12 primary table; its expiry guard covers all colliding fallback entries
///
/// T12 activation requires a state transition that establishes the bucket guards
/// for all live legacy entries, or guarantees those entries have expired. This
/// prototype does not implement that migration.
///
/// Note: Protocol nonce (key 0) is stored directly in account state, not here.
/// Only user nonce keys (1-N) are managed by this precompile.
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract(addr = NONCE_PRECOMPILE_ADDRESS)]
pub struct NonceManager {
    nonces: Mapping<Address, Mapping<U256, u64>>,
    expiring_nonce_seen: Mapping<B256, u64>,
    expiring_nonce_ring: Mapping<u32, B256>,
    expiring_nonce_ring_ptr: u32,
    expiring_nonce_primary: Mapping<u32, U256>,
}

impl NonceManager {
    /// Initializes the nonce manager precompile storage layout.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the current nonce for `account` at the given `nonceKey`.
    ///
    /// # Errors
    /// - `ProtocolNonceNotSupported` — nonce key 0 is the protocol nonce and cannot be read here
    pub fn get_nonce(&self, call: INonce::getNonceCall) -> Result<u64> {
        // Protocol nonce (key 0) is stored in account state, not in this precompile
        // Users should query account nonce directly, not through this precompile
        if call.nonceKey == 0 {
            return Err(NonceError::protocol_nonce_not_supported().into());
        }

        // For user nonce keys, read from precompile storage
        self.nonces[call.account][call.nonceKey].read()
    }

    /// Increments the 2D nonce for `account` at `nonce_key` and returns the new value, enabling
    /// concurrent transaction execution. Key `0` is reserved for the protocol nonce.
    ///
    /// # Errors
    /// - `InvalidNonceKey` — `nonce_key` is 0, which is reserved for the protocol nonce
    /// - `NonceOverflow` — the current nonce value is `u64::MAX` and cannot be incremented
    pub fn increment_nonce(&mut self, account: Address, nonce_key: U256) -> Result<u64> {
        if nonce_key == 0 {
            return Err(NonceError::invalid_nonce_key().into());
        }

        let current = self.nonces[account][nonce_key].read()?;

        let new_nonce = current
            .checked_add(1)
            .ok_or_else(NonceError::nonce_overflow)?;

        self.nonces[account][nonce_key].write(new_nonce)?;

        self.emit_event(NonceEvent::nonce_incremented(account, nonce_key, new_nonce))?;

        Ok(new_nonce)
    }

    /// Checks replay protection after the caller validates the transaction's absolute expiry.
    /// A bucket guard can outlive its primary transaction, and its modular timestamp
    /// can conservatively retain ancient entries after a wrap.
    pub fn is_expiring_nonce_seen(&self, hash: B256, now: u64) -> Result<bool> {
        let spec = self.storage.spec();
        if spec.is_t12() && primary_eligible(hash) {
            let primary = self.expiring_nonce_primary[primary_index(hash)].read()?;
            if primary_available(primary, now, spec.expiring_nonce_max_expiry_secs()) {
                return Ok(false);
            }
            if primary_matches(hash, primary) {
                return Ok(true);
            }
        }
        let expiry = self.expiring_nonce_seen[hash].read()?;
        Ok(expiry != 0 && expiry > now)
    }

    /// Validates and records an expiring nonce transaction. Uses a
    /// circular buffer that overwrites expired entries as the pointer
    /// advances. The hash is `keccak256(encode_for_signing || sender)`,
    /// invariant to fee payer changes.
    ///
    /// At T12, a fixed primary table handles noncolliding hashes with one storage
    /// read and write. Its bucket expiry guard covers both the primary hash and
    /// every colliding fallback entry, so an available primary skips the seen set.
    ///
    /// The `expiring_nonce_hash` parameter is
    /// (`keccak256(encode_for_signing || sender)`), which is invariant to fee payer changes.
    ///
    /// This is called during transaction execution to:
    /// 1. Validate the expiry is within the allowed window
    /// 2. Check for replay (hash already seen and not expired)
    /// 3. Check if we can evict the entry at current pointer (must be expired or empty)
    /// 4. Mark the hash as seen
    ///
    /// # Errors
    /// - `InvalidExpiringNonceExpiry` — `valid_before` exceeds the active fork's expiry window
    /// - `ExpiringNonceReplay` — transaction hash is already recorded and has not yet expired
    /// - `ExpiringNonceSetFull` — the circular buffer slot holds an unexpired entry that can't be evicted
    pub fn check_and_mark_expiring_nonce(
        &mut self,
        expiring_nonce_hash: B256,
        valid_before: u64,
    ) -> Result<()> {
        let now: u64 = self.storage.timestamp().saturating_to();
        let spec = self.storage.spec();
        let max_expiry_secs = spec.expiring_nonce_max_expiry_secs();
        let capacity = spec.expiring_nonce_set_capacity();

        // 1. Validate expiry window for the active fork.
        if valid_before <= now || valid_before > now.saturating_add(max_expiry_secs) {
            return Err(NonceError::invalid_expiring_nonce_expiry().into());
        }

        let primary = if spec.is_t12() && primary_eligible(expiring_nonce_hash) {
            let value = self.expiring_nonce_primary[primary_index(expiring_nonce_hash)].read()?;
            if primary_matches(expiring_nonce_hash, value) {
                // The replay hash commits to the absolute expiry, which was validated above.
                return Err(NonceError::expiring_nonce_replay().into());
            }
            if primary_available(value, now, max_expiry_secs) {
                self.expiring_nonce_primary[primary_index(expiring_nonce_hash)]
                    .write(encode_primary(expiring_nonce_hash, valid_before))?;
                return Ok(());
            }
            Some(value)
        } else {
            None
        };

        // 2. Replay check: reject if hash is already seen and not expired
        let seen_expiry = self.expiring_nonce_seen[expiring_nonce_hash].read()?;
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
        self.expiring_nonce_ring[idx].write(expiring_nonce_hash)?;
        self.expiring_nonce_seen[expiring_nonce_hash].write(valid_before)?;

        // 6. Advance pointer (wraps at CAPACITY, not u32::MAX)
        let next = if ptr + 1 >= capacity { 0 } else { ptr + 1 };
        self.expiring_nonce_ring_ptr.write(next)?;

        // Keep this bucket unavailable until every accepted fallback has expired.
        // Only successful inserts may extend the guard; preserve the primary hash.
        if let Some(primary) = primary {
            let guarded = extend_primary_guard(primary, now, valid_before);
            if guarded != primary {
                self.expiring_nonce_primary[primary_index(expiring_nonce_hash)].write(guarded)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
    };

    use super::*;
    use alloy::primitives::address;
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_expiring_nonce_parameters_activate_at_t11() {
        assert_eq!(TempoHardfork::T9.expiring_nonce_max_expiry_secs(), 30);
        assert_eq!(TempoHardfork::T9.expiring_nonce_set_capacity(), 300_000);
        assert_eq!(TempoHardfork::T10.expiring_nonce_max_expiry_secs(), 30);
        assert_eq!(TempoHardfork::T10.expiring_nonce_set_capacity(), 300_000);
        assert_eq!(TempoHardfork::T11.expiring_nonce_max_expiry_secs(), 300);
        assert_eq!(TempoHardfork::T11.expiring_nonce_set_capacity(), 3_000_000);
    }

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

    fn primary_test_hash(index: u32, quotient: u64) -> B256 {
        B256::from(
            ((U256::from(quotient) << EXPIRING_NONCE_PRIMARY_BITS) | U256::from(index))
                .to_be_bytes::<32>(),
        )
    }

    #[test]
    fn test_primary_preserves_complete_hash() {
        let hash = B256::repeat_byte(0xab);
        let expiry = u64::from(EXPIRING_NONCE_PRIMARY_CAPACITY) + 123;
        let value = encode_primary(hash, expiry);

        assert_eq!(decode_primary(primary_index(hash), value), hash);
        assert!(primary_matches(hash, value));
        assert!(!primary_matches(hash, U256::ZERO));
        assert!(!primary_matches(B256::repeat_byte(0xcd), value));
        assert_eq!((value & U256::from(PRIMARY_MASK)).to::<u64>(), 123);
    }

    #[test]
    fn test_primary_mapping_preserves_legacy_storage_layout() {
        fn mapping_slot(key: U256, base: u64) -> U256 {
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(&key.to_be_bytes::<32>());
            input[32..].copy_from_slice(&U256::from(base).to_be_bytes::<32>());
            U256::from_be_bytes(alloy::primitives::keccak256(input).0)
        }

        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mgr = NonceManager::new();
            let hash = B256::repeat_byte(0xab);
            assert_eq!(
                mgr.expiring_nonce_seen[hash].slot(),
                mapping_slot(U256::from_be_bytes(hash.0), 1)
            );
            assert_eq!(
                mgr.expiring_nonce_ring[7].slot(),
                mapping_slot(U256::from(7), 2)
            );
            assert_eq!(mgr.expiring_nonce_ring_ptr.slot(), U256::from(3));
            assert_eq!(
                mgr.expiring_nonce_primary[7].slot(),
                mapping_slot(U256::from(7), 4)
            );
        });
    }

    #[test]
    fn test_primary_modular_expiry() {
        let period = u64::from(EXPIRING_NONCE_PRIMARY_CAPACITY);
        let hash = primary_test_hash(7, 1);
        let value = encode_primary(hash, period + 10);
        assert!(!primary_available(value, period - 10, 300));
        assert!(!primary_available(value, period + 9, 300));
        assert!(primary_available(value, period + 10, 300));
        assert!(primary_available(value, period + 11, 300));
        // Ancient entries may conservatively appear occupied after a timestamp wrap.
        assert!(!primary_available(value, 2 * period, 300));
        assert!(primary_available(U256::ZERO, 2 * period, 300));
    }

    #[test]
    fn test_t12_primary_skips_legacy_seen_access() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let now = 1000;
        let hash = primary_test_hash(7, 1);
        storage.set_timestamp(U256::from(now));
        let seen_slot = StorageCtx::enter(&mut storage, || {
            NonceManager::new().expiring_nonce_seen[hash].slot()
        });
        storage.fail_next_sload_at(NONCE_PRECOMPILE_ADDRESS, seen_slot);

        assert!(!StorageCtx::enter(&mut storage, || {
            NonceManager::new().is_expiring_nonce_seen(hash, now)
        })?);
        assert_eq!(storage.counter_sload(), 1);
        storage.reset_counters();
        StorageCtx::enter(&mut storage, || {
            NonceManager::new().check_and_mark_expiring_nonce(hash, now + 10)
        })?;
        assert_eq!(storage.counter_sload(), 1);
        assert_eq!(storage.counter_sstore(), 1);
        storage.reset_counters();
        assert!(StorageCtx::enter(&mut storage, || {
            NonceManager::new().is_expiring_nonce_seen(hash, now)
        })?);
        assert_eq!(storage.counter_sload(), 1);
        storage.reset_counters();
        assert!(!StorageCtx::enter(&mut storage, || {
            NonceManager::new().is_expiring_nonce_seen(hash, now + 10)
        })?);
        assert_eq!(storage.counter_sload(), 1);
        Ok(())
    }

    #[test]
    fn test_t12_primary_does_not_touch_full_ring() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let now = 1000;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            let old = primary_test_hash(1, 1);
            mgr.expiring_nonce_ring[0].write(old)?;
            mgr.expiring_nonce_seen[old].write(now + 300)?;

            let hash = primary_test_hash(2, 2);
            mgr.check_and_mark_expiring_nonce(hash, now + 300)?;
            assert_eq!(mgr.expiring_nonce_ring_ptr.read()?, 0);
            assert_eq!(mgr.expiring_nonce_ring[0].read()?, old);
            assert_eq!(mgr.expiring_nonce_seen[hash].read()?, 0);
            assert_eq!(
                decode_primary(2, mgr.expiring_nonce_primary[2].read()?),
                hash
            );
            assert!(mgr.is_expiring_nonce_seen(hash, now)?);
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(hash, now + 300)
                    .unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_replay())
            );
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(primary_test_hash(2, 3), now + 300)
                    .unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_set_full())
            );
            Ok(())
        })
    }

    #[test]
    fn test_t12_collision_guard_covers_all_fallback_expiries() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let now = 1000;
        let first = primary_test_hash(7, 1);
        let fallback = primary_test_hash(7, 2);
        let replacement = primary_test_hash(7, 3);
        let longer = primary_test_hash(7, 4);
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            mgr.check_and_mark_expiring_nonce(first, now + 10)?;
            mgr.check_and_mark_expiring_nonce(fallback, now + 100)?;
            assert_eq!(mgr.expiring_nonce_ring_ptr.read()?, 1);
            assert_eq!(mgr.expiring_nonce_ring[0].read()?, fallback);
            assert_eq!(
                mgr.expiring_nonce_primary[7].read()?,
                encode_primary(first, now + 100)
            );
            Ok::<_, eyre::Report>(())
        })?;
        storage.set_timestamp(U256::from(now + 10));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            // The original primary transaction has expired, but its guard is still live.
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(fallback, now + 100)
                    .unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_replay())
            );
            mgr.check_and_mark_expiring_nonce(replacement, now + 50)?;
            assert_eq!(mgr.expiring_nonce_ring_ptr.read()?, 2);
            assert_eq!(
                mgr.expiring_nonce_primary[7].read()?,
                encode_primary(first, now + 100)
            );
            mgr.check_and_mark_expiring_nonce(longer, now + 150)?;
            assert_eq!(mgr.expiring_nonce_ring_ptr.read()?, 3);
            assert_eq!(
                mgr.expiring_nonce_primary[7].read()?,
                encode_primary(first, now + 150)
            );
            assert!(mgr.is_expiring_nonce_seen(fallback, now + 10)?);
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(fallback, now + 100)
                    .unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_replay())
            );
            Ok::<_, eyre::Report>(())
        })?;
        storage.set_timestamp(U256::from(now + 100));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            assert!(!mgr.is_expiring_nonce_seen(fallback, now + 100)?);
            assert!(mgr.is_expiring_nonce_seen(longer, now + 100)?);
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(longer, now + 150)
                    .unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_replay())
            );
            Ok::<_, eyre::Report>(())
        })?;
        storage.set_timestamp(U256::from(now + 150));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            let next = primary_test_hash(7, 5);
            mgr.check_and_mark_expiring_nonce(next, now + 200)?;
            assert_eq!(mgr.expiring_nonce_ring_ptr.read()?, 3);
            assert_eq!(
                mgr.expiring_nonce_primary[7].read()?,
                encode_primary(next, now + 200)
            );
            Ok(())
        })
    }

    #[test]
    fn test_t12_zero_quotient_permanently_uses_fallback() -> eyre::Result<()> {
        let period = u64::from(EXPIRING_NONCE_PRIMARY_CAPACITY);
        let hash = primary_test_hash(7, 0);
        assert!(!primary_eligible(hash));
        assert_eq!(encode_primary(hash, period), U256::ZERO);
        assert_ne!(encode_primary(hash, period + 10), U256::ZERO);
        for expiry in [period, period + 10] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
            storage.set_timestamp(U256::from(expiry - 1));
            let primary_slot = StorageCtx::enter(&mut storage, || {
                NonceManager::new().expiring_nonce_primary[7].slot()
            });
            storage.fail_next_sload_at(NONCE_PRECOMPILE_ADDRESS, primary_slot);
            StorageCtx::enter(&mut storage, || {
                let mut mgr = NonceManager::new();
                mgr.check_and_mark_expiring_nonce(hash, expiry)?;
                assert_eq!(mgr.expiring_nonce_ring_ptr.read()?, 1);
                assert_eq!(mgr.expiring_nonce_seen[hash].read()?, expiry);
                assert!(mgr.is_expiring_nonce_seen(hash, expiry - 1)?);
                assert_eq!(
                    mgr.check_and_mark_expiring_nonce(hash, expiry).unwrap_err(),
                    TempoPrecompileError::NonceError(NonceError::expiring_nonce_replay())
                );
                Ok::<_, eyre::Report>(())
            })?;
            assert!(
                storage
                    .into_storage()
                    .all(|(_, slot, _)| slot != primary_slot)
            );
        }
        Ok(())
    }

    #[test]
    fn test_t12_timestamp_wrap_only_forces_fallback() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let period = u64::from(EXPIRING_NONCE_PRIMARY_CAPACITY);
        let first = primary_test_hash(7, 1);
        let second = primary_test_hash(7, 2);
        storage.set_timestamp(U256::from(10));
        StorageCtx::enter(&mut storage, || {
            NonceManager::new().check_and_mark_expiring_nonce(first, 20)
        })?;
        storage.set_timestamp(U256::from(period + 10));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            mgr.check_and_mark_expiring_nonce(second, period + 30)?;
            assert_eq!(mgr.expiring_nonce_ring[0].read()?, second);
            assert_eq!(
                decode_primary(7, mgr.expiring_nonce_primary[7].read()?),
                first
            );
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(first, 20).unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );
            Ok(())
        })
    }

    #[test]
    fn test_t12_fallback_guard_crosses_timestamp_wrap() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let period = u64::from(EXPIRING_NONCE_PRIMARY_CAPACITY);
        let first = primary_test_hash(7, 1);
        let fallback = primary_test_hash(7, 2);
        let longer = primary_test_hash(7, 3);
        storage.set_timestamp(U256::from(period - 10));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            mgr.check_and_mark_expiring_nonce(first, period - 5)?;
            mgr.check_and_mark_expiring_nonce(fallback, period)?;
            let guarded = mgr.expiring_nonce_primary[7].read()?;
            assert_eq!(guarded, encode_primary(first, period));
            assert!(!guarded.is_zero());
            assert!(!primary_available(guarded, period - 5, 300));
            Ok::<_, eyre::Report>(())
        })?;
        storage.set_timestamp(U256::from(period - 5));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            assert!(mgr.is_expiring_nonce_seen(fallback, period - 5)?);
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(fallback, period)
                    .unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_replay())
            );
            mgr.check_and_mark_expiring_nonce(longer, period + 20)?;
            assert_eq!(
                mgr.expiring_nonce_primary[7].read()?,
                encode_primary(first, period + 20)
            );
            Ok::<_, eyre::Report>(())
        })?;
        storage.set_timestamp(U256::from(period));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            assert!(mgr.is_expiring_nonce_seen(longer, period)?);
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(longer, period + 20)
                    .unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_replay())
            );
            assert_eq!(mgr.expiring_nonce_ring_ptr.read()?, 2);
            Ok(())
        })
    }

    #[test]
    fn test_t12_failed_fallback_does_not_extend_guard() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let now = 1000;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            let first = primary_test_hash(7, 1);
            let fallback = primary_test_hash(7, 2);
            let old = primary_test_hash(8, 3);
            mgr.check_and_mark_expiring_nonce(first, now + 10)?;
            mgr.expiring_nonce_ring[0].write(old)?;
            mgr.expiring_nonce_seen[old].write(now + 300)?;
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(fallback, now + 100)
                    .unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_set_full())
            );
            assert_eq!(
                mgr.expiring_nonce_primary[7].read()?,
                encode_primary(first, now + 10)
            );
            assert_eq!(mgr.expiring_nonce_ring_ptr.read()?, 0);
            assert_eq!(mgr.expiring_nonce_seen[fallback].read()?, 0);
            Ok(())
        })
    }

    #[test]
    fn test_t12_activation_after_legacy_expiry() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let now = 1000;
        let hash = primary_test_hash(7, 1);
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            mgr.check_and_mark_expiring_nonce(hash, now + 300)?;
            assert_eq!(mgr.expiring_nonce_primary[7].read()?, U256::ZERO);
            assert_eq!(mgr.expiring_nonce_ring_ptr.read()?, 1);
            Ok::<_, eyre::Report>(())
        })?;
        // A production fork must migrate live entries or fence their expiry first.
        // This prototype starts after all legacy transactions have expired.
        storage.set_timestamp(U256::from(now + 300));
        storage.set_spec(TempoHardfork::T12);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            assert!(!mgr.is_expiring_nonce_seen(hash, now + 300)?);
            assert_eq!(
                mgr.check_and_mark_expiring_nonce(hash, now + 300)
                    .unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );
            let next = primary_test_hash(7, 2);
            mgr.check_and_mark_expiring_nonce(next, now + 400)?;
            assert_eq!(
                mgr.expiring_nonce_primary[7].read()?,
                encode_primary(next, now + 400)
            );
            Ok(())
        })
    }

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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
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
            let mut mgr = NonceManager::new();

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

    fn assert_ring_buffer_pointer_wraps_at_capacity(spec: TempoHardfork) -> eyre::Result<()> {
        let capacity = spec.expiring_nonce_set_capacity();
        let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            // Manually set pointer to just before capacity to test wrap
            mgr.expiring_nonce_ring_ptr.write(capacity - 1)?;

            // Insert a tx - pointer should wrap to 0
            let tx_hash = B256::repeat_byte(0x77);
            let valid_before = now + 20;
            if spec.is_t12() {
                let collision = B256::from(
                    (U256::from_be_bytes(tx_hash.0) ^ (U256::ONE << EXPIRING_NONCE_PRIMARY_BITS))
                        .to_be_bytes::<32>(),
                );
                mgr.expiring_nonce_primary[primary_index(tx_hash)]
                    .write(encode_primary(collision, valid_before))?;
            }
            mgr.check_and_mark_expiring_nonce(tx_hash, valid_before)?;

            // Pointer should now be 0 (wrapped at capacity)
            let ptr = mgr.expiring_nonce_ring_ptr.read()?;
            assert_eq!(ptr, 0, "Pointer should wrap to 0 at capacity");

            // Insert another tx - pointer should be 1
            let tx_hash2 = B256::repeat_byte(0x88);
            if spec.is_t12() {
                let collision = B256::from(
                    (U256::from_be_bytes(tx_hash2.0) ^ (U256::ONE << EXPIRING_NONCE_PRIMARY_BITS))
                        .to_be_bytes::<32>(),
                );
                mgr.expiring_nonce_primary[primary_index(tx_hash2)]
                    .write(encode_primary(collision, valid_before))?;
            }
            mgr.check_and_mark_expiring_nonce(tx_hash2, valid_before)?;

            let ptr = mgr.expiring_nonce_ring_ptr.read()?;
            assert_eq!(ptr, 1, "Pointer should increment to 1 after wrap");

            Ok(())
        })
    }

    #[test]
    fn test_ring_buffer_pointer_wraps_at_pre_t11_capacity() -> eyre::Result<()> {
        assert_ring_buffer_pointer_wraps_at_capacity(TempoHardfork::T10)
    }

    #[test]
    fn test_ring_buffer_pointer_wraps_at_t11_capacity() -> eyre::Result<()> {
        assert_ring_buffer_pointer_wraps_at_capacity(TempoHardfork::T11)
    }

    #[test]
    fn test_t12_fallback_ring_pointer_wraps_at_capacity() -> eyre::Result<()> {
        assert_ring_buffer_pointer_wraps_at_capacity(TempoHardfork::T12)
    }

    #[test]
    fn test_initialize_sets_storage_state() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            // Before initialization, contract should not be initialized
            assert!(!mgr.is_initialized()?);

            // Initialize
            mgr.initialize()?;

            // After initialization, contract should be initialized
            assert!(mgr.is_initialized()?);

            // Re-initializing a new handle should still see initialized state
            let mgr2 = NonceManager::new();
            assert!(mgr2.is_initialized()?);

            Ok(())
        })
    }
}
