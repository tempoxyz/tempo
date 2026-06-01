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
use alloy::primitives::{Address, B256, U256, keccak256};

/// Maximum allowed skew for expiring nonce transactions (30 seconds).
/// Transactions must have valid_before in (now, now + MAX_EXPIRY_SECS].
pub const EXPIRING_NONCE_MAX_EXPIRY_SECS: u64 = 30;

/// Number of reusable time buckets in the expiring nonce replay table.
pub const EXPIRING_NONCE_BUCKET_COUNT: u32 = 32;

/// Number of replay cells in each time bucket.
pub const EXPIRING_NONCE_BUCKET_CAPACITY: u32 = 32_768;

/// Maximum number of replay cells checked on one transaction's deterministic probe path.
pub const EXPIRING_NONCE_MAX_PROBES: usize = 32;

const EXPIRING_NONCE_CELL_DOMAIN: &[u8] = b"tempo-expiring-nonce-cell";
const EXPIRING_NONCE_FINGERPRINT_DOMAIN: &[u8] = b"tempo-expiring-nonce-fingerprint";
const EXPIRING_NONCE_FINGERPRINT_MASK: U256 = U256::from_limbs([u64::MAX, u64::MAX, u64::MAX, 0]);

/// NonceManager contract for managing 2D nonces as per the AA spec
///
/// Storage Layout (similar to Solidity contract):
/// ```solidity
/// contract Nonce {
///     mapping(address => mapping(uint256 => uint64)) public nonces;      // slot 0
///
///     // Expiring nonce storage (for hash-based replay protection).
///     mapping(uint32 => bytes32) public expiringNonceCells;              // slot 1: cell_id => packed replay cell
/// }
/// ```
///
/// - Slot 0: 2D nonce mapping - keccak256(abi.encode(nonce_key, keccak256(abi.encode(account, 0))))
/// - Slot 1: Expiring nonce time wheel cells - cell_id => valid_before_u64 || fingerprint_192
///
/// Note: Protocol nonce (key 0) is stored directly in account state, not here.
/// Only user nonce keys (1-N) are managed by this precompile.
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract(addr = NONCE_PRECOMPILE_ADDRESS)]
pub struct NonceManager {
    nonces: Mapping<Address, Mapping<U256, u64>>,
    expiring_nonce_cells: Mapping<u32, U256>,
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

    /// Checks if a hash has been seen and is still valid (not expired).
    /// NOTE: internally used by the transaction pool.
    pub fn is_expiring_nonce_seen(&self, hash: B256, now: u64) -> Result<bool> {
        for valid_before in
            now.saturating_add(1)..=now.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            if self.is_expiring_nonce_seen_at(hash, valid_before)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Checks if a hash has been seen for a specific live `valid_before` value.
    pub fn is_expiring_nonce_seen_at(&self, hash: B256, valid_before: u64) -> Result<bool> {
        let fingerprint = Self::expiring_nonce_fingerprint(hash);

        for probe in 0..EXPIRING_NONCE_MAX_PROBES {
            let cell_id = Self::expiring_nonce_cell_id(hash, valid_before, probe);
            let word = self.expiring_nonce_cells[cell_id].read()?;
            let (stored_v, stored_fingerprint) = Self::unpack_expiring_nonce_cell(word);

            if stored_v != valid_before {
                return Ok(false);
            }

            if stored_fingerprint == fingerprint {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Validates an expiring nonce transaction without recording it. Uses a fixed time wheel where
    /// `valid_before` selects the reusable bucket and the replay hash selects a deterministic
    /// probe path inside that bucket.
    ///
    /// The `expiring_nonce_hash` parameter is
    /// (`keccak256(encode_for_signing || sender)`), which is invariant to fee payer changes.
    ///
    /// This is called during transaction execution to:
    /// 1. Validate the expiry is within the allowed window
    /// 2. Probe the `valid_before` bucket for an empty/expired cell or matching fingerprint
    ///
    /// # Errors
    /// - `InvalidExpiringNonceExpiry` — `valid_before` not in (now, now + EXPIRING_NONCE_MAX_EXPIRY_SECS]
    /// - `ExpiringNonceReplay` — transaction hash is already recorded and has not yet expired
    /// - `ExpiringNonceProbeExhausted` — all cells on the deterministic probe path are occupied
    pub fn check_expiring_nonce(&self, expiring_nonce_hash: B256, valid_before: u64) -> Result<()> {
        self.checked_expiring_nonce_cell(expiring_nonce_hash, valid_before)
            .map(|_| ())
    }

    /// Validates and records an expiring nonce transaction.
    pub fn check_and_mark_expiring_nonce(
        &mut self,
        expiring_nonce_hash: B256,
        valid_before: u64,
    ) -> Result<()> {
        let (cell_id, cell) =
            self.checked_expiring_nonce_cell(expiring_nonce_hash, valid_before)?;
        self.write_expiring_nonce_cell(cell_id, cell)
    }

    /// Returns the replay-cell write for a valid expiring nonce transaction.
    pub fn checked_expiring_nonce_cell(
        &self,
        expiring_nonce_hash: B256,
        valid_before: u64,
    ) -> Result<(u32, U256)> {
        let (cell_id, fingerprint) =
            self.expiring_nonce_insert_cell(expiring_nonce_hash, valid_before)?;
        Ok((
            cell_id,
            Self::pack_expiring_nonce_cell(valid_before, fingerprint),
        ))
    }

    /// Writes a previously validated expiring nonce replay cell.
    pub fn write_expiring_nonce_cell(&mut self, cell_id: u32, cell: U256) -> Result<()> {
        self.expiring_nonce_cells[cell_id].write(cell)
    }

    fn expiring_nonce_insert_cell(
        &self,
        expiring_nonce_hash: B256,
        valid_before: u64,
    ) -> Result<(u32, U256)> {
        let now: u64 = self.storage.timestamp().saturating_to();

        // 1. Validate expiry window: must be in (now, now + EXPIRING_NONCE_MAX_EXPIRY_SECS]
        if valid_before <= now || valid_before > now.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            return Err(NonceError::invalid_expiring_nonce_expiry().into());
        }

        let fingerprint = Self::expiring_nonce_fingerprint(expiring_nonce_hash);

        for probe in 0..EXPIRING_NONCE_MAX_PROBES {
            let cell_id = Self::expiring_nonce_cell_id(expiring_nonce_hash, valid_before, probe);
            let word = self.expiring_nonce_cells[cell_id].read()?;
            let (stored_v, stored_fingerprint) = Self::unpack_expiring_nonce_cell(word);

            if stored_v != valid_before {
                return Ok((cell_id, fingerprint));
            }

            if stored_fingerprint == fingerprint {
                return Err(NonceError::expiring_nonce_replay().into());
            }

            // Same live bucket, different fingerprint: continue along this tx's probe path.
        }

        Err(NonceError::expiring_nonce_probe_exhausted().into())
    }

    /// Returns all storage slots on a transaction's deterministic probe path.
    pub fn expiring_nonce_cell_slots(
        expiring_nonce_hash: B256,
        valid_before: u64,
    ) -> [U256; EXPIRING_NONCE_MAX_PROBES] {
        std::array::from_fn(|probe| {
            let cell_id = Self::expiring_nonce_cell_id(expiring_nonce_hash, valid_before, probe);
            Self::new().expiring_nonce_cells[cell_id].slot()
        })
    }

    /// Returns the first replay-table storage slot touched by an expiring nonce transaction.
    pub fn expiring_nonce_first_cell_slot(expiring_nonce_hash: B256, valid_before: u64) -> U256 {
        let cell_id = Self::expiring_nonce_cell_id(expiring_nonce_hash, valid_before, 0);
        Self::new().expiring_nonce_cells[cell_id].slot()
    }

    /// Returns true if a packed replay cell is the record for this transaction.
    pub fn expiring_nonce_cell_matches(
        word: U256,
        expiring_nonce_hash: B256,
        valid_before: u64,
    ) -> bool {
        let (stored_v, stored_fingerprint) = Self::unpack_expiring_nonce_cell(word);
        stored_v == valid_before
            && stored_fingerprint == Self::expiring_nonce_fingerprint(expiring_nonce_hash)
    }

    /// Returns the packed replay-cell word written for this transaction.
    pub fn expiring_nonce_cell_word(expiring_nonce_hash: B256, valid_before: u64) -> U256 {
        Self::pack_expiring_nonce_cell(
            valid_before,
            Self::expiring_nonce_fingerprint(expiring_nonce_hash),
        )
    }

    fn expiring_nonce_cell_id(expiring_nonce_hash: B256, valid_before: u64, probe: usize) -> u32 {
        debug_assert!(u64::from(EXPIRING_NONCE_BUCKET_COUNT) > EXPIRING_NONCE_MAX_EXPIRY_SECS);
        debug_assert!(EXPIRING_NONCE_BUCKET_CAPACITY.is_power_of_two());
        debug_assert!(probe < EXPIRING_NONCE_MAX_PROBES);

        let bucket = (valid_before % u64::from(EXPIRING_NONCE_BUCKET_COUNT)) as u32;
        let (home, step) = Self::expiring_nonce_probe(expiring_nonce_hash);
        let position =
            home.wrapping_add((probe as u32).wrapping_mul(step)) % EXPIRING_NONCE_BUCKET_CAPACITY;

        bucket * EXPIRING_NONCE_BUCKET_CAPACITY + position
    }

    fn expiring_nonce_probe(expiring_nonce_hash: B256) -> (u32, u32) {
        let seed =
            Self::expiring_nonce_domain_hash(EXPIRING_NONCE_CELL_DOMAIN, expiring_nonce_hash);
        let seed = seed.as_slice();
        let home = u32::from_be_bytes(seed[0..4].try_into().expect("slice has 4 bytes"))
            % EXPIRING_NONCE_BUCKET_CAPACITY;
        let step = (u32::from_be_bytes(seed[4..8].try_into().expect("slice has 4 bytes")) | 1)
            % EXPIRING_NONCE_BUCKET_CAPACITY;

        (home, step)
    }

    fn expiring_nonce_fingerprint(expiring_nonce_hash: B256) -> U256 {
        U256::from_be_bytes(
            Self::expiring_nonce_domain_hash(
                EXPIRING_NONCE_FINGERPRINT_DOMAIN,
                expiring_nonce_hash,
            )
            .0,
        ) & EXPIRING_NONCE_FINGERPRINT_MASK
    }

    fn expiring_nonce_domain_hash(domain: &[u8], expiring_nonce_hash: B256) -> B256 {
        let mut input = Vec::new();
        input.extend_from_slice(domain);
        input.extend_from_slice(expiring_nonce_hash.as_slice());
        keccak256(input)
    }

    fn pack_expiring_nonce_cell(valid_before: u64, fingerprint: U256) -> U256 {
        (U256::from(valid_before) << 192) | (fingerprint & EXPIRING_NONCE_FINGERPRINT_MASK)
    }

    fn unpack_expiring_nonce_cell(word: U256) -> (u64, U256) {
        let valid_before_word: U256 = word >> 192usize;
        (
            valid_before_word.saturating_to::<u64>(),
            word & EXPIRING_NONCE_FINGERPRINT_MASK,
        )
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
    fn test_check_expiring_nonce_does_not_mark() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let tx_hash = B256::repeat_byte(0x12);
            let valid_before = now + 20;

            mgr.check_expiring_nonce(tx_hash, valid_before)?;
            assert!(!mgr.is_expiring_nonce_seen_at(tx_hash, valid_before)?);

            mgr.check_and_mark_expiring_nonce(tx_hash, valid_before)?;
            assert!(mgr.is_expiring_nonce_seen_at(tx_hash, valid_before)?);

            Ok(())
        })
    }

    #[test]
    fn test_check_expiring_nonce_rejects_replay() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let tx_hash = B256::repeat_byte(0x13);
            let valid_before = now + 20;

            mgr.check_and_mark_expiring_nonce(tx_hash, valid_before)?;

            let result = mgr.check_expiring_nonce(tx_hash, valid_before);
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

            // valid_before at exactly EXPIRING_NONCE_MAX_EXPIRY_SECS should succeed
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

            assert!(mgr.is_expiring_nonce_seen(tx_hash2, new_now)?);

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_same_bucket_reuses_expired_cell() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let now = 1000u64;
        let tx_hash = B256::repeat_byte(0x77);
        let valid_before = now + 20;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            mgr.check_and_mark_expiring_nonce(tx_hash, valid_before)?;
            assert!(mgr.is_expiring_nonce_seen_at(tx_hash, valid_before)?);
            Ok::<_, eyre::Report>(())
        })?;

        let new_now = valid_before + 2;
        let bucket_count = u64::from(EXPIRING_NONCE_BUCKET_COUNT);
        let new_valid_before = valid_before + bucket_count;
        assert_eq!(valid_before % bucket_count, new_valid_before % bucket_count);
        storage.set_timestamp(U256::from(new_now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            mgr.check_and_mark_expiring_nonce(tx_hash, new_valid_before)?;

            assert!(!mgr.is_expiring_nonce_seen_at(tx_hash, valid_before)?);
            assert!(mgr.is_expiring_nonce_seen_at(tx_hash, new_valid_before)?);

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_probe_exhausted() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let tx_hash = B256::repeat_byte(0x88);
            let valid_before = now + 20;
            let tx_fingerprint = NonceManager::expiring_nonce_fingerprint(tx_hash);

            for probe in 0..EXPIRING_NONCE_MAX_PROBES {
                let cell_id = NonceManager::expiring_nonce_cell_id(tx_hash, valid_before, probe);
                let occupant_hash = B256::with_last_byte(probe as u8);
                let occupant_fingerprint = NonceManager::expiring_nonce_fingerprint(occupant_hash);
                assert_ne!(occupant_fingerprint, tx_fingerprint);
                let cell =
                    NonceManager::pack_expiring_nonce_cell(valid_before, occupant_fingerprint);
                mgr.expiring_nonce_cells[cell_id].write(cell)?;
            }

            let result = mgr.check_and_mark_expiring_nonce(tx_hash, valid_before);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_probe_exhausted())
            );

            Ok(())
        })
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
