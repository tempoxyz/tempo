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
    storage::{Handler, Mapping, Slot},
};
use alloy::primitives::{Address, B256, U256, uint};
use tempo_chainspec::hardfork::TempoHardfork;

/// Maximum allowed skew for expiring nonce transactions before TIP-1077.
pub const PRE_TIP_1077_MAX_EXPIRY_SECS: u64 = 30;

/// Capacity of the pre-TIP-1077 expiring nonce seen set.
pub const PRE_TIP_1077_EXPIRING_NONCE_SET_CAPACITY: u32 = 300_000;

/// Maximum allowed skew for expiring nonce transactions (5 minutes).
/// Transactions must have valid_before in (now, now + MAX_EXPIRY_SECS].
pub const EXPIRING_NONCE_MAX_EXPIRY_SECS: u64 = 300;

/// Number of reusable time buckets in the expiring nonce time wheel.
pub const EXPIRING_NONCE_BUCKET_COUNT: u64 = 301;

/// Number of replay cells in each time bucket.
pub const EXPIRING_NONCE_BUCKET_CAPACITY: u64 = 131_072;

/// Number of hash bits used for each probe position.
pub const EXPIRING_NONCE_POSITION_BITS: usize = 17;

/// Maximum number of replay cells probed for one expiring nonce transaction.
pub const EXPIRING_NONCE_MAX_PROBES: usize = 4;

/// Number of replay cells reserved for the whole time wheel.
pub const EXPIRING_NONCE_CELL_COUNT: u64 =
    EXPIRING_NONCE_BUCKET_COUNT * EXPIRING_NONCE_BUCKET_CAPACITY;

/// Base slot of the reserved direct expiring nonce replay-cell range.
pub const EXPIRING_NONCE_CELL_BASE_SLOT: U256 =
    uint!(0x387ee7e371ffafdf29537b927a83c9af016eb1493da1fe163fab229fa2400000_U256);

/// End slot of the reserved direct expiring nonce replay-cell range.
pub const EXPIRING_NONCE_CELL_END_SLOT: U256 =
    uint!(0x387ee7e371ffafdf29537b927a83c9af016eb1493da1fe163fab229fa499ffff_U256);

/// Number of 64-bit fingerprint lanes packed into a replay cell.
pub const EXPIRING_NONCE_PACKED_SLOTS: usize = 3;

const FINGERPRINT_MASK: U256 = U256::from_limbs([u64::MAX, 0, 0, 0]);

/// Returns the active expiring nonce validity window for a hardfork spec.
pub const fn expiring_nonce_max_expiry_secs_for_spec(spec: TempoHardfork) -> u64 {
    if spec.is_t8() {
        EXPIRING_NONCE_MAX_EXPIRY_SECS
    } else {
        PRE_TIP_1077_MAX_EXPIRY_SECS
    }
}

/// Returns the nonzero 64-bit replay fingerprint for `expiring_nonce_hash`.
pub fn expiring_nonce_fingerprint(expiring_nonce_hash: B256) -> u64 {
    let hash = expiring_nonce_hash.as_slice();
    let primary = u64::from_be_bytes(hash[24..32].try_into().expect("slice length is 8"));
    if primary != 0 {
        return primary;
    }

    let fallback = u64::from_be_bytes(hash[16..24].try_into().expect("slice length is 8"));
    if fallback != 0 { fallback } else { 1 }
}

/// Returns the direct replay-cell slot for one deterministic probe.
pub fn expiring_nonce_cell_slot(
    expiring_nonce_hash: B256,
    valid_before: u64,
    probe: usize,
) -> U256 {
    debug_assert!(probe < EXPIRING_NONCE_MAX_PROBES);
    let bucket = valid_before % EXPIRING_NONCE_BUCKET_COUNT;
    let position = expiring_nonce_probe_position(expiring_nonce_hash, probe);
    let cell_id = bucket * EXPIRING_NONCE_BUCKET_CAPACITY + position;
    EXPIRING_NONCE_CELL_BASE_SLOT + U256::from(cell_id)
}

/// Returns all deterministic replay-cell slots for an expiring nonce transaction.
pub fn expiring_nonce_probe_slots(
    expiring_nonce_hash: B256,
    valid_before: u64,
) -> [U256; EXPIRING_NONCE_MAX_PROBES] {
    core::array::from_fn(|probe| expiring_nonce_cell_slot(expiring_nonce_hash, valid_before, probe))
}

/// Encodes a TIP-1077 replay cell.
pub fn pack_expiring_nonce_cell(valid_before: u64, fingerprints: [u64; 3]) -> U256 {
    (U256::from(valid_before) << 192)
        | (U256::from(fingerprints[0]) << 128)
        | (U256::from(fingerprints[1]) << 64)
        | U256::from(fingerprints[2])
}

/// Returns true if a packed replay cell contains the live transaction fingerprint.
pub fn expiring_nonce_cell_contains(word: U256, valid_before: u64, fingerprint: u64) -> bool {
    let (stored_valid_before, fingerprints) = unpack_expiring_nonce_cell(word);
    stored_valid_before == valid_before && fingerprints.contains(&fingerprint)
}

fn expiring_nonce_probe_position(expiring_nonce_hash: B256, probe: usize) -> u64 {
    let hash = expiring_nonce_hash.as_slice();
    let start_bit = probe * EXPIRING_NONCE_POSITION_BITS;
    let mut position = 0u64;

    for offset in 0..EXPIRING_NONCE_POSITION_BITS {
        let bit_index = start_bit + offset;
        let byte = hash[bit_index / 8];
        let bit = (byte >> (7 - (bit_index % 8))) & 1;
        position = (position << 1) | u64::from(bit);
    }

    position
}

fn unpack_expiring_nonce_cell(word: U256) -> (u64, [u64; 3]) {
    let valid_before = (word >> 192usize).to::<u64>();
    let fingerprints = [
        ((word >> 128usize) & FINGERPRINT_MASK).to::<u64>(),
        ((word >> 64usize) & FINGERPRINT_MASK).to::<u64>(),
        (word & FINGERPRINT_MASK).to::<u64>(),
    ];

    (valid_before, fingerprints)
}

/// NonceManager contract for managing 2D nonces as per the AA spec
///
/// Storage Layout (similar to Solidity contract):
/// ```solidity
/// contract Nonce {
///     mapping(address => mapping(uint256 => uint64)) public nonces;      // slot 0
///
///     // Slots 1, 2, and 3 are reserved for pre-TIP-1077 expiring nonce state.
/// }
/// ```
///
/// - Slot 0: 2D nonce mapping - keccak256(abi.encode(nonce_key, keccak256(abi.encode(account, 0))))
/// - Slot 1: Reserved old expiring nonce seen set - txHash => expiry timestamp
/// - Slot 2: Reserved old expiring nonce circular buffer - index => txHash
/// - Slot 3: Reserved old circular buffer pointer
/// - EXPIRING_NONCE_CELL_BASE_SLOT..=EXPIRING_NONCE_CELL_END_SLOT: TIP-1077 replay cells
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

    /// Checks if a hash is present in the pre-TIP-1077 seen mapping.
    pub fn is_pre_tip_1077_expiring_nonce_seen(&self, hash: B256, now: u64) -> Result<bool> {
        let expiry = self.expiring_nonce_seen[hash].read()?;
        Ok(expiry != 0 && expiry > now)
    }

    /// Validates and records an expiring nonce transaction in the TIP-1077 time wheel.
    ///
    /// # Errors
    /// - `InvalidExpiringNonceExpiry` — `valid_before` not in (now, now + EXPIRING_NONCE_MAX_EXPIRY_SECS]
    /// - `ExpiringNonceReplay` — transaction fingerprint is already recorded for `valid_before`
    /// - `ExpiringNonceSetFull` — all cells on the deterministic probe path are full
    pub fn check_and_mark_expiring_nonce(
        &mut self,
        expiring_nonce_hash: B256,
        valid_before: u64,
    ) -> Result<()> {
        if !self.storage.spec().is_t8() {
            return self
                .check_and_mark_pre_tip_1077_expiring_nonce(expiring_nonce_hash, valid_before);
        }

        self.check_and_mark_timewheel_expiring_nonce(expiring_nonce_hash, valid_before)
    }

    fn check_and_mark_pre_tip_1077_expiring_nonce(
        &mut self,
        expiring_nonce_hash: B256,
        valid_before: u64,
    ) -> Result<()> {
        let now: u64 = self.storage.timestamp().saturating_to();

        if valid_before <= now || valid_before > now.saturating_add(PRE_TIP_1077_MAX_EXPIRY_SECS) {
            return Err(NonceError::invalid_expiring_nonce_expiry().into());
        }

        let seen_expiry = self.expiring_nonce_seen[expiring_nonce_hash].read()?;
        if seen_expiry != 0 && seen_expiry > now {
            return Err(NonceError::expiring_nonce_replay().into());
        }

        let ptr = self.expiring_nonce_ring_ptr.read()?;
        let old_hash = self.expiring_nonce_ring[ptr].read()?;

        if old_hash != B256::ZERO {
            let old_expiry = self.expiring_nonce_seen[old_hash].read()?;
            if old_expiry != 0 && old_expiry > now {
                return Err(NonceError::expiring_nonce_set_full().into());
            }
            self.expiring_nonce_seen[old_hash].write(0)?;
        }

        self.expiring_nonce_ring[ptr].write(expiring_nonce_hash)?;
        self.expiring_nonce_seen[expiring_nonce_hash].write(valid_before)?;

        let next = if ptr + 1 >= PRE_TIP_1077_EXPIRING_NONCE_SET_CAPACITY {
            0
        } else {
            ptr + 1
        };
        self.expiring_nonce_ring_ptr.write(next)?;

        Ok(())
    }

    fn check_and_mark_timewheel_expiring_nonce(
        &mut self,
        expiring_nonce_hash: B256,
        valid_before: u64,
    ) -> Result<()> {
        let now: u64 = self.storage.timestamp().saturating_to();

        // 1. Validate expiry window: must be in (now, now + EXPIRING_NONCE_MAX_EXPIRY_SECS]
        if valid_before <= now || valid_before > now.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            return Err(NonceError::invalid_expiring_nonce_expiry().into());
        }

        let fingerprint = expiring_nonce_fingerprint(expiring_nonce_hash);

        for slot in expiring_nonce_probe_slots(expiring_nonce_hash, valid_before) {
            let mut cell = Slot::<U256>::new(slot, NONCE_PRECOMPILE_ADDRESS);
            let word = cell.read()?;
            let (stored_valid_before, mut fingerprints) = unpack_expiring_nonce_cell(word);

            if stored_valid_before != valid_before {
                cell.write(pack_expiring_nonce_cell(valid_before, [fingerprint, 0, 0]))?;
                return Ok(());
            }

            if fingerprints.contains(&fingerprint) {
                return Err(NonceError::expiring_nonce_replay().into());
            }

            if let Some(empty) = fingerprints
                .iter_mut()
                .find(|fingerprint| **fingerprint == 0)
            {
                *empty = fingerprint;
                cell.write(pack_expiring_nonce_cell(valid_before, fingerprints))?;
                return Ok(());
            }
        }

        Err(NonceError::expiring_nonce_set_full().into())
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

    fn hash_with_fingerprint(fingerprint: u64) -> B256 {
        hash_with_probe_path_and_fingerprint([0, 0, 0, 0], fingerprint)
    }

    fn hash_with_probe_path_and_fingerprint(positions: [u64; 4], fingerprint: u64) -> B256 {
        let mut hash = [0u8; 32];

        for (probe, position) in positions.into_iter().enumerate() {
            for offset in 0..EXPIRING_NONCE_POSITION_BITS {
                let bit = (position >> (EXPIRING_NONCE_POSITION_BITS - 1 - offset)) & 1;
                if bit == 0 {
                    continue;
                }

                let bit_index = probe * EXPIRING_NONCE_POSITION_BITS + offset;
                hash[bit_index / 8] |= 1 << (7 - (bit_index % 8));
            }
        }

        hash[24..32].copy_from_slice(&fingerprint.to_be_bytes());
        B256::from(hash)
    }

    fn t8_storage() -> HashMapStorageProvider {
        HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8)
    }

    #[test]
    fn test_expiring_nonce_basic_flow() -> eyre::Result<()> {
        let mut storage = t8_storage();
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let tx_hash = hash_with_fingerprint(0x11);
            let valid_before = now + 200;

            mgr.check_and_mark_expiring_nonce(tx_hash, valid_before)?;

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
        let mut storage = t8_storage();
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

            let result = mgr
                .check_and_mark_expiring_nonce(tx_hash, now + EXPIRING_NONCE_MAX_EXPIRY_SECS + 1);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );

            // valid_before at exactly EXPIRING_NONCE_MAX_EXPIRY_SECS should succeed
            mgr.check_and_mark_expiring_nonce(tx_hash, now + EXPIRING_NONCE_MAX_EXPIRY_SECS)?;

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_packs_three_fingerprints_per_cell() -> eyre::Result<()> {
        let mut storage = t8_storage();
        let now = 1000u64;
        let valid_before = now + 100;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            for fingerprint in 1..=3 {
                mgr.check_and_mark_expiring_nonce(
                    hash_with_fingerprint(fingerprint),
                    valid_before,
                )?;
            }

            let slot = expiring_nonce_cell_slot(hash_with_fingerprint(1), valid_before, 0);
            let word = Slot::<U256>::new(slot, NONCE_PRECOMPILE_ADDRESS).read()?;

            for fingerprint in 1..=3 {
                assert!(expiring_nonce_cell_contains(
                    word,
                    valid_before,
                    fingerprint
                ));
            }

            Ok::<_, eyre::Report>(())
        })
    }

    #[test]
    fn test_expiring_nonce_probe_exhaustion_rejects() -> eyre::Result<()> {
        let mut storage = t8_storage();
        let now = 1000u64;
        let valid_before = now + 100;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            for fingerprint in 1..=(EXPIRING_NONCE_MAX_PROBES * EXPIRING_NONCE_PACKED_SLOTS) {
                mgr.check_and_mark_expiring_nonce(
                    hash_with_probe_path_and_fingerprint([0, 1, 2, 3], fingerprint as u64),
                    valid_before,
                )?;
            }

            let result = mgr.check_and_mark_expiring_nonce(
                hash_with_probe_path_and_fingerprint([0, 1, 2, 3], 13),
                valid_before,
            );
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::expiring_nonce_set_full())
            );

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_reuses_same_bucket_after_expiry_window() -> eyre::Result<()> {
        let mut storage = t8_storage();
        let now = 1000u64;
        let valid_before = now + 100;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            mgr.check_and_mark_expiring_nonce(hash_with_fingerprint(1), valid_before)?;
            Ok::<_, eyre::Report>(())
        })?;

        let new_now = valid_before + 1;
        let new_valid_before = valid_before + EXPIRING_NONCE_BUCKET_COUNT;
        assert_eq!(
            valid_before % EXPIRING_NONCE_BUCKET_COUNT,
            new_valid_before % EXPIRING_NONCE_BUCKET_COUNT
        );
        assert!(new_valid_before <= new_now + EXPIRING_NONCE_MAX_EXPIRY_SECS);

        storage.set_timestamp(U256::from(new_now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            mgr.check_and_mark_expiring_nonce(hash_with_fingerprint(2), new_valid_before)?;

            let slot = expiring_nonce_cell_slot(hash_with_fingerprint(2), new_valid_before, 0);
            let word = Slot::<U256>::new(slot, NONCE_PRECOMPILE_ADDRESS).read()?;
            assert!(expiring_nonce_cell_contains(
                word,
                new_valid_before,
                expiring_nonce_fingerprint(hash_with_fingerprint(2))
            ));

            Ok::<_, eyre::Report>(())
        })
    }

    #[test]
    fn test_pre_tip_1077_expiring_nonce_uses_legacy_ring_window() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        let now = 1000u64;
        storage.set_timestamp(U256::from(now));
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();
            let tx_hash = B256::repeat_byte(0x42);

            let too_far =
                mgr.check_and_mark_expiring_nonce(tx_hash, now + PRE_TIP_1077_MAX_EXPIRY_SECS + 1);
            assert_eq!(
                too_far.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::invalid_expiring_nonce_expiry())
            );

            mgr.check_and_mark_expiring_nonce(tx_hash, now + PRE_TIP_1077_MAX_EXPIRY_SECS)?;
            assert!(mgr.is_pre_tip_1077_expiring_nonce_seen(tx_hash, now)?);
            assert_eq!(mgr.expiring_nonce_ring_ptr.read()?, 1);

            let timewheel_slot =
                expiring_nonce_cell_slot(tx_hash, now + PRE_TIP_1077_MAX_EXPIRY_SECS, 0);
            assert_eq!(
                Slot::<U256>::new(timewheel_slot, NONCE_PRECOMPILE_ADDRESS).read()?,
                U256::ZERO
            );

            Ok::<_, eyre::Report>(())
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
