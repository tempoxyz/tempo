use alloy_primitives::{Address, B256, U256};
use std::collections::BTreeMap;

/// Capacity of the expiring nonce circular buffer (matches NonceManager).
pub const EXPIRING_NONCE_SET_CAPACITY: u32 = 300_000;

/// Maximum allowed expiry skew in seconds.
pub const EXPIRING_NONCE_MAX_EXPIRY_SECS: u64 = 30;

/// Error types from the nonce oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceOracleError {
    ProtocolNonceNotSupported,
    InvalidNonceKey,
    NonceOverflow,
    InvalidExpiringNonceExpiry,
    ExpiringNonceReplay,
    ExpiringNonceSetFull,
}

/// Pure model of the NonceManager precompile state.
#[derive(Debug, Clone)]
pub struct NonceOracle {
    /// 2D nonces: (account, nonce_key) -> current_nonce
    user_nonces: BTreeMap<(Address, U256), u64>,
    /// Expiring nonce seen set: hash -> expiry_timestamp
    expiring_seen: BTreeMap<B256, u64>,
    /// Expiring nonce ring buffer: slot_index -> hash
    expiring_ring: BTreeMap<u32, B256>,
    /// Current ring buffer pointer
    ring_ptr: u32,
}

impl NonceOracle {
    pub fn new() -> Self {
        Self {
            user_nonces: BTreeMap::new(),
            expiring_seen: BTreeMap::new(),
            expiring_ring: BTreeMap::new(),
            ring_ptr: 0,
        }
    }

    /// Set initial nonce state (for pre-seeding).
    pub fn set_nonce(&mut self, account: Address, nonce_key: U256, value: u64) {
        self.user_nonces.insert((account, nonce_key), value);
    }

    /// Get the current nonce for account at nonce_key.
    /// Key 0 (protocol nonce) returns an error.
    pub fn get_nonce(&self, account: Address, nonce_key: U256) -> Result<u64, NonceOracleError> {
        if nonce_key.is_zero() {
            return Err(NonceOracleError::ProtocolNonceNotSupported);
        }
        Ok(*self.user_nonces.get(&(account, nonce_key)).unwrap_or(&0))
    }

    /// Increment nonce for account at nonce_key. Returns the NEW nonce value.
    /// Key 0 is rejected.
    pub fn increment_nonce(
        &mut self,
        account: Address,
        nonce_key: U256,
    ) -> Result<u64, NonceOracleError> {
        if nonce_key.is_zero() {
            return Err(NonceOracleError::InvalidNonceKey);
        }

        let current = *self.user_nonces.get(&(account, nonce_key)).unwrap_or(&0);
        let new_nonce = current
            .checked_add(1)
            .ok_or(NonceOracleError::NonceOverflow)?;
        self.user_nonces.insert((account, nonce_key), new_nonce);
        Ok(new_nonce)
    }

    /// Check if an expiring nonce hash has been seen and is still valid.
    pub fn is_expiring_nonce_seen(&self, hash: B256, now: u64) -> bool {
        if let Some(&expiry) = self.expiring_seen.get(&hash) {
            expiry != 0 && expiry > now
        } else {
            false
        }
    }

    /// Validate and record an expiring nonce transaction.
    /// Models the exact semantics from NonceManager::check_and_mark_expiring_nonce.
    pub fn check_and_mark_expiring_nonce(
        &mut self,
        hash: B256,
        valid_before: u64,
        now: u64,
    ) -> Result<(), NonceOracleError> {
        // 1. Validate expiry window: must be in (now, now + max_skew]
        if valid_before <= now || valid_before > now.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS) {
            return Err(NonceOracleError::InvalidExpiringNonceExpiry);
        }

        // 2. Replay check: reject if hash is already seen and not expired
        if let Some(&seen_expiry) = self.expiring_seen.get(&hash) {
            if seen_expiry != 0 && seen_expiry > now {
                return Err(NonceOracleError::ExpiringNonceReplay);
            }
        }

        // 3. Get current pointer and check if we can evict the existing entry
        let idx = self.ring_ptr;
        let old_hash = self.expiring_ring.get(&idx).copied().unwrap_or(B256::ZERO);

        // 4. If there's an existing entry, check if it's expired (can be evicted)
        if old_hash != B256::ZERO {
            if let Some(&old_expiry) = self.expiring_seen.get(&old_hash) {
                if old_expiry != 0 && old_expiry > now {
                    return Err(NonceOracleError::ExpiringNonceSetFull);
                }
            }
            // Clear old entry from seen set
            self.expiring_seen.insert(old_hash, 0);
        }

        // 5. Insert new entry
        self.expiring_ring.insert(idx, hash);
        self.expiring_seen.insert(hash, valid_before);

        // 6. Advance pointer (wraps at CAPACITY)
        self.ring_ptr = if self.ring_ptr + 1 >= EXPIRING_NONCE_SET_CAPACITY {
            0
        } else {
            self.ring_ptr + 1
        };

        Ok(())
    }

    /// Compute a digest of the current nonce state for comparison.
    pub fn state_digest(&self) -> B256 {
        use alloy_primitives::keccak256;

        let mut data = Vec::new();

        // Include all user nonces
        for ((addr, key), val) in &self.user_nonces {
            data.extend_from_slice(addr.as_slice());
            data.extend_from_slice(&key.to_be_bytes::<32>());
            data.extend_from_slice(&val.to_be_bytes());
        }

        // Include ring pointer
        data.extend_from_slice(&self.ring_ptr.to_be_bytes());

        // Include non-zero seen entries
        for (hash, expiry) in &self.expiring_seen {
            if *expiry != 0 {
                data.extend_from_slice(hash.as_slice());
                data.extend_from_slice(&expiry.to_be_bytes());
            }
        }

        keccak256(&data)
    }
}

impl Default for NonceOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment_nonce() {
        let mut oracle = NonceOracle::new();
        let addr = Address::repeat_byte(1);
        let key = U256::from(1);

        assert_eq!(oracle.get_nonce(addr, key).unwrap(), 0);
        assert_eq!(oracle.increment_nonce(addr, key).unwrap(), 1);
        assert_eq!(oracle.get_nonce(addr, key).unwrap(), 1);
        assert_eq!(oracle.increment_nonce(addr, key).unwrap(), 2);
    }

    #[test]
    fn test_protocol_nonce_rejected() {
        let mut oracle = NonceOracle::new();
        let addr = Address::repeat_byte(1);

        assert_eq!(
            oracle.get_nonce(addr, U256::ZERO),
            Err(NonceOracleError::ProtocolNonceNotSupported)
        );
        assert_eq!(
            oracle.increment_nonce(addr, U256::ZERO),
            Err(NonceOracleError::InvalidNonceKey)
        );
    }

    #[test]
    fn test_expiring_nonce_basic() {
        let mut oracle = NonceOracle::new();
        let hash = B256::repeat_byte(1);
        let now = 1000;

        // Valid: now < valid_before <= now + 30
        assert!(oracle
            .check_and_mark_expiring_nonce(hash, now + 15, now)
            .is_ok());

        // Replay: same hash, still valid
        assert_eq!(
            oracle.check_and_mark_expiring_nonce(hash, now + 20, now),
            Err(NonceOracleError::ExpiringNonceReplay)
        );
    }

    #[test]
    fn test_expiring_nonce_boundary() {
        let mut oracle = NonceOracle::new();
        let now = 1000;

        // valid_before == now → invalid
        assert_eq!(
            oracle.check_and_mark_expiring_nonce(B256::repeat_byte(1), now, now),
            Err(NonceOracleError::InvalidExpiringNonceExpiry)
        );

        // valid_before == now + 1 → valid (minimum)
        assert!(oracle
            .check_and_mark_expiring_nonce(B256::repeat_byte(2), now + 1, now)
            .is_ok());

        // valid_before == now + 30 → valid (maximum)
        assert!(oracle
            .check_and_mark_expiring_nonce(B256::repeat_byte(3), now + 30, now)
            .is_ok());

        // valid_before == now + 31 → invalid
        assert_eq!(
            oracle.check_and_mark_expiring_nonce(B256::repeat_byte(4), now + 31, now),
            Err(NonceOracleError::InvalidExpiringNonceExpiry)
        );
    }

    #[test]
    fn test_expiring_nonce_ring_wraparound() {
        let mut oracle = NonceOracle::new();
        let now = 1000;

        // Set pointer near end
        oracle.ring_ptr = EXPIRING_NONCE_SET_CAPACITY - 1;

        // Insert at last slot
        assert!(oracle
            .check_and_mark_expiring_nonce(B256::repeat_byte(1), now + 10, now)
            .is_ok());
        assert_eq!(oracle.ring_ptr, 0); // Wrapped around

        // Insert at slot 0
        assert!(oracle
            .check_and_mark_expiring_nonce(B256::repeat_byte(2), now + 10, now)
            .is_ok());
        assert_eq!(oracle.ring_ptr, 1);
    }
}
