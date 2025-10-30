pub mod dispatch;

use crate::{error::TempoPrecompileError, storage::PrecompileStorageProvider};
use alloy::{
    primitives::{Address, B256, U256},
    sol,
};

// Define the Solidity interface for the keychain
sol! {
    /// Token spending limit structure
    struct TokenLimit {
        address token;
        uint256 amount;
    }

    /// Key information structure
    struct KeyInfo {
        uint8 signatureType;
        address keyId;
        uint64 expiry;

    }

    interface IAccountKeychain {
        /// Emitted when a new key is authorized
        event KeyAuthorized(address indexed account, bytes32 indexed publicKey, uint8 signatureType, uint64 expiry);

        /// Emitted when a key is revoked
        event KeyRevoked(address indexed account, bytes32 indexed publicKey);

        /// Emitted when a spending limit is updated
        event SpendingLimitUpdated(address indexed account, bytes32 indexed publicKey, address indexed token, uint256 newLimit);

        /// Authorize a new key for the caller's account
        /// @param publicKey The public key or key identifier to authorize
        /// @param signatureType 0: secp256k1, 1: P256, 2: WebAuthn
        /// @param expiry Block timestamp when the key expires
        /// @param limits Initial spending limits for tokens
        function authorizeKey(
            bytes32 publicKey,
            uint8 signatureType,
            uint64 expiry,
            TokenLimit[] calldata limits
        ) external;

        /// Revoke an authorized key
        /// @param publicKey The public key to revoke
        function revokeKey(bytes32 publicKey) external;

        /// Update spending limit for a key-token pair
        /// @param publicKey The public key
        /// @param token The token address
        /// @param newLimit The new spending limit
        function updateSpendingLimit(
            bytes32 publicKey,
            address token,
            uint256 newLimit
        ) external;

        /// Get key information
        /// @param account The account address
        /// @param publicKey The public key
        /// @return Key information
        function getKey(address account, bytes32 publicKey) external view returns (KeyInfo memory);

        /// Get remaining spending limit
        /// @param account The account address
        /// @param publicKey The public key
        /// @param token The token address
        /// @return Remaining spending amount
        function getRemainingLimit(
            address account,
            bytes32 publicKey,
            address token
        ) external view returns (uint256);

        /// Get the key used in the current transaction
        /// @return The public key used in the current transaction
        function getLastUsedKey() external view returns (bytes32);
    }
}

pub use IAccountKeychain::*;

/// Errors for the Account Keychain precompile
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountKeychainError {
    UnauthorizedCaller,
    KeyAlreadyExists,
    KeyNotFound,
    KeyExpired,
    KeyInactive,
    SpendingLimitExceeded,
    InvalidSignatureType,
    ZeroPublicKey,
}

/// Storage slots for Account Keychain precompile data
pub mod slots {
    use crate::storage::slots::abi_encode_with_signature;
    use alloy::primitives::{Address, B256, U256};

    /// Base slot for keys mapping: keys[account][publicKey]
    pub const KEYS_BASE: U256 = U256::ZERO;

    /// Base slot for spending limits mapping: spendingLimits[account][publicKey][token]
    pub const SPENDING_LIMITS_BASE: U256 = U256::from_limbs([1, 0, 0, 0]);

    /// Base slot for last used key mapping: lastUsedKey[account]
    pub const LAST_USED_KEY: U256 = U256::from_limbs([2, 0, 0, 0]);

    /// Compute storage slot for keys[account][publicKey]
    pub fn key_slot(account: &Address, public_key: &B256) -> U256 {
        // First hash: keccak256(abi.encode(account, KEYS_BASE))
        let inner_data = abi_encode_with_signature(account, KEYS_BASE.to_be_bytes::<32>());
        let inner_hash = alloy::primitives::keccak256(&inner_data);

        // Second hash: keccak256(abi.encode(publicKey, inner_hash))
        let outer_data = abi_encode_with_signature(public_key, inner_hash.0);
        U256::from_be_bytes(alloy::primitives::keccak256(&outer_data).0)
    }

    /// Compute storage slot for spendingLimits[account][publicKey][token]
    pub fn spending_limit_slot(account: &Address, public_key: &B256, token: &Address) -> U256 {
        // First hash: keccak256(abi.encode(account, SPENDING_LIMITS_BASE))
        let inner1_data =
            abi_encode_with_signature(account, SPENDING_LIMITS_BASE.to_be_bytes::<32>());
        let inner1_hash = alloy::primitives::keccak256(&inner1_data);

        // Second hash: keccak256(abi.encode(publicKey, inner1_hash))
        let inner2_data = abi_encode_with_signature(public_key, inner1_hash.0);
        let inner2_hash = alloy::primitives::keccak256(&inner2_data);

        // Third hash: keccak256(abi.encode(token, inner2_hash))
        let outer_data = abi_encode_with_signature(token, inner2_hash.0);
        U256::from_be_bytes(alloy::primitives::keccak256(&outer_data).0)
    }

    /// Compute storage slot for lastUsedKey[account]
    pub fn last_used_key_slot(account: &Address) -> U256 {
        let data = abi_encode_with_signature(account, LAST_USED_KEY.to_be_bytes::<32>());
        U256::from_be_bytes(alloy::primitives::keccak256(&data).0)
    }
}

/// Key information stored in the precompile
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedKey {
    pub signature_type: u8, // 0: secp256k1, 1: P256, 2: WebAuthn
    pub expiry: u64,        // Block timestamp when key expires
    pub is_active: bool,    // Whether key is active
}

impl AuthorizedKey {
    /// Pack the key struct into a single U256 for storage
    /// Layout: [signature_type (1 byte)][expiry (8 bytes)][is_active (1 byte)][padding (22 bytes)]
    pub fn pack(&self) -> U256 {
        let mut packed = [0u8; 32];
        packed[0] = self.signature_type;
        packed[1..9].copy_from_slice(&self.expiry.to_be_bytes());
        packed[9] = if self.is_active { 1 } else { 0 };
        U256::from_be_bytes(packed)
    }

    /// Unpack a U256 storage value into a key struct
    pub fn unpack(value: U256) -> Self {
        let bytes = value.to_be_bytes::<32>();
        let expiry = u64::from_be_bytes(bytes[1..9].try_into().unwrap());

        Self {
            signature_type: bytes[0],
            expiry,
            is_active: bytes[9] != 0,
        }
    }
}

/// Account Keychain contract for managing authorized keys
#[derive(Debug)]
pub struct AccountKeychain<'a, S: PrecompileStorageProvider> {
    pub storage: &'a mut S,
    pub precompile_address: Address,
}

impl<'a, S: PrecompileStorageProvider> AccountKeychain<'a, S> {
    pub fn new(storage: &'a mut S, precompile_address: Address) -> Self {
        Self {
            storage,
            precompile_address,
        }
    }

    /// Authorize a new key for an account
    /// This can only be called by the account itself (using main key)
    pub fn authorize_key(
        &mut self,
        call: authorizeKeyCall,
        msg_sender: &Address,
    ) -> Result<(), TempoPrecompileError> {
        // Check that the last used key for this transaction is empty (main key)
        let last_used_key_slot = slots::last_used_key_slot(msg_sender);
        let last_used_key = self
            .storage
            .sload(self.precompile_address, last_used_key_slot)?;

        // If last_used_key is not zero, it means a secondary key is being used
        if last_used_key != U256::ZERO {
            return Err(AccountKeychainError::UnauthorizedCaller.into());
        }

        // Validate inputs
        if call.publicKey == B256::ZERO {
            return Err(AccountKeychainError::ZeroPublicKey.into());
        }

        if call.signatureType > 2 {
            return Err(AccountKeychainError::InvalidSignatureType.into());
        }

        // Check if key already exists
        let key_slot = slots::key_slot(msg_sender, &call.publicKey);
        let existing = self.storage.sload(self.precompile_address, key_slot)?;

        if existing != U256::ZERO {
            let existing_key = AuthorizedKey::unpack(existing);
            if existing_key.is_active {
                return Err(AccountKeychainError::KeyAlreadyExists.into());
            }
        }

        // Create and store the new key
        let new_key = AuthorizedKey {
            signature_type: call.signatureType,
            expiry: call.expiry,
            is_active: true,
        };

        self.storage
            .sstore(self.precompile_address, key_slot, new_key.pack())?;

        // Set initial spending limits
        for limit in call.limits {
            let limit_slot = slots::spending_limit_slot(msg_sender, &call.publicKey, &limit.token);
            self.storage
                .sstore(self.precompile_address, limit_slot, limit.amount)?;
        }

        Ok(())
    }

    /// Revoke an authorized key
    pub fn revoke_key(
        &mut self,
        call: revokeKeyCall,
        msg_sender: &Address,
    ) -> Result<(), TempoPrecompileError> {
        let last_used_key_slot = slots::last_used_key_slot(msg_sender);
        let last_used_key = self
            .storage
            .sload(self.precompile_address, last_used_key_slot)?;

        if last_used_key != U256::ZERO {
            return Err(AccountKeychainError::UnauthorizedCaller.into());
        }

        let key_slot = slots::key_slot(msg_sender, &call.publicKey);
        let existing = self.storage.sload(self.precompile_address, key_slot)?;

        if existing == U256::ZERO {
            return Err(AccountKeychainError::KeyNotFound.into());
        }

        let mut key = AuthorizedKey::unpack(existing);
        if !key.is_active {
            return Err(AccountKeychainError::KeyInactive.into());
        }

        // Mark key as inactive
        key.is_active = false;
        self.storage
            .sstore(self.precompile_address, key_slot, key.pack())?;

        Ok(())
    }

    /// Update spending limit for a key-token pair
    pub fn update_spending_limit(
        &mut self,
        call: updateSpendingLimitCall,
        msg_sender: &Address,
    ) -> Result<(), TempoPrecompileError> {
        let last_used_key_slot = slots::last_used_key_slot(msg_sender);
        let last_used_key = self
            .storage
            .sload(self.precompile_address, last_used_key_slot)?;

        if last_used_key != U256::ZERO {
            return Err(AccountKeychainError::UnauthorizedCaller.into());
        }

        // Verify key exists and is active
        let key_slot = slots::key_slot(msg_sender, &call.publicKey);
        let existing = self.storage.sload(self.precompile_address, key_slot)?;

        if existing == U256::ZERO {
            return Err(AccountKeychainError::KeyNotFound.into());
        }

        let key = AuthorizedKey::unpack(existing);
        if !key.is_active {
            return Err(AccountKeychainError::KeyInactive.into());
        }

        // Update the spending limit
        let limit_slot = slots::spending_limit_slot(msg_sender, &call.publicKey, &call.token);
        self.storage
            .sstore(self.precompile_address, limit_slot, call.newLimit)?;

        Ok(())
    }

    /// Get key information
    pub fn get_key(&mut self, call: getKeyCall) -> Result<KeyInfo, TempoPrecompileError> {
        let key_slot = slots::key_slot(&call.account, &call.publicKey);
        let value = self.storage.sload(self.precompile_address, key_slot)?;

        if value == U256::ZERO {
            // Return default (non-existent key)
            return Ok(KeyInfo {
                signatureType: 0,
                keyId: Address::ZERO,
                expiry: 0,
            });
        }

        let key = AuthorizedKey::unpack(value);
        // Derive keyId from the public key hash
        // For now, we use the public key hash directly as the key ID
        let key_id = Address::from_slice(&call.publicKey.as_slice()[0..20]);
        Ok(KeyInfo {
            signatureType: key.signature_type,
            keyId: key_id,
            expiry: key.expiry,
        })
    }

    /// Get remaining spending limit
    pub fn get_remaining_limit(
        &mut self,
        call: getRemainingLimitCall,
    ) -> Result<U256, TempoPrecompileError> {
        let limit_slot = slots::spending_limit_slot(&call.account, &call.publicKey, &call.token);
        self.storage.sload(self.precompile_address, limit_slot)
    }

    /// Get the last used key for the current transaction
    pub fn get_last_used_key(
        &mut self,
        _call: getLastUsedKeyCall,
        msg_sender: &Address,
    ) -> Result<B256, TempoPrecompileError> {
        let slot = slots::last_used_key_slot(msg_sender);
        let value = self.storage.sload(self.precompile_address, slot)?;
        Ok(B256::from(value.to_be_bytes::<32>()))
    }

    /// Internal: Set the last used key (called during transaction validation)
    ///
    /// SECURITY CRITICAL: This must be called by the transaction validation logic
    /// BEFORE the transaction is executed, to store which key authorized the transaction.
    /// - If auth_key is B256::ZERO (main key), this should store U256::ZERO
    /// - If auth_key is a specific public key, this should store that key
    ///
    /// This creates a secure channel between validation and the precompile to ensure
    /// only the main key can authorize/revoke other keys.
    pub fn set_last_used_key(
        &mut self,
        account: &Address,
        public_key: &B256,
    ) -> Result<(), TempoPrecompileError> {
        let slot = slots::last_used_key_slot(account);
        // Store U256::ZERO if using main key (public_key == B256::ZERO)
        // Otherwise store the actual public key
        let value = if *public_key == B256::ZERO {
            U256::ZERO
        } else {
            U256::from_be_bytes(public_key.0)
        };
        self.storage.sstore(self.precompile_address, slot, value)?;
        Ok(())
    }

    /// Validate keychain authorization (existence, active status, expiry)
    ///
    /// This consolidates all validation checks into one method.
    /// Returns Ok(()) if the key is valid and authorized, Err otherwise.
    pub fn validate_keychain_authorization(
        &mut self,
        account: &Address,
        public_key: &B256,
        current_timestamp: u64,
    ) -> Result<(), TempoPrecompileError> {
        // If using main key (zero public key), always valid
        if *public_key == B256::ZERO {
            return Ok(());
        }

        let key_slot = slots::key_slot(account, public_key);
        let value = self.storage.sload(self.precompile_address, key_slot)?;

        if value == U256::ZERO {
            return Err(AccountKeychainError::KeyNotFound.into());
        }

        let key = AuthorizedKey::unpack(value);

        if !key.is_active {
            return Err(AccountKeychainError::KeyInactive.into());
        }

        if key.expiry > 0 && current_timestamp >= key.expiry {
            return Err(AccountKeychainError::KeyExpired.into());
        }

        Ok(())
    }

    /// Internal: Verify and update spending for a token transfer
    pub fn verify_and_update_spending(
        &mut self,
        account: &Address,
        public_key: &B256,
        token: &Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        // If using main key (zero public key), no spending limits apply
        if *public_key == B256::ZERO {
            return Ok(());
        }

        // Check key is valid
        let key_slot = slots::key_slot(account, public_key);
        let key_value = self.storage.sload(self.precompile_address, key_slot)?;

        if key_value == U256::ZERO {
            return Err(AccountKeychainError::KeyNotFound.into());
        }

        let key = AuthorizedKey::unpack(key_value);
        if !key.is_active {
            return Err(AccountKeychainError::KeyInactive.into());
        }

        // Check and update spending limit
        let limit_slot = slots::spending_limit_slot(account, public_key, token);
        let remaining = self.storage.sload(self.precompile_address, limit_slot)?;

        if amount > remaining {
            return Err(AccountKeychainError::SpendingLimitExceeded.into());
        }

        // Update remaining limit
        self.storage
            .sstore(self.precompile_address, limit_slot, remaining - amount)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorized_key_pack_unpack() {
        let key = AuthorizedKey {
            signature_type: 1,
            expiry: 1234567890,
            is_active: true,
        };

        let packed = key.pack();
        let unpacked = AuthorizedKey::unpack(packed);

        assert_eq!(key, unpacked);
    }

    #[test]
    fn test_storage_slot_computation() {
        let account = Address::from([1u8; 20]);
        let public_key = B256::from([2u8; 32]);
        let token = Address::from([3u8; 20]);

        // Slots should be deterministic
        let key_slot1 = slots::key_slot(&account, &public_key);
        let key_slot2 = slots::key_slot(&account, &public_key);
        assert_eq!(key_slot1, key_slot2);

        let limit_slot1 = slots::spending_limit_slot(&account, &public_key, &token);
        let limit_slot2 = slots::spending_limit_slot(&account, &public_key, &token);
        assert_eq!(limit_slot1, limit_slot2);

        // Different inputs should produce different slots
        let different_key = B256::from([4u8; 32]);
        let different_slot = slots::key_slot(&account, &different_key);
        assert_ne!(key_slot1, different_slot);
    }
}
