pub mod dispatch;

use tempo_contracts::precompiles::AccountKeychainError;
pub use tempo_contracts::precompiles::{
    IAccountKeychain,
    IAccountKeychain::{
        authorizeKeyCall, getKeyCall, getRemainingLimitCall, getTransactionKeyCall, revokeKeyCall,
        updateSpendingLimitCall,
    },
    KeyInfo, SignatureType, TokenLimit,
};

use crate::{error::TempoPrecompileError, storage::PrecompileStorageProvider};
use alloy::primitives::{Address, U256};

/// Storage slots for Account Keychain precompile data
pub mod slots {
    use crate::storage::slots::abi_encode_with_signature;
    use alloy::primitives::{Address, U256};

    /// Base slot for keys mapping: keys\[account\]\[keyId\]
    pub const KEYS_BASE: U256 = U256::ZERO;

    /// Base slot for spending limits mapping: spendingLimits\[account\]\[keyId\]\[token\]
    pub const SPENDING_LIMITS_BASE: U256 = U256::from_limbs([1, 0, 0, 0]);

    /// Base slot for transaction key mapping: transactionKey\[account\]
    pub const TRANSACTION_KEY: U256 = U256::from_limbs([2, 0, 0, 0]);

    /// Compute storage slot for keys\[account\]\[keyId\]
    pub fn key_slot(account: &Address, key_id: &Address) -> U256 {
        // First hash: keccak256(abi.encode(account, KEYS_BASE))
        let inner_data = abi_encode_with_signature(account, KEYS_BASE.to_be_bytes::<32>());
        let inner_hash = alloy::primitives::keccak256(&inner_data);

        // Second hash: keccak256(abi.encode(keyId, inner_hash))
        let outer_data = abi_encode_with_signature(key_id, inner_hash.0);
        U256::from_be_bytes(alloy::primitives::keccak256(&outer_data).0)
    }

    /// Compute storage slot for spendingLimits\[account\]\[keyId\]\[token\]
    pub fn spending_limit_slot(account: &Address, key_id: &Address, token: &Address) -> U256 {
        // First hash: keccak256(abi.encode(account, SPENDING_LIMITS_BASE))
        let inner1_data =
            abi_encode_with_signature(account, SPENDING_LIMITS_BASE.to_be_bytes::<32>());
        let inner1_hash = alloy::primitives::keccak256(&inner1_data);

        // Second hash: keccak256(abi.encode(keyId, inner1_hash))
        let inner2_data = abi_encode_with_signature(key_id, inner1_hash.0);
        let inner2_hash = alloy::primitives::keccak256(&inner2_data);

        // Third hash: keccak256(abi.encode(token, inner2_hash))
        let outer_data = abi_encode_with_signature(token, inner2_hash.0);
        U256::from_be_bytes(alloy::primitives::keccak256(&outer_data).0)
    }

    /// Compute storage slot for transactionKey\[account\]
    pub fn transaction_key_slot(account: &Address) -> U256 {
        let data = abi_encode_with_signature(account, TRANSACTION_KEY.to_be_bytes::<32>());
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
        // Check that the transaction key for this transaction is zero (main key)
        let transaction_key_slot = slots::transaction_key_slot(msg_sender);
        let transaction_key = self
            .storage
            .sload(self.precompile_address, transaction_key_slot)?;

        // If transaction_key is not zero, it means a secondary key is being used
        if transaction_key != U256::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        // Validate inputs
        if call.keyId == Address::ZERO {
            return Err(AccountKeychainError::zero_public_key().into());
        }

        // Check if key already exists
        let key_slot = slots::key_slot(msg_sender, &call.keyId);
        let existing = self.storage.sload(self.precompile_address, key_slot)?;

        if existing != U256::ZERO {
            let existing_key = AuthorizedKey::unpack(existing);
            if existing_key.is_active {
                return Err(AccountKeychainError::key_already_exists().into());
            }
        }

        // Convert SignatureType enum to u8 for storage
        let signature_type = match call.signatureType {
            SignatureType::Secp256k1 => 0,
            SignatureType::P256 => 1,
            SignatureType::WebAuthn => 2,
            _ => return Err(AccountKeychainError::invalid_signature_type().into()),
        };

        // Create and store the new key
        let new_key = AuthorizedKey {
            signature_type,
            expiry: call.expiry,
            is_active: true,
        };

        self.storage
            .sstore(self.precompile_address, key_slot, new_key.pack())?;

        // Set initial spending limits
        for limit in call.limits {
            let limit_slot = slots::spending_limit_slot(msg_sender, &call.keyId, &limit.token);
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
        let transaction_key_slot = slots::transaction_key_slot(msg_sender);
        let transaction_key = self
            .storage
            .sload(self.precompile_address, transaction_key_slot)?;

        if transaction_key != U256::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        let key_slot = slots::key_slot(msg_sender, &call.keyId);
        let existing = self.storage.sload(self.precompile_address, key_slot)?;

        if existing == U256::ZERO {
            return Err(AccountKeychainError::key_not_found().into());
        }

        let mut key = AuthorizedKey::unpack(existing);
        if !key.is_active {
            return Err(AccountKeychainError::key_inactive().into());
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
        let transaction_key_slot = slots::transaction_key_slot(msg_sender);
        let transaction_key = self
            .storage
            .sload(self.precompile_address, transaction_key_slot)?;

        if transaction_key != U256::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        // Verify key exists and is active
        let key_slot = slots::key_slot(msg_sender, &call.keyId);
        let existing = self.storage.sload(self.precompile_address, key_slot)?;

        if existing == U256::ZERO {
            return Err(AccountKeychainError::key_not_found().into());
        }

        let key = AuthorizedKey::unpack(existing);
        if !key.is_active {
            return Err(AccountKeychainError::key_inactive().into());
        }

        // Update the spending limit
        let limit_slot = slots::spending_limit_slot(msg_sender, &call.keyId, &call.token);
        self.storage
            .sstore(self.precompile_address, limit_slot, call.newLimit)?;

        Ok(())
    }

    /// Get key information
    pub fn get_key(&mut self, call: getKeyCall) -> Result<KeyInfo, TempoPrecompileError> {
        let key_slot = slots::key_slot(&call.account, &call.keyId);
        let value = self.storage.sload(self.precompile_address, key_slot)?;

        if value == U256::ZERO {
            // Return default (non-existent key)
            return Ok(KeyInfo {
                signatureType: SignatureType::Secp256k1,
                keyId: Address::ZERO,
                expiry: 0,
            });
        }

        let key = AuthorizedKey::unpack(value);

        // Convert u8 signature_type to SignatureType enum
        let signature_type = match key.signature_type {
            0 => SignatureType::Secp256k1,
            1 => SignatureType::P256,
            2 => SignatureType::WebAuthn,
            _ => SignatureType::Secp256k1, // Default fallback
        };

        Ok(KeyInfo {
            signatureType: signature_type,
            keyId: call.keyId,
            expiry: key.expiry,
        })
    }

    /// Get remaining spending limit
    pub fn get_remaining_limit(
        &mut self,
        call: getRemainingLimitCall,
    ) -> Result<U256, TempoPrecompileError> {
        let limit_slot = slots::spending_limit_slot(&call.account, &call.keyId, &call.token);
        self.storage.sload(self.precompile_address, limit_slot)
    }

    /// Get the transaction key used in the current transaction
    pub fn get_transaction_key(
        &mut self,
        _call: getTransactionKeyCall,
        msg_sender: &Address,
    ) -> Result<Address, TempoPrecompileError> {
        let slot = slots::transaction_key_slot(msg_sender);
        let value = self.storage.sload(self.precompile_address, slot)?;

        // Convert U256 to Address (take the lower 20 bytes)
        if value == U256::ZERO {
            Ok(Address::ZERO)
        } else {
            let bytes = value.to_be_bytes::<32>();
            Ok(Address::from_slice(&bytes[12..]))
        }
    }

    /// Internal: Set the transaction key (called during transaction validation)
    ///
    /// SECURITY CRITICAL: This must be called by the transaction validation logic
    /// BEFORE the transaction is executed, to store which key authorized the transaction.
    /// - If key_id is Address::ZERO (main key), this should store U256::ZERO
    /// - If key_id is a specific key address, this should store that key
    ///
    /// This creates a secure channel between validation and the precompile to ensure
    /// only the main key can authorize/revoke other keys.
    pub fn set_transaction_key(
        &mut self,
        account: &Address,
        key_id: &Address,
    ) -> Result<(), TempoPrecompileError> {
        let slot = slots::transaction_key_slot(account);
        // Store U256::ZERO if using main key (key_id == Address::ZERO)
        // Otherwise store the actual key_id (padded to U256)
        let value = if *key_id == Address::ZERO {
            U256::ZERO
        } else {
            // Convert Address to U256 by padding with zeros
            let mut bytes = [0u8; 32];
            bytes[12..].copy_from_slice(key_id.as_slice());
            U256::from_be_bytes(bytes)
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
        key_id: &Address,
        current_timestamp: u64,
    ) -> Result<(), TempoPrecompileError> {
        // If using main key (zero address), always valid
        if *key_id == Address::ZERO {
            return Ok(());
        }

        let key_slot = slots::key_slot(account, key_id);
        let value = self.storage.sload(self.precompile_address, key_slot)?;

        if value == U256::ZERO {
            return Err(AccountKeychainError::key_not_found().into());
        }

        let key = AuthorizedKey::unpack(value);

        if !key.is_active {
            return Err(AccountKeychainError::key_inactive().into());
        }

        if key.expiry > 0 && current_timestamp >= key.expiry {
            return Err(AccountKeychainError::key_expired().into());
        }

        Ok(())
    }

    /// Internal: Verify and update spending for a token transfer
    pub fn verify_and_update_spending(
        &mut self,
        account: &Address,
        key_id: &Address,
        token: &Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        // If using main key (zero address), no spending limits apply
        if *key_id == Address::ZERO {
            return Ok(());
        }

        // Check key is valid
        let key_slot = slots::key_slot(account, key_id);
        let key_value = self.storage.sload(self.precompile_address, key_slot)?;

        if key_value == U256::ZERO {
            return Err(AccountKeychainError::key_not_found().into());
        }

        let key = AuthorizedKey::unpack(key_value);
        if !key.is_active {
            return Err(AccountKeychainError::key_inactive().into());
        }

        // Check and update spending limit
        let limit_slot = slots::spending_limit_slot(account, key_id, token);
        let remaining = self.storage.sload(self.precompile_address, limit_slot)?;

        if amount > remaining {
            return Err(AccountKeychainError::spending_limit_exceeded().into());
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
        let key_id = Address::from([2u8; 20]);
        let token = Address::from([3u8; 20]);

        // Slots should be deterministic
        let key_slot1 = slots::key_slot(&account, &key_id);
        let key_slot2 = slots::key_slot(&account, &key_id);
        assert_eq!(key_slot1, key_slot2);

        let limit_slot1 = slots::spending_limit_slot(&account, &key_id, &token);
        let limit_slot2 = slots::spending_limit_slot(&account, &key_id, &token);
        assert_eq!(limit_slot1, limit_slot2);

        // Different inputs should produce different slots
        let different_key = Address::from([4u8; 20]);
        let different_slot = slots::key_slot(&account, &different_key);
        assert_ne!(key_slot1, different_slot);
    }
}
