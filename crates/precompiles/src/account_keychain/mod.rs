pub mod dispatch;

use tempo_contracts::precompiles::{AccountKeychainError, AccountKeychainEvent};
pub use tempo_contracts::precompiles::{
    IAccountKeychain,
    IAccountKeychain::{
        KeyInfo, SignatureType, TokenLimit, authorizeKeyCall, getKeyCall, getRemainingLimitCall,
        getTransactionKeyCall, revokeKeyCall, updateSpendingLimitCall,
    },
};

use crate::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    error::Result,
    storage::{PrecompileStorageProvider, Storable, double_mapping_slot},
};
use alloy::primitives::{Address, B256, Bytes, IntoLogData, U256};
use revm::{
    interpreter::instructions::utility::{IntoAddress, IntoU256},
    state::Bytecode,
};
use tempo_precompiles_macros::{Storable, contract};

/// Key information stored in the precompile
///
/// Storage layout (packed into single slot, right-aligned):
/// - byte 0: signature_type (u8)
/// - bytes 1-8: expiry (u64, little-endian)
/// - byte 9: enforce_limits (bool)
/// - byte 10: is_revoked (bool)
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct AuthorizedKey {
    /// Signature type: 0 = secp256k1, 1 = P256, 2 = WebAuthn
    pub signature_type: u8,
    /// Block timestamp when key expires
    pub expiry: u64,
    /// Whether to enforce spending limits for this key
    pub enforce_limits: bool,
    /// Whether this key has been revoked. Once revoked, a key cannot be re-authorized
    /// with the same key_id. This prevents replay attacks.
    pub is_revoked: bool,
}

impl AuthorizedKey {
    /// Decode AuthorizedKey from a storage slot value
    ///
    /// This is useful for read-only contexts (like pool validation) that don't have
    /// access to PrecompileStorageProvider but need to decode the packed struct.
    pub fn decode_from_slot(slot_value: U256) -> Self {
        Self::from_evm_words([slot_value]).unwrap()
    }
}

/// Account Keychain contract for managing authorized keys
#[contract]
pub struct AccountKeychain {
    // keys[account][keyId] -> AuthorizedKey
    keys: Mapping<Address, Mapping<Address, AuthorizedKey>>,
    // spendingLimits[(account, keyId)][token] -> amount
    // Using a hash of account and keyId as the key to avoid triple nesting
    spending_limits: Mapping<B256, Mapping<Address, U256>>,
}

/// Transient storage slot for the transaction key
/// Using slot 0 since there's only one transaction key at a time
const TRANSACTION_KEY_SLOT: U256 = U256::ZERO;

/// Compute the storage slot for keys\[account\]\[key_id\]
///
/// This is useful for read-only contexts (like pool validation) that need to
/// directly read the keychain state using StateProvider without going through
/// the precompile abstraction.
///
/// The keys mapping is at slot 0 (first field in the contract).
pub fn compute_keys_slot(account: Address, key_id: Address) -> U256 {
    double_mapping_slot(account, key_id, slots::KEYS)
}

impl<'a, S: PrecompileStorageProvider> AccountKeychain<'a, S> {
    /// Creates an instance of the precompile.
    ///
    /// Caution: This does not initialize the account, see [`Self::initialize`].
    pub fn new(storage: &'a mut S) -> Self {
        Self::_new(ACCOUNT_KEYCHAIN_ADDRESS, storage)
    }

    /// Load transaction key from transient storage
    fn tload_transaction_key(&mut self) -> Result<Address> {
        let value = self.storage.tload(self.address, TRANSACTION_KEY_SLOT)?;
        Ok(value.into_address())
    }

    /// Store transaction key in transient storage
    fn tstore_transaction_key(&mut self, key_id: Address) -> Result<()> {
        self.storage.tstore(ACCOUNT_KEYCHAIN_ADDRESS, TRANSACTION_KEY_SLOT, key_id.into_u256())?;
        Ok(())
    }

    /// Create a hash key for spending limits mapping from account and keyId
    fn spending_limit_key(account: Address, key_id: Address) -> B256 {
        use alloy::primitives::keccak256;
        let mut data = [0u8; 40];
        data[..20].copy_from_slice(account.as_slice());
        data[20..].copy_from_slice(key_id.as_slice());
        keccak256(data)
    }

    /// Initializes the account keychain contract.
    pub fn initialize(&mut self) -> Result<()> {
        self.storage.set_code(
            ACCOUNT_KEYCHAIN_ADDRESS,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )?;

        Ok(())
    }

    /// Authorize a new key for an account
    /// This can only be called by the account itself (using main key)
    pub fn authorize_key(&mut self, msg_sender: Address, call: authorizeKeyCall) -> Result<()> {
        // Check that the transaction key for this transaction is zero (main key)
        let transaction_key = self.tload_transaction_key()?;

        // If transaction_key is not zero, it means a secondary key is being used
        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        // Validate inputs
        if call.keyId == Address::ZERO {
            return Err(AccountKeychainError::zero_public_key().into());
        }

        // Check if key already exists (key exists if expiry > 0)
        let existing_key = self.sload_keys(msg_sender, call.keyId)?;
        if existing_key.expiry > 0 {
            return Err(AccountKeychainError::key_already_exists().into());
        }

        // Check if this key was previously revoked - prevents replay attacks
        if existing_key.is_revoked {
            return Err(AccountKeychainError::key_already_revoked().into());
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
            enforce_limits: call.enforceLimits,
            is_revoked: false,
        };

        self.sstore_keys(msg_sender, call.keyId, new_key)?;

        // Set initial spending limits (only if enforce_limits is true)
        if call.enforceLimits {
            let limit_key = Self::spending_limit_key(msg_sender, call.keyId);
            for limit in call.limits {
                self.sstore_spending_limits(limit_key, limit.token, limit.amount)?;
            }
        }

        // Emit event
        let mut public_key_bytes = [0u8; 32];
        public_key_bytes[12..].copy_from_slice(call.keyId.as_slice());
        self.storage.emit_event(
            ACCOUNT_KEYCHAIN_ADDRESS,
            AccountKeychainEvent::KeyAuthorized(IAccountKeychain::KeyAuthorized {
                account: msg_sender,
                publicKey: B256::from(public_key_bytes),
                signatureType: signature_type,
                expiry: call.expiry,
            })
            .into_log_data(),
        )?;

        Ok(())
    }

    /// Revoke an authorized key
    ///
    /// This marks the key as revoked by setting is_revoked to true and expiry to 0.
    /// Once revoked, a key_id can never be re-authorized for this account, preventing
    /// replay attacks where old KeyAuthorization signatures could be reused.
    pub fn revoke_key(&mut self, msg_sender: Address, call: revokeKeyCall) -> Result<()> {
        let transaction_key = self.tload_transaction_key()?;

        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        let key = self.sload_keys(msg_sender, call.keyId)?;

        // Key exists if expiry > 0
        if key.expiry == 0 {
            return Err(AccountKeychainError::key_not_found().into());
        }

        // Mark the key as revoked - this prevents replay attacks by ensuring
        // the same key_id can never be re-authorized for this account.
        // We keep is_revoked=true but clear other fields.
        let revoked_key = AuthorizedKey { is_revoked: true, ..Default::default() };
        self.sstore_keys(msg_sender, call.keyId, revoked_key)?;

        // Note: We don't clear spending limits here - they become inaccessible

        // Emit event
        let mut public_key_bytes = [0u8; 32];
        public_key_bytes[12..].copy_from_slice(call.keyId.as_slice());
        self.storage.emit_event(
            ACCOUNT_KEYCHAIN_ADDRESS,
            AccountKeychainEvent::KeyRevoked(IAccountKeychain::KeyRevoked {
                account: msg_sender,
                publicKey: B256::from(public_key_bytes),
            })
            .into_log_data(),
        )?;

        Ok(())
    }

    /// Update spending limit for a key-token pair
    ///
    /// This can be used to add limits to an unlimited key (converting it to limited)
    /// or to update existing limits.
    pub fn update_spending_limit(
        &mut self,
        msg_sender: Address,
        call: updateSpendingLimitCall,
    ) -> Result<()> {
        let transaction_key = self.tload_transaction_key()?;

        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        // Verify key exists, hasn't been revoked, and hasn't expired
        let mut key = self.load_active_key(msg_sender, call.keyId)?;

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        if current_timestamp >= key.expiry {
            return Err(AccountKeychainError::key_expired().into());
        }

        // If this key had unlimited spending (enforce_limits=false), enable limits now
        if !key.enforce_limits {
            key.enforce_limits = true;
            self.sstore_keys(msg_sender, call.keyId, key)?;
        }

        // Update the spending limit
        let limit_key = Self::spending_limit_key(msg_sender, call.keyId);
        self.sstore_spending_limits(limit_key, call.token, call.newLimit)?;

        // Emit event
        let mut public_key_bytes = [0u8; 32];
        public_key_bytes[12..].copy_from_slice(call.keyId.as_slice());
        self.storage.emit_event(
            ACCOUNT_KEYCHAIN_ADDRESS,
            AccountKeychainEvent::SpendingLimitUpdated(IAccountKeychain::SpendingLimitUpdated {
                account: msg_sender,
                publicKey: B256::from(public_key_bytes),
                token: call.token,
                newLimit: call.newLimit,
            })
            .into_log_data(),
        )?;

        Ok(())
    }

    /// Get key information
    pub fn get_key(&mut self, call: getKeyCall) -> Result<KeyInfo> {
        let key = self.sload_keys(call.account, call.keyId)?;

        // Key doesn't exist if expiry == 0, or key has been revoked
        if key.expiry == 0 || key.is_revoked {
            return Ok(KeyInfo {
                signatureType: SignatureType::Secp256k1,
                keyId: Address::ZERO,
                expiry: 0,
                enforceLimits: false,
                isRevoked: key.is_revoked,
            });
        }

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
            enforceLimits: key.enforce_limits,
            isRevoked: key.is_revoked,
        })
    }

    /// Get remaining spending limit
    pub fn get_remaining_limit(&mut self, call: getRemainingLimitCall) -> Result<U256> {
        let limit_key = Self::spending_limit_key(call.account, call.keyId);
        self.sload_spending_limits(limit_key, call.token)
    }

    /// Get the transaction key used in the current transaction
    pub fn get_transaction_key(
        &mut self,
        _call: getTransactionKeyCall,
        _msg_sender: Address,
    ) -> Result<Address> {
        self.tload_transaction_key()
    }

    /// Internal: Set the transaction key (called during transaction validation)
    ///
    /// SECURITY CRITICAL: This must be called by the transaction validation logic
    /// BEFORE the transaction is executed, to store which key authorized the transaction.
    /// - If key_id is Address::ZERO (main key), this should store Address::ZERO
    /// - If key_id is a specific key address, this should store that key
    ///
    /// This creates a secure channel between validation and the precompile to ensure
    /// only the main key can authorize/revoke other keys.
    /// Uses transient storage, so the key is automatically cleared after the transaction.
    pub fn set_transaction_key(&mut self, key_id: Address) -> Result<()> {
        self.tstore_transaction_key(key_id)?;
        Ok(())
    }

    /// Load and validate a key exists and is not revoked.
    ///
    /// Returns the key if valid, or an error if:
    /// - Key doesn't exist (expiry == 0)
    /// - Key has been revoked
    ///
    /// Note: This does NOT check expiry against current timestamp.
    /// Callers should check expiry separately if needed.
    fn load_active_key(&mut self, account: Address, key_id: Address) -> Result<AuthorizedKey> {
        let key = self.sload_keys(account, key_id)?;

        if key.is_revoked {
            return Err(AccountKeychainError::key_already_revoked().into());
        }

        if key.expiry == 0 {
            return Err(AccountKeychainError::key_not_found().into());
        }

        Ok(key)
    }

    /// Validate keychain authorization (existence, revocation, and expiry)
    ///
    /// This consolidates all validation checks into one method.
    /// Returns Ok(()) if the key is valid and authorized, Err otherwise.
    pub fn validate_keychain_authorization(
        &mut self,
        account: Address,
        key_id: Address,
        current_timestamp: u64,
    ) -> Result<()> {
        let key = self.load_active_key(account, key_id)?;

        if current_timestamp >= key.expiry {
            return Err(AccountKeychainError::key_expired().into());
        }

        Ok(())
    }

    /// Internal: Verify and update spending for a token transfer
    pub fn verify_and_update_spending(
        &mut self,
        account: Address,
        key_id: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        // If using main key (zero address), no spending limits apply
        if key_id == Address::ZERO {
            return Ok(());
        }

        // Check key is valid (exists and not revoked)
        let key = self.load_active_key(account, key_id)?;

        // If enforce_limits is false, this key has unlimited spending
        if !key.enforce_limits {
            return Ok(());
        }

        // Check and update spending limit
        let limit_key = Self::spending_limit_key(account, key_id);
        let remaining = self.sload_spending_limits(limit_key, token)?;

        if amount > remaining {
            return Err(AccountKeychainError::spending_limit_exceeded().into());
        }

        // Update remaining limit
        self.sstore_spending_limits(limit_key, token, remaining - amount)?;

        Ok(())
    }

    /// Authorize a token transfer with access key spending limits
    ///
    /// This method checks if the transaction is using an access key, and if so,
    /// verifies and updates the spending limits for that key.
    /// Should be called before executing a transfer.
    ///
    /// # Arguments
    /// * `account` - The account performing the transfer
    /// * `token` - The token being transferred
    /// * `amount` - The amount being transferred
    ///
    /// # Returns
    /// Ok(()) if authorized (either using main key or access key with sufficient limits)
    /// Err if unauthorized or spending limit exceeded
    pub fn authorize_transfer(
        &mut self,
        account: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        // Get the transaction key for this account
        let transaction_key = self.tload_transaction_key()?;

        // If using main key (Address::ZERO), no spending limits apply
        if transaction_key == Address::ZERO {
            return Ok(());
        }

        // Verify and update spending limits for this access key
        self.verify_and_update_spending(account, transaction_key, token, amount)
    }

    /// Authorize a token approval with access key spending limits
    ///
    /// This method checks if the transaction is using an access key, and if so,
    /// verifies and updates the spending limits for that key.
    /// Should be called before executing an approval.
    ///
    /// # Arguments
    /// * `account` - The account performing the approval
    /// * `token` - The token being approved
    /// * `old_approval` - The current approval amount
    /// * `new_approval` - The new approval amount being set
    ///
    /// # Returns
    /// Ok(()) if authorized (either using main key or access key with sufficient limits)
    /// Err if unauthorized or spending limit exceeded
    pub fn authorize_approve(
        &mut self,
        account: Address,
        token: Address,
        old_approval: U256,
        new_approval: U256,
    ) -> Result<()> {
        // Get the transaction key for this account
        let transaction_key = self.tload_transaction_key()?;

        // If using main key (Address::ZERO), no spending limits apply
        if transaction_key == Address::ZERO {
            return Ok(());
        }

        // Calculate the increase in approval (only deduct if increasing)
        // If old approval is 100 and new approval is 120, deduct 20 from spending limit
        // If old approval is 100 and new approval is 80, deduct 0 (decreasing approval is free)
        let approval_increase = new_approval.saturating_sub(old_approval);

        // Only check spending limits if there's an increase in approval
        if approval_increase.is_zero() {
            return Ok(());
        }

        // Verify and update spending limits for this access key
        self.verify_and_update_spending(account, transaction_key, token, approval_increase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;
    use alloy::primitives::{Address, U256};
    use tempo_contracts::precompiles::IAccountKeychain::SignatureType;

    #[test]
    fn test_transaction_key_transient_storage() {
        let mut storage = HashMapStorageProvider::new(1); // chain_id = 1 for testing
        let mut keychain = AccountKeychain::new(&mut storage);

        // Test 1: Initially transaction key should be zero
        let initial_key = keychain.tload_transaction_key().unwrap();
        assert_eq!(initial_key, Address::ZERO, "Initial transaction key should be zero");

        // Test 2: Set transaction key to an access key address
        let access_key_addr = Address::from([0x01; 20]);
        keychain.set_transaction_key(access_key_addr).unwrap();

        // Test 3: Verify it was stored
        let loaded_key = keychain.tload_transaction_key().unwrap();
        assert_eq!(loaded_key, access_key_addr, "Transaction key should be set");

        // Test 4: Verify getTransactionKey works
        let get_tx_key_call = getTransactionKeyCall {};
        let result = keychain.get_transaction_key(get_tx_key_call, Address::ZERO).unwrap();
        assert_eq!(result, access_key_addr, "getTransactionKey should return the set key");

        // Test 5: Clear transaction key
        keychain.set_transaction_key(Address::ZERO).unwrap();
        let cleared_key = keychain.tload_transaction_key().unwrap();
        assert_eq!(cleared_key, Address::ZERO, "Transaction key should be cleared");
    }

    #[test]
    fn test_admin_operations_blocked_with_access_key() {
        let mut storage = HashMapStorageProvider::new(1); // chain_id = 1 for testing
        let mut keychain = AccountKeychain::new(&mut storage);

        // Initialize the keychain
        keychain.initialize().unwrap();

        let msg_sender = Address::from([0x01; 20]);
        let existing_key = Address::from([0x02; 20]);
        let access_key = Address::from([0x03; 20]);
        let token = Address::from([0x04; 20]);

        // First, authorize a key with main key (transaction_key = 0) to set up the test
        keychain.set_transaction_key(Address::ZERO).unwrap();
        let setup_call = authorizeKeyCall {
            keyId: existing_key,
            signatureType: SignatureType::Secp256k1,
            expiry: u64::MAX,
            enforceLimits: true,
            limits: vec![],
        };
        keychain.authorize_key(msg_sender, setup_call).unwrap();

        // Now set transaction key to non-zero (simulating access key usage)
        keychain.set_transaction_key(access_key).unwrap();

        // Test 1: authorize_key should fail with access key
        let auth_call = authorizeKeyCall {
            keyId: Address::from([0x05; 20]),
            signatureType: SignatureType::P256,
            expiry: u64::MAX,
            enforceLimits: true,
            limits: vec![],
        };
        let auth_result = keychain.authorize_key(msg_sender, auth_call);
        assert!(auth_result.is_err(), "authorize_key should fail when using access key");
        assert_unauthorized_error(auth_result.unwrap_err());

        // Test 2: revoke_key should fail with access key
        let revoke_call = revokeKeyCall { keyId: existing_key };
        let revoke_result = keychain.revoke_key(msg_sender, revoke_call);
        assert!(revoke_result.is_err(), "revoke_key should fail when using access key");
        assert_unauthorized_error(revoke_result.unwrap_err());

        // Test 3: update_spending_limit should fail with access key
        let update_call =
            updateSpendingLimitCall { keyId: existing_key, token, newLimit: U256::from(1000) };
        let update_result = keychain.update_spending_limit(msg_sender, update_call);
        assert!(update_result.is_err(), "update_spending_limit should fail when using access key");
        assert_unauthorized_error(update_result.unwrap_err());

        // Helper function to assert unauthorized error
        fn assert_unauthorized_error(error: crate::error::TempoPrecompileError) {
            match error {
                crate::error::TempoPrecompileError::AccountKeychainError(e) => {
                    assert!(
                        matches!(e, AccountKeychainError::UnauthorizedCaller(_)),
                        "Expected UnauthorizedCaller error, got: {e:?}"
                    );
                }
                _ => panic!("Expected AccountKeychainError, got: {error:?}"),
            }
        }
    }

    #[test]
    fn test_replay_protection_revoked_key_cannot_be_reauthorized() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut keychain = AccountKeychain::new(&mut storage);
        keychain.initialize().unwrap();

        let account = Address::from([0x01; 20]);
        let key_id = Address::from([0x02; 20]);

        // Use main key for all operations
        keychain.set_transaction_key(Address::ZERO).unwrap();

        // Step 1: Authorize a key
        let auth_call = authorizeKeyCall {
            keyId: key_id,
            signatureType: SignatureType::Secp256k1,
            expiry: u64::MAX,
            enforceLimits: false,
            limits: vec![],
        };
        keychain.authorize_key(account, auth_call.clone()).unwrap();

        // Verify key exists
        let key_info = keychain.get_key(getKeyCall { account, keyId: key_id }).unwrap();
        assert_eq!(key_info.expiry, u64::MAX);
        assert!(!key_info.isRevoked);

        // Step 2: Revoke the key
        let revoke_call = revokeKeyCall { keyId: key_id };
        keychain.revoke_key(account, revoke_call).unwrap();

        // Verify key is revoked
        let key_info = keychain.get_key(getKeyCall { account, keyId: key_id }).unwrap();
        assert_eq!(key_info.expiry, 0);
        assert!(key_info.isRevoked);

        // Step 3: Try to re-authorize the same key (replay attack)
        // This should fail because the key was revoked
        let replay_result = keychain.authorize_key(account, auth_call);
        assert!(replay_result.is_err(), "Re-authorizing a revoked key should fail");

        // Verify it's the correct error
        match replay_result.unwrap_err() {
            crate::error::TempoPrecompileError::AccountKeychainError(e) => {
                assert!(
                    matches!(e, AccountKeychainError::KeyAlreadyRevoked(_)),
                    "Expected KeyAlreadyRevoked error, got: {e:?}"
                );
            }
            e => panic!("Expected AccountKeychainError, got: {e:?}"),
        }
    }

    #[test]
    fn test_different_key_id_can_be_authorized_after_revocation() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut keychain = AccountKeychain::new(&mut storage);
        keychain.initialize().unwrap();

        let account = Address::from([0x01; 20]);
        let key_id_1 = Address::from([0x02; 20]);
        let key_id_2 = Address::from([0x03; 20]);

        // Use main key for all operations
        keychain.set_transaction_key(Address::ZERO).unwrap();

        // Authorize key 1
        let auth_call_1 = authorizeKeyCall {
            keyId: key_id_1,
            signatureType: SignatureType::Secp256k1,
            expiry: u64::MAX,
            enforceLimits: false,
            limits: vec![],
        };
        keychain.authorize_key(account, auth_call_1).unwrap();

        // Revoke key 1
        keychain.revoke_key(account, revokeKeyCall { keyId: key_id_1 }).unwrap();

        // Authorizing a different key (key 2) should still work
        let auth_call_2 = authorizeKeyCall {
            keyId: key_id_2,
            signatureType: SignatureType::P256,
            expiry: 1000,
            enforceLimits: true,
            limits: vec![],
        };
        keychain.authorize_key(account, auth_call_2).unwrap();

        // Verify key 2 is authorized
        let key_info = keychain.get_key(getKeyCall { account, keyId: key_id_2 }).unwrap();
        assert_eq!(key_info.expiry, 1000);
        assert!(!key_info.isRevoked);
    }
}
