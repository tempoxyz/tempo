mod dispatch;

pub use crate::contracts::account_keychain::{IAccountKeychain, IAccountKeychain::prelude::*};

use crate::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    error::Result,
    storage::{Handler, Mapping, packing::insert_into_word},
};
use alloy::primitives::{Address, B256, U256};
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
    /// Signature type of this key
    pub signature_type: SignatureType,
    /// Block timestamp when key expires
    pub expiry: u64,
    /// Whether to enforce spending limits for this key
    pub enforce_limits: bool,
    /// Whether this key has been revoked. Once revoked, a key cannot be re-authorized
    /// with the same key_id. This prevents replay attacks.
    pub is_revoked: bool,
}

// TODO(rusowsky): remove this and create a read-only wrapper that is callable from read-only ctx with db access
impl AuthorizedKey {
    /// Decode AuthorizedKey from a storage slot value
    ///
    /// This is useful for read-only contexts (like pool validation) that don't have
    /// access to PrecompileStorageProvider but need to decode the packed struct.
    pub fn decode_from_slot(slot_value: U256) -> Self {
        use crate::storage::{LayoutCtx, Storable, packing::PackedSlot};

        // NOTE: fine to expect, as `StorageOps` on `PackedSlot` are infallible
        Self::load(&PackedSlot(slot_value), U256::ZERO, LayoutCtx::FULL)
            .expect("unable to decode AuthorizedKey from slot")
    }

    /// Encode AuthorizedKey to a storage slot value
    ///
    /// This is useful for tests that need to set up storage state directly.
    pub fn encode_to_slot(&self) -> U256 {
        use __packing_authorized_key::*;

        let encoded = insert_into_word(
            U256::ZERO,
            &self.signature_type,
            SIGNATURE_TYPE_LOC.offset_bytes,
            SIGNATURE_TYPE_LOC.size,
        )
        .expect("unable to insert 'signature_type'");

        let encoded = insert_into_word(
            encoded,
            &self.expiry,
            EXPIRY_LOC.offset_bytes,
            EXPIRY_LOC.size,
        )
        .expect("unable to insert 'expiry'");

        let encoded = insert_into_word(
            encoded,
            &self.enforce_limits,
            ENFORCE_LIMITS_LOC.offset_bytes,
            ENFORCE_LIMITS_LOC.size,
        )
        .expect("unable to insert 'enforce_limits'");

        insert_into_word(
            encoded,
            &self.is_revoked,
            IS_REVOKED_LOC.offset_bytes,
            IS_REVOKED_LOC.size,
        )
        .expect("unable to insert 'is_revoked'")
    }
}

/// Account Keychain contract for managing authorized keys
#[contract(addr = ACCOUNT_KEYCHAIN_ADDRESS, abi = IAccountKeychain, dispatch)]
pub struct AccountKeychain {
    // keys[account][keyId] -> AuthorizedKey
    keys: Mapping<Address, Mapping<Address, AuthorizedKey>>,
    // spendingLimits[(account, keyId)][token] -> amount
    // Using a hash of account and keyId as the key to avoid triple nesting
    spending_limits: Mapping<B256, Mapping<Address, U256>>,

    // WARNING(rusowsky): transient storage slots must always be placed at the very end until the `contract`
    // macro is refactored and has 2 independent layouts (persistent and transient).
    // If new (persistent) storage fields need to be added to the precompile, they must go above this one.
    transaction_key: Address,
    // The transaction origin (tx.origin) - the EOA that signed the transaction.
    // Used to ensure spending limits only apply when msg_sender == tx_origin.
    tx_origin: Address,
}

impl AccountKeychain {
    /// Create a hash key for spending limits mapping from account and keyId.
    ///
    /// This is used to access `spending_limits[key][token]` where `key` is the result
    /// of this function. The hash combines account and key_id to avoid triple nesting.
    pub fn spending_limit_key(account: Address, key_id: Address) -> B256 {
        use alloy::primitives::keccak256;
        let mut data = [0u8; 40];
        data[..20].copy_from_slice(account.as_slice());
        data[20..].copy_from_slice(key_id.as_slice());
        keccak256(data)
    }

    /// Initializes the account keychain contract.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }
}

impl IAccountKeychain::Interface for AccountKeychain {
    /// Authorize a new key for an account
    /// This can only be called by the account itself (using main key)
    fn authorize_key(
        &mut self,
        msg_sender: Address,
        key_id: Address,
        signature_type: SignatureType,
        expiry: u64,
        enforce_limits: bool,
        limits: Vec<TokenLimit>,
    ) -> Result<()> {
        // Check that the transaction key for this transaction is zero (main key)
        let transaction_key = self.transaction_key.t_read()?;

        // If transaction_key is not zero, it means a secondary key is being used
        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        // Validate inputs
        if key_id == Address::ZERO {
            return Err(AccountKeychainError::zero_public_key().into());
        }

        // T0+: Expiry must be in the future (also catches expiry == 0 which means "key doesn't exist")
        if self.storage.spec().is_t0() {
            let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
            if expiry <= current_timestamp {
                return Err(AccountKeychainError::expiry_in_past().into());
            }
        }

        // Check if key already exists (key exists if expiry > 0)
        let existing_key = self.keys[msg_sender][key_id].read()?;
        if existing_key.expiry > 0 {
            return Err(AccountKeychainError::key_already_exists().into());
        }

        // Check if this key was previously revoked - prevents replay attacks
        if existing_key.is_revoked {
            return Err(AccountKeychainError::key_already_revoked().into());
        }

        // Ensure valid signature type
        signature_type.validate()?;

        // Create and store the new key
        let new_key = AuthorizedKey {
            signature_type,
            expiry,
            enforce_limits,
            is_revoked: false,
        };

        self.keys[msg_sender][key_id].write(new_key)?;

        // Set initial spending limits (only if enforce_limits is true)
        if enforce_limits {
            let limit_key = Self::spending_limit_key(msg_sender, key_id);
            for limit in limits {
                self.spending_limits[limit_key][limit.token].write(limit.amount)?;
            }
        }

        // Emit event
        self.emit_event(AccountKeychainEvent::key_authorized(
            msg_sender,
            key_id,
            signature_type,
            expiry,
        ))
    }

    /// Revoke an authorized key
    ///
    /// This marks the key as revoked by setting is_revoked to true and expiry to 0.
    /// Once revoked, a key_id can never be re-authorized for this account, preventing
    /// replay attacks where old KeyAuthorization signatures could be reused.
    fn revoke_key(&mut self, msg_sender: Address, key_id: Address) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;

        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        let key = self.keys[msg_sender][key_id].read()?;

        // Key exists if expiry > 0
        if key.expiry == 0 {
            return Err(AccountKeychainError::key_not_found().into());
        }

        // Mark the key as revoked - this prevents replay attacks by ensuring
        // the same key_id can never be re-authorized for this account.
        // We keep is_revoked=true but clear other fields.
        let revoked_key = AuthorizedKey {
            is_revoked: true,
            ..Default::default()
        };
        self.keys[msg_sender][key_id].write(revoked_key)?;

        // Note: We don't clear spending limits here - they become inaccessible

        // Emit event
        self.emit_event(AccountKeychainEvent::key_revoked(msg_sender, key_id))
    }

    /// Update spending limit for a key-token pair
    ///
    /// This can be used to add limits to an unlimited key (converting it to limited)
    /// or to update existing limits.
    fn update_spending_limit(
        &mut self,
        msg_sender: Address,
        key_id: Address,
        token: Address,
        new_limit: U256,
    ) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;

        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        // Verify key exists, hasn't been revoked, and hasn't expired
        let mut key = self.load_active_key(msg_sender, key_id)?;

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        if current_timestamp >= key.expiry {
            return Err(AccountKeychainError::key_expired().into());
        }

        // If this key had unlimited spending (enforce_limits=false), enable limits now
        if !key.enforce_limits {
            key.enforce_limits = true;
            self.keys[msg_sender][key_id].write(key)?;
        }

        // Update the spending limit
        let limit_key = Self::spending_limit_key(msg_sender, key_id);
        self.spending_limits[limit_key][token].write(new_limit)?;

        // Emit event
        self.emit_event(AccountKeychainEvent::spending_limit_updated(
            msg_sender, key_id, token, new_limit,
        ))
    }

    /// Get key information
    fn get_key(&self, account: Address, key_id: Address) -> Result<KeyInfo> {
        let key = self.keys[account][key_id].read()?;

        // Key doesn't exist if expiry == 0, or key has been revoked
        if key.expiry == 0 || key.is_revoked {
            return Ok(KeyInfo {
                signature_type: SignatureType::Secp256k1,
                key_id: Address::ZERO,
                expiry: 0,
                enforce_limits: false,
                is_revoked: key.is_revoked,
            });
        }

        Ok(KeyInfo {
            signature_type: key.signature_type,
            key_id,
            expiry: key.expiry,
            enforce_limits: key.enforce_limits,
            is_revoked: key.is_revoked,
        })
    }

    /// Get remaining spending limit
    fn get_remaining_limit(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
    ) -> Result<U256> {
        // T2+: return zero if key doesn't exist or has been revoked
        if self.storage.spec().is_t2() {
            let key = self.keys[account][key_id].read()?;
            if key.expiry == 0 || key.is_revoked {
                return Ok(U256::ZERO);
            }
        }

        let limit_key = Self::spending_limit_key(account, key_id);
        self.spending_limits[limit_key][token].read()
    }

    /// Get the transaction key used in the current transaction
    fn get_transaction_key(&self) -> Result<Address> {
        self.transaction_key.t_read()
    }
}

impl AccountKeychain {
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
        self.transaction_key.t_write(key_id)
    }

    /// Sets the transaction origin (tx.origin) for the current transaction.
    ///
    /// Called by the handler before transaction execution.
    /// Uses transient storage, so it's automatically cleared after the transaction.
    pub fn set_tx_origin(&mut self, origin: Address) -> Result<()> {
        self.tx_origin.t_write(origin)
    }

    /// Load and validate a key exists and is not revoked.
    ///
    /// Returns the key if valid, or an error if:
    /// - Key doesn't exist (expiry == 0)
    /// - Key has been revoked
    ///
    /// Note: This does NOT check expiry against current timestamp.
    /// Callers should check expiry separately if needed.
    fn load_active_key(&self, account: Address, key_id: Address) -> Result<AuthorizedKey> {
        let key = self.keys[account][key_id].read()?;

        if key.is_revoked {
            return Err(AccountKeychainError::key_already_revoked().into());
        }

        if key.expiry == 0 {
            return Err(AccountKeychainError::key_not_found().into());
        }

        Ok(key)
    }

    /// Validate keychain authorization (existence, revocation, expiry, and optionally signature type)
    ///
    /// This consolidates all validation checks into one method.
    /// Returns Ok(()) if the key is valid and authorized, Err otherwise.
    ///
    /// # Arguments
    /// * `account` - The account that owns the key
    /// * `key_id` - The key identifier to validate
    /// * `current_timestamp` - Current block timestamp for expiry check
    /// * `expected_sig_type` - The signature type from the actual signature (0=Secp256k1, 1=P256, 2=WebAuthn).
    ///   Pass `None` to skip signature type validation (for backward compatibility with pre-T1 blocks).
    pub fn validate_keychain_authorization(
        &self,
        account: Address,
        key_id: Address,
        current_timestamp: u64,
        expected_sig_type: Option<SignatureType>,
    ) -> Result<()> {
        let key = self.load_active_key(account, key_id)?;

        if current_timestamp >= key.expiry {
            return Err(AccountKeychainError::key_expired().into());
        }

        // Validate that the signature type matches the key type stored in the keychain
        // Only check if expected_sig_type is provided (T1+ hardfork)
        if let Some(sig_type) = expected_sig_type
            && key.signature_type != sig_type
        {
            return Err(AccountKeychainError::signature_type_mismatch(
                key.signature_type,
                sig_type,
            )
            .into());
        }

        Ok(())
    }

    /// Verify and update spending for a token transfer
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
        let remaining = self.spending_limits[limit_key][token].read()?;

        if amount > remaining {
            return Err(AccountKeychainError::spending_limit_exceeded().into());
        }

        // Update remaining limit
        self.spending_limits[limit_key][token].write(remaining - amount)
    }

    /// Refund spending limit after a fee refund.
    ///
    /// Restores the spending limit by the refunded amount, clamped so it never
    /// exceeds the limit that was set when the key was authorized.
    /// Should be called after a fee refund to avoid permanently reducing the spending limit.
    pub fn refund_spending_limit(
        &mut self,
        account: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;

        if transaction_key == Address::ZERO {
            return Ok(());
        }

        let tx_origin = self.tx_origin.t_read()?;
        if account != tx_origin {
            return Ok(());
        }

        // Silently skip refund if the key was revoked or expired — the fee was already
        // collected and the key is no longer active, so there is nothing to restore.
        let key = match self.load_active_key(account, transaction_key) {
            Ok(key) => key,
            Err(_) => return Ok(()),
        };

        if !key.enforce_limits {
            return Ok(());
        }

        let limit_key = Self::spending_limit_key(account, transaction_key);
        let remaining = self.spending_limits[limit_key][token].read()?;

        let new_remaining = remaining.saturating_add(amount);

        self.spending_limits[limit_key][token].write(new_remaining)
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
        let transaction_key = self.transaction_key.t_read()?;

        // If using main key (Address::ZERO), no spending limits apply
        if transaction_key == Address::ZERO {
            return Ok(());
        }

        // Only apply spending limits if the caller is the tx origin.
        let tx_origin = self.tx_origin.t_read()?;
        if account != tx_origin {
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
        let transaction_key = self.transaction_key.t_read()?;

        // If using main key (Address::ZERO), no spending limits apply
        if transaction_key == Address::ZERO {
            return Ok(());
        }

        // Only apply spending limits if the caller is the tx origin.
        let tx_origin = self.tx_origin.t_read()?;
        if account != tx_origin {
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
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::{Address, U256};
    use tempo_chainspec::hardfork::TempoHardfork;
    fn assert_unauthorized_error(error: TempoPrecompileError) {
        assert_eq!(error, AccountKeychainError::unauthorized_caller().into());
    }

    #[test]
    fn test_transaction_key_transient_storage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let access_key_addr = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();

            // Test 1: Initially transaction key should be zero
            let initial_key = keychain.transaction_key.t_read()?;
            assert_eq!(
                initial_key,
                Address::ZERO,
                "Initial transaction key should be zero"
            );

            // Test 2: Set transaction key to an access key address
            keychain.set_transaction_key(access_key_addr)?;

            // Test 3: Verify it was stored
            let loaded_key = keychain.transaction_key.t_read()?;
            assert_eq!(loaded_key, access_key_addr, "Transaction key should be set");

            // Test 4: Verify getTransactionKey works
            let result = keychain.get_transaction_key()?;
            assert_eq!(
                result, access_key_addr,
                "getTransactionKey should return the set key"
            );

            // Test 5: Clear transaction key
            keychain.set_transaction_key(Address::ZERO)?;
            let cleared_key = keychain.transaction_key.t_read()?;
            assert_eq!(
                cleared_key,
                Address::ZERO,
                "Transaction key should be cleared"
            );

            Ok(())
        })
    }

    #[test]
    fn test_admin_operations_blocked_with_access_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let msg_sender = Address::random();
        let existing_key = Address::random();
        let access_key = Address::random();
        let token = Address::random();
        let other = Address::random();
        StorageCtx::enter(&mut storage, || {
            // Initialize the keychain
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // First, authorize a key with main key (transaction_key = 0) to set up the test
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.authorize_key(
                msg_sender,
                existing_key,
                SignatureType::Secp256k1,
                u64::MAX,
                true,
                vec![],
            )?;

            // Now set transaction key to non-zero (simulating access key usage)
            keychain.set_transaction_key(access_key)?;

            // Test 1: authorize_key should fail with access key
            let auth_result = keychain.authorize_key(
                msg_sender,
                other,
                SignatureType::P256,
                u64::MAX,
                true,
                vec![],
            );
            assert!(
                auth_result.is_err(),
                "authorize_key should fail when using access key"
            );
            assert_unauthorized_error(auth_result.unwrap_err());

            // Test 2: revoke_key should fail with access key
            let revoke_result = keychain.revoke_key(msg_sender, existing_key);
            assert!(
                revoke_result.is_err(),
                "revoke_key should fail when using access key"
            );
            assert_unauthorized_error(revoke_result.unwrap_err());

            // Test 3: update_spending_limit should fail with access key
            let update_result =
                keychain.update_spending_limit(msg_sender, existing_key, token, U256::from(1000));
            assert!(
                update_result.is_err(),
                "update_spending_limit should fail when using access key"
            );
            assert_unauthorized_error(update_result.unwrap_err());

            Ok(())
        })
    }

    #[test]
    fn test_replay_protection_revoked_key_cannot_be_reauthorized() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Use main key for all operations
            keychain.set_transaction_key(Address::ZERO)?;

            // Step 1: Authorize a key with a spending limit
            keychain.authorize_key(
                account,
                key_id,
                SignatureType::Secp256k1,
                u64::MAX,
                true,
                vec![TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            )?;

            // Verify key exists and limit is set
            let key_info = keychain.get_key(account, key_id)?;
            assert_eq!(key_info.expiry, u64::MAX);
            assert!(!key_info.is_revoked);
            assert_eq!(
                keychain.get_remaining_limit(account, key_id, token)?,
                U256::from(100)
            );

            // Step 2: Revoke the key
            keychain.revoke_key(account, key_id)?;

            // Verify key is revoked and remaining limit returns 0
            let key_info = keychain.get_key(account, key_id)?;
            assert_eq!(key_info.expiry, 0);
            assert!(key_info.is_revoked);
            assert_eq!(
                keychain.get_remaining_limit(account, key_id, token)?,
                U256::ZERO
            );

            // Step 3: Try to re-authorize the same key (replay attack)
            // This should fail because the key was revoked
            let replay_result = keychain.authorize_key(
                account,
                key_id,
                SignatureType::Secp256k1,
                u64::MAX,
                true,
                vec![],
            );
            assert_eq!(
                replay_result.unwrap_err(),
                AccountKeychainError::key_already_revoked().into(),
            );
            Ok(())
        })
    }

    #[test]
    fn test_authorize_key_rejects_expiry_in_past() -> eyre::Result<()> {
        // Must use T0 hardfork for expiry validation to be enforced
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let account = Address::random();
        let key_id = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Use main key for the operation
            keychain.set_transaction_key(Address::ZERO)?;

            // Try to authorize with expiry = 0 (in the past)
            let result =
                keychain.authorize_key(account, key_id, SignatureType::Secp256k1, 0, false, vec![]);
            assert_eq!(
                result.unwrap_err(),
                AccountKeychainError::expiry_in_past().into(),
            );

            // Also test with a non-zero but past expiry
            let result_past =
                keychain.authorize_key(account, key_id, SignatureType::Secp256k1, 1, false, vec![]);
            assert_eq!(
                result_past.unwrap_err(),
                AccountKeychainError::expiry_in_past().into(),
            );

            Ok(())
        })
    }

    #[test]
    fn test_different_key_id_can_be_authorized_after_revocation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id_1 = Address::random();
        let key_id_2 = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Use main key for all operations
            keychain.set_transaction_key(Address::ZERO)?;

            // Authorize key 1
            keychain.authorize_key(
                account,
                key_id_1,
                SignatureType::Secp256k1,
                u64::MAX,
                false,
                vec![],
            )?;

            // Revoke key 1
            keychain.revoke_key(account, key_id_1)?;

            // Authorizing a different key (key 2) should still work
            keychain.authorize_key(
                account,
                key_id_2,
                SignatureType::P256,
                u64::MAX,
                true,
                vec![],
            )?;

            // Verify key 2 is authorized
            let key_info = keychain.get_key(account, key_id_2)?;
            assert_eq!(key_info.expiry, u64::MAX);
            assert!(!key_info.is_revoked);

            Ok(())
        })
    }

    #[test]
    fn test_authorize_approve() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let eoa = Address::random();
        let access_key = Address::random();
        let token = Address::random();
        let contract = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // authorize access key with 100 token spending limit
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(eoa)?;

            keychain.authorize_key(
                eoa,
                access_key,
                SignatureType::Secp256k1,
                u64::MAX,
                true,
                vec![TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            )?;

            let initial_limit = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(initial_limit, U256::from(100));

            // Switch to access key for remaining tests
            keychain.set_transaction_key(access_key)?;

            // Increase approval by 30, which deducts from the limit
            keychain.authorize_approve(eoa, token, U256::ZERO, U256::from(30))?;

            let limit_after = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(limit_after, U256::from(70));

            // Decrease approval to 20, does not affect limit
            keychain.authorize_approve(eoa, token, U256::from(30), U256::from(20))?;

            let limit_unchanged = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(limit_unchanged, U256::from(70));

            // Increase from 20 to 50, reducing the limit by 30
            keychain.authorize_approve(eoa, token, U256::from(20), U256::from(50))?;

            let limit_after_increase = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(limit_after_increase, U256::from(40));

            // Assert that spending limits only applied when account is tx origin
            keychain.authorize_approve(contract, token, U256::ZERO, U256::from(1000))?;

            let limit_after_contract = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(limit_after_contract, U256::from(40)); // unchanged

            // Assert that exceeding remaining limit fails
            let exceed_result = keychain.authorize_approve(eoa, token, U256::ZERO, U256::from(50));
            assert!(matches!(
                exceed_result,
                Err(TempoPrecompileError::AccountKeychainError(
                    AccountKeychainError::SpendingLimitExceeded(_)
                ))
            ));

            // Assert that the main key bypasses spending limits, does not affect existing limits
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.authorize_approve(eoa, token, U256::ZERO, U256::from(1000))?;

            let limit_main_key = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(limit_main_key, U256::from(40));

            Ok(())
        })
    }

    /// Test that spending limits are only enforced when msg_sender == tx_origin.
    ///
    /// This test verifies the fix for the bug where spending limits were incorrectly
    /// applied to contract-initiated transfers. The scenario:
    ///
    /// 1. EOA Alice uses an access key with spending limits
    /// 2. Alice calls a contract that transfers tokens
    /// 3. The contract's transfer should NOT be subject to Alice's spending limits
    ///    (the contract is transferring its own tokens, not Alice's)
    #[test]
    fn test_spending_limits_only_apply_to_tx_origin() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let eoa_alice = Address::random(); // The EOA that signs the transaction
        let access_key = Address::random(); // Alice's access key with spending limits
        let contract_address = Address::random(); // A contract that Alice calls
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Setup: Alice authorizes an access key with a spending limit of 100 tokens
            keychain.set_transaction_key(Address::ZERO)?; // Use main key for setup
            keychain.set_tx_origin(eoa_alice)?;

            keychain.authorize_key(
                eoa_alice,
                access_key,
                SignatureType::Secp256k1,
                u64::MAX,
                true,
                vec![TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            )?;

            // Verify spending limit is set
            let limit = keychain.get_remaining_limit(eoa_alice, access_key, token)?;
            assert_eq!(
                limit,
                U256::from(100),
                "Initial spending limit should be 100"
            );

            // Now simulate a transaction where Alice uses her access key
            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa_alice)?;

            // Test 1: When msg_sender == tx_origin (Alice directly transfers)
            // Spending limit SHOULD be enforced
            keychain.authorize_transfer(eoa_alice, token, U256::from(30))?;

            let limit_after = keychain.get_remaining_limit(eoa_alice, access_key, token)?;
            assert_eq!(
                limit_after,
                U256::from(70),
                "Spending limit should be reduced to 70 after Alice's direct transfer"
            );

            // Test 2: When msg_sender != tx_origin (contract transfers its own tokens)
            // Spending limit should NOT be enforced - the contract isn't spending Alice's tokens
            keychain.authorize_transfer(contract_address, token, U256::from(1000))?;

            let limit_unchanged = keychain.get_remaining_limit(eoa_alice, access_key, token)?;
            assert_eq!(
                limit_unchanged,
                U256::from(70),
                "Spending limit should remain 70 - contract transfer doesn't affect Alice's limit"
            );

            // Test 3: Alice can still spend her remaining limit
            keychain.authorize_transfer(eoa_alice, token, U256::from(70))?;

            let limit_depleted = keychain.get_remaining_limit(eoa_alice, access_key, token)?;
            assert_eq!(
                limit_depleted,
                U256::ZERO,
                "Spending limit should be depleted after Alice spends remaining 70"
            );

            // Test 4: Alice cannot exceed her spending limit
            let exceed_result = keychain.authorize_transfer(eoa_alice, token, U256::from(1));
            assert!(
                exceed_result.is_err(),
                "Should fail when Alice tries to exceed spending limit"
            );

            // Test 5: But contracts can still transfer (they're not subject to Alice's limits)
            keychain.authorize_transfer(contract_address, token, U256::from(999999))?;

            Ok(())
        })
    }

    #[test]
    fn test_authorized_key_encode_decode_roundtrip() {
        let original = AuthorizedKey {
            signature_type: SignatureType::WebAuthn,
            expiry: 1234567890, // some timestamp
            enforce_limits: true,
            is_revoked: false,
        };

        let encoded = original.encode_to_slot();
        let decoded = AuthorizedKey::decode_from_slot(encoded);

        assert_eq!(
            decoded, original,
            "encode/decode roundtrip should be lossless"
        );

        // Test with revoked key
        let revoked = AuthorizedKey {
            signature_type: SignatureType::Secp256k1,
            expiry: 0,
            enforce_limits: false,
            is_revoked: true,
        };
        let encoded = revoked.encode_to_slot();
        let decoded = AuthorizedKey::decode_from_slot(encoded);
        assert_eq!(decoded, revoked);
    }

    #[test]
    fn test_authorize_key_rejects_existing_key_boundary() -> eyre::Result<()> {
        // Use pre-T0 to avoid expiry validation (focus on existence check)
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Genesis);
        let account = Address::random();
        let key_id = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Authorize a key with expiry = 1 (minimal positive value)
            keychain.authorize_key(
                account,
                key_id,
                SignatureType::Secp256k1,
                1, // Minimal positive expiry
                false,
                vec![],
            )?;

            // Verify key exists with expiry = 1
            let key_info = keychain.get_key(account, key_id)?;
            assert_eq!(key_info.expiry, 1, "Key should have expiry = 1");

            // Try to re-authorize - should fail because expiry > 0
            let result = keychain.authorize_key(
                account,
                key_id,
                SignatureType::Secp256k1,
                1, // Minimal positive expiry
                false,
                vec![],
            );
            assert_eq!(
                result.unwrap_err(),
                AccountKeychainError::key_already_exists().into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_spending_limit_key_derivation() {
        let account1 = Address::repeat_byte(0x01);
        let account2 = Address::repeat_byte(0x02);
        let key_id1 = Address::repeat_byte(0xAA);
        let key_id2 = Address::repeat_byte(0xBB);

        // Same inputs should produce same output
        let hash1a = AccountKeychain::spending_limit_key(account1, key_id1);
        let hash1b = AccountKeychain::spending_limit_key(account1, key_id1);
        assert_eq!(hash1a, hash1b, "Same inputs must produce same hash");

        // Different accounts should produce different hashes
        let hash2 = AccountKeychain::spending_limit_key(account2, key_id1);
        assert_ne!(
            hash1a, hash2,
            "Different accounts must produce different hashes"
        );

        // Different key_ids should produce different hashes
        let hash3 = AccountKeychain::spending_limit_key(account1, key_id2);
        assert_ne!(
            hash1a, hash3,
            "Different key_ids must produce different hashes"
        );

        // Order matters: (account1, key_id2) != (key_id2, account1) if we swap
        // But since the types are the same, let's verify swapping produces different result
        let hash_swapped = AccountKeychain::spending_limit_key(key_id1, account1);
        assert_ne!(
            hash1a, hash_swapped,
            "Swapped order must produce different hash"
        );

        // Verify hash is not default/zero
        assert_ne!(hash1a, B256::ZERO, "Hash should not be zero");
    }

    #[test]
    fn test_initialize_sets_up_storage_state() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();

            // Before initialize: operations should work after init
            keychain.initialize()?;

            // Verify we can perform operations after initialize
            keychain.set_transaction_key(Address::ZERO)?;

            let account = Address::random();
            let key_id = Address::random();

            // This would fail if initialize didn't set up storage properly
            keychain.authorize_key(
                account,
                key_id,
                SignatureType::Secp256k1,
                u64::MAX,
                false,
                vec![],
            )?;

            // Verify key was stored
            let key_info = keychain.get_key(account, key_id)?;
            assert_eq!(key_info.expiry, u64::MAX, "Key should be stored after init");

            Ok(())
        })
    }

    #[test]
    fn test_authorize_key_webauthn_signature_type() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Authorize with WebAuthn signature type
            keychain.authorize_key(
                account,
                key_id,
                SignatureType::WebAuthn,
                u64::MAX,
                false,
                vec![],
            )?;

            // Verify key was stored with WebAuthn type (value = 2)
            let key_info = keychain.get_key(account, key_id)?;
            assert_eq!(key_info.signature_type, SignatureType::WebAuthn);

            // Verify via validation that signature type 2 is accepted
            keychain.validate_keychain_authorization(
                account,
                key_id,
                0,
                Some(SignatureType::WebAuthn),
            )?;

            // Verify signature type mismatch is rejected
            let mismatch = keychain.validate_keychain_authorization(
                account,
                key_id,
                0,
                Some(SignatureType::Secp256k1),
            );
            assert!(mismatch.is_err(), "Secp256k1 should not match WebAuthn key");

            Ok(())
        })
    }

    #[test]
    fn test_update_spending_limit_expiry_boundary() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Authorize a key with expiry far in the future
            keychain.authorize_key(
                account,
                key_id,
                SignatureType::Secp256k1,
                u64::MAX,
                true,
                vec![TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            )?;

            // Update should work when key is not expired
            keychain.update_spending_limit(account, key_id, token, U256::from(200))?;

            // Verify the limit was updated
            let limit = keychain.get_remaining_limit(account, key_id, token)?;
            assert_eq!(limit, U256::from(200), "Limit should be updated to 200");

            Ok(())
        })
    }

    #[test]
    fn test_update_spending_limit_enforce_limits_toggle() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Case 1: Key with enforce_limits = false
            keychain.authorize_key(
                account,
                key_id,
                SignatureType::Secp256k1,
                u64::MAX,
                false, // Initially no limits
                vec![],
            )?;

            // Verify key has enforce_limits = false
            let key_before = keychain.get_key(account, key_id)?;
            assert!(
                !key_before.enforce_limits,
                "Key should start with enforce_limits=false"
            );

            // Update spending limit - this should toggle enforce_limits to true
            keychain.update_spending_limit(account, key_id, token, U256::from(500))?;

            // Verify enforce_limits is now true
            let key_after = keychain.get_key(account, key_id)?;
            assert!(
                key_after.enforce_limits,
                "enforce_limits should be true after update"
            );

            // Verify the spending limit was set
            let limit = keychain.get_remaining_limit(account, key_id, token)?;
            assert_eq!(limit, U256::from(500), "Spending limit should be 500");

            Ok(())
        })
    }

    #[test]
    fn test_get_key_or_logic_existence_check() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id_revoked = Address::random();
        let key_id_valid = Address::random();
        let key_id_never_existed = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Setup: Create and revoke a key
            keychain.authorize_key(
                account,
                key_id_revoked,
                SignatureType::P256,
                u64::MAX,
                false,
                vec![],
            )?;
            keychain.revoke_key(account, key_id_revoked)?;

            // Setup: Create a valid key
            keychain.authorize_key(
                account,
                key_id_valid,
                SignatureType::Secp256k1,
                u64::MAX,
                false,
                vec![],
            )?;

            // Test 1: Revoked key (expiry=0, is_revoked=true) - should return empty with isRevoked=true
            let revoked_info = keychain.get_key(account, key_id_revoked)?;
            assert_eq!(
                revoked_info.key_id,
                Address::ZERO,
                "Revoked key should return zero keyId"
            );
            assert!(
                revoked_info.is_revoked,
                "Revoked key should have isRevoked=true"
            );

            // Test 2: Never existed key (expiry=0, is_revoked=false) - should return empty
            let never_info = keychain.get_key(account, key_id_never_existed)?;
            assert_eq!(
                never_info.key_id,
                Address::ZERO,
                "Non-existent key should return zero keyId"
            );
            assert_eq!(
                never_info.expiry, 0,
                "Non-existent key should have expiry=0"
            );

            // Test 3: Valid key (expiry>0, is_revoked=false) - should return actual key info
            let valid_info = keychain.get_key(account, key_id_valid)?;
            assert_eq!(
                valid_info.key_id, key_id_valid,
                "Valid key should return actual keyId"
            );
            assert_eq!(
                valid_info.expiry,
                u64::MAX,
                "Valid key should have correct expiry"
            );
            assert!(!valid_info.is_revoked, "Valid key should not be revoked");

            Ok(())
        })
    }

    #[test]
    fn test_get_key_signature_type_match_arms() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_secp = Address::random();
        let key_p256 = Address::random();
        let key_webauthn = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Create keys with each signature type
            keychain.authorize_key(
                account,
                key_secp,
                SignatureType::Secp256k1, // type 0
                u64::MAX,
                false,
                vec![],
            )?;

            keychain.authorize_key(
                account,
                key_p256,
                SignatureType::P256, // type 1
                u64::MAX,
                false,
                vec![],
            )?;

            keychain.authorize_key(
                account,
                key_webauthn,
                SignatureType::WebAuthn, // type 2
                u64::MAX,
                false,
                vec![],
            )?;

            // Verify each key returns the correct signature type
            let secp_info = keychain.get_key(account, key_secp)?;
            assert_eq!(
                secp_info.signature_type,
                SignatureType::Secp256k1,
                "Secp256k1 key should return Secp256k1"
            );

            let p256_info = keychain.get_key(account, key_p256)?;
            assert_eq!(
                p256_info.signature_type,
                SignatureType::P256,
                "P256 key should return P256"
            );

            let webauthn_info = keychain.get_key(account, key_webauthn)?;
            assert_eq!(
                webauthn_info.signature_type,
                SignatureType::WebAuthn,
                "WebAuthn key should return WebAuthn"
            );

            // Verify they are all distinct
            assert_ne!(secp_info.signature_type, p256_info.signature_type);
            assert_ne!(secp_info.signature_type, webauthn_info.signature_type);
            assert_ne!(p256_info.signature_type, webauthn_info.signature_type);

            Ok(())
        })
    }

    #[test]
    fn test_validate_keychain_authorization_checks_signature_type() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Use main key for authorization
            keychain.set_transaction_key(Address::ZERO)?;

            // Authorize a P256 key
            keychain.authorize_key(
                account,
                key_id,
                SignatureType::P256,
                u64::MAX,
                false,
                vec![],
            )?;

            // Test 1: Validation should succeed with matching signature type (P256 = 1)
            keychain.validate_keychain_authorization(
                account,
                key_id,
                0,
                Some(SignatureType::P256),
            )?;

            // Test 2: Validation should fail with mismatched signature type (Secp256k1 = 0)
            let mismatch_result = keychain.validate_keychain_authorization(
                account,
                key_id,
                0,
                Some(SignatureType::Secp256k1),
            );
            assert_eq!(
                mismatch_result.unwrap_err(),
                AccountKeychainError::signature_type_mismatch(
                    SignatureType::P256,
                    SignatureType::Secp256k1
                )
                .into(),
            );

            // Test 3: Validation should fail with WebAuthn (2) when key is P256 (1)
            let webauthn_mismatch = keychain.validate_keychain_authorization(
                account,
                key_id,
                0,
                Some(SignatureType::WebAuthn),
            );
            assert_eq!(
                webauthn_mismatch.unwrap_err(),
                AccountKeychainError::signature_type_mismatch(
                    SignatureType::P256,
                    SignatureType::WebAuthn
                )
                .into(),
            );

            // Test 4: Validation should succeed with None (backward compatibility, pre-T1)
            keychain.validate_keychain_authorization(account, key_id, 0, None)?;

            Ok(())
        })
    }

    #[test]
    fn test_refund_spending_limit_restores_limit() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let eoa = Address::random();
        let access_key = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain.set_transaction_key(Address::ZERO)?;

            keychain.authorize_key(
                eoa,
                access_key,
                SignatureType::Secp256k1,
                u64::MAX,
                true,
                vec![TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            )?;

            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa)?;

            keychain.authorize_transfer(eoa, token, U256::from(60))?;

            let remaining = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(remaining, U256::from(40));

            keychain.refund_spending_limit(eoa, token, U256::from(25))?;

            let after_refund = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(after_refund, U256::from(65));

            Ok(())
        })
    }

    #[test]
    fn test_refund_spending_limit_noop_for_main_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let eoa = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(eoa)?;

            keychain.refund_spending_limit(eoa, token, U256::from(50))?;

            Ok(())
        })
    }

    #[test]
    fn test_refund_spending_limit_noop_after_key_revocation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let eoa = Address::random();
        let access_key = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain.set_transaction_key(Address::ZERO)?;

            keychain.authorize_key(
                eoa,
                access_key,
                SignatureType::Secp256k1,
                u64::MAX,
                true,
                vec![TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            )?;

            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa)?;

            keychain.authorize_transfer(eoa, token, U256::from(60))?;

            let remaining = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(remaining, U256::from(40));

            keychain.set_transaction_key(Address::ZERO)?;
            keychain.revoke_key(eoa, access_key)?;

            keychain.set_transaction_key(access_key)?;

            keychain.refund_spending_limit(eoa, token, U256::from(25))?;

            let after_refund = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(
                after_refund,
                U256::from(40),
                "limit should be unchanged after revoked key refund"
            );

            Ok(())
        })
    }

    #[test]
    fn test_refund_spending_limit_clamped_by_saturating_add() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let eoa = Address::random();
        let access_key = Address::random();
        let token = Address::random();
        let original_limit = U256::from(100);

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain.set_transaction_key(Address::ZERO)?;

            keychain.authorize_key(
                eoa,
                access_key,
                SignatureType::Secp256k1,
                u64::MAX,
                true,
                vec![TokenLimit {
                    token,
                    amount: original_limit,
                }],
            )?;

            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa)?;

            keychain.authorize_transfer(eoa, token, U256::from(10))?;

            let remaining = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(remaining, U256::from(90));

            keychain.refund_spending_limit(eoa, token, U256::from(50))?;

            let after_refund = keychain.get_remaining_limit(eoa, access_key, token)?;
            assert_eq!(
                after_refund,
                U256::from(140),
                "saturating_add should allow refund beyond original limit without overflow"
            );

            Ok(())
        })
    }
}
