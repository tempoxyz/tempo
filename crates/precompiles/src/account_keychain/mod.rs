pub mod dispatch;

use __packing_authorized_key::{
    ACTIVATES_AT_LOC, ENFORCE_LIMITS_LOC, EXPIRY_LOC, IS_REVOKED_LOC, SIGNATURE_TYPE_LOC,
};
use tempo_contracts::precompiles::{AccountKeychainError, AccountKeychainEvent};
pub use tempo_contracts::precompiles::{
    IAccountKeychain,
    IAccountKeychain::{
        KeyInfo, SignatureType, TokenLimit, authorizeKeyCall, extendActivationCall,
        getActivationWindowCall, getActivationWindowReturn, getAllowedDestinationsCall,
        getKeyCall, getRemainingLimitCall, getTransactionKeyCall, revokeKeyCall,
        updateSpendingLimitCall,
    },
};

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
/// - bytes 11-18: activates_at (u64, little-endian) - TIP-1013
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
    /// TIP-1013: Block timestamp when key becomes usable.
    /// Computed as max(valid_after, authorization_time + activation_delay).
    /// A value of 0 means the key is immediately usable (no activation delay).
    pub activates_at: u64,
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

        let encoded = insert_into_word(
            encoded,
            &self.is_revoked,
            IS_REVOKED_LOC.offset_bytes,
            IS_REVOKED_LOC.size,
        )
        .expect("unable to insert 'is_revoked'");

        insert_into_word(
            encoded,
            &self.activates_at,
            ACTIVATES_AT_LOC.offset_bytes,
            ACTIVATES_AT_LOC.size,
        )
        .expect("unable to insert 'activates_at'")
    }
}

/// Account Keychain contract for managing authorized keys
#[contract(addr = ACCOUNT_KEYCHAIN_ADDRESS)]
pub struct AccountKeychain {
    // keys[account][keyId] -> AuthorizedKey
    keys: Mapping<Address, Mapping<Address, AuthorizedKey>>,
    // spendingLimits[(account, keyId)][token] -> amount (remainingInPeriod for periodic limits)
    // Using a hash of account and keyId as the key to avoid triple nesting
    spending_limits: Mapping<B256, Mapping<Address, U256>>,

    // TIP-1011: Periodic spending limit storage
    // spending_limit_max[(account, keyId)][token] -> per-period cap (0 = one-time limit)
    spending_limit_max: Mapping<B256, Mapping<Address, U256>>,
    // spending_limit_period[(account, keyId)][token] -> period duration in seconds (0 = one-time)
    spending_limit_period: Mapping<B256, Mapping<Address, u64>>,
    // spending_limit_period_end[(account, keyId)][token] -> current period end timestamp
    spending_limit_period_end: Mapping<B256, Mapping<Address, u64>>,

    // TIP-1011: Destination scoping storage
    // allowed_destinations_len[(account, keyId)] -> number of allowed destinations (0 = unrestricted)
    allowed_destinations_len: Mapping<B256, u64>,
    // allowed_destinations[(account, keyId)][index] -> allowed destination address
    allowed_destinations: Mapping<B256, Mapping<u64, Address>>,

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

    /// Authorize a new key for an account
    /// This can only be called by the account itself (using main key)
    pub fn authorize_key(&mut self, msg_sender: Address, call: authorizeKeyCall) -> Result<()> {
        // Check that the transaction key for this transaction is zero (main key)
        let transaction_key = self.transaction_key.t_read()?;

        // If transaction_key is not zero, it means a secondary key is being used
        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        // Validate inputs
        if call.keyId == Address::ZERO {
            return Err(AccountKeychainError::zero_public_key().into());
        }

        // T0+: Expiry must be in the future (also catches expiry == 0 which means "key doesn't exist")
        if self.storage.spec().is_t0() {
            let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
            if call.expiry <= current_timestamp {
                return Err(AccountKeychainError::expiry_in_past().into());
            }
        }

        // Check if key already exists (key exists if expiry > 0)
        let existing_key = self.keys[msg_sender][call.keyId].read()?;
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

        // TIP-1013: Get activatesAt (pre-computed by handler from validAfter + activationDelay)
        let activates_at = call.activatesAt;

        // TIP-1013: Validate activatesAt doesn't exceed expiry
        if activates_at > 0 && call.expiry != u64::MAX && activates_at >= call.expiry {
            return Err(AccountKeychainError::activation_exceeds_expiry().into());
        }

        // Create and store the new key
        let new_key = AuthorizedKey {
            signature_type,
            expiry: call.expiry,
            enforce_limits: call.enforceLimits,
            is_revoked: false,
            activates_at,
        };

        self.keys[msg_sender][call.keyId].write(new_key)?;

        // Set initial spending limits (only if enforce_limits is true)
        if call.enforceLimits {
            let limit_key = Self::spending_limit_key(msg_sender, call.keyId);
            for limit in call.limits {
                self.spending_limits[limit_key][limit.token].write(limit.amount)?;
            }
        }

        // Emit event
        self.emit_event(AccountKeychainEvent::KeyAuthorized(
            IAccountKeychain::KeyAuthorized {
                account: msg_sender,
                publicKey: call.keyId,
                signatureType: signature_type,
                expiry: call.expiry,
            },
        ))
    }

    /// Revoke an authorized key
    ///
    /// This marks the key as revoked by setting is_revoked to true and expiry to 0.
    /// Once revoked, a key_id can never be re-authorized for this account, preventing
    /// replay attacks where old KeyAuthorization signatures could be reused.
    pub fn revoke_key(&mut self, msg_sender: Address, call: revokeKeyCall) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;

        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        let key = self.keys[msg_sender][call.keyId].read()?;

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
        self.keys[msg_sender][call.keyId].write(revoked_key)?;

        // Note: We don't clear spending limits here - they become inaccessible

        // Emit event
        self.emit_event(AccountKeychainEvent::KeyRevoked(
            IAccountKeychain::KeyRevoked {
                account: msg_sender,
                publicKey: call.keyId,
            },
        ))
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
        let transaction_key = self.transaction_key.t_read()?;

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
            self.keys[msg_sender][call.keyId].write(key)?;
        }

        // Update the spending limit
        let limit_key = Self::spending_limit_key(msg_sender, call.keyId);
        self.spending_limits[limit_key][call.token].write(call.newLimit)?;

        // Emit event
        self.emit_event(AccountKeychainEvent::SpendingLimitUpdated(
            IAccountKeychain::SpendingLimitUpdated {
                account: msg_sender,
                publicKey: call.keyId,
                token: call.token,
                newLimit: call.newLimit,
            },
        ))
    }

    /// Get key information
    pub fn get_key(&self, call: getKeyCall) -> Result<KeyInfo> {
        let key = self.keys[call.account][call.keyId].read()?;

        // Key doesn't exist if expiry == 0, or key has been revoked
        if key.expiry == 0 || key.is_revoked {
            return Ok(KeyInfo {
                signatureType: SignatureType::Secp256k1,
                keyId: Address::ZERO,
                expiry: 0,
                enforceLimits: false,
                isRevoked: key.is_revoked,
                activatesAt: 0,
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
            activatesAt: key.activates_at,
        })
    }

    /// Get remaining spending limit
    pub fn get_remaining_limit(&self, call: getRemainingLimitCall) -> Result<U256> {
        let limit_key = Self::spending_limit_key(call.account, call.keyId);
        self.spending_limits[limit_key][call.token].read()
    }

    /// TIP-1011: Get allowed destinations for a key (Solidity interface wrapper)
    pub fn get_allowed_destinations_sol(
        &self,
        call: getAllowedDestinationsCall,
    ) -> Result<Vec<Address>> {
        self.get_allowed_destinations(call.account, call.keyId)
    }

    /// TIP-1013: Get the activation window for a key
    pub fn get_activation_window(
        &self,
        call: getActivationWindowCall,
    ) -> Result<getActivationWindowReturn> {
        let key = self.keys[call.account][call.keyId].read()?;

        // Key doesn't exist if expiry == 0
        if key.expiry == 0 {
            return Ok(getActivationWindowReturn {
                activatesAt: 0,
                expiry: 0,
            });
        }

        Ok(getActivationWindowReturn {
            activatesAt: key.activates_at,
            expiry: key.expiry,
        })
    }

    /// TIP-1013: Extend the activation time for an existing key
    ///
    /// Can only increase activatesAt (push activation further into the future).
    /// This allows account owners to delay guardian key activation.
    pub fn extend_activation(
        &mut self,
        msg_sender: Address,
        call: extendActivationCall,
    ) -> Result<()> {
        // Only main key can extend activation
        let transaction_key = self.transaction_key.t_read()?;
        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        // Load the key
        let mut key = self.load_active_key(msg_sender, call.keyId)?;

        // Check expiry hasn't passed
        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        if current_timestamp >= key.expiry {
            return Err(AccountKeychainError::key_expired().into());
        }

        // Cannot reduce activatesAt (security constraint)
        if call.newActivatesAt <= key.activates_at {
            return Err(AccountKeychainError::cannot_reduce_activation().into());
        }

        // activatesAt must be less than expiry
        if key.expiry != u64::MAX && call.newActivatesAt >= key.expiry {
            return Err(AccountKeychainError::activation_exceeds_expiry().into());
        }

        // Update activatesAt
        key.activates_at = call.newActivatesAt;
        self.keys[msg_sender][call.keyId].write(key)?;

        Ok(())
    }

    /// Get the transaction key used in the current transaction
    pub fn get_transaction_key(
        &self,
        _call: getTransactionKeyCall,
        _msg_sender: Address,
    ) -> Result<Address> {
        self.transaction_key.t_read()
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

    /// Validate keychain authorization (existence, revocation, activation, expiry, and signature type)
    ///
    /// This consolidates all validation checks into one method.
    /// Returns Ok(()) if the key is valid and authorized, Err otherwise.
    ///
    /// # Arguments
    /// * `account` - The account that owns the key
    /// * `key_id` - The key identifier to validate
    /// * `current_timestamp` - Current block timestamp for expiry and activation check
    /// * `expected_sig_type` - The signature type from the actual signature (0=Secp256k1, 1=P256, 2=WebAuthn)
    pub fn validate_keychain_authorization(
        &self,
        account: Address,
        key_id: Address,
        current_timestamp: u64,
        expected_sig_type: u8,
    ) -> Result<()> {
        let key = self.load_active_key(account, key_id)?;

        // TIP-1013: Check activation time first (key must be active)
        if key.activates_at > 0 && current_timestamp < key.activates_at {
            return Err(AccountKeychainError::key_not_yet_active(key.activates_at).into());
        }

        // Check expiry
        if current_timestamp >= key.expiry {
            return Err(AccountKeychainError::key_expired().into());
        }

        // Validate that the signature type matches the key type stored in the keychain
        if key.signature_type != expected_sig_type {
            return Err(AccountKeychainError::signature_type_mismatch(
                key.signature_type,
                expected_sig_type,
            )
            .into());
        }

        Ok(())
    }

    /// Internal: Verify and update spending for a token transfer (TIP-1011 with periodic limit support)
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

        let limit_key = Self::spending_limit_key(account, key_id);

        // TIP-1011: Check for periodic limit and handle reset
        let period = self.spending_limit_period[limit_key][token].read()?;

        let mut remaining = if period > 0 {
            // Periodic limit - check if period has expired and reset if needed
            let period_end = self.spending_limit_period_end[limit_key][token].read()?;
            let current_timestamp = self.storage.timestamp().saturating_to::<u64>();

            if current_timestamp >= period_end {
                // Period expired - reset the remaining amount and update period_end
                let limit_max = self.spending_limit_max[limit_key][token].read()?;
                let new_period_end = current_timestamp.saturating_add(period);

                self.spending_limit_period_end[limit_key][token].write(new_period_end)?;
                self.spending_limits[limit_key][token].write(limit_max)?;

                limit_max
            } else {
                // Within current period - use current remaining
                self.spending_limits[limit_key][token].read()?
            }
        } else {
            // One-time limit - use current remaining
            self.spending_limits[limit_key][token].read()?
        };

        if amount > remaining {
            return Err(AccountKeychainError::spending_limit_exceeded().into());
        }

        // Update remaining limit
        remaining -= amount;
        self.spending_limits[limit_key][token].write(remaining)
    }

    /// TIP-1011: Set periodic spending limit data for a token
    ///
    /// Called by the handler when authorizing a key with periodic limits.
    /// This stores the periodic limit configuration (max, period, period_end).
    ///
    /// # Arguments
    /// * `account` - The account owning the key
    /// * `key_id` - The key identifier
    /// * `token` - The token address
    /// * `limit_max` - Per-period spending cap
    /// * `period` - Period duration in seconds (0 = one-time limit)
    /// * `period_end` - Initial period end timestamp (usually 0, set on first use)
    pub fn set_periodic_limit(
        &mut self,
        account: Address,
        key_id: Address,
        token: Address,
        limit_max: U256,
        period: u64,
        period_end: u64,
    ) -> Result<()> {
        let limit_key = Self::spending_limit_key(account, key_id);

        self.spending_limit_max[limit_key][token].write(limit_max)?;
        self.spending_limit_period[limit_key][token].write(period)?;
        self.spending_limit_period_end[limit_key][token].write(period_end)
    }

    /// TIP-1011: Set allowed destinations for a key
    ///
    /// Called by the handler when authorizing a key with destination restrictions.
    ///
    /// # Arguments
    /// * `account` - The account owning the key
    /// * `key_id` - The key identifier
    /// * `destinations` - Array of allowed destination addresses (empty = unrestricted)
    pub fn set_allowed_destinations(
        &mut self,
        account: Address,
        key_id: Address,
        destinations: &[Address],
    ) -> Result<()> {
        let limit_key = Self::spending_limit_key(account, key_id);

        // Store the count
        self.allowed_destinations_len[limit_key].write(destinations.len() as u64)?;

        // Store each destination
        for (i, dest) in destinations.iter().enumerate() {
            self.allowed_destinations[limit_key][i as u64].write(*dest)?;
        }

        Ok(())
    }

    /// TIP-1011: Get allowed destinations for a key
    ///
    /// Returns the list of allowed destination addresses for a key.
    /// Empty array means unrestricted (can call any address).
    pub fn get_allowed_destinations(&self, account: Address, key_id: Address) -> Result<Vec<Address>> {
        let limit_key = Self::spending_limit_key(account, key_id);
        let len = self.allowed_destinations_len[limit_key].read()?;

        let mut destinations = Vec::with_capacity(len as usize);
        for i in 0..len {
            let dest = self.allowed_destinations[limit_key][i].read()?;
            destinations.push(dest);
        }

        Ok(destinations)
    }

    /// TIP-1011: Check if a destination is allowed for the current transaction key
    ///
    /// Called by the handler before transaction execution.
    /// Returns Ok(()) if destination is allowed, Err(DestinationNotAllowed) otherwise.
    pub fn validate_destination(&self, account: Address, destination: Address) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;

        // Main key (Address::ZERO) has no destination restrictions
        if transaction_key == Address::ZERO {
            return Ok(());
        }

        let limit_key = Self::spending_limit_key(account, transaction_key);
        let len = self.allowed_destinations_len[limit_key].read()?;

        // Empty allowed list = unrestricted
        if len == 0 {
            return Ok(());
        }

        // Check if destination is in the allowed list
        for i in 0..len {
            let allowed = self.allowed_destinations[limit_key][i].read()?;
            if allowed == destination {
                return Ok(());
            }
        }

        Err(AccountKeychainError::destination_not_allowed(destination).into())
    }

    /// TIP-1011: Get remaining limit with period info
    ///
    /// Returns the remaining spending limit and period end for a token.
    /// For one-time limits, period_end is 0.
    pub fn get_remaining_limit_with_period(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
    ) -> Result<(U256, u64)> {
        let limit_key = Self::spending_limit_key(account, key_id);

        let remaining = self.spending_limits[limit_key][token].read()?;
        let period_end = self.spending_limit_period_end[limit_key][token].read()?;

        Ok((remaining, period_end))
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
    use tempo_contracts::precompiles::IAccountKeychain::SignatureType;

    // Helper function to assert unauthorized error
    fn assert_unauthorized_error(error: TempoPrecompileError) {
        match error {
            TempoPrecompileError::AccountKeychainError(e) => {
                assert!(
                    matches!(e, AccountKeychainError::UnauthorizedCaller(_)),
                    "Expected UnauthorizedCaller error, got: {e:?}"
                );
            }
            _ => panic!("Expected AccountKeychainError, got: {error:?}"),
        }
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
            let get_tx_key_call = getTransactionKeyCall {};
            let result = keychain.get_transaction_key(get_tx_key_call, Address::ZERO)?;
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
            let setup_call = authorizeKeyCall {
                keyId: existing_key,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: true,
                limits: vec![],
            };
            keychain.authorize_key(msg_sender, setup_call)?;

            // Now set transaction key to non-zero (simulating access key usage)
            keychain.set_transaction_key(access_key)?;

            // Test 1: authorize_key should fail with access key
            let auth_call = authorizeKeyCall {
                keyId: other,
                signatureType: SignatureType::P256,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: true,
                limits: vec![],
            };
            let auth_result = keychain.authorize_key(msg_sender, auth_call);
            assert!(
                auth_result.is_err(),
                "authorize_key should fail when using access key"
            );
            assert_unauthorized_error(auth_result.unwrap_err());

            // Test 2: revoke_key should fail with access key
            let revoke_call = revokeKeyCall {
                keyId: existing_key,
            };
            let revoke_result = keychain.revoke_key(msg_sender, revoke_call);
            assert!(
                revoke_result.is_err(),
                "revoke_key should fail when using access key"
            );
            assert_unauthorized_error(revoke_result.unwrap_err());

            // Test 3: update_spending_limit should fail with access key
            let update_call = updateSpendingLimitCall {
                keyId: existing_key,
                token,
                newLimit: U256::from(1000),
            };
            let update_result = keychain.update_spending_limit(msg_sender, update_call);
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
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Use main key for all operations
            keychain.set_transaction_key(Address::ZERO)?;

            // Step 1: Authorize a key
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call.clone())?;

            // Verify key exists
            let key_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id,
            })?;
            assert_eq!(key_info.expiry, u64::MAX);
            assert!(!key_info.isRevoked);

            // Step 2: Revoke the key
            let revoke_call = revokeKeyCall { keyId: key_id };
            keychain.revoke_key(account, revoke_call)?;

            // Verify key is revoked
            let key_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id,
            })?;
            assert_eq!(key_info.expiry, 0);
            assert!(key_info.isRevoked);

            // Step 3: Try to re-authorize the same key (replay attack)
            // This should fail because the key was revoked
            let replay_result = keychain.authorize_key(account, auth_call);
            assert!(
                replay_result.is_err(),
                "Re-authorizing a revoked key should fail"
            );

            // Verify it's the correct error
            match replay_result.unwrap_err() {
                TempoPrecompileError::AccountKeychainError(e) => {
                    assert!(
                        matches!(e, AccountKeychainError::KeyAlreadyRevoked(_)),
                        "Expected KeyAlreadyRevoked error, got: {e:?}"
                    );
                }
                e => panic!("Expected AccountKeychainError, got: {e:?}"),
            }
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
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: 0, // Zero expiry is in the past - should fail
                activatesAt: 0,
                enforceLimits: false,
                limits: vec![],
            };
            let result = keychain.authorize_key(account, auth_call);
            assert!(
                result.is_err(),
                "Authorizing with expiry in past should fail"
            );

            // Verify it's the correct error
            match result.unwrap_err() {
                TempoPrecompileError::AccountKeychainError(e) => {
                    assert!(
                        matches!(e, AccountKeychainError::ExpiryInPast(_)),
                        "Expected ExpiryInPast error, got: {e:?}"
                    );
                }
                e => panic!("Expected AccountKeychainError, got: {e:?}"),
            }

            // Also test with a non-zero but past expiry
            let auth_call_past = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: 1, // Very old timestamp - should fail
                activatesAt: 0,
                enforceLimits: false,
                limits: vec![],
            };
            let result_past = keychain.authorize_key(account, auth_call_past);
            assert!(
                matches!(
                    result_past,
                    Err(TempoPrecompileError::AccountKeychainError(
                        AccountKeychainError::ExpiryInPast(_)
                    ))
                ),
                "Expected ExpiryInPast error for past expiry, got: {result_past:?}"
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
            let auth_call_1 = authorizeKeyCall {
                keyId: key_id_1,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call_1)?;

            // Revoke key 1
            keychain.revoke_key(account, revokeKeyCall { keyId: key_id_1 })?;

            // Authorizing a different key (key 2) should still work
            let auth_call_2 = authorizeKeyCall {
                keyId: key_id_2,
                signatureType: SignatureType::P256,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: true,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call_2)?;

            // Verify key 2 is authorized
            let key_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id_2,
            })?;
            assert_eq!(key_info.expiry, u64::MAX);
            assert!(!key_info.isRevoked);

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

            let auth_call = authorizeKeyCall {
                keyId: access_key,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: true,
                limits: vec![TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            };
            keychain.authorize_key(eoa, auth_call)?;

            let initial_limit = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(initial_limit, U256::from(100));

            // Switch to access key for remaining tests
            keychain.set_transaction_key(access_key)?;

            // Increase approval by 30, which deducts from the limit
            keychain.authorize_approve(eoa, token, U256::ZERO, U256::from(30))?;

            let limit_after = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(limit_after, U256::from(70));

            // Decrease approval to 20, does not affect limit
            keychain.authorize_approve(eoa, token, U256::from(30), U256::from(20))?;

            let limit_unchanged = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(limit_unchanged, U256::from(70));

            // Increase from 20 to 50, reducing the limit by 30
            keychain.authorize_approve(eoa, token, U256::from(20), U256::from(50))?;

            let limit_after_increase = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(limit_after_increase, U256::from(40));

            // Assert that spending limits only applied when account is tx origin
            keychain.authorize_approve(contract, token, U256::ZERO, U256::from(1000))?;

            let limit_after_contract = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
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

            let limit_main_key = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
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

            let auth_call = authorizeKeyCall {
                keyId: access_key,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: true,
                limits: vec![TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            };
            keychain.authorize_key(eoa_alice, auth_call)?;

            // Verify spending limit is set
            let limit = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa_alice,
                keyId: access_key,
                token,
            })?;
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

            let limit_after = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa_alice,
                keyId: access_key,
                token,
            })?;
            assert_eq!(
                limit_after,
                U256::from(70),
                "Spending limit should be reduced to 70 after Alice's direct transfer"
            );

            // Test 2: When msg_sender != tx_origin (contract transfers its own tokens)
            // Spending limit should NOT be enforced - the contract isn't spending Alice's tokens
            keychain.authorize_transfer(contract_address, token, U256::from(1000))?;

            let limit_unchanged = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa_alice,
                keyId: access_key,
                token,
            })?;
            assert_eq!(
                limit_unchanged,
                U256::from(70),
                "Spending limit should remain 70 - contract transfer doesn't affect Alice's limit"
            );

            // Test 3: Alice can still spend her remaining limit
            keychain.authorize_transfer(eoa_alice, token, U256::from(70))?;

            let limit_depleted = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa_alice,
                keyId: access_key,
                token,
            })?;
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
            let contract_result =
                keychain.authorize_transfer(contract_address, token, U256::from(999999));
            assert!(
                contract_result.is_ok(),
                "Contract should still be able to transfer even though Alice's limit is depleted"
            );

            Ok(())
        })
    }

    #[test]
    fn test_authorized_key_encode_decode_roundtrip() {
        let original = AuthorizedKey {
            signature_type: 2,  // WebAuthn
            expiry: 1234567890, // some timestamp
            activates_at: 0,
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
            signature_type: 0,
            expiry: 0,
            activates_at: 0,
            enforce_limits: false,
            is_revoked: true,
        };
        let encoded = revoked.encode_to_slot();
        let decoded = AuthorizedKey::decode_from_slot(encoded);
        assert_eq!(decoded, revoked);
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
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::P256,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call)?;

            // Test 1: Validation should succeed with matching signature type (P256 = 1)
            let result = keychain.validate_keychain_authorization(account, key_id, 0, 1);
            assert!(
                result.is_ok(),
                "Validation should succeed with matching signature type"
            );

            // Test 2: Validation should fail with mismatched signature type (Secp256k1 = 0)
            let mismatch_result = keychain.validate_keychain_authorization(account, key_id, 0, 0);
            assert!(
                mismatch_result.is_err(),
                "Validation should fail with mismatched signature type"
            );
            match mismatch_result.unwrap_err() {
                TempoPrecompileError::AccountKeychainError(e) => {
                    assert!(
                        matches!(e, AccountKeychainError::SignatureTypeMismatch(_)),
                        "Expected SignatureTypeMismatch error, got: {e:?}"
                    );
                }
                e => panic!("Expected AccountKeychainError, got: {e:?}"),
            }

            // Test 3: Validation should fail with WebAuthn (2) when key is P256 (1)
            let webauthn_mismatch = keychain.validate_keychain_authorization(account, key_id, 0, 2);
            assert!(
                webauthn_mismatch.is_err(),
                "Validation should fail with WebAuthn when key is P256"
            );

            Ok(())
        })
    }

    // =============================================================================
    // TIP-1011: Periodic Limits and Destination Scoping Tests
    // =============================================================================

    #[test]
    fn test_periodic_limit_reset_on_period_expiry() -> eyre::Result<()> {
        use tempo_chainspec::hardfork::TempoHardfork;

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);

        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Get the current timestamp from storage
            let current_timestamp = keychain.storage.timestamp().saturating_to::<u64>();

            // Setup: Authorize key and set up periodic limit
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: true,
                limits: vec![TokenLimit {
                    token,
                    amount: U256::from(100), // Initial remaining
                }],
            };
            keychain.authorize_key(account, auth_call)?;

            // Set periodic limit: 100 tokens per 3600 seconds (1 hour)
            // period_end in the past (before current timestamp) to trigger reset
            let past_period_end = current_timestamp.saturating_sub(100);
            keychain.set_periodic_limit(
                account,
                key_id,
                token,
                U256::from(100), // max per period
                3600,            // period duration
                past_period_end, // period end in the past
            )?;

            // Now use the access key
            keychain.set_transaction_key(key_id)?;

            // First spending attempt - period expired, should reset
            keychain.verify_and_update_spending(account, key_id, token, U256::from(30))?;

            // Check remaining - should be 100 - 30 = 70 after reset
            let (remaining, period_end) =
                keychain.get_remaining_limit_with_period(account, key_id, token)?;
            assert_eq!(remaining, U256::from(70));
            // Period end should be updated to current_timestamp + 3600
            assert_eq!(period_end, current_timestamp + 3600);

            Ok(())
        })
    }

    #[test]
    fn test_periodic_limit_partial_usage_no_rollover() -> eyre::Result<()> {
        use tempo_chainspec::hardfork::TempoHardfork;

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);

        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Get current timestamp
            let current_timestamp = keychain.storage.timestamp().saturating_to::<u64>();

            // Setup
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: true,
                limits: vec![TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            };
            keychain.authorize_key(account, auth_call)?;

            // Set periodic limit with period end in future
            let future_period_end = current_timestamp + 1000;
            keychain.set_periodic_limit(
                account,
                key_id,
                token,
                U256::from(100),   // max
                3600,              // period
                future_period_end, // period_end in future
            )?;

            keychain.set_transaction_key(key_id)?;

            // Spend 50 tokens (within period)
            keychain.verify_and_update_spending(account, key_id, token, U256::from(50))?;

            // Check remaining - should be 100 - 50 = 50
            let (remaining, _) = keychain.get_remaining_limit_with_period(account, key_id, token)?;
            assert_eq!(remaining, U256::from(50));

            Ok(())
        })
    }

    #[test]
    fn test_destination_scoping_allow_and_deny() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let account = Address::random();
        let key_id = Address::random();
        let allowed_dest1 = Address::random();
        let allowed_dest2 = Address::random();
        let disallowed_dest = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Setup: Authorize key
            keychain.set_transaction_key(Address::ZERO)?;

            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call)?;

            // Set allowed destinations
            keychain.set_allowed_destinations(account, key_id, &[allowed_dest1, allowed_dest2])?;

            // Switch to using the access key
            keychain.set_transaction_key(key_id)?;

            // Test 1: Allowed destinations should pass
            let result1 = keychain.validate_destination(account, allowed_dest1);
            assert!(result1.is_ok(), "Should allow dest1");

            let result2 = keychain.validate_destination(account, allowed_dest2);
            assert!(result2.is_ok(), "Should allow dest2");

            // Test 2: Disallowed destination should fail
            let result3 = keychain.validate_destination(account, disallowed_dest);
            assert!(result3.is_err(), "Should deny disallowed destination");

            match result3.unwrap_err() {
                TempoPrecompileError::AccountKeychainError(
                    AccountKeychainError::DestinationNotAllowed(_),
                ) => {}
                e => panic!("Expected DestinationNotAllowed error, got: {e:?}"),
            }

            Ok(())
        })
    }

    #[test]
    fn test_empty_destinations_allows_any() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let account = Address::random();
        let key_id = Address::random();
        let any_dest = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain.set_transaction_key(Address::ZERO)?;

            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call)?;

            // Don't set any destinations (empty = unrestricted)
            // Alternatively: keychain.set_allowed_destinations(account, key_id, &[])?;

            keychain.set_transaction_key(key_id)?;

            // Should allow any destination
            let result = keychain.validate_destination(account, any_dest);
            assert!(result.is_ok(), "Empty destinations should allow any address");

            Ok(())
        })
    }

    #[test]
    fn test_get_allowed_destinations() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let account = Address::random();
        let key_id = Address::random();
        let dest1 = Address::random();
        let dest2 = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain.set_transaction_key(Address::ZERO)?;

            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call)?;

            // Set destinations
            keychain.set_allowed_destinations(account, key_id, &[dest1, dest2])?;

            // Get destinations
            let destinations = keychain.get_allowed_destinations(account, key_id)?;
            assert_eq!(destinations.len(), 2);
            assert!(destinations.contains(&dest1));
            assert!(destinations.contains(&dest2));

            Ok(())
        })
    }

    #[test]
    fn test_one_time_limit_backwards_compatible() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            // Setup with one-time limit (no periodic data set)
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: true,
                limits: vec![TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            };
            keychain.authorize_key(account, auth_call)?;

            // Don't set periodic limit - period=0 means one-time limit

            keychain.set_transaction_key(key_id)?;

            // Spend some tokens
            keychain.verify_and_update_spending(account, key_id, token, U256::from(30))?;

            // Check remaining - should be 70, no reset
            let (remaining, period_end) =
                keychain.get_remaining_limit_with_period(account, key_id, token)?;
            assert_eq!(remaining, U256::from(70));
            assert_eq!(period_end, 0, "One-time limit should have period_end=0");

            // Spend remaining
            keychain.verify_and_update_spending(account, key_id, token, U256::from(70))?;

            let (remaining, _) = keychain.get_remaining_limit_with_period(account, key_id, token)?;
            assert_eq!(remaining, U256::ZERO);

            // Should fail now - one-time limit depleted
            let result = keychain.verify_and_update_spending(account, key_id, token, U256::from(1));
            assert!(result.is_err(), "Should fail when one-time limit depleted");

            Ok(())
        })
    }

    #[test]
    fn test_main_key_bypasses_destination_restrictions() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let account = Address::random();
        let key_id = Address::random();
        let any_dest = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain.set_transaction_key(Address::ZERO)?;

            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call)?;

            // Set restricted destinations for the access key
            let allowed = Address::random();
            keychain.set_allowed_destinations(account, key_id, &[allowed])?;

            // Main key (Address::ZERO) should bypass destination restrictions
            // (transaction_key is still Address::ZERO from setup)
            let result = keychain.validate_destination(account, any_dest);
            assert!(
                result.is_ok(),
                "Main key should bypass destination restrictions"
            );

            Ok(())
        })
    }

    // ==================== TIP-1013 Tests ====================

    #[test]
    fn test_tip1013_key_with_activation_delay() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();
        let current_timestamp = 1700000000u64;

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Authorize key with activatesAt in the future
            let activates_at = current_timestamp + 86400; // 1 day later
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: activates_at,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call)?;

            // Verify key was stored with correct activatesAt
            let key_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id,
            })?;
            assert_eq!(key_info.activatesAt, activates_at);

            // Validate should fail before activatesAt
            let result = keychain.validate_keychain_authorization(
                account,
                key_id,
                current_timestamp, // Before activatesAt
                0,                 // Secp256k1
            );
            assert!(result.is_err(), "Key should not be usable before activatesAt");

            // Validate should succeed after activatesAt
            let result = keychain.validate_keychain_authorization(
                account,
                key_id,
                activates_at + 1, // After activatesAt
                0,                // Secp256k1
            );
            assert!(result.is_ok(), "Key should be usable after activatesAt");

            Ok(())
        })
    }

    #[test]
    fn test_tip1013_key_immediately_active() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();
        let current_timestamp = 1700000000u64;

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Authorize key with activatesAt = 0 (immediately active)
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: 0,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call)?;

            // Validate should succeed immediately
            let result = keychain.validate_keychain_authorization(
                account,
                key_id,
                current_timestamp,
                0, // Secp256k1
            );
            assert!(result.is_ok(), "Key with activatesAt=0 should be immediately usable");

            Ok(())
        })
    }

    #[test]
    fn test_tip1013_extend_activation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Authorize key with activatesAt in the future
            let initial_activates_at = 1700100000u64;
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: initial_activates_at,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call)?;

            // Extend activation time
            let new_activates_at = 1700200000u64;
            let extend_call = extendActivationCall {
                keyId: key_id,
                newActivatesAt: new_activates_at,
            };
            keychain.extend_activation(account, extend_call)?;

            // Verify new activatesAt
            let result = keychain.get_activation_window(getActivationWindowCall {
                account,
                keyId: key_id,
            })?;
            assert_eq!(result.activatesAt, new_activates_at);

            Ok(())
        })
    }

    #[test]
    fn test_tip1013_cannot_reduce_activation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Authorize key with activatesAt in the future
            let initial_activates_at = 1700100000u64;
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                activatesAt: initial_activates_at,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call)?;

            // Attempt to reduce activation time (should fail)
            let extend_call = extendActivationCall {
                keyId: key_id,
                newActivatesAt: 1700050000u64, // Earlier than current
            };
            let result = keychain.extend_activation(account, extend_call);
            assert!(result.is_err(), "Should not be able to reduce activatesAt");

            Ok(())
        })
    }

    #[test]
    fn test_tip1013_activation_exceeds_expiry() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            // Try to authorize key where activatesAt >= expiry (should fail)
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry: 1700100000,      // Expiry
                activatesAt: 1700200000, // After expiry
                enforceLimits: false,
                limits: vec![],
            };
            let result = keychain.authorize_key(account, auth_call);
            assert!(result.is_err(), "Should not allow activatesAt >= expiry");

            Ok(())
        })
    }

    #[test]
    fn test_tip1013_get_activation_window() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let account = Address::random();
        let key_id = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            let activates_at = 1700100000u64;
            let expiry = 1800000000u64;
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                expiry,
                activatesAt: activates_at,
                enforceLimits: false,
                limits: vec![],
            };
            keychain.authorize_key(account, auth_call)?;

            // Get activation window
            let result = keychain.get_activation_window(getActivationWindowCall {
                account,
                keyId: key_id,
            })?;
            assert_eq!(result.activatesAt, activates_at);
            assert_eq!(result.expiry, expiry);

            Ok(())
        })
    }
}
