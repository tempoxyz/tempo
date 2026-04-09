//! [Account keychain] precompile for managing session keys and spending limits.
//!
//! Each account can authorize secondary keys (session keys) with per-token spending caps,
//! signature type constraints, and expiry. The main key (address zero) retains full control
//! and is the only key allowed to authorize, revoke, or update other keys.
//!
//! [Account keychain]: <https://docs.tempo.xyz/protocol/transactions/AccountKeychain>

pub mod dispatch;

use std::collections::HashSet;

use alloy::sol_types::SolCall;
use tempo_contracts::precompiles::{AccountKeychainError, AccountKeychainEvent, ITIP20};
pub use tempo_contracts::precompiles::{
    IAccountKeychain,
    IAccountKeychain::{
        CallScope, KeyInfo, KeyRestrictions, SelectorRule, SignatureType, TokenLimit,
        getAllowedCallsCall, getKeyCall, getRemainingLimitCall, getRemainingLimitWithPeriodCall,
        getTransactionKeyCall, removeAllowedCallsCall, revokeKeyCall, setAllowedCallsCall,
        updateSpendingLimitCall,
    },
    authorizeKeyCall, getAllowedCallsReturn, getRemainingLimitReturn,
};

use crate::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    error::Result,
    storage::{Handler, Mapping, Set},
    tip20_factory::TIP20Factory,
};
use alloy::primitives::{Address, B256, FixedBytes, TxKind, U256, keccak256};
use tempo_precompiles_macros::{Storable, contract};

/// Allowed TIP-20 selectors for recipient-constrained rules.
const TIP20_TRANSFER_SELECTOR: [u8; 4] = ITIP20::transferCall::SELECTOR;
const TIP20_APPROVE_SELECTOR: [u8; 4] = ITIP20::approveCall::SELECTOR;
const TIP20_TRANSFER_WITH_MEMO_SELECTOR: [u8; 4] = ITIP20::transferWithMemoCall::SELECTOR;

#[inline]
pub fn is_constrained_tip20_selector(selector: [u8; 4]) -> bool {
    matches!(
        selector,
        TIP20_TRANSFER_SELECTOR | TIP20_APPROVE_SELECTOR | TIP20_TRANSFER_WITH_MEMO_SELECTOR
    )
}

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

/// Account Keychain contract for managing authorized keys (session keys, spending limits).
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract(addr = ACCOUNT_KEYCHAIN_ADDRESS)]
pub struct AccountKeychain {
    // keys[account][keyId] -> AuthorizedKey
    keys: Mapping<Address, Mapping<Address, AuthorizedKey>>,
    // spendingLimits[(account, keyId)][token] -> { remaining, max, period, period_end }
    // Using a hash of account and keyId as the key to avoid triple nesting
    spending_limits: Mapping<B256, Mapping<Address, SpendingLimitState>>,

    // key_scopes[(account, keyId)] -> call scoping configuration.
    key_scopes: Mapping<B256, KeyScope>,

    // WARNING(rusowsky): transient storage slots must always be placed at the very end until the `contract`
    // macro is refactored and has 2 independent layouts (persistent and transient).
    // If new (persistent) storage fields need to be added to the precompile, they must go above this one.
    transaction_key: Address,
    // The transaction origin (tx.origin) - the EOA that signed the transaction.
    // Used to ensure spending limits only apply when msg_sender == tx_origin.
    tx_origin: Address,
}

/// Key-level call scope.
///
/// This is the only level that needs an explicit mode bit: an empty `targets` set is ambiguous
/// between "unrestricted" and "scoped deny-all". `is_scoped = false` means ignore the tree and
/// allow any call, while `is_scoped = true && targets.is_empty()` means the key currently allows
/// no targets.
#[derive(Debug, Clone, Storable, Default)]
pub struct KeyScope {
    pub is_scoped: bool,
    pub targets: Set<Address>,
    pub target_scopes: Mapping<Address, TargetScope>,
}

/// Target-level scope for one target under one account key.
///
/// Only persisted for targets present in the parent `targets` set. An empty `selectors` set means
/// any selector on the target is allowed; deleting the target from `targets` removes the scope.
/// This asymmetry is intentional: once the parent target is explicitly allowed, an empty child set
/// means "no further restriction", not "deny all selectors".
#[derive(Debug, Clone, Storable, Default)]
pub struct TargetScope {
    pub selectors: Set<FixedBytes<4>>,
    pub selector_scopes: Mapping<FixedBytes<4>, SelectorScope>,
}

/// Selector-level scope for one selector under one target.
///
/// Only persisted for selectors present in the parent `selectors` set. An empty `recipients` set
/// means any recipient is allowed; deleting the selector from `selectors` removes the scope.
/// Future incremental remove APIs must delete the selector entry when the last recipient is
/// removed; leaving an existing selector with `recipients = []` would widen permissions to
/// allow-all recipients.
#[derive(Debug, Clone, Storable, Default)]
pub struct SelectorScope {
    pub recipients: Set<Address>,
}

/// Per-token spending limit state.
///
/// `remaining` stays in the first slot so the legacy `spending_limits` layout remains intact.
/// It remains `U256` for the same reason, even though T3 caps `max` to TIP-20's `u128` supply
/// range and runtime logic maintains `remaining <= max` for periodic limits.
/// T3+ extends the same row with period metadata in later slots.
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct SpendingLimitState {
    /// Remaining amount currently available to spend.
    pub remaining: U256,
    /// Maximum amount allowed per period, capped to TIP-20's `u128` supply range.
    pub max: u128,
    /// Duration of each period in seconds. `0` means non-periodic.
    pub period: u64,
    /// End timestamp of the current period window.
    pub period_end: u64,
}

impl SpendingLimitState {
    /// Computes the period end for the current rollover window, saturating on
    /// all intermediate operations to avoid overflow in extreme timestamps.
    fn compute_next_period_end(&self, current_timestamp: u64) -> u64 {
        let elapsed = current_timestamp.saturating_sub(self.period_end);
        let periods_elapsed = (elapsed / self.period).saturating_add(1);
        let advance = self.period.saturating_mul(periods_elapsed);
        self.period_end.saturating_add(advance)
    }
}

impl AccountKeychain {
    /// Create a hash key for account+key scoped storage rows.
    ///
    /// This is used to access account-key rows like `spending_limits[key][token]` and
    /// `key_scopes[key]`. The hash combines account and key_id to avoid triple nesting.
    pub fn spending_limit_key(account: Address, key_id: Address) -> B256 {
        let mut data = [0u8; 40];
        data[..20].copy_from_slice(account.as_slice());
        data[20..].copy_from_slice(key_id.as_slice());
        keccak256(data)
    }

    #[inline]
    fn t3_spending_limit_cap(limit: U256) -> Result<u128> {
        if limit > U256::from(u128::MAX) {
            return Err(AccountKeychainError::invalid_spending_limit().into());
        }

        Ok(limit.to::<u128>())
    }

    /// Initializes the account keychain precompile.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Registers a new access key with signature type, expiry, and optional per-token spending
    /// limits. Only callable with the account's main key (not a session key).
    ///
    /// # Errors
    /// - `UnauthorizedCaller` — only the main key can authorize/revoke and, for contract
    ///   callers on T2+, `msg.sender` must match `tx.origin`
    /// - `ZeroPublicKey` — `keyId` cannot be the zero address
    /// - `ExpiryInPast` — expiry must be in the future (enforced since T0)
    /// - `KeyAlreadyExists` — a key with this ID is already registered
    /// - `KeyAlreadyRevoked` — revoked keys cannot be re-authorized
    /// - `InvalidSignatureType` — must be Secp256k1, P256, or WebAuthn
    pub fn authorize_key(&mut self, msg_sender: Address, call: authorizeKeyCall) -> Result<()> {
        let config = &call.config;

        self.ensure_admin_caller(msg_sender)?;
        let is_t3 = self.storage.spec().is_t3();

        // Validate inputs
        if call.keyId == Address::ZERO {
            return Err(AccountKeychainError::zero_public_key().into());
        }

        // T0+: Expiry must be in the future (also catches expiry == 0 which means "key doesn't exist")
        if self.storage.spec().is_t0() {
            let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
            if config.expiry <= current_timestamp {
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

        // TIP-1011 fields are hardfork-gated at T3, so reject them before mutating state.
        let allowed_call_configs = if is_t3 {
            if config.enforceLimits {
                let mut seen_tokens = HashSet::with_capacity(config.limits.len());
                for limit in &config.limits {
                    if !seen_tokens.insert(limit.token) {
                        return Err(AccountKeychainError::invalid_spending_limit().into());
                    }
                }
            }

            if config.allowAnyCalls {
                None
            } else {
                Some(config.allowedCalls.as_slice())
            }
        } else {
            if config.limits.iter().any(|limit| limit.period != 0) {
                return Err(AccountKeychainError::invalid_spending_limit().into());
            }

            if !config.allowAnyCalls || !config.allowedCalls.is_empty() {
                return Err(AccountKeychainError::invalid_call_scope().into());
            }

            None
        };

        // Create and store the new key
        let new_key = AuthorizedKey {
            signature_type,
            expiry: config.expiry,
            enforce_limits: config.enforceLimits,
            is_revoked: false,
        };

        self.keys[msg_sender][call.keyId].write(new_key)?;

        let limits = config
            .enforceLimits
            .then_some(config.limits.iter())
            .into_iter()
            .flatten();

        self.apply_key_authorization_restrictions(
            msg_sender,
            call.keyId,
            limits,
            allowed_call_configs,
        )?;

        // Emit event
        self.emit_event(AccountKeychainEvent::KeyAuthorized(
            IAccountKeychain::KeyAuthorized {
                account: msg_sender,
                publicKey: call.keyId,
                signatureType: signature_type,
                expiry: config.expiry,
            },
        ))
    }

    /// Permanently revokes an access key. Once revoked, a key ID can never be re-authorized for
    /// this account, preventing replay of old `KeyAuthorization` signatures.
    ///
    /// # Errors
    /// - `UnauthorizedCaller` — only the main key can authorize/revoke and, for contract
    ///   callers on T2+, `msg.sender` must match `tx.origin`
    /// - `KeyNotFound` — no key registered with this ID
    pub fn revoke_key(&mut self, msg_sender: Address, call: revokeKeyCall) -> Result<()> {
        self.ensure_admin_caller(msg_sender)?;

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

    /// Updates the spending limit for a key-token pair. Can also convert an unlimited key into a
    /// limited one. Delegates to `load_active_key` for existence/revocation/expiry checks.
    ///
    /// # Errors
    /// - `UnauthorizedCaller` — the transaction wasn't signed by the main key, or on T2+
    ///   contract callers where `msg.sender != tx.origin`
    /// - `KeyAlreadyRevoked` — the target key has been permanently revoked
    /// - `KeyNotFound` — no key is registered under the given `keyId`
    /// - `KeyExpired` — the key's expiry is at or before the current block timestamp
    pub fn update_spending_limit(
        &mut self,
        msg_sender: Address,
        call: updateSpendingLimitCall,
    ) -> Result<()> {
        self.ensure_admin_caller(msg_sender)?;

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let mut key = self.load_active_key(msg_sender, call.keyId, current_timestamp)?;

        // If this key had unlimited spending (enforce_limits=false), enable limits now
        if !key.enforce_limits {
            key.enforce_limits = true;
            self.keys[msg_sender][call.keyId].write(key)?;
        }

        // Update the spending limit
        let limit_key = Self::spending_limit_key(msg_sender, call.keyId);
        if self.storage.spec().is_t3() {
            // T3: newLimit updates both the configured cap and current remaining amount,
            // while preserving period + period_end.
            let mut limit_state = self.spending_limits[limit_key][call.token].read()?;
            limit_state.remaining = call.newLimit;
            limit_state.max = Self::t3_spending_limit_cap(call.newLimit)?;
            self.spending_limits[limit_key][call.token].write(limit_state)?;
        } else {
            self.spending_limits[limit_key][call.token]
                .remaining
                .write(call.newLimit)?;
        }

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

    /// Returns key info for the given account-key pair, or a blank entry if inexistent or revoked.
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

    /// Returns the remaining spending limit for a key-token pair.
    ///
    /// T2+ returns zero for missing, revoked, or expired keys. Pre-T2 preserves the historical
    /// behavior of reading the raw stored remaining amount so old blocks reexecute identically.
    pub fn get_remaining_limit(&self, call: getRemainingLimitCall) -> Result<U256> {
        if !self.storage.spec().is_t2() {
            let limit_key = Self::spending_limit_key(call.account, call.keyId);
            return self.spending_limits[limit_key][call.token].remaining.read();
        }

        self.get_remaining_limit_with_period(getRemainingLimitWithPeriodCall {
            account: call.account,
            keyId: call.keyId,
            token: call.token,
        })
        .map(|ret| ret.remaining)
    }

    /// Returns the remaining spending limit together with the active period end timestamp.
    ///
    /// Missing, revoked, or expired keys report zeroed values instead of erroring.
    pub fn get_remaining_limit_with_period(
        &self,
        call: getRemainingLimitWithPeriodCall,
    ) -> Result<getRemainingLimitReturn> {
        let (remaining, period_end) = self.effective_limit_state(
            call.account,
            call.keyId,
            call.token,
            self.storage.timestamp().saturating_to::<u64>(),
        )?;

        Ok(getRemainingLimitReturn {
            remaining,
            periodEnd: period_end,
        })
    }

    /// Root-only create-or-replace updates for one or more target call scopes.
    pub fn set_allowed_calls(
        &mut self,
        msg_sender: Address,
        call: setAllowedCallsCall,
    ) -> Result<()> {
        if !self.storage.spec().is_t3() {
            return Err(AccountKeychainError::invalid_call_scope().into());
        }

        self.ensure_admin_caller(msg_sender)?;

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        self.load_active_key(msg_sender, call.keyId, current_timestamp)?;

        let key_hash = Self::spending_limit_key(msg_sender, call.keyId);
        let scopes = call.scopes;

        if scopes.is_empty() {
            return Err(AccountKeychainError::invalid_call_scope().into());
        }

        let mut seen_targets = HashSet::with_capacity(scopes.len());
        for scope in &scopes {
            if !seen_targets.insert(scope.target) {
                return Err(AccountKeychainError::invalid_call_scope().into());
            }
        }

        for scope in &scopes {
            self.upsert_target_scope(key_hash, scope)?;
        }

        self.key_scopes[key_hash].is_scoped.write(true)
    }

    /// Root-only removal of one target call scope.
    pub fn remove_allowed_calls(
        &mut self,
        msg_sender: Address,
        call: removeAllowedCallsCall,
    ) -> Result<()> {
        self.ensure_admin_caller(msg_sender)?;

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        self.load_active_key(msg_sender, call.keyId, current_timestamp)?;

        let key_hash = Self::spending_limit_key(msg_sender, call.keyId);
        let current_mode = self.key_scopes[key_hash].is_scoped.read()?;
        if !current_mode {
            return Ok(());
        }

        self.remove_target_scope(key_hash, call.target)?;

        Ok(())
    }

    /// Returns whether an account key is call-scoped together with its configured call scopes.
    ///
    /// `isScoped = false` means unrestricted. `isScoped = true` with an empty `scopes` vec means
    /// the key is scoped but currently allows no targets. Missing, revoked, or expired access
    /// keys also report scoped deny-all so this getter never exposes stale persisted scope state.
    pub fn get_allowed_calls(&self, call: getAllowedCallsCall) -> Result<getAllowedCallsReturn> {
        if call.keyId.is_zero() {
            return Ok(getAllowedCallsReturn {
                isScoped: false,
                scopes: Vec::new(),
            });
        }

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let key = self.keys[call.account][call.keyId].read()?;
        if key.expiry == 0 || key.is_revoked || current_timestamp >= key.expiry {
            return Ok(getAllowedCallsReturn {
                isScoped: true,
                scopes: Vec::new(),
            });
        }

        let key_hash = Self::spending_limit_key(call.account, call.keyId);
        let is_scoped = self.key_scopes[key_hash].is_scoped.read()?;

        if !is_scoped {
            return Ok(getAllowedCallsReturn {
                isScoped: false,
                scopes: Vec::new(),
            });
        }

        let targets = self.key_scopes[key_hash].targets.read()?;
        let mut scopes = Vec::new();
        for target in targets {
            let selectors = self.key_scopes[key_hash].target_scopes[target]
                .selectors
                .read()?;

            let scope = if selectors.is_empty() {
                CallScope {
                    target,
                    selectorRules: Vec::new(),
                }
            } else {
                let mut rules = Vec::new();

                for selector in selectors {
                    let recipients: Vec<Address> = self.key_scopes[key_hash].target_scopes[target]
                        .selector_scopes[selector]
                        .recipients
                        .read()?
                        .into();

                    rules.push(SelectorRule {
                        selector,
                        recipients,
                    });
                }

                CallScope {
                    target,
                    selectorRules: rules,
                }
            };

            scopes.push(scope);
        }

        Ok(getAllowedCallsReturn {
            isScoped: true,
            scopes,
        })
    }

    /// Returns the access key used to authorize the current transaction (`Address::ZERO` = root key).
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

    /// Persists the authorization-time restrictions for a freshly created key.
    ///
    /// T0-T2 only store raw spending limits. T3 additionally seeds periodic metadata and replaces
    /// the key's call-scope tree in one pass.
    fn apply_key_authorization_restrictions<'a>(
        &mut self,
        account: Address,
        key_id: Address,
        limits: impl IntoIterator<Item = &'a TokenLimit>,
        allowed_calls: Option<&[CallScope]>,
    ) -> Result<()> {
        let limit_key = Self::spending_limit_key(account, key_id);

        let is_t3 = self.storage.spec().is_t3();
        debug_assert!(is_t3 || allowed_calls.is_none());

        let now = self.storage.timestamp().saturating_to::<u64>();
        for limit in limits {
            if is_t3 {
                let period_end = if limit.period == 0 {
                    0
                } else {
                    now.saturating_add(limit.period)
                };

                self.spending_limits[limit_key][limit.token].write(SpendingLimitState {
                    remaining: limit.amount,
                    max: Self::t3_spending_limit_cap(limit.amount)?,
                    period: limit.period,
                    period_end,
                })?;
            } else {
                self.spending_limits[limit_key][limit.token]
                    .remaining
                    .write(limit.amount)?;
            }
        }

        if !is_t3 {
            return Ok(());
        }

        self.replace_allowed_calls(limit_key, allowed_calls)
    }

    /// Validates a top-level call against scoped permissions for this key.
    ///
    /// Validation walks the scope tree from coarse to fine:
    /// - `is_scoped = false` => unrestricted key
    /// - target missing from `targets` => target denied
    /// - target present with `selectors = []` => allow any selector on that target
    /// - selector missing from `selectors` => selector denied
    /// - selector present with `recipients = []` => allow any recipient for that selector
    pub fn validate_call_scope_for_transaction(
        &self,
        account: Address,
        key_id: Address,
        to: &TxKind,
        input: &[u8],
    ) -> Result<()> {
        if key_id == Address::ZERO || !self.storage.spec().is_t3() {
            return Ok(());
        }

        let target = match to {
            TxKind::Call(target) => *target,
            TxKind::Create => return Err(AccountKeychainError::call_not_allowed().into()),
        };

        let key_hash = Self::spending_limit_key(account, key_id);

        // Key-level scoped flag decides whether this CALL must match the stored scope tree.
        if !self.key_scopes[key_hash].is_scoped.read()? {
            return Ok(());
        }

        if !self.key_scopes[key_hash].targets.contains(&target)? {
            return Err(AccountKeychainError::call_not_allowed().into());
        }

        // Empty child sets mean "no further restriction" once the parent target was explicitly
        // allowed, so a present target with `selectors = []` allows any selector.
        let target_is_unconstrained = self.key_scopes[key_hash].target_scopes[target]
            .selectors
            .is_empty()?;
        if target_is_unconstrained {
            return Ok(());
        }

        if input.len() < 4 {
            return Err(AccountKeychainError::call_not_allowed().into());
        }

        // Scoped targets next match on the 4-byte selector.
        let selector = FixedBytes::<4>::from(
            <[u8; 4]>::try_from(&input[..4]).expect("input len checked above"),
        );
        if !self.key_scopes[key_hash].target_scopes[target]
            .selectors
            .contains(&selector)?
        {
            return Err(AccountKeychainError::call_not_allowed().into());
        }

        // Likewise, a present selector with `recipients = []` means any recipient is allowed.
        let selector_is_unconstrained = self.key_scopes[key_hash].target_scopes[target]
            .selector_scopes[selector]
            .recipients
            .is_empty()?;
        if selector_is_unconstrained {
            return Ok(());
        }

        if input.len() < 36 {
            return Err(AccountKeychainError::call_not_allowed().into());
        }

        // Recipient-constrained selectors only permit ABI-encoded address arguments.
        let recipient_word = &input[4..36];
        if recipient_word[..12].iter().any(|byte| *byte != 0) {
            return Err(AccountKeychainError::call_not_allowed().into());
        }

        let recipient = Address::from_slice(&recipient_word[12..]);
        if self.key_scopes[key_hash].target_scopes[target].selector_scopes[selector]
            .recipients
            .contains(&recipient)?
        {
            Ok(())
        } else {
            Err(AccountKeychainError::call_not_allowed().into())
        }
    }

    /// Replaces the full call-scope tree for an account key.
    ///
    /// `None` switches the key back to unrestricted mode, while `Some([])` preserves scoped mode
    /// with no targets so reads can distinguish scoped deny-all from unrestricted mode. This is
    /// the only place where an empty top-level list means deny-all; below the key level, empty
    /// child sets mean "no further restriction".
    fn replace_allowed_calls(
        &mut self,
        account_key: B256,
        allowed_calls: Option<&[CallScope]>,
    ) -> Result<()> {
        // Fresh authorizations should not have any pre-existing call-scope rows because
        // `authorize_key` rejects both existing and previously revoked keys before reaching this
        // path. We still clear the scope tree first as a defense-in-depth measure against stale or
        // out-of-band state, and keep it because the valid-path cost is low (empty target set).
        self.clear_all_target_scopes(account_key)?;

        match allowed_calls {
            None => {
                self.key_scopes[account_key].is_scoped.write(false)?;
                Ok(())
            }
            Some(scopes) => {
                self.key_scopes[account_key].is_scoped.write(true)?;

                if scopes.is_empty() {
                    return Ok(());
                }

                let mut seen_targets = HashSet::new();
                for scope in scopes {
                    if !seen_targets.insert(scope.target) {
                        return Err(AccountKeychainError::invalid_call_scope().into());
                    }
                }

                for scope in scopes {
                    self.upsert_target_scope(account_key, scope)?;
                }

                Ok(())
            }
        }
    }

    /// Deletes every persisted target scope under an account key.
    fn clear_all_target_scopes(&mut self, account_key: B256) -> Result<()> {
        let targets = self.key_scopes[account_key].targets.read()?;
        for target in targets {
            self.clear_target_selectors(account_key, target)?;
        }

        self.key_scopes[account_key].targets.delete()
    }

    /// Deletes one target scope and all nested selector/recipient rows beneath it.
    fn remove_target_scope(&mut self, account_key: B256, target: Address) -> Result<()> {
        if !self.key_scopes[account_key].targets.remove(&target)? {
            return Ok(());
        }

        self.clear_target_selectors(account_key, target)
    }

    /// Clears every selector scope stored under one target.
    fn clear_target_selectors(&mut self, account_key: B256, target: Address) -> Result<()> {
        let selectors = self.key_scopes[account_key].target_scopes[target]
            .selectors
            .read()?;
        for selector in selectors {
            self.key_scopes[account_key].target_scopes[target].selector_scopes[selector]
                .recipients
                .delete()?;
        }

        self.key_scopes[account_key].target_scopes[target]
            .selectors
            .delete()
    }

    /// Creates or replaces one target scope, including all nested selector rules.
    fn upsert_target_scope(&mut self, account_key: B256, scope: &CallScope) -> Result<()> {
        let target = scope.target;

        // The public API uses the absence of a target to block it, so persisting address(0) as a
        // real target is always confusing and serves no useful purpose.
        if target.is_zero() {
            return Err(AccountKeychainError::invalid_call_scope().into());
        }

        if !scope.selectorRules.is_empty() {
            self.validate_selector_rules(target, &scope.selectorRules)?;
        }

        self.key_scopes[account_key].targets.insert(target)?;
        self.clear_target_selectors(account_key, target)?;

        if scope.selectorRules.is_empty() {
            // Keeping the target while clearing nested selector rows intentionally widens this
            // target to allow-all selectors. Future incremental remove APIs must delete the target
            // instead of leaving `selectors = []` behind accidentally.
            return Ok(());
        }

        for rule in &scope.selectorRules {
            let selector = rule.selector;
            self.key_scopes[account_key].target_scopes[target]
                .selectors
                .insert(selector)?;

            if rule.recipients.is_empty() {
                self.key_scopes[account_key].target_scopes[target].selector_scopes[selector]
                    .recipients
                    .delete()?;
            } else {
                // `validate_selector_rules` already rejected duplicates.
                self.key_scopes[account_key].target_scopes[target].selector_scopes[selector]
                    .recipients
                    .write(Set::new_unchecked(rule.recipients.clone()))?;
            }
        }

        Ok(())
    }

    /// Validates per-selector scope rules for one target before they are persisted.
    ///
    /// `recipients = []` is an explicit allow-all sentinel at the selector level. To deny a
    /// selector entirely, omit it from `selectorRules` or remove the target scope instead of
    /// leaving behind an empty child set via incremental mutation.
    fn validate_selector_rules(&self, target: Address, rules: &[SelectorRule]) -> Result<()> {
        let mut cached_is_tip20: Option<bool> = None;
        let mut is_tip20 = || -> Result<bool> {
            match cached_is_tip20 {
                Some(v) => Ok(v),
                None => Ok(*cached_is_tip20.insert(TIP20Factory::new().is_tip20(target)?)),
            }
        };

        let mut selectors = HashSet::new();
        for rule in rules {
            if !selectors.insert(rule.selector) {
                return Err(AccountKeychainError::invalid_call_scope().into());
            }

            if rule.recipients.is_empty() {
                continue;
            }

            if !is_constrained_tip20_selector(*rule.selector) || !is_tip20()? {
                return Err(AccountKeychainError::invalid_call_scope().into());
            }

            let mut unique_recipients = HashSet::new();
            for recipient in &rule.recipients {
                if recipient.is_zero() || !unique_recipients.insert(*recipient) {
                    return Err(AccountKeychainError::invalid_call_scope().into());
                }
            }
        }

        Ok(())
    }

    /// Ensures admin operations are authorized for this caller.
    ///
    /// Rules:
    /// - transaction must be signed by the main key (`transaction_key == Address::ZERO`)
    /// - T2+: caller must match tx.origin
    ///
    /// # Errors
    /// - `UnauthorizedCaller` when called via an access key
    /// - `UnauthorizedCaller` on T2+ when `msg.sender != tx.origin`
    /// - storage read errors from transient key/origin or account metadata lookups
    ///
    /// The T2 check prevents transaction-global root-key status from being reused by
    /// intermediate contracts (confused-deputy self-administration).
    ///
    /// `tx_origin` is seeded by the handler before validation/execution.
    /// If origin is not seeded (zero), admin ops are rejected.
    fn ensure_admin_caller(&self, msg_sender: Address) -> Result<()> {
        if !self.transaction_key.t_read()?.is_zero() {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        if self.storage.spec().is_t2() {
            let tx_origin = self.tx_origin.t_read()?;
            if tx_origin.is_zero() || tx_origin != msg_sender {
                return Err(AccountKeychainError::unauthorized_caller().into());
            }
        }

        Ok(())
    }

    /// Load and validate a key exists, is not revoked, and is not expired.
    ///
    /// Returns the key if valid, or an error if:
    /// - Key doesn't exist (expiry == 0)
    /// - Key has been revoked
    /// - Key has expired at or before `current_timestamp`
    fn load_active_key(
        &self,
        account: Address,
        key_id: Address,
        current_timestamp: u64,
    ) -> Result<AuthorizedKey> {
        let key = self.keys[account][key_id].read()?;

        if key.is_revoked {
            return Err(AccountKeychainError::key_already_revoked().into());
        }

        if key.expiry == 0 {
            return Err(AccountKeychainError::key_not_found().into());
        }

        if current_timestamp >= key.expiry {
            return Err(AccountKeychainError::key_expired().into());
        }

        Ok(key)
    }

    /// Validate keychain authorization (existence, revocation, expiry, and optionally signature type).
    ///
    /// # Arguments
    /// * `account` - The account that owns the key
    /// * `key_id` - The key identifier to validate
    /// * `current_timestamp` - Current block timestamp for expiry check
    /// * `expected_sig_type` - The signature type from the actual signature (0=Secp256k1, 1=P256,
    ///   2=WebAuthn). Pass `None` to skip validation (for backward compatibility pre-T1).
    ///
    /// # Errors
    /// - `KeyAlreadyRevoked` — the key has been permanently revoked
    /// - `KeyNotFound` — no key is registered under the given `key_id`
    /// - `KeyExpired` — `current_timestamp` is at or past the key's expiry
    /// - `SignatureTypeMismatch` — the key's stored type differs from `expected_sig_type`
    pub fn validate_keychain_authorization(
        &self,
        account: Address,
        key_id: Address,
        current_timestamp: u64,
        expected_sig_type: Option<u8>,
    ) -> Result<AuthorizedKey> {
        let key = self.load_active_key(account, key_id, current_timestamp)?;

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

        Ok(key)
    }

    /// Computes the effective remaining limit at `current_timestamp` without mutating storage.
    pub fn effective_remaining_limit(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
        current_timestamp: u64,
    ) -> Result<U256> {
        self.effective_limit_state(account, key_id, token, current_timestamp)
            .map(|(remaining, _)| remaining)
    }

    /// Computes the effective remaining limit and period end at `current_timestamp`
    /// without mutating storage.
    fn effective_limit_state(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
        current_timestamp: u64,
    ) -> Result<(U256, u64)> {
        if key_id.is_zero() && self.storage.spec().is_t3() {
            return Ok((U256::ZERO, 0));
        }

        let key = self.keys[account][key_id].read()?;
        // Missing keys deserialize with `expiry = 0`, so the expiry check covers both nonexistent
        // and expired keys here.
        if key.is_revoked || current_timestamp >= key.expiry {
            return Ok((U256::ZERO, 0));
        }

        let limit_key = Self::spending_limit_key(account, key_id);
        let remaining = self.spending_limits[limit_key][token].remaining.read()?;

        if !self.storage.spec().is_t3() {
            return Ok((remaining, 0));
        }

        let period = self.spending_limits[limit_key][token].period.read()?;
        if period == 0 {
            return Ok((remaining, 0));
        }

        let period_end = self.spending_limits[limit_key][token].period_end.read()?;
        if current_timestamp < period_end {
            return Ok((remaining, period_end));
        }

        let elapsed = current_timestamp.saturating_sub(period_end);
        let periods_elapsed = (elapsed / period).saturating_add(1);
        let advance = period.saturating_mul(periods_elapsed);
        let next_end = period_end.saturating_add(advance);

        let max = self.spending_limits[limit_key][token].max.read()?;

        Ok((U256::from(max), next_end))
    }

    /// Deducts `amount` from the key's remaining spending limit for `token`, failing if exceeded.
    ///
    /// # Errors
    /// - `KeyAlreadyRevoked` — the key has been permanently revoked
    /// - `KeyNotFound` — no key is registered under the given `key_id`
    /// - `SpendingLimitExceeded` — `amount` exceeds the key's remaining limit for `token`
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
        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let key = self.load_active_key(account, key_id, current_timestamp)?;

        // If enforce_limits is false, this key has unlimited spending
        if !key.enforce_limits {
            return Ok(());
        }

        // Check and update spending limit
        let limit_key = Self::spending_limit_key(account, key_id);
        if !self.storage.spec().is_t3() {
            let remaining = self.spending_limits[limit_key][token].remaining.read()?;
            if amount > remaining {
                return Err(AccountKeychainError::spending_limit_exceeded().into());
            }

            let new_remaining = remaining - amount;
            self.spending_limits[limit_key][token]
                .remaining
                .write(new_remaining)?;
            return Ok(());
        }

        let mut limit_state = self.spending_limits[limit_key][token].read()?;
        let mut remaining = limit_state.remaining;
        let is_periodic = limit_state.period != 0;

        if is_periodic && current_timestamp >= limit_state.period_end {
            let next_end = limit_state.compute_next_period_end(current_timestamp);

            remaining = U256::from(limit_state.max);
            limit_state.remaining = remaining;
            limit_state.period_end = next_end;
        }

        if amount > remaining {
            return Err(AccountKeychainError::spending_limit_exceeded().into());
        }

        // Update remaining limit
        let new_remaining = remaining - amount;
        if is_periodic {
            limit_state.remaining = new_remaining;
            self.spending_limits[limit_key][token].write(limit_state)?;
        } else {
            self.spending_limits[limit_key][token]
                .remaining
                .write(new_remaining)?;
        }

        self.emit_event(AccountKeychainEvent::AccessKeySpend(
            IAccountKeychain::AccessKeySpend {
                account,
                publicKey: key_id,
                token,
                amount,
                remainingLimit: new_remaining,
            },
        ))?;

        Ok(())
    }

    /// Refund spending limit after a fee refund.
    ///
    /// Restores the spending limit by the refunded amount.
    /// Should be called after a fee refund to avoid permanently reducing the spending limit.
    /// On T3, this should never restore more than the configured max in the current fee flow,
    /// but we still clamp as defense in depth in case a future caller violates that invariant.
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
        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let key = match self.load_active_key(account, transaction_key, current_timestamp) {
            Ok(key) => key,
            Err(_) => return Ok(()),
        };

        if !key.enforce_limits {
            return Ok(());
        }

        let limit_key = Self::spending_limit_key(account, transaction_key);
        if !self.storage.spec().is_t3() {
            let remaining = self.spending_limits[limit_key][token].remaining.read()?;
            let refunded = remaining.saturating_add(amount);
            return self.spending_limits[limit_key][token]
                .remaining
                .write(refunded);
        }

        let mut limit_state = self.spending_limits[limit_key][token].read()?;
        let refunded = limit_state.remaining.saturating_add(amount);
        // Legacy pre-T3 rows only persisted `remaining`, so migrated keys deserialize with
        // `max = 0`. Preserve that legacy behavior and only clamp rows that were configured
        // with a real T3 max.
        limit_state.remaining = if limit_state.max == 0 {
            refunded
        } else {
            refunded.min(U256::from(limit_state.max))
        };

        self.spending_limits[limit_key][token].write(limit_state)
    }

    /// Authorize a token transfer with access key spending limits.
    ///
    /// This method checks if the transaction is using an access key, and if so,
    /// verifies and updates the spending limits for that key.
    /// Should be called before executing a transfer.
    ///
    /// # Errors
    /// - `KeyAlreadyRevoked` — the session key has been permanently revoked
    /// - `KeyNotFound` — no key is registered for the current transaction key
    /// - `SpendingLimitExceeded` — `amount` exceeds the key's remaining limit for `token`
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

    /// Authorize a token approval with access key spending limits.
    ///
    /// This method checks if the transaction is using an access key, and if so,
    /// verifies and updates the spending limits for that key.
    /// Should be called before executing an approval.
    ///
    /// # Errors
    /// - `KeyAlreadyRevoked` — the session key has been permanently revoked
    /// - `KeyNotFound` — no key is registered for the current transaction key
    /// - `SpendingLimitExceeded` — the approval increase exceeds the remaining limit for `token`
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
        test_util::TIP20Setup,
    };
    use alloy::primitives::{Address, TxKind, U256};
    use revm::state::Bytecode;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, IAccountKeychain::SignatureType};

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

    fn assert_call_not_allowed(error: TempoPrecompileError) {
        match error {
            TempoPrecompileError::AccountKeychainError(e) => {
                assert!(
                    matches!(e, AccountKeychainError::CallNotAllowed(_)),
                    "Expected CallNotAllowed error, got: {e:?}"
                );
            }
            _ => panic!("Expected AccountKeychainError, got: {error:?}"),
        }
    }

    fn assert_invalid_call_scope(error: TempoPrecompileError) {
        match error {
            TempoPrecompileError::AccountKeychainError(e) => {
                assert!(
                    matches!(e, AccountKeychainError::InvalidCallScope(_)),
                    "Expected InvalidCallScope error, got: {e:?}"
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
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(msg_sender, setup_call)?;

            // Now set transaction key to non-zero (simulating access key usage)
            keychain.set_transaction_key(access_key)?;

            // Test 1: authorize_key should fail with access key
            let auth_call = authorizeKeyCall {
                keyId: other,
                signatureType: SignatureType::P256,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
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
    fn test_admin_operations_require_tx_origin_on_t2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let tx_origin = Address::random();
        let delegated_sender = Address::random();
        let existing_key = Address::random();
        let token = Address::random();
        let other = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Mark delegated sender as a contract account to model the confused-deputy path.
            keychain
                .storage
                .set_code(delegated_sender, Bytecode::new_raw(vec![0x60, 0x00].into()))?;

            // Setup a key for delegated_sender under a direct-root call.
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(delegated_sender)?;
            keychain.authorize_key(
                delegated_sender,
                authorizeKeyCall {
                    keyId: existing_key,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            // Simulate a contract-mediated call where tx.origin != msg.sender.
            keychain.set_tx_origin(tx_origin)?;

            let auth_result = keychain.authorize_key(
                delegated_sender,
                authorizeKeyCall {
                    keyId: other,
                    signatureType: SignatureType::P256,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            );
            assert!(auth_result.is_err());
            assert_unauthorized_error(auth_result.unwrap_err());

            let revoke_result = keychain.revoke_key(
                delegated_sender,
                revokeKeyCall {
                    keyId: existing_key,
                },
            );
            assert!(revoke_result.is_err());
            assert_unauthorized_error(revoke_result.unwrap_err());

            let update_result = keychain.update_spending_limit(
                delegated_sender,
                updateSpendingLimitCall {
                    keyId: existing_key,
                    token,
                    newLimit: U256::from(1000),
                },
            );
            assert!(update_result.is_err());
            assert_unauthorized_error(update_result.unwrap_err());

            Ok(())
        })
    }

    #[test]
    fn test_admin_operations_allow_contract_origin_on_t2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let contract_sender = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain
                .storage
                .set_code(contract_sender, Bytecode::new_raw(vec![0x60, 0x00].into()))?;

            // On T2, contract callers are allowed for admin operations only when
            // `msg.sender == tx.origin`.
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(contract_sender)?;

            keychain.authorize_key(
                contract_sender,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100),
                            period: 0,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            keychain.update_spending_limit(
                contract_sender,
                updateSpendingLimitCall {
                    keyId: key_id,
                    token,
                    newLimit: U256::from(200),
                },
            )?;

            assert_eq!(
                keychain.get_remaining_limit(getRemainingLimitCall {
                    account: contract_sender,
                    keyId: key_id,
                    token,
                })?,
                U256::from(200)
            );

            keychain.revoke_key(contract_sender, revokeKeyCall { keyId: key_id })?;

            let key_info = keychain.get_key(getKeyCall {
                account: contract_sender,
                keyId: key_id,
            })?;
            assert!(key_info.isRevoked);

            Ok(())
        })
    }

    #[test]
    fn test_admin_operations_allow_origin_mismatch_pre_t2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let msg_sender = Address::random();
        let other_origin = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Pre-T2, admin operations do not enforce msg.sender == tx.origin.
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(other_origin)?;

            keychain.authorize_key(
                msg_sender,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100),
                            period: 0,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            keychain.update_spending_limit(
                msg_sender,
                updateSpendingLimitCall {
                    keyId: key_id,
                    token,
                    newLimit: U256::from(200),
                },
            )?;

            keychain.revoke_key(msg_sender, revokeKeyCall { keyId: key_id })?;

            let key_info = keychain.get_key(getKeyCall {
                account: msg_sender,
                keyId: key_id,
            })?;
            assert!(key_info.isRevoked);

            Ok(())
        })
    }

    #[test]
    fn test_admin_operations_reject_eoa_mismatch_on_t2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let account = Address::random();
        let other_origin = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Setup under matching tx.origin first.
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;
            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100),
                            period: 0,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            // On T2+, admin ops require `msg.sender == tx.origin`.
            keychain.set_tx_origin(other_origin)?;
            let result = keychain.update_spending_limit(
                account,
                updateSpendingLimitCall {
                    keyId: key_id,
                    token,
                    newLimit: U256::from(200),
                },
            );
            assert!(result.is_err());
            assert_unauthorized_error(result.unwrap_err());

            Ok(())
        })
    }

    /// Admin ops on T2 must reject when `tx_origin` is never seeded (zero).
    ///
    /// This catches any execution path that forgets to call `seed_tx_origin`.
    #[test]
    fn test_admin_operations_reject_unseeded_origin_on_t2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let account = Address::random();
        let key_id = Address::random();
        let other_key = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            // Bootstrap: seed origin so we can authorize a key for later revoke/update tests.
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;
            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100),
                            period: 0,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            // Clear tx_origin back to zero — simulates an execution path that
            // never called seed_tx_origin.
            keychain.set_tx_origin(Address::ZERO)?;

            // authorize_key must reject
            let auth_result = keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: other_key,
                    signatureType: SignatureType::P256,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            );
            assert!(
                auth_result.is_err(),
                "authorize_key must reject when tx_origin is not seeded on T2"
            );
            assert_unauthorized_error(auth_result.unwrap_err());

            // revoke_key must reject
            let revoke_result = keychain.revoke_key(account, revokeKeyCall { keyId: key_id });
            assert!(
                revoke_result.is_err(),
                "revoke_key must reject when tx_origin is not seeded on T2"
            );
            assert_unauthorized_error(revoke_result.unwrap_err());

            // update_spending_limit must reject
            let update_result = keychain.update_spending_limit(
                account,
                updateSpendingLimitCall {
                    keyId: key_id,
                    token,
                    newLimit: U256::from(200),
                },
            );
            assert!(
                update_result.is_err(),
                "update_spending_limit must reject when tx_origin is not seeded on T2"
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
            keychain.set_tx_origin(account)?;

            // Step 1: Authorize a key with a spending limit
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![TokenLimit {
                        token,
                        amount: U256::from(100),
                        period: 0,
                    }],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(account, auth_call.clone())?;

            // Verify key exists and limit is set
            let key_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id,
            })?;
            assert_eq!(key_info.expiry, u64::MAX);
            assert!(!key_info.isRevoked);
            assert_eq!(
                keychain.get_remaining_limit(getRemainingLimitCall {
                    account,
                    keyId: key_id,
                    token,
                })?,
                U256::from(100)
            );

            // Step 2: Revoke the key
            let revoke_call = revokeKeyCall { keyId: key_id };
            keychain.revoke_key(account, revoke_call)?;

            // Verify key is revoked and remaining limit returns 0
            let key_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id,
            })?;
            assert_eq!(key_info.expiry, 0);
            assert!(key_info.isRevoked);
            assert_eq!(
                keychain.get_remaining_limit(getRemainingLimitCall {
                    account,
                    keyId: key_id,
                    token,
                })?,
                U256::ZERO
            );

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
                config: KeyRestrictions {
                    expiry: 0, // Zero expiry is in the past - should fail
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
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
                config: KeyRestrictions {
                    expiry: 1, // Very old timestamp - should fail
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
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
    fn test_pre_t3_authorize_key_rejects_tip_1011_fields_without_writing_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            let result = keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100u64),
                            period: 60,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            );

            assert!(
                matches!(
                    result,
                    Err(TempoPrecompileError::AccountKeychainError(
                        AccountKeychainError::InvalidSpendingLimit(_)
                    ))
                ),
                "expected InvalidSpendingLimit, got {result:?}"
            );

            assert_eq!(
                keychain.keys[account][key_id].read()?,
                AuthorizedKey::default(),
                "pre-T3 invalid TIP-1011 fields must not leave behind a key"
            );

            let limit_key = AccountKeychain::spending_limit_key(account, key_id);
            assert_eq!(
                keychain.spending_limits[limit_key][token].read()?,
                SpendingLimitState::default(),
                "pre-T3 invalid TIP-1011 fields must not initialize limits"
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
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(account, auth_call_1)?;

            // Revoke key 1
            keychain.revoke_key(account, revokeKeyCall { keyId: key_id_1 })?;

            // Authorizing a different key (key 2) should still work
            let auth_call_2 = authorizeKeyCall {
                keyId: key_id_2,
                signatureType: SignatureType::P256,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
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
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![TokenLimit {
                        token,
                        amount: U256::from(100),
                        period: 0,
                    }],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
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
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![TokenLimit {
                        token,
                        amount: U256::from(100),
                        period: 0,
                    }],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
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
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: 1, // Minimal positive expiry
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(account, auth_call.clone())?;

            // Verify key exists with expiry = 1
            let key_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id,
            })?;
            assert_eq!(key_info.expiry, 1, "Key should have expiry = 1");

            // Try to re-authorize - should fail because expiry > 0
            let result = keychain.authorize_key(account, auth_call);
            assert!(result.is_err(), "Should reject when key.expiry > 0");
            match result.unwrap_err() {
                TempoPrecompileError::AccountKeychainError(e) => {
                    assert!(
                        matches!(e, AccountKeychainError::KeyAlreadyExists(_)),
                        "Expected KeyAlreadyExists, got: {e:?}"
                    );
                }
                e => panic!("Expected AccountKeychainError, got: {e:?}"),
            }

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
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            // This would fail if initialize didn't set up storage properly
            keychain.authorize_key(account, auth_call)?;

            // Verify key was stored
            let key_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id,
            })?;
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
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::WebAuthn,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(account, auth_call)?;

            // Verify key was stored with WebAuthn type (value = 2)
            let key_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id,
            })?;
            assert_eq!(
                key_info.signatureType,
                SignatureType::WebAuthn,
                "Signature type should be WebAuthn"
            );

            // Verify via validation that signature type 2 is accepted
            let result = keychain.validate_keychain_authorization(account, key_id, 0, Some(2));
            assert!(
                result.is_ok(),
                "WebAuthn (type 2) validation should succeed"
            );

            // Verify signature type mismatch is rejected
            let mismatch = keychain.validate_keychain_authorization(account, key_id, 0, Some(0));
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
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![TokenLimit {
                        token,
                        amount: U256::from(100),
                        period: 0,
                    }],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(account, auth_call)?;

            // Update should work when key is not expired
            let update_call = updateSpendingLimitCall {
                keyId: key_id,
                token,
                newLimit: U256::from(200),
            };
            let result = keychain.update_spending_limit(account, update_call);
            assert!(
                result.is_ok(),
                "Update should succeed when key not expired: {result:?}"
            );

            // Verify the limit was updated
            let limit = keychain.get_remaining_limit(getRemainingLimitCall {
                account,
                keyId: key_id,
                token,
            })?;
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
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false, // Initially no limits
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(account, auth_call)?;

            // Verify key has enforce_limits = false
            let key_before = keychain.get_key(getKeyCall {
                account,
                keyId: key_id,
            })?;
            assert!(
                !key_before.enforceLimits,
                "Key should start with enforce_limits=false"
            );

            // Update spending limit - this should toggle enforce_limits to true
            let update_call = updateSpendingLimitCall {
                keyId: key_id,
                token,
                newLimit: U256::from(500),
            };
            keychain.update_spending_limit(account, update_call)?;

            // Verify enforce_limits is now true
            let key_after = keychain.get_key(getKeyCall {
                account,
                keyId: key_id,
            })?;
            assert!(
                key_after.enforceLimits,
                "enforce_limits should be true after update"
            );

            // Verify the spending limit was set
            let limit = keychain.get_remaining_limit(getRemainingLimitCall {
                account,
                keyId: key_id,
                token,
            })?;
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
            let auth_call = authorizeKeyCall {
                keyId: key_id_revoked,
                signatureType: SignatureType::P256,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(account, auth_call)?;
            keychain.revoke_key(
                account,
                revokeKeyCall {
                    keyId: key_id_revoked,
                },
            )?;

            // Setup: Create a valid key
            let auth_valid = authorizeKeyCall {
                keyId: key_id_valid,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(account, auth_valid)?;

            // Test 1: Revoked key (expiry=0, is_revoked=true) - should return empty with isRevoked=true
            let revoked_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id_revoked,
            })?;
            assert_eq!(
                revoked_info.keyId,
                Address::ZERO,
                "Revoked key should return zero keyId"
            );
            assert!(
                revoked_info.isRevoked,
                "Revoked key should have isRevoked=true"
            );

            // Test 2: Never existed key (expiry=0, is_revoked=false) - should return empty
            let never_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id_never_existed,
            })?;
            assert_eq!(
                never_info.keyId,
                Address::ZERO,
                "Non-existent key should return zero keyId"
            );
            assert_eq!(
                never_info.expiry, 0,
                "Non-existent key should have expiry=0"
            );

            // Test 3: Valid key (expiry>0, is_revoked=false) - should return actual key info
            let valid_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_id_valid,
            })?;
            assert_eq!(
                valid_info.keyId, key_id_valid,
                "Valid key should return actual keyId"
            );
            assert_eq!(
                valid_info.expiry,
                u64::MAX,
                "Valid key should have correct expiry"
            );
            assert!(!valid_info.isRevoked, "Valid key should not be revoked");

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
                authorizeKeyCall {
                    keyId: key_secp,
                    signatureType: SignatureType::Secp256k1, // type 0
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_p256,
                    signatureType: SignatureType::P256, // type 1
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_webauthn,
                    signatureType: SignatureType::WebAuthn, // type 2
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            // Verify each key returns the correct signature type
            let secp_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_secp,
            })?;
            assert_eq!(
                secp_info.signatureType,
                SignatureType::Secp256k1,
                "Secp256k1 key should return Secp256k1"
            );

            let p256_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_p256,
            })?;
            assert_eq!(
                p256_info.signatureType,
                SignatureType::P256,
                "P256 key should return P256"
            );

            let webauthn_info = keychain.get_key(getKeyCall {
                account,
                keyId: key_webauthn,
            })?;
            assert_eq!(
                webauthn_info.signatureType,
                SignatureType::WebAuthn,
                "WebAuthn key should return WebAuthn"
            );

            // Verify they are all distinct
            assert_ne!(secp_info.signatureType, p256_info.signatureType);
            assert_ne!(secp_info.signatureType, webauthn_info.signatureType);
            assert_ne!(p256_info.signatureType, webauthn_info.signatureType);

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
            let auth_call = authorizeKeyCall {
                keyId: key_id,
                signatureType: SignatureType::P256,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(account, auth_call)?;

            // Test 1: Validation should succeed with matching signature type (P256 = 1)
            let result = keychain.validate_keychain_authorization(account, key_id, 0, Some(1));
            assert!(
                result.is_ok(),
                "Validation should succeed with matching signature type"
            );

            // Test 2: Validation should fail with mismatched signature type (Secp256k1 = 0)
            let mismatch_result =
                keychain.validate_keychain_authorization(account, key_id, 0, Some(0));
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
            let webauthn_mismatch =
                keychain.validate_keychain_authorization(account, key_id, 0, Some(2));
            assert!(
                webauthn_mismatch.is_err(),
                "Validation should fail with WebAuthn when key is P256"
            );

            // Test 4: Validation should succeed with None (backward compatibility, pre-T1)
            let none_result = keychain.validate_keychain_authorization(account, key_id, 0, None);
            assert!(
                none_result.is_ok(),
                "Validation should succeed when signature type check is skipped (pre-T1)"
            );

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

            let auth_call = authorizeKeyCall {
                keyId: access_key,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![TokenLimit {
                        token,
                        amount: U256::from(100),
                        period: 0,
                    }],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(eoa, auth_call)?;

            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa)?;

            keychain.authorize_transfer(eoa, token, U256::from(60))?;

            let remaining = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(remaining, U256::from(40));

            keychain.refund_spending_limit(eoa, token, U256::from(25))?;

            let after_refund = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
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

            let result = keychain.refund_spending_limit(eoa, token, U256::from(50));
            assert!(result.is_ok());

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

            let auth_call = authorizeKeyCall {
                keyId: access_key,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![TokenLimit {
                        token,
                        amount: U256::from(100),
                        period: 0,
                    }],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(eoa, auth_call)?;

            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa)?;

            keychain.authorize_transfer(eoa, token, U256::from(60))?;

            let remaining = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(remaining, U256::from(40));

            keychain.set_transaction_key(Address::ZERO)?;
            keychain.revoke_key(eoa, revokeKeyCall { keyId: access_key })?;

            keychain.set_transaction_key(access_key)?;

            let result = keychain.refund_spending_limit(eoa, token, U256::from(25));
            assert!(result.is_ok());

            let after_refund = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(
                after_refund,
                U256::from(40),
                "limit should be unchanged after revoked key refund"
            );

            Ok(())
        })
    }

    #[test]
    fn test_refund_spending_limit_noop_after_key_expiry() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let eoa = Address::random();
        let access_key = Address::random();
        let token = Address::random();

        storage.set_timestamp(U256::from(100u64));
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain.set_transaction_key(Address::ZERO)?;

            let auth_call = authorizeKeyCall {
                keyId: access_key,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: 200,
                    enforceLimits: true,
                    limits: vec![TokenLimit {
                        token,
                        amount: U256::from(100),
                        period: 0,
                    }],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(eoa, auth_call)?;

            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa)?;
            keychain.authorize_transfer(eoa, token, U256::from(60))?;

            Ok::<_, eyre::Report>(())
        })?;

        storage.set_timestamp(U256::from(200u64));
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa)?;

            let result = keychain.refund_spending_limit(eoa, token, U256::from(25));
            assert!(result.is_ok());

            let after_refund = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(
                after_refund,
                U256::from(40),
                "limit should be unchanged after expired key refund"
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

            let auth_call = authorizeKeyCall {
                keyId: access_key,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![TokenLimit {
                        token,
                        amount: original_limit,
                        period: 0,
                    }],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(eoa, auth_call)?;

            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa)?;

            keychain.authorize_transfer(eoa, token, U256::from(10))?;

            let remaining = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(remaining, U256::from(90));

            keychain.refund_spending_limit(eoa, token, U256::from(50))?;

            let after_refund = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(
                after_refund,
                U256::from(140),
                "saturating_add should allow refund beyond original limit without overflow"
            );

            Ok(())
        })
    }

    #[test]
    fn test_t3_refund_spending_limit_clamps_to_max() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let eoa = Address::random();
        let access_key = Address::random();
        let token = Address::random();
        let original_limit = U256::from(100);

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(eoa)?;

            let auth_call = authorizeKeyCall {
                keyId: access_key,
                signatureType: SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![TokenLimit {
                        token,
                        amount: original_limit,
                        period: 0,
                    }],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            };
            keychain.authorize_key(eoa, auth_call)?;

            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa)?;

            keychain.authorize_transfer(eoa, token, U256::from(60))?;
            keychain.refund_spending_limit(eoa, token, U256::from(30))?;

            let after_partial_refund = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(
                after_partial_refund,
                U256::from(70),
                "refund should restore the spent amount without forcing the max"
            );

            keychain.refund_spending_limit(eoa, token, U256::from(50))?;

            let after_refund = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(
                after_refund, original_limit,
                "refund should not restore more than the configured max"
            );

            Ok(())
        })
    }

    #[test]
    fn test_t3_refund_spending_limit_preserves_legacy_rows_without_max() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let eoa = Address::random();
        let access_key = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let limit_key = AccountKeychain::spending_limit_key(eoa, access_key);
            keychain.keys[eoa][access_key].write(AuthorizedKey {
                signature_type: SignatureType::Secp256k1 as u8,
                expiry: u64::MAX,
                enforce_limits: true,
                is_revoked: false,
            })?;
            keychain.spending_limits[limit_key][token].write(SpendingLimitState {
                remaining: U256::from(90),
                max: 0,
                period: 0,
                period_end: 0,
            })?;

            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(eoa)?;
            keychain.refund_spending_limit(eoa, token, U256::from(10))?;

            let after_refund = keychain.get_remaining_limit(getRemainingLimitCall {
                account: eoa,
                keyId: access_key,
                token,
            })?;
            assert_eq!(
                after_refund,
                U256::from(100),
                "migrated pre-T3 rows should keep legacy saturating-add refund semantics"
            );

            Ok(())
        })
    }

    #[test]
    fn test_t3_authorize_key_ignores_limits_when_enforce_limits_false() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100),
                            period: 60,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            let limit_key = AccountKeychain::spending_limit_key(account, key_id);
            assert_eq!(
                keychain.spending_limits[limit_key][token].read()?,
                SpendingLimitState::default()
            );

            let remaining =
                keychain.get_remaining_limit_with_period(getRemainingLimitWithPeriodCall {
                    account,
                    keyId: key_id,
                    token,
                })?;
            assert_eq!(remaining.remaining, U256::ZERO);
            assert_eq!(remaining.periodEnd, 0);

            Ok(())
        })
    }

    #[test]
    fn test_t3_rejects_spending_limits_above_u128() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let invalid_key_id = Address::random();
        let valid_key_id = Address::random();
        let token = Address::random();
        let oversized_limit = U256::from(u128::MAX) + U256::from(1u8);

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            let authorize_result = keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: invalid_key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: oversized_limit,
                            period: 60,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            );

            assert!(
                matches!(
                    authorize_result,
                    Err(TempoPrecompileError::AccountKeychainError(
                        AccountKeychainError::InvalidSpendingLimit(_)
                    ))
                ),
                "expected InvalidSpendingLimit, got {authorize_result:?}"
            );

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: valid_key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100u64),
                            period: 60,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            let update_result = keychain.update_spending_limit(
                account,
                updateSpendingLimitCall {
                    keyId: valid_key_id,
                    token,
                    newLimit: oversized_limit,
                },
            );

            assert!(
                matches!(
                    update_result,
                    Err(TempoPrecompileError::AccountKeychainError(
                        AccountKeychainError::InvalidSpendingLimit(_)
                    ))
                ),
                "expected InvalidSpendingLimit, got {update_result:?}"
            );

            Ok(())
        })
    }

    #[test]
    fn test_t3_rejects_duplicate_token_limits() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            let result = keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![
                            TokenLimit {
                                token,
                                amount: U256::from(100_u64),
                                period: 0,
                            },
                            TokenLimit {
                                token,
                                amount: U256::from(200_u64),
                                period: 60,
                            },
                        ],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            );

            assert!(
                matches!(
                    result,
                    Err(TempoPrecompileError::AccountKeychainError(
                        AccountKeychainError::InvalidSpendingLimit(_)
                    ))
                ),
                "expected duplicate token limits to be rejected, got: {result:?}"
            );

            let stored_key = keychain.keys[account][key_id].read()?;
            assert_eq!(
                stored_key.expiry, 0,
                "duplicate rejection must not persist the key"
            );

            Ok(())
        })
    }

    #[test]
    fn test_spending_limit_state_preserves_legacy_remaining_slot() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let limit_key = AccountKeychain::spending_limit_key(account, key_id);
            let handler = &mut keychain.spending_limits[limit_key][token];
            let remaining = U256::from(123u64);
            handler.write(SpendingLimitState {
                remaining,
                max: 456,
                period: 60,
                period_end: 120,
            })?;

            assert_eq!(
                StorageCtx.sload(ACCOUNT_KEYCHAIN_ADDRESS, handler.as_slot().slot())?,
                remaining
            );

            Ok(())
        })
    }

    #[test]
    fn test_t3_rejects_recipient_constrained_scope_for_undeployed_tip20() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();
        let recipient = Address::repeat_byte(0x44);
        let mut target_bytes = [0u8; 20];
        target_bytes[0] = 0x20;
        target_bytes[1] = 0xc0;
        target_bytes[19] = 0x42;
        let undeployed_tip20 = Address::from(target_bytes);

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            let err = keychain
                .apply_key_authorization_restrictions(
                    account,
                    key_id,
                    &[],
                    Some(&[CallScope {
                        target: undeployed_tip20,
                        selectorRules: vec![SelectorRule {
                            selector: TIP20_TRANSFER_SELECTOR.into(),
                            recipients: vec![recipient],
                        }],
                    }]),
                )
                .expect_err("unexpected success for undeployed TIP-20 target");

            match err {
                TempoPrecompileError::AccountKeychainError(
                    AccountKeychainError::InvalidCallScope(_),
                ) => {}
                other => panic!("expected InvalidCallScope, got {other:?}"),
            }

            Ok(())
        })
    }

    #[test]
    fn test_t3_periodic_limit_rollover() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        storage.set_timestamp(U256::from(1_000u64));

        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;
            TIP20Setup::path_usd(account).apply()?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100),
                            period: 0,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            keychain.apply_key_authorization_restrictions(
                account,
                key_id,
                &[TokenLimit {
                    token,
                    amount: U256::from(100),
                    period: 60,
                }],
                None,
            )?;

            keychain.set_transaction_key(key_id)?;
            keychain.authorize_transfer(account, token, U256::from(80))?;

            let remaining = keychain.get_remaining_limit(getRemainingLimitCall {
                account,
                keyId: key_id,
                token,
            })?;
            assert_eq!(remaining, U256::from(20));

            Ok::<_, eyre::Report>(())
        })?;

        storage.set_timestamp(U256::from(1_070u64));
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.set_transaction_key(key_id)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_transfer(account, token, U256::from(10))?;

            let remaining = keychain.get_remaining_limit(getRemainingLimitCall {
                account,
                keyId: key_id,
                token,
            })?;
            assert_eq!(remaining, U256::from(90));
            Ok(())
        })
    }

    #[test]
    fn test_t3_get_allowed_calls_distinguishes_unrestricted_and_deny_all() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            let scopes = keychain.get_allowed_calls(getAllowedCallsCall {
                account,
                keyId: key_id,
            })?;
            assert!(!scopes.isScoped);
            assert!(scopes.scopes.is_empty());

            keychain.apply_key_authorization_restrictions(account, key_id, &[], Some(&[]))?;

            let deny_all = keychain.get_allowed_calls(getAllowedCallsCall {
                account,
                keyId: key_id,
            })?;
            assert!(deny_all.isScoped);
            assert!(deny_all.scopes.is_empty());

            Ok(())
        })
    }

    #[test]
    fn test_t3_get_allowed_calls_returns_deny_all_for_inactive_keys() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let revoked_key = Address::random();
        let expiring_key = Address::random();
        let target = DEFAULT_FEE_TOKEN;

        storage.set_timestamp(U256::from(1_000u64));
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            for (key_id, expiry) in [(revoked_key, u64::MAX), (expiring_key, 1_005)] {
                keychain.authorize_key(
                    account,
                    authorizeKeyCall {
                        keyId: key_id,
                        signatureType: SignatureType::Secp256k1,
                        config: KeyRestrictions {
                            expiry,
                            enforceLimits: false,
                            limits: vec![],
                            allowAnyCalls: false,
                            allowedCalls: vec![CallScope {
                                target,
                                selectorRules: vec![],
                            }],
                        },
                    },
                )?;
            }

            keychain.revoke_key(account, revokeKeyCall { keyId: revoked_key })?;

            let revoked = keychain.get_allowed_calls(getAllowedCallsCall {
                account,
                keyId: revoked_key,
            })?;
            assert!(revoked.isScoped);
            assert!(revoked.scopes.is_empty());

            let root = keychain.get_allowed_calls(getAllowedCallsCall {
                account,
                keyId: Address::ZERO,
            })?;
            assert!(!root.isScoped);
            assert!(root.scopes.is_empty());

            Ok::<_, eyre::Report>(())
        })?;

        storage.set_timestamp(U256::from(1_010u64));
        StorageCtx::enter(&mut storage, || {
            let keychain = AccountKeychain::new();

            let expired = keychain.get_allowed_calls(getAllowedCallsCall {
                account,
                keyId: expiring_key,
            })?;
            assert!(expired.isScoped);
            assert!(expired.scopes.is_empty());

            Ok(())
        })
    }

    #[test]
    fn test_t3_expired_key_has_zero_effective_remaining_limit() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        storage.set_timestamp(U256::from(1_000u64));
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: 1_005,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100u64),
                            period: 60,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            Ok::<_, eyre::Report>(())
        })?;

        storage.set_timestamp(U256::from(1_010u64));
        StorageCtx::enter(&mut storage, || {
            let keychain = AccountKeychain::new();

            let remaining =
                keychain.get_remaining_limit_with_period(getRemainingLimitWithPeriodCall {
                    account,
                    keyId: key_id,
                    token,
                })?;
            assert_eq!(remaining.remaining, U256::ZERO);
            assert_eq!(remaining.periodEnd, 0);

            assert_eq!(
                keychain.effective_remaining_limit(account, key_id, token, 1_010)?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_pre_t3_expired_key_has_zero_remaining_limit() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        storage.set_timestamp(U256::from(1_000u64));
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: 1_005,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100u64),
                            period: 0,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            Ok::<_, eyre::Report>(())
        })?;

        storage.set_timestamp(U256::from(1_010u64));
        StorageCtx::enter(&mut storage, || {
            let keychain = AccountKeychain::new();

            assert_eq!(
                keychain.get_remaining_limit(getRemainingLimitCall {
                    account,
                    keyId: key_id,
                    token,
                })?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_pre_t2_expired_key_preserves_raw_remaining_limit() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        storage.set_timestamp(U256::from(1_000u64));
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: 1_005,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token,
                            amount: U256::from(100u64),
                            period: 0,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            Ok::<_, eyre::Report>(())
        })?;

        storage.set_timestamp(U256::from(1_010u64));
        StorageCtx::enter(&mut storage, || {
            let keychain = AccountKeychain::new();

            assert_eq!(
                keychain.get_remaining_limit(getRemainingLimitCall {
                    account,
                    keyId: key_id,
                    token,
                })?,
                U256::from(100u64)
            );

            Ok(())
        })
    }

    #[test]
    fn test_zero_key_remaining_limit_reads_storage_on_t2_but_not_t3() -> eyre::Result<()> {
        let (account, token) = (Address::random(), Address::random());

        for (hardfork, expected_sloads) in [(TempoHardfork::T2, 1_u64), (TempoHardfork::T3, 0)] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            StorageCtx::enter(&mut storage, || {
                let mut keychain = AccountKeychain::new();
                let _ = keychain.initialize();

                let sloads_before = StorageCtx.counter_sload();
                assert_eq!(
                    keychain.get_remaining_limit(getRemainingLimitCall {
                        account,
                        keyId: Address::ZERO,
                        token,
                    })?,
                    U256::ZERO
                );

                assert_eq!(
                    StorageCtx.counter_sload() - sloads_before,
                    expected_sloads,
                    "{hardfork:?} should perform the expected number of storage reads for zero key_id"
                );

                Ok::<_, eyre::Report>(())
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_t3_set_allowed_calls_rejects_zero_target() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            let err = keychain
                .set_allowed_calls(
                    account,
                    setAllowedCallsCall {
                        keyId: key_id,
                        scopes: vec![CallScope {
                            target: Address::ZERO,
                            selectorRules: vec![],
                        }],
                    },
                )
                .expect_err("unexpected success for zero target scope");
            assert_invalid_call_scope(err);

            Ok(())
        })
    }

    #[test]
    fn test_t3_set_allowed_calls_rejects_empty_scope_batch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            let err = keychain
                .set_allowed_calls(
                    account,
                    setAllowedCallsCall {
                        keyId: key_id,
                        scopes: vec![],
                    },
                )
                .expect_err("unexpected success for empty scope batch");
            assert_invalid_call_scope(err);

            let scopes = keychain.get_allowed_calls(getAllowedCallsCall {
                account,
                keyId: key_id,
            })?;
            assert!(!scopes.isScoped);
            assert!(scopes.scopes.is_empty());

            Ok(())
        })
    }

    #[test]
    fn test_t3_set_allowed_calls_roundtrip_and_remove_target_scope() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();
        let target = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            keychain.set_allowed_calls(
                account,
                setAllowedCallsCall {
                    keyId: key_id,
                    scopes: vec![CallScope {
                        target,
                        selectorRules: vec![SelectorRule {
                            selector: TIP20_TRANSFER_SELECTOR.into(),
                            recipients: vec![],
                        }],
                    }],
                },
            )?;

            let scopes = keychain.get_allowed_calls(getAllowedCallsCall {
                account,
                keyId: key_id,
            })?;
            assert!(scopes.isScoped);
            assert_eq!(scopes.scopes.len(), 1);
            assert_eq!(scopes.scopes[0].target, target);
            assert_eq!(scopes.scopes[0].selectorRules.len(), 1);
            assert_eq!(
                *scopes.scopes[0].selectorRules[0].selector,
                TIP20_TRANSFER_SELECTOR
            );
            assert!(scopes.scopes[0].selectorRules[0].recipients.is_empty());

            let allow = keychain.validate_call_scope_for_transaction(
                account,
                key_id,
                &TxKind::Call(target),
                &TIP20_TRANSFER_SELECTOR,
            );
            assert!(allow.is_ok());

            keychain.remove_allowed_calls(
                account,
                removeAllowedCallsCall {
                    keyId: key_id,
                    target,
                },
            )?;

            let removed = keychain.get_allowed_calls(getAllowedCallsCall {
                account,
                keyId: key_id,
            })?;
            assert!(removed.isScoped);
            assert!(removed.scopes.is_empty());

            let denied = keychain
                .validate_call_scope_for_transaction(
                    account,
                    key_id,
                    &TxKind::Call(target),
                    &TIP20_TRANSFER_SELECTOR,
                )
                .expect_err("unexpected success for removed target scope");
            assert_call_not_allowed(denied);

            Ok(())
        })
    }

    #[test]
    fn test_t3_set_allowed_calls_empty_selector_rules_allow_all_selectors() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();
        let target = DEFAULT_FEE_TOKEN;

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            keychain.set_allowed_calls(
                account,
                setAllowedCallsCall {
                    keyId: key_id,
                    scopes: vec![CallScope {
                        target,
                        selectorRules: vec![],
                    }],
                },
            )?;

            let scopes = keychain.get_allowed_calls(getAllowedCallsCall {
                account,
                keyId: key_id,
            })?;
            assert!(scopes.isScoped);
            assert_eq!(scopes.scopes.len(), 1);
            assert_eq!(scopes.scopes[0].target, target);
            assert!(scopes.scopes[0].selectorRules.is_empty());

            let allow = keychain.validate_call_scope_for_transaction(
                account,
                key_id,
                &TxKind::Call(target),
                &[],
            );
            assert!(allow.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_t3_call_scope_selector_and_recipient_checks() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();
        let target = DEFAULT_FEE_TOKEN;
        let allowed_recipient = Address::repeat_byte(0x22);
        let denied_recipient = Address::repeat_byte(0x33);

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;
            TIP20Setup::path_usd(account).apply()?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            keychain.apply_key_authorization_restrictions(
                account,
                key_id,
                &[],
                Some(&[CallScope {
                    target,
                    selectorRules: vec![SelectorRule {
                        selector: TIP20_TRANSFER_SELECTOR.into(),
                        recipients: vec![allowed_recipient],
                    }],
                }]),
            )?;

            let make_calldata = |selector: [u8; 4], recipient: Address| {
                let mut data = selector.to_vec();
                let mut recipient_word = [0u8; 32];
                recipient_word[12..].copy_from_slice(recipient.as_slice());
                data.extend_from_slice(&recipient_word);
                data.extend_from_slice(&[0u8; 32]);
                data
            };

            let allow = keychain.validate_call_scope_for_transaction(
                account,
                key_id,
                &TxKind::Call(target),
                &make_calldata(TIP20_TRANSFER_SELECTOR, allowed_recipient),
            );
            assert!(allow.is_ok());

            let denied = keychain
                .validate_call_scope_for_transaction(
                    account,
                    key_id,
                    &TxKind::Call(target),
                    &make_calldata(TIP20_TRANSFER_SELECTOR, denied_recipient),
                )
                .expect_err("unexpected success for denied recipient");
            assert_call_not_allowed(denied);

            let wrong_selector = keychain
                .validate_call_scope_for_transaction(
                    account,
                    key_id,
                    &TxKind::Call(target),
                    &make_calldata([0xde, 0xad, 0xbe, 0xef], allowed_recipient),
                )
                .expect_err("unexpected success for wrong selector");
            assert_call_not_allowed(wrong_selector);

            Ok(())
        })
    }

    #[test]
    fn test_t3_contract_creation_rejected_for_access_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();
        let key_id = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;

            keychain.authorize_key(
                account,
                authorizeKeyCall {
                    keyId: key_id,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            let err = keychain
                .validate_call_scope_for_transaction(account, key_id, &TxKind::Create, &[])
                .expect_err("unexpected success for CREATE");
            assert_call_not_allowed(err);

            Ok(())
        })
    }
}
