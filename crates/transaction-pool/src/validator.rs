use crate::{
    amm::AmmLiquidityCache,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
};
use std::collections::HashSet;

use alloy_consensus::Transaction;

use alloy_primitives::{Address, U256};
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_primitives_traits::{
    GotExpected, SealedBlock, transaction::error::InvalidTransactionError,
};
use reth_storage_api::{StateProvider, StateProviderFactory, errors::ProviderError};
use reth_transaction_pool::{
    EthTransactionValidator, PoolTransaction, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidator, error::InvalidPoolTransactionError,
};
use revm::context_interface::cfg::GasId;
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
};
use tempo_evm::TempoEvmConfig;
#[cfg(test)]
use tempo_precompiles::account_keychain::{AuthorizedKey, SpendingLimitState};
use tempo_precompiles::{
    account_keychain::{AccountKeychain, is_constrained_tip20_selector},
    nonce::{INonce, NonceManager},
    storage::Handler,
    tip20_factory::TIP20Factory,
};
use tempo_primitives::{
    Block,
    subblock::has_sub_block_nonce_key_prefix,
    transaction::{
        RecoveredTempoAuthorization, TEMPO_EXPIRING_NONCE_KEY,
        TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS, TempoTransaction,
    },
};
use tempo_revm::{
    TempoBatchCallEnv, TempoStateAccess, calculate_aa_batch_intrinsic_gas,
    gas_params::{TempoGasParams, tempo_gas_params},
    handler::EXPIRING_NONCE_GAS,
};

// Reject AA txs where `valid_before` is too close to current time (or already expired) to prevent block invalidation.
const AA_VALID_BEFORE_MIN_SECS: u64 = 3;

/// Default maximum number of authorizations allowed in an AA transaction's authorization list.
pub const DEFAULT_MAX_TEMPO_AUTHORIZATIONS: usize = 16;

/// Maximum number of calls allowed per AA transaction (DoS protection).
pub const MAX_AA_CALLS: usize = 32;

/// Maximum size of input data per call in bytes (128KB, DoS protection).
pub const MAX_CALL_INPUT_SIZE: usize = 128 * 1024;

/// Maximum number of accounts in the access list (DoS protection).
pub const MAX_ACCESS_LIST_ACCOUNTS: usize = 256;

/// Maximum number of storage keys per account in the access list (DoS protection).
pub const MAX_STORAGE_KEYS_PER_ACCOUNT: usize = 256;

/// Maximum total number of storage keys across all accounts in the access list (DoS protection).
pub const MAX_ACCESS_LIST_STORAGE_KEYS_TOTAL: usize = 2048;

/// Maximum number of token limits in a KeyAuthorization (DoS protection).
pub const MAX_TOKEN_LIMITS: usize = 256;

/// Default maximum allowed `valid_after` offset for AA txs (in seconds).
///
/// Aligned with the default queued transaction lifetime (`max_queued_lifetime = 120s`)
/// so that transactions with a future `valid_after` are not silently evicted before
/// they become executable.
pub const DEFAULT_AA_VALID_AFTER_MAX_SECS: u64 = 120;

/// Maximum number of call scopes per account key.
const MAX_KEYCHAIN_CALL_SCOPES: u8 = 64;
/// Maximum number of selector rules per call scope.
const MAX_KEYCHAIN_SELECTOR_RULES_PER_SCOPE: u8 = 64;
/// Maximum number of recipients per selector rule.
const MAX_KEYCHAIN_RECIPIENTS_PER_SELECTOR: u8 = 64;

/// Validator for Tempo transactions.
#[derive(Debug)]
pub struct TempoTransactionValidator<Client> {
    /// Inner validator that performs default Ethereum tx validation.
    pub(crate) inner: EthTransactionValidator<Client, TempoPooledTransaction, TempoEvmConfig>,
    /// Maximum allowed `valid_after` offset for AA txs.
    pub(crate) aa_valid_after_max_secs: u64,
    /// Maximum number of authorizations allowed in an AA transaction.
    pub(crate) max_tempo_authorizations: usize,
    /// Cache of AMM liquidity for validator tokens.
    pub(crate) amm_liquidity_cache: AmmLiquidityCache,
}

impl<Client> TempoTransactionValidator<Client>
where
    Client: ChainSpecProvider<ChainSpec = TempoChainSpec> + StateProviderFactory,
{
    pub fn new(
        inner: EthTransactionValidator<Client, TempoPooledTransaction, TempoEvmConfig>,
        aa_valid_after_max_secs: u64,
        max_tempo_authorizations: usize,
        amm_liquidity_cache: AmmLiquidityCache,
    ) -> Self {
        Self {
            inner,
            aa_valid_after_max_secs,
            max_tempo_authorizations,
            amm_liquidity_cache,
        }
    }

    /// Obtains a clone of the shared [`AmmLiquidityCache`].
    pub fn amm_liquidity_cache(&self) -> AmmLiquidityCache {
        self.amm_liquidity_cache.clone()
    }

    /// Returns the configured client
    pub fn client(&self) -> &Client {
        self.inner.client()
    }

    /// Validates that keychain transactions specify the expected version
    /// depending on the current chainspec.
    fn validate_keychain_version(
        &self,
        transaction: &TempoPooledTransaction,
        spec: TempoHardfork,
    ) -> Result<(), TempoPoolTransactionError> {
        let Some(tx) = transaction.inner().as_aa() else {
            return Ok(());
        };

        if let Err(e) = tx.signature().validate_version(spec.is_t1c()) {
            return Err(e.into());
        }
        for auth_sig in &tx.tx().tempo_authorization_list {
            if let Err(e) = auth_sig.signature().validate_version(spec.is_t1c()) {
                return Err(e.into());
            }
        }

        Ok(())
    }

    fn validate_spending_limit(
        &self,
        transaction: &TempoPooledTransaction,
        fee_token: Address,
        remaining_limit: U256,
    ) -> Result<(), TempoPoolTransactionError> {
        let fee_cost = transaction.fee_token_cost();
        if fee_cost > remaining_limit {
            return Err(TempoPoolTransactionError::SpendingLimitExceeded {
                fee_token,
                cost: fee_cost,
                remaining: remaining_limit,
            });
        }

        Ok(())
    }

    /// Validates the T3-only key-authorization restrictions before any state lookups.
    ///
    /// This keeps txpool admission aligned with runtime and precompile expectations so malformed
    /// limits, call scopes, or recipient-scoped undeployed TIP-20 targets are rejected before
    /// propagation.
    fn validate_t3_key_authorization_restrictions(
        &self,
        auth: &tempo_primitives::transaction::SignedKeyAuthorization,
        state_provider: &mut impl StateProvider,
        spec: TempoHardfork,
    ) -> Result<Result<(), TempoPoolTransactionError>, ProviderError> {
        // Spending limits must stay unique and fit the precompile's u128-backed storage layout.
        if let Some(limits) = auth.limits.as_ref() {
            let mut seen_tokens = HashSet::with_capacity(limits.len());
            for limit in limits {
                if !seen_tokens.insert(limit.token) {
                    return Ok(Err(TempoPoolTransactionError::Keychain(
                        "duplicate token limits are not allowed",
                    )));
                }

                if limit.limit > U256::from(u128::MAX) {
                    return Ok(Err(TempoPoolTransactionError::Keychain(
                        "spending limit exceeds u128::MAX",
                    )));
                }
            }
        }

        let Some(scopes) = auth.allowed_calls.as_ref() else {
            return Ok(Ok(()));
        };

        if scopes.len() > MAX_KEYCHAIN_CALL_SCOPES as usize {
            return Ok(Err(TempoPoolTransactionError::Keychain(
                "too many call scopes in key authorization",
            )));
        }

        // Validate each scope as a unit so target and selector constraints stay grouped.
        let mut seen_targets = HashSet::with_capacity(scopes.len());
        for scope in scopes {
            if scope.target.is_zero() {
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "call scope target cannot be the zero address",
                )));
            }
            if !seen_targets.insert(scope.target) {
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "duplicate call scope targets are not allowed",
                )));
            }

            let selector_rules = &scope.selector_rules;
            if selector_rules.is_empty() {
                continue;
            }

            if selector_rules.len() > MAX_KEYCHAIN_SELECTOR_RULES_PER_SCOPE as usize {
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "too many selector rules in call scope",
                )));
            }

            let mut requires_deployed_tip20 = false;

            // Selector rules are unique per target and must stay within the per-scope bound.
            let mut seen_selectors = HashSet::with_capacity(selector_rules.len());
            for rule in selector_rules {
                if !seen_selectors.insert(rule.selector) {
                    return Ok(Err(TempoPoolTransactionError::Keychain(
                        "duplicate selector rules are not allowed",
                    )));
                }

                let recipients = &rule.recipients;
                if recipients.is_empty() {
                    continue;
                }

                // Recipient-constrained rules only make sense for constrained TIP-20 selectors and
                // must carry a de-duplicated recipient set.
                if recipients.len() > MAX_KEYCHAIN_RECIPIENTS_PER_SELECTOR as usize {
                    return Ok(Err(TempoPoolTransactionError::Keychain(
                        "too many recipients in selector rule",
                    )));
                }

                if !is_constrained_tip20_selector(rule.selector) {
                    return Ok(Err(TempoPoolTransactionError::Keychain(
                        "recipient-constrained selector rules require TIP-20 target and constrained selector",
                    )));
                }

                requires_deployed_tip20 = true;

                let mut seen_recipients = HashSet::with_capacity(recipients.len());
                for recipient in recipients {
                    if recipient.is_zero() || !seen_recipients.insert(*recipient) {
                        return Ok(Err(TempoPoolTransactionError::Keychain(
                            "selector rule recipients must be non-zero and unique",
                        )));
                    }
                }
            }

            if !requires_deployed_tip20 {
                continue;
            }

            let is_tip20 = state_provider
                .with_read_only_storage_ctx(spec, || TIP20Factory::new().is_tip20(scope.target))
                .map_err(ProviderError::other)?;

            if !is_tip20 {
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "recipient-constrained selector rules require a deployed TIP-20 target",
                )));
            }
        }

        Ok(Ok(()))
    }

    fn call_scope_allows_call(
        scopes: Option<&[tempo_primitives::transaction::CallScope]>,
        to: &alloy_primitives::TxKind,
        input: &[u8],
    ) -> bool {
        if to.is_create() {
            return false;
        }

        let Some(scopes) = scopes else {
            return true;
        };
        if scopes.is_empty() {
            return false;
        }

        let Some(target) = to.to().copied() else {
            return false;
        };

        let Some(scope) = scopes.iter().find(|scope| scope.target == target) else {
            return false;
        };

        let selector_rules = &scope.selector_rules;
        if selector_rules.is_empty() {
            return true;
        }
        if input.len() < 4 {
            return false;
        }

        let selector = [input[0], input[1], input[2], input[3]];
        let Some(rule) = selector_rules.iter().find(|rule| rule.selector == selector) else {
            return false;
        };

        let recipients = &rule.recipients;
        if recipients.is_empty() {
            return true;
        }
        if input.len() < 36 {
            return false;
        }

        let recipient_word = &input[4..36];
        if recipient_word[..12].iter().any(|byte| *byte != 0) {
            return false;
        }

        recipients.contains(&Address::from_slice(&recipient_word[12..]))
    }

    /// Rejects inline AA calls that fall outside the already-authorized T3 call scopes.
    ///
    /// This mirrors runtime scope matching closely enough to keep obvious mismatches out of the
    /// pool before execution.
    fn validate_inline_t3_call_scopes(
        tx: &TempoTransaction,
        auth: &tempo_primitives::transaction::SignedKeyAuthorization,
    ) -> Result<(), TempoPoolTransactionError> {
        for call in &tx.calls {
            if call.to.is_create() {
                return Err(TempoPoolTransactionError::Keychain(
                    "contract creation not allowed with access keys",
                ));
            }

            if !Self::call_scope_allows_call(auth.allowed_calls.as_deref(), &call.to, &call.input) {
                return Err(TempoPoolTransactionError::Keychain(
                    "call not allowed by key scope",
                ));
            }
        }

        Ok(())
    }

    /// Validates AA transactions against the keychain: signature recovery, key authorization,
    /// on-chain key existence/revocation/expiry, and spending limits.
    ///
    /// Version checks are handled separately by [`Self::validate_keychain_version`] early
    /// in the path to ensure permanently invalid signatures trigger proper peer penalties.
    fn validate_against_keychain(
        &self,
        transaction: &TempoPooledTransaction,
        state_provider: &mut impl StateProvider,
        fee_payer: Address,
        fee_token: Address,
    ) -> Result<Result<(), TempoPoolTransactionError>, ProviderError> {
        let Some(tx) = transaction.inner().as_aa() else {
            return Ok(Ok(()));
        };

        let current_time = self.inner.fork_tracker().tip_timestamp();
        let spec = self.inner.chain_spec().tempo_hardfork_at(current_time);

        let auth = tx.tx().key_authorization.as_ref();

        // Ensure that key auth is valid if present.
        if let Some(auth) = auth {
            // Validate signature
            if !auth
                .recover_signer()
                .is_ok_and(|signer| signer == transaction.sender())
            {
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "Invalid KeyAuthorization signature",
                )));
            }

            // Validate chain_id.
            // T1C+: chain_id must exactly match (wildcard 0 is no longer allowed).
            // Pre-T1C: chain_id == 0 is wildcard, works on any chain.
            if auth
                .validate_chain_id(self.inner.chain_spec().chain_id(), spec.is_t1c())
                .is_err()
            {
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "KeyAuthorization chain_id does not match current chain",
                )));
            }

            // TIP-1011 fields are T3-gated. Keep pre-T3 admission semantics unchanged.
            if !spec.is_t3() {
                if auth.has_periodic_limits() {
                    return Ok(Err(TempoPoolTransactionError::Keychain(
                        "periodic token limits are not active before T3",
                    )));
                }

                if auth.has_call_scopes() {
                    return Ok(Err(TempoPoolTransactionError::Keychain(
                        "call scopes are not active before T3",
                    )));
                }
            } else if let Err(err) =
                self.validate_t3_key_authorization_restrictions(auth, state_provider, spec)?
            {
                return Ok(Err(err));
            }

            // Validate KeyAuthorization expiry, reject if expiring within the propagation
            // buffer. This prevents near-expiry authorizations from entering the pool only to
            // expire at peers with slightly newer tip timestamps.
            let min_allowed = current_time.saturating_add(AA_VALID_BEFORE_MIN_SECS);
            if let Some(expiry) = auth.expiry
                && expiry <= min_allowed
            {
                return Ok(Err(TempoPoolTransactionError::KeyAuthorizationExpired {
                    expiry,
                    min_allowed,
                }));
            }
        }

        let Some(sig) = tx.signature().as_keychain() else {
            return Ok(Ok(()));
        };

        // This should never fail because we set sender based on the sig.
        if sig.user_address != transaction.sender() {
            return Ok(Err(TempoPoolTransactionError::Keychain(
                "Keychain signature user_address does not match sender",
            )));
        }

        // This should never happen because we validate the signature validity in `recover_signer`.
        let Ok(key_id) = sig.key_id(&tx.signature_hash()) else {
            return Ok(Err(TempoPoolTransactionError::Keychain(
                "Failed to recover access key ID from Keychain signature",
            )));
        };

        let authorized_key = state_provider
            .with_read_only_storage_ctx(spec, || {
                AccountKeychain::new().keys[transaction.sender()][key_id].read()
            })
            .map_err(ProviderError::other)?;

        // Inline key authorization must still be validated against current key state and
        // fee-token spending limits to prevent deterministic execution failures from entering
        // the pool.
        if let Some(auth) = auth {
            if auth.key_id != key_id {
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "KeyAuthorization key_id does not match Keychain signature key_id",
                )));
            }

            if spec.is_t1() && auth.key_type != sig.signature.signature_type() {
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "key authorization key_type does not match the keychain signature type",
                )));
            }

            if authorized_key.expiry > 0 {
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "access key already exists",
                )));
            }

            if authorized_key.is_revoked {
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "access key has been revoked",
                )));
            }

            if let Some(expiry) = auth.expiry
                && expiry < u64::MAX
            {
                transaction.set_key_expiry(Some(expiry));
            }

            if fee_payer == transaction.sender()
                && let Some(limits) = &auth.limits
            {
                let remaining_limit = limits
                    .iter()
                    .rev()
                    .find(|limit| limit.token == fee_token)
                    .map(|limit| limit.limit)
                    .unwrap_or(U256::ZERO);

                if let Err(err) =
                    self.validate_spending_limit(transaction, fee_token, remaining_limit)
                {
                    return Ok(Err(err));
                }
            }

            if spec.is_t3()
                && let Err(err) = Self::validate_inline_t3_call_scopes(tx.tx(), auth)
            {
                return Ok(Err(err));
            }

            return Ok(Ok(()));
        }

        // Check if key was revoked (revoked keys cannot be used)
        if authorized_key.is_revoked {
            return Ok(Err(TempoPoolTransactionError::Keychain(
                "access key has been revoked",
            )));
        }

        // Check if key exists (key exists if expiry > 0)
        if authorized_key.expiry == 0 {
            return Ok(Err(TempoPoolTransactionError::Keychain(
                "access key does not exist",
            )));
        }

        // Check if key has expired or is expiring within the propagation buffer, reject
        // transactions using near-expiry access keys to prevent them from entering the pool
        // only to expire at peers with slightly newer tip timestamps.
        let min_allowed = current_time.saturating_add(AA_VALID_BEFORE_MIN_SECS);
        if authorized_key.expiry <= min_allowed {
            return Ok(Err(TempoPoolTransactionError::AccessKeyExpired {
                expiry: authorized_key.expiry,
                min_allowed,
            }));
        }

        // Cache key expiry for pool maintenance eviction (only if finite expiry)
        if authorized_key.expiry < u64::MAX {
            transaction.set_key_expiry(Some(authorized_key.expiry));
        }

        // Check spending limit for fee token if enforce_limits is enabled.
        // This prevents transactions that would exceed the spending limit from entering the pool.
        if fee_payer == transaction.sender() && authorized_key.enforce_limits {
            let remaining_limit = state_provider
                .with_read_only_storage_ctx(spec, || {
                    AccountKeychain::new().effective_remaining_limit(
                        transaction.sender(),
                        key_id,
                        fee_token,
                        current_time,
                    )
                })
                .map_err(ProviderError::other)?;

            if let Err(err) = self.validate_spending_limit(transaction, fee_token, remaining_limit)
            {
                return Ok(Err(err));
            }
        }

        if spec.is_t3() {
            let call_scope_result: tempo_precompiles::Result<()> = state_provider
                .with_read_only_storage_ctx(spec, || {
                    let keychain = AccountKeychain::new();
                    for call in &tx.tx().calls {
                        keychain.validate_call_scope_for_transaction(
                            transaction.sender(),
                            key_id,
                            &call.to,
                            &call.input,
                        )?;
                    }
                    Ok(())
                });

            if let Err(err) = call_scope_result {
                if err.is_system_error() {
                    return Err(ProviderError::other(err));
                }
                return Ok(Err(TempoPoolTransactionError::Keychain(
                    "call not allowed by key scope",
                )));
            }
        }

        Ok(Ok(()))
    }

    /// Validates that an AA transaction does not exceed the maximum authorization list size.
    fn ensure_authorization_list_size(
        &self,
        transaction: &TempoPooledTransaction,
    ) -> Result<(), TempoPoolTransactionError> {
        let Some(aa_tx) = transaction.inner().as_aa() else {
            return Ok(());
        };

        let count = aa_tx.tx().tempo_authorization_list.len();
        if count > self.max_tempo_authorizations {
            return Err(TempoPoolTransactionError::TooManyAuthorizations {
                count,
                max_allowed: self.max_tempo_authorizations,
            });
        }

        Ok(())
    }

    /// Validates AA transaction time-bound conditionals
    fn ensure_valid_conditionals(
        &self,
        tx: &TempoTransaction,
    ) -> Result<(), TempoPoolTransactionError> {
        let current_time = self.inner.fork_tracker().tip_timestamp();

        // Check if T1 is active for expiring nonce specific validations
        let spec = self.inner.chain_spec().tempo_hardfork_at(current_time);
        let is_expiring_nonce = tx.is_expiring_nonce_tx() && spec.is_t1();

        // Expiring nonce transactions MUST have valid_before set
        if is_expiring_nonce && tx.valid_before.is_none() {
            return Err(TempoPoolTransactionError::ExpiringNonceMissingValidBefore);
        }

        // Expiring nonce transactions MUST have nonce == 0
        if is_expiring_nonce && tx.nonce != 0 {
            return Err(TempoPoolTransactionError::ExpiringNonceNonceNotZero);
        }

        // Reject AA txs where `valid_before` is too close to current time (or already expired).
        if let Some(valid_before) = tx.valid_before {
            // Uses tip_timestamp, as if the node is lagging lagging, the maintenance task will evict expired txs.
            let min_allowed = current_time.saturating_add(AA_VALID_BEFORE_MIN_SECS);
            if valid_before <= min_allowed {
                return Err(TempoPoolTransactionError::InvalidValidBefore {
                    valid_before,
                    min_allowed,
                });
            }

            // For expiring nonce transactions, valid_before must also be within the max expiry window
            if is_expiring_nonce {
                let max_allowed = current_time.saturating_add(TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS);
                if valid_before > max_allowed {
                    return Err(TempoPoolTransactionError::ExpiringNonceValidBeforeTooFar {
                        valid_before,
                        max_allowed,
                    });
                }
            }
        }

        // Reject AA txs where `valid_after` is too far in the future.
        if let Some(valid_after) = tx.valid_after {
            // Uses local time to avoid rejecting valid txs when node is lagging.
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let max_allowed = current_time.saturating_add(self.aa_valid_after_max_secs);
            if valid_after > max_allowed {
                return Err(TempoPoolTransactionError::InvalidValidAfter {
                    valid_after,
                    max_allowed,
                });
            }
        }

        Ok(())
    }

    /// Validates that the gas limit of an AA transaction is sufficient for its intrinsic gas cost.
    ///
    /// This prevents transactions from being admitted to the mempool that would fail during execution
    /// due to insufficient gas for:
    /// - Per-call cold account access (2600 gas per call target)
    /// - Calldata gas for ALL calls in the batch
    /// - Signature verification gas (P256/WebAuthn signatures)
    /// - Per-call CREATE costs
    /// - Key authorization costs
    /// - 2D nonce gas (if nonce_key != 0)
    ///
    /// Without this validation, malicious transactions could clog the mempool at zero cost by
    /// passing pool validation (which only sees the first call's input) but failing at execution time.
    fn ensure_aa_intrinsic_gas(
        &self,
        transaction: &TempoPooledTransaction,
        spec: TempoHardfork,
        state_provider: &impl StateProvider,
    ) -> Result<(), TempoPoolTransactionError> {
        let sender = transaction.sender();
        let Some(aa_tx) = transaction.inner().as_aa() else {
            return Ok(());
        };

        let tx = aa_tx.tx();

        // Build the TempoBatchCallEnv needed for gas calculation
        let aa_env = TempoBatchCallEnv {
            signature: aa_tx.signature().clone(),
            valid_before: tx.valid_before,
            valid_after: tx.valid_after,
            aa_calls: tx.calls.clone(),
            tempo_authorization_list: tx
                .tempo_authorization_list
                .iter()
                .map(|auth| RecoveredTempoAuthorization::recover(auth.clone()))
                .collect(),
            nonce_key: tx.nonce_key,
            subblock_transaction: tx.subblock_proposer().is_some(),
            key_authorization: tx.key_authorization.clone(),
            signature_hash: aa_tx.signature_hash(),
            tx_hash: *aa_tx.hash(),
            expiring_nonce_hash: tx
                .is_expiring_nonce_tx()
                .then(|| aa_tx.expiring_nonce_hash(sender)),
            override_key_id: None,
        };

        // Calculate the intrinsic gas for the AA transaction
        let gas_params = tempo_gas_params(spec);

        let mut init_and_floor_gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            &gas_params,
            Some(tx.access_list.iter()),
            spec,
        )
        .map_err(|_| TempoPoolTransactionError::NonZeroValue)?;

        // Add nonce gas based on hardfork
        // If tx nonce is 0, it's a new key (0 -> 1 transition), otherwise existing key
        if spec.is_t1() {
            // Expiring nonce transactions
            if tx.nonce_key == TEMPO_EXPIRING_NONCE_KEY {
                init_and_floor_gas.initial_gas += EXPIRING_NONCE_GAS;
            } else if tx.nonce == 0 {
                // TIP-1000: Storage pricing updates for launch
                // Tempo transactions with any `nonce_key` and `nonce == 0` require an additional 250,000 gas
                init_and_floor_gas.initial_gas += gas_params.get(GasId::new_account_cost());
            } else if !tx.nonce_key.is_zero() {
                // Existing 2D nonce key (nonce > 0): cold SLOAD + warm SSTORE reset
                // TIP-1000 Invariant 3: existing state updates charge 5,000 gas
                init_and_floor_gas.initial_gas += spec.gas_existing_nonce_key();
            }
            // In CREATE tx with 2d nonce, check if account.nonce is 0, if so, add 250,000 gas.
            // This covers caller creation of account.
            if !tx.nonce_key.is_zero()
                && tx.is_create()
                // in case of provider error, we assume the account nonce is 0 and charge additional gas.
                && state_provider
                    .account_nonce(&sender)
                    .ok()
                    .flatten()
                    .unwrap_or_default()
                    == 0
            {
                init_and_floor_gas.initial_gas += gas_params.get(GasId::new_account_cost());
            }
        } else if !tx.nonce_key.is_zero() {
            // Pre-T1: Add 2D nonce gas if nonce_key is non-zero
            if tx.nonce == 0 {
                // New key - cold SLOAD + SSTORE set (0 -> non-zero)
                init_and_floor_gas.initial_gas += spec.gas_new_nonce_key();
            } else {
                // Existing key - cold SLOAD + warm SSTORE reset
                init_and_floor_gas.initial_gas += spec.gas_existing_nonce_key();
            }
        }

        let gas_limit = tx.gas_limit;

        // Check if gas limit is sufficient for initial gas
        if gas_limit < init_and_floor_gas.initial_gas {
            return Err(
                TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost {
                    gas_limit,
                    intrinsic_gas: init_and_floor_gas.initial_gas,
                },
            );
        }

        // Check floor gas (Prague+ / EIP-7623)
        if gas_limit < init_and_floor_gas.floor_gas {
            return Err(
                TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost {
                    gas_limit,
                    intrinsic_gas: init_and_floor_gas.floor_gas,
                },
            );
        }

        Ok(())
    }

    /// Validates AA transaction field limits (calls, access list, token limits).
    ///
    /// These limits are enforced at the pool level rather than RLP decoding to:
    /// - Keep the core transaction format flexible
    /// - Allow peer penalization for sending bad transactions
    fn ensure_aa_field_limits(
        &self,
        transaction: &TempoPooledTransaction,
    ) -> Result<(), TempoPoolTransactionError> {
        let Some(aa_tx) = transaction.inner().as_aa() else {
            return Ok(());
        };

        let tx = aa_tx.tx();

        if tx.calls.is_empty() {
            return Err(TempoPoolTransactionError::NoCalls);
        }

        // Check number of calls
        if tx.calls.len() > MAX_AA_CALLS {
            return Err(TempoPoolTransactionError::TooManyCalls {
                count: tx.calls.len(),
                max_allowed: MAX_AA_CALLS,
            });
        }

        // Check each call's input size
        for (idx, call) in tx.calls.iter().enumerate() {
            if call.to.is_create() {
                // CREATE call must be the first call in the transaction.
                if idx != 0 {
                    return Err(TempoPoolTransactionError::CreateCallNotFirst);
                }
                // CREATE calls are not allowed in transactions with an authorization list.
                if !tx.tempo_authorization_list.is_empty() {
                    return Err(TempoPoolTransactionError::CreateCallWithAuthorizationList);
                }
            }

            if call.input.len() > MAX_CALL_INPUT_SIZE {
                return Err(TempoPoolTransactionError::CallInputTooLarge {
                    call_index: idx,
                    size: call.input.len(),
                    max_allowed: MAX_CALL_INPUT_SIZE,
                });
            }
        }

        // Check access list accounts
        if tx.access_list.len() > MAX_ACCESS_LIST_ACCOUNTS {
            return Err(TempoPoolTransactionError::TooManyAccessListAccounts {
                count: tx.access_list.len(),
                max_allowed: MAX_ACCESS_LIST_ACCOUNTS,
            });
        }

        // Check storage keys per account and total
        let mut total_storage_keys = 0usize;
        for (idx, entry) in tx.access_list.iter().enumerate() {
            if entry.storage_keys.len() > MAX_STORAGE_KEYS_PER_ACCOUNT {
                return Err(TempoPoolTransactionError::TooManyStorageKeysPerAccount {
                    account_index: idx,
                    count: entry.storage_keys.len(),
                    max_allowed: MAX_STORAGE_KEYS_PER_ACCOUNT,
                });
            }
            total_storage_keys = total_storage_keys.saturating_add(entry.storage_keys.len());
        }

        if total_storage_keys > MAX_ACCESS_LIST_STORAGE_KEYS_TOTAL {
            return Err(TempoPoolTransactionError::TooManyTotalStorageKeys {
                count: total_storage_keys,
                max_allowed: MAX_ACCESS_LIST_STORAGE_KEYS_TOTAL,
            });
        }

        // Check token limits in key_authorization
        if let Some(ref key_auth) = tx.key_authorization
            && let Some(ref limits) = key_auth.limits
            && limits.len() > MAX_TOKEN_LIMITS
        {
            return Err(TempoPoolTransactionError::TooManyTokenLimits {
                count: limits.len(),
                max_allowed: MAX_TOKEN_LIMITS,
            });
        }

        Ok(())
    }

    /// Validates that a transaction's max_fee_per_gas is at least the minimum base fee
    /// for the current hardfork.
    ///
    /// - T0: 10 billion attodollars minimum
    /// - T1+: 20 billion attodollars minimum
    fn ensure_min_base_fee(
        &self,
        transaction: &TempoPooledTransaction,
        spec: TempoHardfork,
    ) -> Result<(), TempoPoolTransactionError> {
        let min_base_fee = spec.base_fee();
        let max_fee_per_gas = transaction.max_fee_per_gas();

        if max_fee_per_gas < min_base_fee as u128 {
            return Err(TempoPoolTransactionError::FeeCapBelowMinBaseFee {
                max_fee_per_gas,
                min_base_fee,
            });
        }

        Ok(())
    }

    fn validate_one(
        &self,
        origin: TransactionOrigin,
        transaction: TempoPooledTransaction,
        mut state_provider: impl StateProvider,
    ) -> TransactionValidationOutcome<TempoPooledTransaction> {
        // Get the current hardfork based on tip timestamp
        let spec = self
            .inner
            .chain_spec()
            .tempo_hardfork_at(self.inner.fork_tracker().tip_timestamp());

        // Reject system transactions, those are never allowed in the pool.
        if transaction.inner().is_system_tx() {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
            );
        }

        // Early reject oversized transactions before doing any expensive validation.
        let tx_size = transaction.encoded_length();
        let max_size = self.inner.max_tx_input_bytes();
        if tx_size > max_size {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::OversizedData {
                    size: tx_size,
                    limit: max_size,
                },
            );
        }

        // Validate that max_fee_per_gas meets the minimum base fee for the current hardfork.
        if let Err(err) = self.ensure_min_base_fee(&transaction, spec) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(err),
            );
        }

        // Validate keychain signature versions early so that permanently invalid
        // errors before cheaper economic checks that would mask them.
        if let Err(err) = self.validate_keychain_version(&transaction, spec) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(err),
            );
        }

        // Balance transfer is not allowed as there is no balances in accounts yet.
        // Check added in https://github.com/tempoxyz/tempo/pull/759
        // AATx will aggregate all call values, so we dont need additional check for AA transactions.
        if !transaction.inner().value().is_zero() {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(TempoPoolTransactionError::NonZeroValue),
            );
        }

        // Validate AA transaction temporal conditionals (`valid_before` and `valid_after`).
        if let Some(tx) = transaction.inner().as_aa()
            && let Err(err) = self.ensure_valid_conditionals(tx.tx())
        {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(err),
            );
        }

        // Validate AA transaction authorization list size.
        if let Err(err) = self.ensure_authorization_list_size(&transaction) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(err),
            );
        }

        if transaction.inner().is_aa() {
            // Validate AA transaction intrinsic gas.
            // This ensures the gas limit covers all AA-specific costs (per-call overhead,
            // signature verification, etc.) to prevent mempool DoS attacks where transactions
            // pass pool validation but fail at execution time.
            if let Err(err) = self.ensure_aa_intrinsic_gas(&transaction, spec, &state_provider) {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::other(err),
                );
            }
        } else {
            // validate intrinsic gas with additional TIP-1000 and T1 checks
            if let Err(err) = ensure_intrinsic_gas_tempo_tx(&transaction, spec) {
                return TransactionValidationOutcome::Invalid(transaction, err);
            }
        }

        // Validate AA transaction field limits (calls, access list, token limits).
        // This prevents DoS attacks via oversized transactions.
        if let Err(err) = self.ensure_aa_field_limits(&transaction) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(err),
            );
        }

        let fee_payer = match transaction.inner().fee_payer(transaction.sender()) {
            Ok(fee_payer) => fee_payer,
            Err(_err) => {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::other(
                        TempoPoolTransactionError::InvalidFeePayerSignature,
                    ),
                );
            }
        };

        if transaction
            .inner()
            .as_aa()
            .is_some_and(|aa| aa.tx().fee_payer_signature.is_some())
            && fee_payer == transaction.sender()
        {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(
                    TempoPoolTransactionError::SelfSponsoredFeePayer,
                ),
            );
        }

        let fee_token = match state_provider.get_fee_token(transaction.inner(), fee_payer, spec) {
            Ok(fee_token) => fee_token,
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        };

        // Cache the resolved fee token for pool maintenance.
        transaction.set_resolved_fee_token(fee_token);

        // Ensure that fee token is valid.
        match state_provider.is_valid_fee_token(spec, fee_token) {
            Ok(valid) => {
                if !valid {
                    return TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidPoolTransactionError::other(
                            TempoPoolTransactionError::InvalidFeeToken(fee_token),
                        ),
                    );
                }
            }
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        }

        // Ensure that fee token is not paused.
        match state_provider.is_fee_token_paused(spec, fee_token) {
            Ok(paused) => {
                if paused {
                    return TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidPoolTransactionError::other(
                            TempoPoolTransactionError::PausedFeeToken(fee_token),
                        ),
                    );
                }
            }
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        }

        // Ensure that the fee payer is not blacklisted
        match state_provider.can_fee_payer_transfer(fee_token, fee_payer, spec) {
            Ok(valid) => {
                if !valid {
                    return TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidPoolTransactionError::other(
                            TempoPoolTransactionError::BlackListedFeePayer {
                                fee_token,
                                fee_payer,
                            },
                        ),
                    );
                }
            }
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        }

        let balance = match state_provider.get_token_balance(fee_token, fee_payer, spec) {
            Ok(balance) => balance,
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        };

        // Get the tx cost and adjust for fee token decimals
        let cost = transaction.fee_token_cost();
        if balance < cost {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::InsufficientFunds(
                    GotExpected {
                        got: balance,
                        expected: cost,
                    }
                    .into(),
                )
                .into(),
            );
        }

        match self
            .amm_liquidity_cache
            .has_enough_liquidity(fee_token, cost, &mut state_provider)
        {
            Ok(true) => {}
            Ok(false) => {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::other(
                        TempoPoolTransactionError::InsufficientLiquidity(fee_token),
                    ),
                );
            }
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        }

        // Validate transactions that involve keychain keys.
        match self.validate_against_keychain(
            &transaction,
            &mut state_provider,
            fee_payer,
            fee_token,
        ) {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::other(err),
                );
            }
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        }

        match self
            .inner
            .validate_one_with_state_provider(origin, transaction, &state_provider)
        {
            TransactionValidationOutcome::Valid {
                balance,
                mut state_nonce,
                bytecode_hash,
                transaction,
                propagate,
                authorities,
            } => {
                // Additional nonce validations for non-protocol nonce keys
                if let Some(nonce_key) = transaction.transaction().nonce_key()
                    && !nonce_key.is_zero()
                {
                    // ensure the nonce key isn't prefixed with the sub-block prefix
                    if has_sub_block_nonce_key_prefix(&nonce_key) {
                        return TransactionValidationOutcome::Invalid(
                            transaction.into_transaction(),
                            InvalidPoolTransactionError::other(
                                TempoPoolTransactionError::SubblockNonceKey,
                            ),
                        );
                    }

                    // Check if T1 hardfork is active for expiring nonce handling
                    let current_time = self.inner.fork_tracker().tip_timestamp();
                    let is_t1_active = self
                        .inner
                        .chain_spec()
                        .is_t1_active_at_timestamp(current_time);

                    if is_t1_active && nonce_key == TEMPO_EXPIRING_NONCE_KEY {
                        // Expiring nonce transaction - check if the replay hash is already seen.
                        //
                        // Pre-T1B: use tx_hash to match handler behavior (handler writes seen[tx_hash]).
                        // T1B+: use expiring_nonce_hash (invariant to fee payer changes) to match
                        //        the updated handler replay protection.
                        //
                        // TODO: Remove the tx_hash path after T1B is active on mainnet.
                        let replay_hash = if spec.is_t1b() {
                            transaction
                                .transaction()
                                .inner()
                                .as_aa()
                                .expect("expiring nonce tx must be AA")
                                .expiring_nonce_hash(transaction.transaction().sender())
                        } else {
                            *transaction.hash()
                        };

                        // If the replay hash is still active (seen and not expired), reject.
                        // Note: This is also enforced at the protocol level in handler.rs via
                        // `check_and_mark_expiring_nonce`, so even if a tx bypasses pool validation
                        // (e.g., injected directly into a block), execution will still reject it.
                        match state_provider.with_read_only_storage_ctx(spec, || {
                            NonceManager::new().is_expiring_nonce_seen(replay_hash, current_time)
                        }) {
                            Err(err) => {
                                return TransactionValidationOutcome::Error(
                                    *transaction.hash(),
                                    Box::new(err),
                                );
                            }
                            Ok(true) => {
                                return TransactionValidationOutcome::Invalid(
                                    transaction.into_transaction(),
                                    InvalidPoolTransactionError::other(
                                        TempoPoolTransactionError::ExpiringNonceReplay,
                                    ),
                                );
                            }
                            Ok(false) => (),
                        };
                    } else {
                        // This is a 2D nonce transaction - validate against 2D nonce
                        state_nonce = match state_provider.with_read_only_storage_ctx(spec, || {
                            NonceManager::new().get_nonce(INonce::getNonceCall {
                                account: transaction.transaction().sender(),
                                nonceKey: nonce_key,
                            })
                        }) {
                            Ok(nonce) => nonce,
                            Err(err) => {
                                return TransactionValidationOutcome::Error(
                                    *transaction.hash(),
                                    Box::new(err),
                                );
                            }
                        };
                        let tx_nonce = transaction.nonce();
                        if tx_nonce < state_nonce {
                            return TransactionValidationOutcome::Invalid(
                                transaction.into_transaction(),
                                InvalidTransactionError::NonceNotConsistent {
                                    tx: tx_nonce,
                                    state: state_nonce,
                                }
                                .into(),
                            );
                        }
                    }
                }

                // Pre-compute TempoTxEnv to avoid the cost during payload building.
                transaction.transaction().prepare_tx_env();

                TransactionValidationOutcome::Valid {
                    balance,
                    state_nonce,
                    bytecode_hash,
                    transaction,
                    propagate,
                    authorities,
                }
            }
            outcome => outcome,
        }
    }
}

impl<Client> TransactionValidator for TempoTransactionValidator<Client>
where
    Client: ChainSpecProvider<ChainSpec = TempoChainSpec> + StateProviderFactory,
{
    type Transaction = TempoPooledTransaction;
    type Block = Block;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        let state_provider = match self.inner.client().latest() {
            Ok(provider) => provider,
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        };

        self.validate_one(origin, transaction, state_provider)
    }

    async fn validate_transactions(
        &self,
        transactions: impl IntoIterator<Item = (TransactionOrigin, Self::Transaction), IntoIter: Send>
        + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        let transactions: Vec<_> = transactions.into_iter().collect();
        let state_provider = match self.inner.client().latest() {
            Ok(provider) => provider,
            Err(err) => {
                return transactions
                    .into_iter()
                    .map(|(_, tx)| {
                        TransactionValidationOutcome::Error(*tx.hash(), Box::new(err.clone()))
                    })
                    .collect();
            }
        };

        transactions
            .into_iter()
            .map(|(origin, tx)| self.validate_one(origin, tx, &state_provider))
            .collect()
    }

    async fn validate_transactions_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: impl IntoIterator<Item = Self::Transaction> + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        let state_provider = match self.inner.client().latest() {
            Ok(provider) => provider,
            Err(err) => {
                return transactions
                    .into_iter()
                    .map(|tx| {
                        TransactionValidationOutcome::Error(*tx.hash(), Box::new(err.clone()))
                    })
                    .collect();
            }
        };

        transactions
            .into_iter()
            .map(|tx| self.validate_one(origin, tx, &state_provider))
            .collect()
    }

    fn on_new_head_block(&self, new_tip_block: &SealedBlock<Self::Block>) {
        self.inner.on_new_head_block(new_tip_block)
    }
}

/// Ensures that gas limit of the transaction exceeds the intrinsic gas of the transaction.
pub fn ensure_intrinsic_gas_tempo_tx(
    tx: &TempoPooledTransaction,
    spec: TempoHardfork,
) -> Result<(), InvalidPoolTransactionError> {
    let gas_params = tempo_gas_params(spec);

    let mut gas = gas_params.initial_tx_gas(
        tx.input(),
        tx.is_create(),
        tx.access_list().map(|l| l.len()).unwrap_or_default() as u64,
        tx.access_list()
            .map(|l| l.iter().map(|i| i.storage_keys.len()).sum::<usize>())
            .unwrap_or_default() as u64,
        tx.authorization_list().map(|l| l.len()).unwrap_or_default() as u64,
    );

    // TIP-1000: Storage pricing updates for launch
    // EIP-7702 authorisation list entries with `auth_list.nonce == 0` require an additional 250,000 gas.
    // no need for v1 fork check as gas_params would be zero
    for auth in tx.authorization_list().unwrap_or_default() {
        if auth.nonce == 0 {
            gas.initial_gas += gas_params.tx_tip1000_auth_account_creation_cost();
        }
    }

    // TIP-1000: Storage pricing updates for launch
    // Tempo transactions with `nonce == 0` require additional gas, but the amount depends on nonce type:
    // - Expiring nonce (nonce_key == MAX): EXPIRING_NONCE_GAS (13k) for ring buffer operations
    // - Regular/2D nonce with nonce == 0: new_account_cost (250k) for potential account creation
    if spec.is_t1() && tx.nonce() == 0 {
        if tx.nonce_key() == Some(TEMPO_EXPIRING_NONCE_KEY) {
            gas.initial_gas += EXPIRING_NONCE_GAS;
        } else {
            gas.initial_gas += gas_params.get(GasId::new_account_cost());
        }
    }

    let gas_limit = tx.gas_limit();
    if gas_limit < gas.initial_gas || gas_limit < gas.floor_gas {
        Err(InvalidPoolTransactionError::IntrinsicGasTooLow)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{MockProviderStorageExt, TxBuilder},
        transaction::TempoPoolTransactionError,
    };
    use alloy_consensus::{Header, Signed, Transaction, TxLegacy};
    use alloy_primitives::{Address, B256, TxKind, U256, address, uint};
    use alloy_signer::Signature;
    use reth_primitives_traits::SignedTransaction;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_transaction_pool::{
        PoolTransaction, blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
    };
    use std::sync::Arc;
    use tempo_chainspec::spec::{MODERATO, TEMPO_T1_TX_GAS_LIMIT_CAP};
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        tip20::{TIP20Token, slots as tip20_slots},
        tip403_registry::{ITIP403Registry, PolicyData, TIP403Registry},
    };
    use tempo_primitives::{
        Block, TempoHeader, TempoPrimitives, TempoTxEnvelope,
        transaction::{
            TempoTransaction,
            envelope::TEMPO_SYSTEM_TX_SIGNATURE,
            tempo_transaction::Call,
            tt_signature::{PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        },
    };
    use tempo_revm::TempoStateAccess;

    /// Arbitrary validity window (in seconds) used for expiring-nonce transactions in tests.
    const TEST_VALIDITY_WINDOW: u64 = 25;

    /// Helper to create a mock sealed block with the given timestamp.
    fn create_mock_block(timestamp: u64) -> SealedBlock<Block> {
        let header = TempoHeader {
            inner: Header {
                timestamp,
                gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                ..Default::default()
            },
            ..Default::default()
        };
        let block = Block {
            header,
            body: Default::default(),
        };
        SealedBlock::seal_slow(block)
    }

    /// Helper function to create an AA transaction with the given `valid_after` and `valid_before`
    /// timestamps
    fn create_aa_transaction(
        valid_after: Option<u64>,
        valid_before: Option<u64>,
    ) -> TempoPooledTransaction {
        let mut builder = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"));
        if let Some(va) = valid_after {
            builder = builder.valid_after(va);
        }
        if let Some(vb) = valid_before {
            builder = builder.valid_before(vb);
        }
        builder.build()
    }

    /// Helper function to setup validator with the given transaction and tip timestamp.
    fn setup_validator(
        transaction: &TempoPooledTransaction,
        tip_timestamp: u64,
    ) -> TempoTransactionValidator<MockEthProvider<TempoPrimitives, TempoChainSpec>> {
        let provider = MockEthProvider::<TempoPrimitives>::new()
            .with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()));
        provider.add_account(
            transaction.sender(),
            ExtendedAccount::new(transaction.nonce(), alloy_primitives::U256::ZERO),
        );
        let block_with_gas = Block {
            header: TempoHeader {
                inner: Header {
                    gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        provider.add_block(B256::random(), block_with_gas);

        // Setup PATH_USD as a valid fee token with USD currency and always-allow transfer policy
        // USD_CURRENCY_SLOT_VALUE: "USD" left-padded with length marker (3 bytes * 2 = 6)
        let usd_currency_value =
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);
        // transfer_policy_id is packed at byte offset 20 in slot 7, so we need to shift
        // policy_id=1 left by 160 bits (20 * 8) to position it correctly
        let transfer_policy_id_packed =
            uint!(0x0000000000000000000000010000000000000000000000000000000000000000_U256);
        // Compute the balance slot for the sender in the PATH_USD token
        let balance_slot = TIP20Token::from_address(PATH_USD_ADDRESS)
            .expect("PATH_USD_ADDRESS is a valid TIP20 token")
            .balances[transaction.sender()]
        .slot();
        // Give the sender enough balance to cover the transaction cost
        let fee_payer_balance = U256::from(1_000_000_000_000u64); // 1M USD in 6 decimals
        provider.add_account(
            PATH_USD_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (tip20_slots::CURRENCY.into(), usd_currency_value),
                (
                    tip20_slots::TRANSFER_POLICY_ID.into(),
                    transfer_policy_id_packed,
                ),
                (balance_slot.into(), fee_payer_balance),
            ]),
        );

        let inner =
            EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::mainnet())
                .disable_balance_check()
                .build(InMemoryBlobStore::default());
        let amm_cache =
            AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
        let validator = TempoTransactionValidator::new(
            inner,
            DEFAULT_AA_VALID_AFTER_MAX_SECS,
            DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
            amm_cache,
        );

        // Set the tip timestamp by simulating a new head block
        let mock_block = create_mock_block(tip_timestamp);
        validator.on_new_head_block(&mock_block);

        validator
    }

    #[tokio::test]
    async fn test_some_balance() {
        let transaction = TxBuilder::eip1559(Address::random())
            .value(U256::from(1))
            .build_eip1559();
        let validator = setup_validator(&transaction, 0);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction.clone())
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::NonZeroValue)
                ));
            }
            _ => panic!("Expected Invalid outcome with NonZeroValue error, got: {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn test_system_tx_rejected_as_invalid() {
        let tx = TxLegacy {
            chain_id: Some(MODERATO.chain_id()),
            nonce: 0,
            gas_price: 0,
            gas_limit: 0,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Default::default(),
        };
        let envelope = TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, TEMPO_SYSTEM_TX_SIGNATURE));
        let transaction = TempoPooledTransaction::new(
            reth_primitives_traits::Recovered::new_unchecked(envelope, Address::ZERO),
        );
        let validator = setup_validator(&transaction, 0);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, err) => {
                assert!(matches!(
                    err,
                    InvalidPoolTransactionError::Consensus(
                        InvalidTransactionError::TxTypeNotSupported
                    )
                ));
            }
            _ => panic!("Expected Invalid outcome with TxTypeNotSupported error, got: {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_fee_payer_signature_rejected() {
        let calls: Vec<Call> = vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Default::default(),
        }];

        let tx = TempoTransaction {
            chain_id: MODERATO.chain_id(),
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 1_000_000,
            calls,
            nonce_key: U256::ZERO,
            nonce: 0,
            fee_token: Some(PATH_USD_ADDRESS),
            fee_payer_signature: Some(Signature::new(U256::ZERO, U256::ZERO, false)),
            ..Default::default()
        };

        let signed = AASigned::new_unhashed(
            tx,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        );
        let transaction = TempoPooledTransaction::new(
            TempoTxEnvelope::from(signed).try_into_recovered().unwrap(),
        );
        let validator = setup_validator(&transaction, 0);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::InvalidFeePayerSignature)
                ));
            }
            _ => panic!(
                "Expected Invalid outcome with InvalidFeePayerSignature error, got: {outcome:?}"
            ),
        }
    }

    #[tokio::test]
    async fn test_self_sponsored_fee_payer_rejected() {
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let sender = signer.address();

        let mut tx = TempoTransaction {
            chain_id: MODERATO.chain_id(),
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 1_000_000,
            calls: vec![Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: Default::default(),
            }],
            nonce_key: U256::ZERO,
            nonce: 0,
            fee_token: Some(PATH_USD_ADDRESS),
            fee_payer_signature: Some(Signature::new(U256::ZERO, U256::ZERO, false)),
            ..Default::default()
        };

        let fee_payer_hash = tx.fee_payer_signature_hash(sender);
        tx.fee_payer_signature = Some(
            signer
                .sign_hash_sync(&fee_payer_hash)
                .expect("fee payer signing should succeed"),
        );

        let signed = AASigned::new_unhashed(
            tx,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        );

        let envelope: TempoTxEnvelope = signed.into();
        let transaction = TempoPooledTransaction::new(
            reth_primitives_traits::Recovered::new_unchecked(envelope, sender),
        );
        let validator = setup_validator(&transaction, 0);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::SelfSponsoredFeePayer)
                ));
            }
            _ => panic!(
                "Expected Invalid outcome with SelfSponsoredFeePayer error, got: {outcome:?}"
            ),
        }
    }

    #[tokio::test]
    async fn test_aa_valid_before_check() {
        // NOTE: `setup_validator` will turn `tip_timestamp` into `current_time`
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Test case 1: No `valid_before`
        let tx_no_valid_before = create_aa_transaction(None, None);
        let validator = setup_validator(&tx_no_valid_before, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_no_valid_before)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(!matches!(
                err.downcast_other_ref::<TempoPoolTransactionError>(),
                Some(TempoPoolTransactionError::InvalidValidBefore { .. })
            ));
        }

        // Test case 2: `valid_before` too small (at boundary)
        let tx_too_close =
            create_aa_transaction(None, Some(current_time + AA_VALID_BEFORE_MIN_SECS));
        let validator = setup_validator(&tx_too_close, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_too_close)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::InvalidValidBefore { .. })
                ));
            }
            _ => panic!("Expected Invalid outcome with InvalidValidBefore error, got: {outcome:?}"),
        }

        // Test case 3: `valid_before` sufficiently in the future
        let tx_valid =
            create_aa_transaction(None, Some(current_time + AA_VALID_BEFORE_MIN_SECS + 1));
        let validator = setup_validator(&tx_valid, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_valid)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(!matches!(
                err.downcast_other_ref::<TempoPoolTransactionError>(),
                Some(TempoPoolTransactionError::InvalidValidBefore { .. })
            ));
        }
    }

    #[tokio::test]
    async fn test_aa_valid_after_check() {
        // NOTE: `setup_validator` will turn `tip_timestamp` into `current_time`
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Test case 1: No `valid_after`
        let tx_no_valid_after = create_aa_transaction(None, None);
        let validator = setup_validator(&tx_no_valid_after, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_no_valid_after)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(!matches!(
                err.downcast_other_ref::<TempoPoolTransactionError>(),
                Some(TempoPoolTransactionError::InvalidValidAfter { .. })
            ));
        }

        // Test case 2: `valid_after` within limit (60 seconds)
        let tx_within_limit = create_aa_transaction(Some(current_time + 60), None);
        let validator = setup_validator(&tx_within_limit, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_within_limit)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(!matches!(
                err.downcast_other_ref::<TempoPoolTransactionError>(),
                Some(TempoPoolTransactionError::InvalidValidAfter { .. })
            ));
        }

        // Test case 3: `valid_after` beyond limit (5 minutes, exceeds 120s max)
        let tx_too_far = create_aa_transaction(Some(current_time + 300), None);
        let validator = setup_validator(&tx_too_far, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_too_far)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::InvalidValidAfter { .. })
                ));
            }
            _ => panic!("Expected Invalid outcome with InvalidValidAfter error, got: {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn test_blacklisted_fee_payer_rejected() {
        // Use a valid TIP20 token address (PATH_USD with token_id=1)
        let fee_token = address!("20C0000000000000000000000000000000000001");
        let policy_id: u64 = 2;

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(fee_token)
            .build();
        let fee_payer = transaction.sender();

        // Setup provider with storage
        let provider = MockEthProvider::<TempoPrimitives>::new()
            .with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()));
        provider.add_block(B256::random(), Block::default());

        // Add sender account
        provider.add_account(
            transaction.sender(),
            ExtendedAccount::new(transaction.nonce(), U256::ZERO),
        );

        // Add TIP20 token with transfer_policy_id pointing to blacklist policy
        // USD_CURRENCY_SLOT_VALUE: "USD" left-padded with length marker (3 bytes * 2 = 6)
        let usd_currency_value =
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);
        // transfer_policy_id is packed at byte offset 20 in slot 7, so we need to shift
        // policy_id left by TRANSFER_POLICY_ID_OFFSET bits to position it correctly
        let transfer_policy_id_packed =
            U256::from(policy_id) << tip20_slots::TRANSFER_POLICY_ID_OFFSET;
        provider.add_account(
            fee_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (
                    tip20_slots::TRANSFER_POLICY_ID.into(),
                    transfer_policy_id_packed,
                ),
                (tip20_slots::CURRENCY.into(), usd_currency_value),
            ]),
        );

        // Add TIP403Registry with blacklist policy containing fee_payer
        provider
            .setup_storage(TempoHardfork::default(), || {
                let mut registry = TIP403Registry::new();
                registry.policy_records[policy_id].base.write(PolicyData {
                    policy_type: ITIP403Registry::PolicyType::BLACKLIST as u8,
                    admin: Address::ZERO,
                })?;
                registry.policy_set[policy_id][fee_payer].write(true)
            })
            .unwrap();

        // Create validator and validate
        let inner =
            EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::mainnet())
                .disable_balance_check()
                .build(InMemoryBlobStore::default());
        let validator = TempoTransactionValidator::new(
            inner,
            DEFAULT_AA_VALID_AFTER_MAX_SECS,
            DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
            AmmLiquidityCache::new(provider).unwrap(),
        );

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        // Assert BlackListedFeePayer error
        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::BlackListedFeePayer { .. })
                ));
            }
            _ => {
                panic!("Expected Invalid outcome with BlackListedFeePayer error, got: {outcome:?}")
            }
        }
    }

    /// Test AA intrinsic gas validation rejects insufficient gas and accepts sufficient gas.
    /// This is the fix for the audit finding about mempool DoS via gas calculation mismatch.
    #[tokio::test]
    async fn test_aa_intrinsic_gas_validation() {
        use alloy_primitives::{Signature, TxKind, address};
        use tempo_primitives::transaction::{
            TempoTransaction,
            tempo_transaction::Call,
            tt_signature::{PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        };

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Helper to create AA tx with given gas limit
        let create_aa_tx = |gas_limit: u64| {
            let calls: Vec<Call> = (0..10)
                .map(|i| Call {
                    to: TxKind::Call(Address::from([i as u8; 20])),
                    value: U256::ZERO,
                    input: alloy_primitives::Bytes::from(vec![0x00; 100]),
                })
                .collect();

            let tx = TempoTransaction {
                chain_id: 1,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 20_000_000_000, // 20 gwei, above T1's minimum
                gas_limit,
                calls,
                nonce_key: U256::ZERO,
                nonce: 0,
                fee_token: Some(address!("0000000000000000000000000000000000000002")),
                ..Default::default()
            };

            let signed = AASigned::new_unhashed(
                tx,
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    Signature::test_signature(),
                )),
            );
            TempoPooledTransaction::new(TempoTxEnvelope::from(signed).try_into_recovered().unwrap())
        };

        // Intrinsic gas for 10 calls: 21k base + 10*2600 cold access + 10*100*4 calldata = ~51k
        // Test 1: 30k gas should be rejected
        let tx_low_gas = create_aa_tx(30_000);
        let validator = setup_validator(&tx_low_gas, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_low_gas)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
                ));
            }
            _ => panic!(
                "Expected Invalid outcome with InsufficientGasForAAIntrinsicCost, got: {outcome:?}"
            ),
        }

        // Test 2: 1M gas should pass intrinsic gas check
        let tx_high_gas = create_aa_tx(1_000_000);
        let validator = setup_validator(&tx_high_gas, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_high_gas)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(!matches!(
                err.downcast_other_ref::<TempoPoolTransactionError>(),
                Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
            ));
        }
    }

    /// Test that CREATE transactions with 2D nonce (nonce_key != 0) require additional gas
    /// when the sender's account nonce is 0 (account creation cost).
    ///
    /// The new logic adds 250k gas requirement when:
    /// - Transaction has 2D nonce (nonce_key != 0)
    /// - Transaction is CREATE
    /// - Account nonce is 0
    #[tokio::test]
    async fn test_aa_create_tx_with_2d_nonce_intrinsic_gas() {
        use alloy_primitives::Signature;
        use tempo_primitives::transaction::{
            TempoTransaction,
            tempo_transaction::Call as TxCall,
            tt_signature::{PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        };

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Helper to create AA transaction
        let create_aa_tx = |gas_limit: u64, nonce_key: U256, is_create: bool| {
            let calls: Vec<TxCall> = if is_create {
                vec![TxCall {
                    to: TxKind::Create,
                    value: U256::ZERO,
                    input: alloy_primitives::Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xF3]),
                }]
            } else {
                (0..10)
                    .map(|i| TxCall {
                        to: TxKind::Call(Address::from([i as u8; 20])),
                        value: U256::ZERO,
                        input: alloy_primitives::Bytes::from(vec![0x00; 100]),
                    })
                    .collect()
            };

            let valid_before = if nonce_key == TEMPO_EXPIRING_NONCE_KEY {
                Some(current_time + TEST_VALIDITY_WINDOW)
            } else {
                None
            };

            let tx = TempoTransaction {
                chain_id: 1,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 20_000_000_000,
                gas_limit,
                calls,
                nonce_key,
                nonce: 0,
                valid_before,
                fee_token: Some(address!("0000000000000000000000000000000000000002")),
                ..Default::default()
            };

            let signed = AASigned::new_unhashed(
                tx,
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    Signature::test_signature(),
                )),
            );
            TempoPooledTransaction::new(TempoTxEnvelope::from(signed).try_into_recovered().unwrap())
        };

        // Test 1: Verify 1D nonce (nonce_key=0) with low gas fails intrinsic gas check
        let tx_1d_low_gas = create_aa_tx(30_000, U256::ZERO, false);
        let validator1 = setup_validator(&tx_1d_low_gas, current_time);
        let outcome1 = validator1
            .validate_transaction(TransactionOrigin::External, tx_1d_low_gas)
            .await;

        match outcome1 {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
                    ),
                    "1D nonce with low gas should fail InsufficientGasForAAIntrinsicCost, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome, got: {outcome1:?}"),
        }

        // Test 2: Verify 2D nonce (nonce_key != 0) with same low gas also fails intrinsic gas check
        // This confirms that 2D nonce adds additional gas requirements (for nonce == 0 case)
        let tx_2d_low_gas = create_aa_tx(30_000, TEMPO_EXPIRING_NONCE_KEY, false);
        let validator2 = setup_validator(&tx_2d_low_gas, current_time);
        let outcome2 = validator2
            .validate_transaction(TransactionOrigin::External, tx_2d_low_gas)
            .await;

        match outcome2 {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
                    ),
                    "2D nonce with low gas should fail InsufficientGasForAAIntrinsicCost, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome, got: {outcome2:?}"),
        }

        // Test 3: 1D nonce with sufficient gas should NOT fail intrinsic gas check
        let tx_1d_high_gas = create_aa_tx(1_000_000, U256::ZERO, false);
        let validator3 = setup_validator(&tx_1d_high_gas, current_time);
        let outcome3 = validator3
            .validate_transaction(TransactionOrigin::External, tx_1d_high_gas)
            .await;

        // May fail for other reasons (fee token, etc.) but should NOT fail intrinsic gas
        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome3 {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
                ),
                "1D nonce with high gas should NOT fail InsufficientGasForAAIntrinsicCost, got: {err:?}"
            );
        }

        // Test 4: 2D nonce with sufficient gas should NOT fail intrinsic gas check
        let tx_2d_high_gas = create_aa_tx(1_000_000, TEMPO_EXPIRING_NONCE_KEY, false);
        let validator4 = setup_validator(&tx_2d_high_gas, current_time);
        let outcome4 = validator4
            .validate_transaction(TransactionOrigin::External, tx_2d_high_gas)
            .await;

        // May fail for other reasons (fee token, etc.) but should NOT fail intrinsic gas
        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome4 {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
                ),
                "2D nonce with high gas should NOT fail InsufficientGasForAAIntrinsicCost, got: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_expiring_nonce_intrinsic_gas_uses_lower_cost() {
        use alloy_primitives::{Signature, TxKind, address};
        use tempo_primitives::transaction::{
            TempoTransaction,
            tempo_transaction::Call,
            tt_signature::{PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        };

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Helper to create expiring nonce AA tx with given gas limit
        let create_expiring_nonce_tx = |gas_limit: u64| {
            let calls: Vec<Call> = vec![Call {
                to: TxKind::Call(Address::from([1u8; 20])),
                value: U256::ZERO,
                input: alloy_primitives::Bytes::from(vec![0xd0, 0x9d, 0xe0, 0x8a]), // increment()
            }];

            let tx = TempoTransaction {
                chain_id: 1,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 20_000_000_000,
                gas_limit,
                calls,
                nonce_key: TEMPO_EXPIRING_NONCE_KEY, // Expiring nonce
                nonce: 0,
                valid_before: Some(current_time + 25), // Valid for 25 seconds
                fee_token: Some(address!("0000000000000000000000000000000000000002")),
                ..Default::default()
            };

            let signed = AASigned::new_unhashed(
                tx,
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    Signature::test_signature(),
                )),
            );
            TempoPooledTransaction::new(TempoTxEnvelope::from(signed).try_into_recovered().unwrap())
        };

        // Expiring nonce tx should only need ~35k gas (base + EXPIRING_NONCE_GAS of 13k)
        // NOT 250k+ which would be required for new account creation
        // Test: 50k gas should pass for expiring nonce (would fail if 250k was required)
        let tx = create_expiring_nonce_tx(50_000);
        let validator = setup_validator(&tx, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        // Should NOT fail with InsufficientGasForAAIntrinsicCost or IntrinsicGasTooLow
        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            let is_intrinsic_gas_error = matches!(
                err.downcast_other_ref::<TempoPoolTransactionError>(),
                Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
            ) || matches!(
                err.downcast_other_ref::<InvalidPoolTransactionError>(),
                Some(InvalidPoolTransactionError::IntrinsicGasTooLow)
            );
            assert!(
                !is_intrinsic_gas_error,
                "Expiring nonce tx with 50k gas should NOT fail intrinsic gas check, got: {err:?}"
            );
        }
    }

    /// Test that existing 2D nonce keys (nonce_key != 0 && nonce > 0) charge
    /// EXISTING_NONCE_KEY_GAS (5,000) during pool admission, matching handler.rs.
    ///
    /// Without this charge, transactions with a gas_limit 5,000 too low could
    /// pass pool validation but fail at execution time.
    #[tokio::test]
    async fn test_existing_2d_nonce_key_intrinsic_gas() {
        use alloy_primitives::{Signature, TxKind, address};
        use tempo_primitives::transaction::{
            TempoTransaction,
            tempo_transaction::Call,
            tt_signature::{PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        };

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Helper to create AA tx with a specific nonce_key and nonce
        let create_aa_tx = |gas_limit: u64, nonce_key: U256, nonce: u64| {
            let calls: Vec<Call> = vec![Call {
                to: TxKind::Call(Address::from([1u8; 20])),
                value: U256::ZERO,
                input: alloy_primitives::Bytes::from(vec![0xd0, 0x9d, 0xe0, 0x8a]), // increment()
            }];

            let tx = TempoTransaction {
                chain_id: 1,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 20_000_000_000,
                gas_limit,
                calls,
                nonce_key,
                nonce,
                fee_token: Some(address!("0000000000000000000000000000000000000002")),
                ..Default::default()
            };

            let signed = AASigned::new_unhashed(
                tx,
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    Signature::test_signature(),
                )),
            );
            TempoPooledTransaction::new(TempoTxEnvelope::from(signed).try_into_recovered().unwrap())
        };

        // Test 1: 1D nonce (nonce_key=0) with nonce > 0 has no extra 2D nonce charge.
        // 50k gas should be sufficient (base ~21k + calldata).
        let tx_1d = create_aa_tx(50_000, U256::ZERO, 5);
        let validator = setup_validator(&tx_1d, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_1d)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            let is_gas_error = matches!(
                err.downcast_other_ref::<TempoPoolTransactionError>(),
                Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
            ) || matches!(
                err.downcast_other_ref::<InvalidPoolTransactionError>(),
                Some(InvalidPoolTransactionError::IntrinsicGasTooLow)
            );
            assert!(
                !is_gas_error,
                "1D nonce with nonce>0 and 50k gas should NOT fail intrinsic gas check, got: {err:?}"
            );
        }

        // Test 2: 2D nonce (nonce_key != 0) with nonce > 0, same 50k gas.
        // This triggers the EXISTING_NONCE_KEY_GAS branch (+5k), but 50k is still enough.
        let tx_2d_ok = create_aa_tx(50_000, U256::from(1), 5);
        let validator = setup_validator(&tx_2d_ok, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_2d_ok)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            let is_gas_error = matches!(
                err.downcast_other_ref::<TempoPoolTransactionError>(),
                Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
            ) || matches!(
                err.downcast_other_ref::<InvalidPoolTransactionError>(),
                Some(InvalidPoolTransactionError::IntrinsicGasTooLow)
            );
            assert!(
                !is_gas_error,
                "Existing 2D nonce key with 50k gas should NOT fail intrinsic gas check, got: {err:?}"
            );
        }

        // Test 3: 2D nonce (nonce_key != 0), nonce > 0, with gas that is sufficient for
        // base intrinsic gas but NOT sufficient when EXISTING_NONCE_KEY_GAS (5k) is added.
        // Use 22_000 gas: enough for base ~21k + calldata but not when +5k is charged.
        let tx_2d_low = create_aa_tx(22_000, U256::from(1), 5);
        let validator = setup_validator(&tx_2d_low, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_2d_low)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                let is_gas_error = matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
                ) || matches!(
                    err.downcast_other_ref::<InvalidPoolTransactionError>(),
                    Some(InvalidPoolTransactionError::IntrinsicGasTooLow)
                );
                assert!(
                    is_gas_error,
                    "Existing 2D nonce key with 22k gas should fail intrinsic gas check, got: {err:?}"
                );
            }
            _ => panic!(
                "Expected Invalid outcome for existing 2D nonce with insufficient gas, got: {outcome:?}"
            ),
        }

        // Test 4: Same scenario as test 3, but with 1D nonce (nonce_key=0).
        // Without the 5k charge, 22k should be sufficient.
        let tx_1d_low = create_aa_tx(22_000, U256::ZERO, 5);
        let validator = setup_validator(&tx_1d_low, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_1d_low)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            let is_gas_error = matches!(
                err.downcast_other_ref::<TempoPoolTransactionError>(),
                Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
            ) || matches!(
                err.downcast_other_ref::<InvalidPoolTransactionError>(),
                Some(InvalidPoolTransactionError::IntrinsicGasTooLow)
            );
            assert!(
                !is_gas_error,
                "1D nonce with nonce>0 and 22k gas should NOT fail intrinsic gas check, got: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_non_zero_value_in_eip1559_rejected() {
        let transaction = TxBuilder::eip1559(Address::random())
            .value(U256::from(1))
            .build_eip1559();

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::NonZeroValue)
                ));
            }
            _ => panic!("Expected Invalid outcome with NonZeroValue error, got: {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn test_zero_value_passes_value_check() {
        // Create a zero-value EIP-1559 transaction (value defaults to 0 in TxBuilder)
        let transaction = TxBuilder::eip1559(Address::random()).build_eip1559();
        assert!(transaction.value().is_zero(), "Test expects zero-value tx");

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        assert!(
            matches!(outcome, TransactionValidationOutcome::Valid { .. }),
            "Zero-value tx should pass validation, got: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn test_invalid_fee_token_rejected() {
        let invalid_fee_token = address!("1234567890123456789012345678901234567890");

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(invalid_fee_token)
            .build();

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::InvalidFeeToken(_))
                ));
            }
            _ => panic!("Expected Invalid outcome with InvalidFeeToken error, got: {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn test_aa_valid_after_and_valid_before_both_valid() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let valid_after = current_time + 60;
        let valid_before = current_time + 3600;

        let transaction = create_aa_transaction(Some(valid_after), Some(valid_before));
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            let tempo_err = err.downcast_other_ref::<TempoPoolTransactionError>();
            assert!(
                !matches!(
                    tempo_err,
                    Some(TempoPoolTransactionError::InvalidValidAfter { .. })
                        | Some(TempoPoolTransactionError::InvalidValidBefore { .. })
                ),
                "Should not fail with validity window errors"
            );
        }
    }

    #[tokio::test]
    async fn test_fee_cap_below_min_base_fee_rejected() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // T0 base fee is 10 gwei (10_000_000_000 wei)
        // Create a transaction with max_fee_per_gas below this
        let transaction = TxBuilder::aa(Address::random())
            .max_fee(1_000_000_000) // 1 gwei, below T0's 10 gwei
            .max_priority_fee(1_000_000_000)
            .build();

        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::FeeCapBelowMinBaseFee { .. })
                    ),
                    "Expected FeeCapBelowMinBaseFee error, got: {err:?}"
                );
            }
            _ => panic!(
                "Expected Invalid outcome with FeeCapBelowMinBaseFee error, got: {outcome:?}"
            ),
        }
    }

    #[tokio::test]
    async fn test_fee_cap_at_min_base_fee_passes() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create a transaction with max_fee_per_gas exactly at minimum
        let active_fork = MODERATO.tempo_hardfork_at(current_time);
        let transaction = TxBuilder::aa(Address::random())
            .max_fee(active_fork.base_fee() as u128)
            .max_priority_fee(1_000_000_000)
            .build();

        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        // Should not fail with FeeCapBelowMinBaseFee
        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::FeeCapBelowMinBaseFee { .. })
                ),
                "Should not fail with FeeCapBelowMinBaseFee when fee cap equals min base fee"
            );
        }
    }

    #[tokio::test]
    async fn test_fee_cap_above_min_base_fee_passes() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // T0 base fee is 10 gwei (10_000_000_000 wei)
        // Create a transaction with max_fee_per_gas above minimum
        let transaction = TxBuilder::aa(Address::random())
            .max_fee(20_000_000_000) // 20 gwei, above T0's 10 gwei
            .max_priority_fee(1_000_000_000)
            .build();

        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        // Should not fail with FeeCapBelowMinBaseFee
        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::FeeCapBelowMinBaseFee { .. })
                ),
                "Should not fail with FeeCapBelowMinBaseFee when fee cap is above min base fee"
            );
        }
    }

    #[tokio::test]
    async fn test_eip1559_fee_cap_below_min_base_fee_rejected() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // T0 base fee is 10 gwei, create EIP-1559 tx with lower fee
        let transaction = TxBuilder::eip1559(Address::random())
            .max_fee(1_000_000_000) // 1 gwei, below T0's 10 gwei
            .max_priority_fee(1_000_000_000)
            .build_eip1559();

        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::FeeCapBelowMinBaseFee { .. })
                    ),
                    "Expected FeeCapBelowMinBaseFee error for EIP-1559 tx, got: {err:?}"
                );
            }
            _ => panic!(
                "Expected Invalid outcome with FeeCapBelowMinBaseFee error, got: {outcome:?}"
            ),
        }
    }

    mod keychain_validation {
        use super::*;
        use alloy_primitives::{Signature, TxKind, address};
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;
        use alloy_sol_types::SolCall;
        use reth_chainspec::ForkCondition;
        use reth_primitives_traits::Recovered;
        use reth_transaction_pool::error::PoolTransactionError;
        use tempo_chainspec::hardfork::TempoHardfork;
        use tempo_contracts::precompiles::ITIP20;
        use tempo_precompiles::error::TempoPrecompileError;
        use tempo_primitives::transaction::{
            CallScope, KeyAuthorization, SelectorRule, SignatureType, SignedKeyAuthorization,
            TempoTransaction, TokenLimit,
            tempo_transaction::Call,
            tt_signature::{
                KeychainSignature, KeychainVersion, PrimitiveSignature, TempoSignature,
            },
            tt_signed::AASigned,
        };

        /// Returns a MODERATO chain spec with T1C activated at timestamp 0.
        fn moderato_with_t1c() -> TempoChainSpec {
            let mut spec = Arc::unwrap_or_clone(MODERATO.clone());
            spec.inner
                .hardforks
                .extend([(TempoHardfork::T1C, ForkCondition::Timestamp(0))]);
            spec
        }

        /// Returns a MODERATO chain spec with T3 activated at timestamp 0.
        fn moderato_with_t3() -> TempoChainSpec {
            let mut spec = Arc::unwrap_or_clone(MODERATO.clone());
            spec.inner
                .hardforks
                .extend([(TempoHardfork::T3, ForkCondition::Timestamp(0))]);
            spec
        }

        /// Generate a secp256k1 keypair for testing
        fn generate_keypair() -> (PrivateKeySigner, Address) {
            let signer = PrivateKeySigner::random();
            let address = signer.address();
            (signer, address)
        }

        /// Create an AA transaction with a V2 keychain signature.
        fn create_aa_with_keychain_signature(
            user_address: Address,
            access_key_signer: &PrivateKeySigner,
            key_authorization: Option<SignedKeyAuthorization>,
        ) -> TempoPooledTransaction {
            create_aa_with_keychain_signature_calls(
                user_address,
                access_key_signer,
                key_authorization,
                vec![default_test_call()],
            )
        }

        /// Create an AA transaction with a V1 (legacy) keychain signature.
        fn create_aa_with_v1_keychain_signature(
            user_address: Address,
            access_key_signer: &PrivateKeySigner,
            key_authorization: Option<SignedKeyAuthorization>,
        ) -> TempoPooledTransaction {
            create_aa_with_keychain_signature_calls_versioned(
                user_address,
                access_key_signer,
                key_authorization,
                KeychainVersion::V1,
                vec![default_test_call()],
            )
        }

        fn default_test_call() -> Call {
            Call {
                to: TxKind::Call(address!("0000000000000000000000000000000000000001")),
                value: U256::ZERO,
                input: alloy_primitives::Bytes::new(),
            }
        }

        fn create_aa_with_keychain_signature_calls(
            user_address: Address,
            access_key_signer: &PrivateKeySigner,
            key_authorization: Option<SignedKeyAuthorization>,
            calls: Vec<Call>,
        ) -> TempoPooledTransaction {
            create_aa_with_keychain_signature_calls_versioned(
                user_address,
                access_key_signer,
                key_authorization,
                KeychainVersion::V2,
                calls,
            )
        }

        /// Create an AA transaction with a keychain signature of the specified version.
        fn create_aa_with_keychain_signature_versioned(
            user_address: Address,
            access_key_signer: &PrivateKeySigner,
            key_authorization: Option<SignedKeyAuthorization>,
            version: KeychainVersion,
        ) -> TempoPooledTransaction {
            create_aa_with_keychain_signature_calls_versioned(
                user_address,
                access_key_signer,
                key_authorization,
                version,
                vec![default_test_call()],
            )
        }

        fn create_aa_with_keychain_signature_calls_versioned(
            user_address: Address,
            access_key_signer: &PrivateKeySigner,
            key_authorization: Option<SignedKeyAuthorization>,
            version: KeychainVersion,
            calls: Vec<Call>,
        ) -> TempoPooledTransaction {
            let tx_aa = TempoTransaction {
                chain_id: 42431, // MODERATO chain_id
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 20_000_000_000,
                gas_limit: 1_000_000,
                calls,
                nonce_key: U256::ZERO,
                nonce: 0,
                fee_token: Some(address!("0000000000000000000000000000000000000002")),
                fee_payer_signature: None,
                valid_after: None,
                valid_before: None,
                access_list: Default::default(),
                tempo_authorization_list: vec![],
                key_authorization,
            };

            // Create unsigned transaction to get the signature hash
            let unsigned = AASigned::new_unhashed(
                tx_aa.clone(),
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    Signature::test_signature(),
                )),
            );
            let sig_hash = unsigned.signature_hash();

            let keychain_sig = match version {
                KeychainVersion::V1 => {
                    let signature = access_key_signer
                        .sign_hash_sync(&sig_hash)
                        .expect("signing failed");
                    TempoSignature::Keychain(KeychainSignature::new_v1(
                        user_address,
                        PrimitiveSignature::Secp256k1(signature),
                    ))
                }
                KeychainVersion::V2 => {
                    let sig_hash = KeychainSignature::signing_hash(sig_hash, user_address);
                    let signature = access_key_signer
                        .sign_hash_sync(&sig_hash)
                        .expect("signing failed");
                    TempoSignature::Keychain(KeychainSignature::new(
                        user_address,
                        PrimitiveSignature::Secp256k1(signature),
                    ))
                }
            };

            let signed_tx = AASigned::new_unhashed(tx_aa, keychain_sig);
            let envelope: TempoTxEnvelope = signed_tx.into();
            let recovered = envelope.try_into_recovered().unwrap();
            TempoPooledTransaction::new(recovered)
        }

        fn sign_key_authorization(
            key_authorization: KeyAuthorization,
            user_signer: &PrivateKeySigner,
        ) -> SignedKeyAuthorization {
            let auth_signature = user_signer
                .sign_hash_sync(&key_authorization.signature_hash())
                .expect("signing failed");
            key_authorization.into_signed(PrimitiveSignature::Secp256k1(auth_signature))
        }

        fn tip20_transfer_call(target: Address, recipient: Address) -> Call {
            Call {
                to: TxKind::Call(target),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: recipient,
                    amount: U256::from(1_u64),
                }
                .abi_encode()
                .into(),
            }
        }

        fn tip20_approve_call(target: Address, spender: Address) -> Call {
            Call {
                to: TxKind::Call(target),
                value: U256::ZERO,
                input: ITIP20::approveCall {
                    spender,
                    amount: U256::from(1_u64),
                }
                .abi_encode()
                .into(),
            }
        }

        fn tip20_transfer_with_memo_call(target: Address, recipient: Address) -> Call {
            Call {
                to: TxKind::Call(target),
                value: U256::ZERO,
                input: ITIP20::transferWithMemoCall {
                    to: recipient,
                    amount: U256::from(1_u64),
                    memo: B256::repeat_byte(0x55),
                }
                .abi_encode()
                .into(),
            }
        }

        fn deploy_path_usd(
            provider: &MockEthProvider<TempoPrimitives, TempoChainSpec>,
            _admin: Address,
        ) {
            provider.add_account(
                PATH_USD_ADDRESS,
                ExtendedAccount::new(0, U256::ZERO)
                    .with_bytecode(alloy_primitives::Bytes::from_static(&[0xef])),
            );
        }

        fn validate_t3_key_authorization_result(
            transaction: &TempoPooledTransaction,
            user_address: Address,
            key_id: Address,
            setup_storage: impl FnOnce(&MockEthProvider<TempoPrimitives, TempoChainSpec>),
        ) -> Result<Result<(), TempoPoolTransactionError>, ProviderError> {
            let validator = setup_validator_with_keychain_storage_spec(
                transaction,
                user_address,
                key_id,
                None,
                moderato_with_t3(),
            );
            setup_storage(validator.inner.client());
            let mut state_provider = validator.inner.client().latest().unwrap();
            validate_against_keychain_default_fee_context(
                &validator,
                transaction,
                &mut state_provider,
            )
        }

        fn validate_against_keychain_default_fee_context(
            validator: &TempoTransactionValidator<MockEthProvider<TempoPrimitives, TempoChainSpec>>,
            transaction: &TempoPooledTransaction,
            state_provider: &mut impl StateProvider,
        ) -> Result<Result<(), TempoPoolTransactionError>, ProviderError> {
            validator.validate_against_keychain(
                transaction,
                state_provider,
                transaction.sender(),
                transaction
                    .inner()
                    .fee_token()
                    .unwrap_or(tempo_precompiles::DEFAULT_FEE_TOKEN),
            )
        }

        /// Setup validator with keychain storage for a specific user and key_id.
        fn setup_validator_with_keychain_storage(
            transaction: &TempoPooledTransaction,
            user_address: Address,
            key_id: Address,
            authorized_key: Option<AuthorizedKey>,
        ) -> TempoTransactionValidator<MockEthProvider<TempoPrimitives, TempoChainSpec>> {
            setup_validator_with_keychain_storage_spec(
                transaction,
                user_address,
                key_id,
                authorized_key,
                moderato_with_t1c(),
            )
        }

        fn setup_validator_with_keychain_storage_spec(
            transaction: &TempoPooledTransaction,
            user_address: Address,
            key_id: Address,
            authorized_key: Option<AuthorizedKey>,
            chain_spec: TempoChainSpec,
        ) -> TempoTransactionValidator<MockEthProvider<TempoPrimitives, TempoChainSpec>> {
            let provider = MockEthProvider::<TempoPrimitives>::new().with_chain_spec(chain_spec);

            // Add sender account
            provider.add_account(
                transaction.sender(),
                ExtendedAccount::new(transaction.nonce(), U256::ZERO),
            );
            provider.add_block(B256::random(), Default::default());

            // If authorized key provided, setup AccountKeychain storage
            if let Some(authorized_key) = authorized_key {
                provider
                    .setup_storage(TempoHardfork::default(), || {
                        AccountKeychain::new().keys[user_address][key_id].write(authorized_key)
                    })
                    .unwrap();
            }

            let inner =
                EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::mainnet())
                    .disable_balance_check()
                    .build(InMemoryBlobStore::default());
            let amm_cache =
                AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
            TempoTransactionValidator::new(
                inner,
                DEFAULT_AA_VALID_AFTER_MAX_SECS,
                DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
                amm_cache,
            )
        }

        #[test]
        fn test_non_aa_transaction_skips_keychain_validation() -> Result<(), ProviderError> {
            // Non-AA transaction should return Ok(Ok(())) immediately
            let transaction = TxBuilder::eip1559(Address::random()).build_eip1559();
            let validator = setup_validator(&transaction, 0);
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(result.is_ok(), "Non-AA tx should skip keychain validation");
            Ok(())
        }

        #[test]
        fn test_aa_with_primitive_signature_skips_keychain_validation() -> Result<(), ProviderError>
        {
            // AA transaction with primitive (non-keychain) signature should skip validation
            let transaction = create_aa_transaction(None, None);
            let validator = setup_validator(&transaction, 0);
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "AA tx with primitive signature should skip keychain validation"
            );
            Ok(())
        }

        #[test]
        fn test_keychain_signature_with_valid_authorized_key() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            // Setup storage with a valid authorized key (expiry > 0, not revoked)
            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                Some(AuthorizedKey {
                    signature_type: 0, // secp256k1
                    expiry: u64::MAX,  // never expires
                    enforce_limits: false,
                    is_revoked: false,
                }),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "Valid authorized key should pass validation, got: {result:?}"
            );
            Ok(())
        }

        #[test]
        fn test_keychain_signature_with_revoked_key_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            // Setup storage with a revoked key
            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                Some(AuthorizedKey {
                    signature_type: 0,
                    expiry: 0, // revoked keys have expiry=0
                    enforce_limits: false,
                    is_revoked: true,
                }),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::Keychain(
                        "access key has been revoked"
                    ))
                ),
                "Revoked key should be rejected"
            );
        }

        #[test]
        fn test_keychain_signature_with_nonexistent_key_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            // Setup storage with expiry = 0 (key doesn't exist)
            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                Some(AuthorizedKey {
                    signature_type: 0,
                    expiry: 0, // expiry = 0 means key doesn't exist
                    enforce_limits: false,
                    is_revoked: false,
                }),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::Keychain(
                        "access key does not exist"
                    ))
                ),
                "Non-existent key should be rejected"
            );
        }

        #[test]
        fn test_keychain_signature_with_no_storage_rejected() {
            let (access_key_signer, _) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            // No storage setup - slot value defaults to 0
            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                Address::ZERO,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::Keychain(
                        "access key does not exist"
                    ))
                ),
                "Missing storage should result in non-existent key error"
            );
        }

        #[test]
        fn test_key_authorization_without_existing_key_passes() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            // Create KeyAuthorization signed by the user's main key
            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            // No key exists yet, so same-tx key authorization should pass.
            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "Valid KeyAuthorization should pass when key does not exist, got: {result:?}"
            );
            Ok(())
        }

        #[test]
        fn test_key_authorization_with_existing_key_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                Some(AuthorizedKey {
                    signature_type: 0,
                    expiry: u64::MAX,
                    enforce_limits: false,
                    is_revoked: false,
                }),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::Keychain(
                        "access key already exists"
                    ))
                ),
                "KeyAuthorization should be rejected when key already exists"
            );
        }

        #[test]
        fn test_key_authorization_spending_limit_exceeded_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let fee_token = address!("0000000000000000000000000000000000000002");

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_limits(vec![TokenLimit {
                        token: fee_token,
                        limit: U256::ZERO,
                        period: 0,
                    }]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::SpendingLimitExceeded {
                        fee_token: rejected_fee_token,
                        remaining,
                        ..
                    }) if rejected_fee_token == fee_token && remaining == U256::ZERO
                ),
                "KeyAuthorization with insufficient fee-token limit should be rejected"
            );
        }

        #[test]
        fn test_key_authorization_empty_limits_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let fee_token = address!("0000000000000000000000000000000000000002");

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_no_spending();

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::SpendingLimitExceeded {
                        fee_token: rejected_fee_token,
                        remaining,
                        ..
                    }) if rejected_fee_token == fee_token && remaining == U256::ZERO
                ),
                "KeyAuthorization with empty limits should be rejected"
            );
        }

        #[test]
        fn test_key_authorization_fee_token_not_in_limits_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let fee_token = address!("0000000000000000000000000000000000000002");
            let non_fee_token = Address::random();
            assert_ne!(non_fee_token, fee_token);

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_limits(vec![TokenLimit {
                        token: non_fee_token,
                        limit: U256::MAX,
                        period: 0,
                    }]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::SpendingLimitExceeded {
                        fee_token: rejected_fee_token,
                        remaining,
                        ..
                    }) if rejected_fee_token == fee_token && remaining == U256::ZERO
                ),
                "KeyAuthorization should reject when limits omit the fee token"
            );
        }

        #[test]
        fn test_key_authorization_pre_t3_duplicate_token_limits_use_last_value()
        -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let fee_token = address!("0000000000000000000000000000000000000002");

            let probe_tx =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);
            let fee_cost = probe_tx.fee_token_cost();

            // Duplicate limits for the same token: execution keeps the last write.
            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_limits(vec![
                        TokenLimit {
                            token: fee_token,
                            limit: U256::ZERO,
                            period: 0,
                        },
                        TokenLimit {
                            token: fee_token,
                            limit: fee_cost + U256::from(100),
                            period: 0,
                        },
                    ]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "Inline key authorization should use the last duplicate token limit"
            );
            Ok(())
        }

        #[test]
        fn test_key_authorization_t3_rejects_duplicate_token_limits() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let fee_token = address!("0000000000000000000000000000000000000002");

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_limits(vec![
                        TokenLimit {
                            token: fee_token,
                            limit: U256::from(100_u64),
                            period: 0,
                        },
                        TokenLimit {
                            token: fee_token,
                            limit: U256::from(200_u64),
                            period: 60,
                        },
                    ]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_spec(
                &transaction,
                user_address,
                access_key_address,
                None,
                moderato_with_t3(),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "duplicate token limits are not allowed"
                    ))
                ),
                "Expected duplicate token limits rejection, got: {result:?}"
            );

            Ok(())
        }

        #[test]
        fn test_key_authorization_spending_limit_uses_resolved_fee_token()
        -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let resolved_fee_token = Address::random();

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_limits(vec![TokenLimit {
                        token: resolved_fee_token,
                        limit: U256::MAX,
                        period: 0,
                    }]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(
                &transaction,
                &mut state_provider,
                user_address,
                resolved_fee_token,
            )?;
            assert!(
                result.is_ok(),
                "Inline key authorization should use the resolved fee token"
            );
            Ok(())
        }

        #[test]
        fn test_key_authorization_spending_limit_skipped_for_sponsored_fee_payer()
        -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let fee_token = address!("0000000000000000000000000000000000000002");

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_limits(vec![TokenLimit {
                        token: fee_token,
                        limit: U256::ZERO,
                        period: 0,
                    }]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let sponsored_fee_payer = Address::random();
            assert_ne!(sponsored_fee_payer, user_address);

            let result = validator.validate_against_keychain(
                &transaction,
                &mut state_provider,
                sponsored_fee_payer,
                fee_token,
            )?;
            assert!(
                result.is_ok(),
                "Inline key authorization spending limits should be skipped for sponsored transactions"
            );
            Ok(())
        }

        #[test]
        fn test_key_authorization_t3_rejects_too_many_call_scopes() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            let mut scopes = Vec::new();
            for _ in 0..=MAX_KEYCHAIN_CALL_SCOPES {
                scopes.push(CallScope {
                    target: Address::random(),
                    selector_rules: vec![],
                });
            }

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_allowed_calls(scopes);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_spec(
                &transaction,
                user_address,
                access_key_address,
                None,
                moderato_with_t3(),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )
            .expect("should not be a provider error");

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "too many call scopes in key authorization"
                    ))
                ),
                "Expected too many call scopes rejection, got: {result:?}"
            );
        }

        #[test]
        fn test_key_authorization_t3_rejects_spending_limit_above_u128_max() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let fee_token = address!("0000000000000000000000000000000000000002");

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_limits(vec![TokenLimit {
                        token: fee_token,
                        limit: U256::from(u128::MAX) + U256::from(1_u8),
                        period: 0,
                    }]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_spec(
                &transaction,
                user_address,
                access_key_address,
                None,
                moderato_with_t3(),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )
            .expect("should not be a provider error");

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "spending limit exceeds u128::MAX"
                    ))
                ),
                "Expected oversized spending limit rejection, got: {result:?}"
            );
        }

        #[test]
        fn test_key_authorization_t3_rejects_duplicate_scope_targets() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let duplicate_target = Address::random();

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_allowed_calls(vec![
                        CallScope {
                            target: duplicate_target,
                            selector_rules: vec![],
                        },
                        CallScope {
                            target: duplicate_target,
                            selector_rules: vec![],
                        },
                    ]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_spec(
                &transaction,
                user_address,
                access_key_address,
                None,
                moderato_with_t3(),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )
            .expect("should not be a provider error");

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "duplicate call scope targets are not allowed"
                    ))
                ),
                "Expected duplicate target rejection, got: {result:?}"
            );
        }

        #[test]
        fn test_key_authorization_t3_accepts_empty_selector_rules_as_address_only_scope() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_allowed_calls(vec![CallScope {
                        target: address!("0000000000000000000000000000000000000001"),
                        selector_rules: vec![],
                    }]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_spec(
                &transaction,
                user_address,
                access_key_address,
                None,
                moderato_with_t3(),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )
            .expect("should not be a provider error");

            assert!(
                result.is_ok(),
                "Expected address-only scope to pass, got: {result:?}"
            );
        }

        #[test]
        fn test_key_authorization_t3_rejects_inline_disallowed_call_scope() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_allowed_calls(vec![CallScope {
                        target: address!("0000000000000000000000000000000000000002"),
                        selector_rules: vec![],
                    }]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_spec(
                &transaction,
                user_address,
                access_key_address,
                None,
                moderato_with_t3(),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )
            .expect("should not be a provider error");

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "call not allowed by key scope"
                    ))
                ),
                "Expected call-scope rejection, got: {result:?}"
            );
        }

        #[test]
        fn test_key_authorization_t3_rejects_inline_contract_creation() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let tx_aa = TempoTransaction {
                chain_id: 42431,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 20_000_000_000,
                gas_limit: 1_000_000,
                calls: vec![Call {
                    to: TxKind::Create,
                    value: U256::ZERO,
                    input: alloy_primitives::Bytes::new(),
                }],
                nonce_key: U256::ZERO,
                nonce: 0,
                fee_token: Some(address!("0000000000000000000000000000000000000002")),
                fee_payer_signature: None,
                valid_after: None,
                valid_before: None,
                access_list: Default::default(),
                tempo_authorization_list: vec![],
                key_authorization: Some(signed_key_auth),
            };

            let unsigned = AASigned::new_unhashed(
                tx_aa.clone(),
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    Signature::test_signature(),
                )),
            );
            let sig_hash = KeychainSignature::signing_hash(unsigned.signature_hash(), user_address);
            let signature = access_key_signer
                .sign_hash_sync(&sig_hash)
                .expect("signing failed");
            let signed = AASigned::new_unhashed(
                tx_aa,
                TempoSignature::Keychain(KeychainSignature::new(
                    user_address,
                    PrimitiveSignature::Secp256k1(signature),
                )),
            );
            let transaction = TempoPooledTransaction::new(Recovered::new_unchecked(
                tempo_primitives::TempoTxEnvelope::AA(signed),
                user_address,
            ));

            let validator = setup_validator_with_keychain_storage_spec(
                &transaction,
                user_address,
                access_key_address,
                None,
                moderato_with_t3(),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )
            .expect("should not be a provider error");

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "contract creation not allowed with access keys"
                    ))
                ),
                "Expected create-call rejection, got: {result:?}"
            );
        }

        #[test]
        fn test_key_authorization_t3_accepts_inline_allowed_call_scope() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_allowed_calls(vec![CallScope {
                        target: address!("0000000000000000000000000000000000000001"),
                        selector_rules: vec![],
                    }]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_spec(
                &transaction,
                user_address,
                access_key_address,
                None,
                moderato_with_t3(),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )
            .expect("should not be a provider error");

            assert!(
                result.is_ok(),
                "Expected allowed call-scope transaction to pass, got: {result:?}"
            );
        }

        #[test]
        fn test_key_authorization_t3_recipient_scope_matches_constrained_tip20_selectors()
        -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let allowed_recipient = Address::repeat_byte(0x11);
            let denied_recipient = Address::repeat_byte(0x22);

            let signed_key_auth = sign_key_authorization(
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_allowed_calls(vec![CallScope {
                        target: PATH_USD_ADDRESS,
                        selector_rules: vec![
                            SelectorRule {
                                selector: ITIP20::transferCall::SELECTOR,
                                recipients: vec![allowed_recipient],
                            },
                            SelectorRule {
                                selector: ITIP20::approveCall::SELECTOR,
                                recipients: vec![allowed_recipient],
                            },
                            SelectorRule {
                                selector: ITIP20::transferWithMemoCall::SELECTOR,
                                recipients: vec![allowed_recipient],
                            },
                        ],
                    }]),
                &user_signer,
            );

            for (name, make_call) in [
                (
                    "transfer",
                    tip20_transfer_call as fn(Address, Address) -> Call,
                ),
                (
                    "approve",
                    tip20_approve_call as fn(Address, Address) -> Call,
                ),
                (
                    "transferWithMemo",
                    tip20_transfer_with_memo_call as fn(Address, Address) -> Call,
                ),
            ] {
                let allowed_tx = create_aa_with_keychain_signature_calls(
                    user_address,
                    &access_key_signer,
                    Some(signed_key_auth.clone()),
                    vec![make_call(PATH_USD_ADDRESS, allowed_recipient)],
                );
                let allowed_result = validate_t3_key_authorization_result(
                    &allowed_tx,
                    user_address,
                    access_key_address,
                    |provider| deploy_path_usd(provider, user_address),
                )?;
                assert!(
                    allowed_result.is_ok(),
                    "{name} should allow the configured recipient, got: {allowed_result:?}"
                );

                let denied_tx = create_aa_with_keychain_signature_calls(
                    user_address,
                    &access_key_signer,
                    Some(signed_key_auth.clone()),
                    vec![make_call(PATH_USD_ADDRESS, denied_recipient)],
                );
                let denied_result = validate_t3_key_authorization_result(
                    &denied_tx,
                    user_address,
                    access_key_address,
                    |provider| deploy_path_usd(provider, user_address),
                )?;
                assert!(
                    matches!(
                        denied_result,
                        Err(TempoPoolTransactionError::Keychain(
                            "call not allowed by key scope"
                        ))
                    ),
                    "{name} should reject an unlisted recipient, got: {denied_result:?}"
                );
            }

            Ok(())
        }

        #[test]
        fn test_key_authorization_t3_rejects_batch_when_any_call_is_out_of_scope()
        -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let allowed_recipient = Address::repeat_byte(0x11);
            let denied_recipient = Address::repeat_byte(0x22);

            let signed_key_auth = sign_key_authorization(
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_allowed_calls(vec![CallScope {
                        target: PATH_USD_ADDRESS,
                        selector_rules: vec![SelectorRule {
                            selector: ITIP20::transferCall::SELECTOR,
                            recipients: vec![allowed_recipient],
                        }],
                    }]),
                &user_signer,
            );

            let transaction = create_aa_with_keychain_signature_calls(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
                vec![
                    tip20_transfer_call(PATH_USD_ADDRESS, allowed_recipient),
                    tip20_transfer_call(PATH_USD_ADDRESS, denied_recipient),
                ],
            );

            let result = validate_t3_key_authorization_result(
                &transaction,
                user_address,
                access_key_address,
                |provider| deploy_path_usd(provider, user_address),
            )?;

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "call not allowed by key scope"
                    ))
                ),
                "Expected batched scope rejection, got: {result:?}"
            );

            Ok(())
        }

        #[test]
        fn test_key_authorization_t3_rejects_duplicate_recipients_in_selector_rule() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let duplicate_recipient = Address::repeat_byte(0x11);

            let signed_key_auth = sign_key_authorization(
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_allowed_calls(vec![CallScope {
                        target: PATH_USD_ADDRESS,
                        selector_rules: vec![SelectorRule {
                            selector: ITIP20::transferCall::SELECTOR,
                            recipients: vec![duplicate_recipient, duplicate_recipient],
                        }],
                    }]),
                &user_signer,
            );

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let result = validate_t3_key_authorization_result(
                &transaction,
                user_address,
                access_key_address,
                |_| {},
            )
            .expect("should not be a provider error");

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "selector rule recipients must be non-zero and unique"
                    ))
                ),
                "Expected duplicate recipient rejection, got: {result:?}"
            );
        }

        #[test]
        fn test_key_authorization_t3_rejects_recipient_scope_for_non_tip20_target() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            let signed_key_auth = sign_key_authorization(
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_allowed_calls(vec![CallScope {
                        target: address!("0000000000000000000000000000000000000042"),
                        selector_rules: vec![SelectorRule {
                            selector: ITIP20::transferCall::SELECTOR,
                            recipients: vec![address!("00000000000000000000000000000000000000aa")],
                        }],
                    }]),
                &user_signer,
            );

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let result = validate_t3_key_authorization_result(
                &transaction,
                user_address,
                access_key_address,
                |_| {},
            )
            .expect("should not be a provider error");

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "recipient-constrained selector rules require a deployed TIP-20 target"
                    ))
                ),
                "Expected non-TIP-20 target rejection, got: {result:?}"
            );
        }

        #[test]
        fn test_key_authorization_t3_rejects_recipient_scope_for_undeployed_tip20() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let mut target_bytes = [0u8; 20];
            target_bytes[0] = 0x20;
            target_bytes[1] = 0xc0;
            target_bytes[19] = 0x42;
            let undeployed_tip20 = Address::from(target_bytes);

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_allowed_calls(vec![CallScope {
                        target: undeployed_tip20,
                        selector_rules: vec![tempo_primitives::transaction::SelectorRule {
                            selector: [0xa9, 0x05, 0x9c, 0xbb],
                            recipients: vec![address!("00000000000000000000000000000000000000aa")],
                        }],
                    }]);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_spec(
                &transaction,
                user_address,
                access_key_address,
                None,
                moderato_with_t3(),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )
            .expect("should not be a provider error");

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "recipient-constrained selector rules require a deployed TIP-20 target"
                    ))
                ),
                "Expected undeployed TIP-20 rejection, got: {result:?}"
            );
        }

        /// Setup a validator using the DEV chain spec (T1C active at genesis).
        fn setup_validator_with_keychain_storage_t1c(
            transaction: &TempoPooledTransaction,
            user_address: Address,
            key_id: Address,
            authorized_key: Option<AuthorizedKey>,
        ) -> TempoTransactionValidator<MockEthProvider<TempoPrimitives, TempoChainSpec>> {
            use tempo_chainspec::spec::DEV;

            setup_validator_with_keychain_storage_spec(
                transaction,
                user_address,
                key_id,
                authorized_key,
                Arc::unwrap_or_clone(DEV.clone()),
            )
        }

        /// Helper: sign a KeyAuthorization and build a V2 transaction with it.
        fn build_key_auth_tx(
            chain_id: u64,
            access_key_signer: &PrivateKeySigner,
            access_key_address: Address,
            user_signer: &PrivateKeySigner,
            user_address: Address,
        ) -> TempoPooledTransaction {
            build_key_auth_tx_versioned(
                chain_id,
                access_key_signer,
                access_key_address,
                user_signer,
                user_address,
                KeychainVersion::V2,
            )
        }

        /// Helper: sign a KeyAuthorization and build a transaction with the given
        /// keychain version.
        fn build_key_auth_tx_versioned(
            chain_id: u64,
            access_key_signer: &PrivateKeySigner,
            access_key_address: Address,
            user_signer: &PrivateKeySigner,
            user_address: Address,
            version: KeychainVersion,
        ) -> TempoPooledTransaction {
            let key_auth = KeyAuthorization::unrestricted(
                chain_id,
                SignatureType::Secp256k1,
                access_key_address,
            );
            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));
            create_aa_with_keychain_signature_versioned(
                user_address,
                access_key_signer,
                Some(signed_key_auth),
                version,
            )
        }

        /// Pre-T1C (MODERATO): chain_id=0 wildcard is accepted, wrong chain_id is rejected,
        /// matching chain_id is accepted.
        #[test]
        fn test_key_authorization_chain_id_pre_t1c() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let moderato = Arc::unwrap_or_clone(MODERATO.clone());

            // chain_id=0 (wildcard) → accepted
            let tx = build_key_auth_tx_versioned(
                0,
                &access_key_signer,
                access_key_address,
                &user_signer,
                user_address,
                KeychainVersion::V1,
            );
            let validator = setup_validator_with_keychain_storage_spec(
                &tx,
                user_address,
                access_key_address,
                None,
                moderato.clone(),
            );
            let mut sp = validator.inner.client().latest().unwrap();
            let result = validate_against_keychain_default_fee_context(&validator, &tx, &mut sp)?;
            assert!(
                result.is_ok(),
                "chain_id=0 should be accepted pre-T1C, got: {result:?}"
            );

            // chain_id=42431 (matching MODERATO) → accepted
            let tx = build_key_auth_tx_versioned(
                42431,
                &access_key_signer,
                access_key_address,
                &user_signer,
                user_address,
                KeychainVersion::V1,
            );
            let validator = setup_validator_with_keychain_storage_spec(
                &tx,
                user_address,
                access_key_address,
                None,
                moderato.clone(),
            );
            let mut sp = validator.inner.client().latest().unwrap();
            let result = validate_against_keychain_default_fee_context(&validator, &tx, &mut sp)?;
            assert!(
                result.is_ok(),
                "matching chain_id should be accepted pre-T1C, got: {result:?}"
            );

            // chain_id=99999 (wrong) → rejected
            let tx = build_key_auth_tx_versioned(
                99999,
                &access_key_signer,
                access_key_address,
                &user_signer,
                user_address,
                KeychainVersion::V1,
            );
            let validator = setup_validator_with_keychain_storage_spec(
                &tx,
                user_address,
                access_key_address,
                None,
                moderato,
            );
            let mut sp = validator.inner.client().latest().unwrap();
            let result = validate_against_keychain_default_fee_context(&validator, &tx, &mut sp);
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::Keychain(
                        "KeyAuthorization chain_id does not match current chain"
                    ))
                ),
                "wrong chain_id should be rejected pre-T1C"
            );

            Ok(())
        }

        /// Post-T1C (DEV): chain_id=0 wildcard is rejected, wrong chain_id is rejected,
        /// matching chain_id is accepted.
        #[test]
        fn test_key_authorization_chain_id_post_t1c() -> Result<(), ProviderError> {
            use tempo_chainspec::spec::DEV;

            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            // chain_id=DEV.chain_id() (1337, matching) → accepted
            let tx = build_key_auth_tx(
                DEV.chain_id(),
                &access_key_signer,
                access_key_address,
                &user_signer,
                user_address,
            );
            let validator = setup_validator_with_keychain_storage_t1c(
                &tx,
                user_address,
                access_key_address,
                None,
            );
            let mut sp = validator.inner.client().latest().unwrap();
            let result = validate_against_keychain_default_fee_context(&validator, &tx, &mut sp)?;
            assert!(
                result.is_ok(),
                "matching chain_id should be accepted post-T1C, got: {result:?}"
            );

            // chain_id=0 (wildcard) → rejected
            let tx = build_key_auth_tx(
                0,
                &access_key_signer,
                access_key_address,
                &user_signer,
                user_address,
            );
            let validator = setup_validator_with_keychain_storage_t1c(
                &tx,
                user_address,
                access_key_address,
                None,
            );
            let mut sp = validator.inner.client().latest().unwrap();
            let result = validate_against_keychain_default_fee_context(&validator, &tx, &mut sp);
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::Keychain(
                        "KeyAuthorization chain_id does not match current chain"
                    ))
                ),
                "chain_id=0 wildcard should be rejected post-T1C"
            );

            // chain_id=99999 (wrong) → rejected
            let tx = build_key_auth_tx(
                99999,
                &access_key_signer,
                access_key_address,
                &user_signer,
                user_address,
            );
            let validator = setup_validator_with_keychain_storage_t1c(
                &tx,
                user_address,
                access_key_address,
                None,
            );
            let mut sp = validator.inner.client().latest().unwrap();
            let result = validate_against_keychain_default_fee_context(&validator, &tx, &mut sp);
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::Keychain(
                        "KeyAuthorization chain_id does not match current chain"
                    ))
                ),
                "wrong chain_id should be rejected post-T1C"
            );

            Ok(())
        }

        #[test]
        fn test_key_authorization_mismatched_key_id_rejected() {
            let (access_key_signer, _access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let different_key_id = Address::random();

            // Create KeyAuthorization with a DIFFERENT key_id than the one signing the tx
            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, different_key_id);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            // Transaction is signed by access_key_signer but KeyAuth has different_key_id
            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                different_key_id,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::Keychain(
                        "KeyAuthorization key_id does not match Keychain signature key_id"
                    ))
                ),
                "Mismatched key_id should be rejected"
            );
        }

        #[test]
        fn test_key_authorization_invalid_signature_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (_user_signer, user_address) = generate_keypair();
            let (random_signer, _) = generate_keypair();

            // Create KeyAuthorization but sign with a random key (not the user's key)
            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address);

            let auth_sig_hash = key_auth.signature_hash();
            // Sign with random_signer instead of user_signer
            let auth_signature = random_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::Keychain(
                        "Invalid KeyAuthorization signature"
                    ))
                ),
                "Invalid KeyAuthorization signature should be rejected"
            );
        }

        #[test]
        fn test_key_authorization_same_tx_key_type_mismatch_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            let key_auth =
                KeyAuthorization::unrestricted(1337, SignatureType::P256, access_key_address);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_t1c(
                &transaction,
                user_address,
                access_key_address,
                None,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )
            .expect("should not be a provider error");

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "key authorization key_type does not match the keychain signature type"
                    ))
                ),
                "Expected key-type mismatch rejection, got: {result:?}"
            );
        }

        #[test]
        fn test_keychain_user_address_mismatch_rejected() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let real_user = Address::random();

            // Create transaction claiming to be from real_user
            let tx_aa = TempoTransaction {
                chain_id: 42431,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 20_000_000_000,
                gas_limit: 1_000_000,
                calls: vec![Call {
                    to: TxKind::Call(address!("0000000000000000000000000000000000000001")),
                    value: U256::ZERO,
                    input: alloy_primitives::Bytes::new(),
                }],
                nonce_key: U256::ZERO,
                nonce: 0,
                fee_token: Some(address!("0000000000000000000000000000000000000002")),
                fee_payer_signature: None,
                valid_after: None,
                valid_before: None,
                access_list: Default::default(),
                tempo_authorization_list: vec![],
                key_authorization: None,
            };

            let unsigned = AASigned::new_unhashed(
                tx_aa.clone(),
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    Signature::test_signature(),
                )),
            );
            // V2: sign keccak256(0x04 || sig_hash || user_address)
            let sig_hash = KeychainSignature::signing_hash(unsigned.signature_hash(), real_user);
            let signature = access_key_signer
                .sign_hash_sync(&sig_hash)
                .expect("signing failed");

            // Create keychain signature with DIFFERENT user_address than what sender() returns
            // The transaction's sender is derived from user_address in KeychainSignature
            let keychain_sig = TempoSignature::Keychain(KeychainSignature::new(
                real_user, // This becomes the sender
                PrimitiveSignature::Secp256k1(signature),
            ));

            let signed_tx = AASigned::new_unhashed(tx_aa, keychain_sig);
            let envelope: TempoTxEnvelope = signed_tx.into();
            let recovered = envelope.try_into_recovered().unwrap();
            let transaction = TempoPooledTransaction::new(recovered);

            // The transaction.sender() == real_user (from keychain sig's user_address)
            // So this validation path checks sig.user_address == transaction.sender()
            // which should always be true by construction.
            // The actual mismatch scenario would require manually constructing an invalid state.

            // Setup with valid key for the actual sender
            let validator = setup_validator_with_keychain_storage(
                &transaction,
                real_user,
                access_key_address,
                Some(AuthorizedKey {
                    signature_type: 0,
                    expiry: u64::MAX,
                    enforce_limits: false,
                    is_revoked: false,
                }),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            // This should pass since user_address matches sender by construction
            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "Properly constructed keychain sig should pass, got: {result:?}"
            );
            Ok(())
        }

        /// Setup validator with keychain storage and a specific tip timestamp.
        fn setup_validator_with_keychain_storage_and_timestamp(
            transaction: &TempoPooledTransaction,
            user_address: Address,
            key_id: Address,
            authorized_key: Option<AuthorizedKey>,
            tip_timestamp: u64,
        ) -> TempoTransactionValidator<MockEthProvider<TempoPrimitives, TempoChainSpec>> {
            let provider =
                MockEthProvider::<TempoPrimitives>::new().with_chain_spec(moderato_with_t1c());

            // Add sender account
            provider.add_account(
                transaction.sender(),
                ExtendedAccount::new(transaction.nonce(), U256::ZERO),
            );

            // Create block with proper timestamp
            let block = Block {
                header: TempoHeader {
                    inner: Header {
                        timestamp: tip_timestamp,
                        gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                body: Default::default(),
            };
            provider.add_block(B256::random(), block);

            // If authorized key provided, setup AccountKeychain storage
            if let Some(authorized_key) = authorized_key {
                provider
                    .setup_storage(TempoHardfork::default(), || {
                        AccountKeychain::new().keys[user_address][key_id].write(authorized_key)
                    })
                    .unwrap();
            }

            let inner =
                EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::mainnet())
                    .disable_balance_check()
                    .build(InMemoryBlobStore::default());
            let amm_cache =
                AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
            let validator = TempoTransactionValidator::new(
                inner,
                DEFAULT_AA_VALID_AFTER_MAX_SECS,
                DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
                amm_cache,
            );

            // Set the tip timestamp
            let mock_block = create_mock_block(tip_timestamp);
            validator.on_new_head_block(&mock_block);

            validator
        }

        #[test]
        fn test_stored_access_key_expired_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();
            let current_time = 1000u64;

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            // Setup storage with an expired key (expiry in the past)
            let validator = setup_validator_with_keychain_storage_and_timestamp(
                &transaction,
                user_address,
                access_key_address,
                Some(AuthorizedKey {
                    signature_type: 0,
                    expiry: current_time - 1, // Expired (in the past)
                    enforce_limits: false,
                    is_revoked: false,
                }),
                current_time,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::AccessKeyExpired { expiry, min_allowed: ct })
                    if expiry == current_time - 1 && ct == current_time + AA_VALID_BEFORE_MIN_SECS
                ),
                "Expired access key should be rejected"
            );
        }

        #[test]
        fn test_stored_access_key_expiry_at_current_time_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();
            let current_time = 1000u64;

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            // Setup storage with expiry == current_time (edge case: expired)
            let validator = setup_validator_with_keychain_storage_and_timestamp(
                &transaction,
                user_address,
                access_key_address,
                Some(AuthorizedKey {
                    signature_type: 0,
                    expiry: current_time, // Expiry at exactly current time should be rejected
                    enforce_limits: false,
                    is_revoked: false,
                }),
                current_time,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::AccessKeyExpired { .. })
                ),
                "Access key with expiry == current_time should be rejected"
            );
        }

        #[test]
        fn test_stored_access_key_valid_expiry_accepted() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();
            let current_time = 1000u64;

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            // Setup storage with a future expiry
            let validator = setup_validator_with_keychain_storage_and_timestamp(
                &transaction,
                user_address,
                access_key_address,
                Some(AuthorizedKey {
                    signature_type: 0,
                    expiry: current_time + 100, // Valid (in the future)
                    enforce_limits: false,
                    is_revoked: false,
                }),
                current_time,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "Access key with future expiry should be accepted, got: {result:?}"
            );
            Ok(())
        }

        #[test]
        fn test_key_authorization_expired_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let current_time = 1000u64;

            // Create KeyAuthorization with expired expiry
            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_expiry(current_time - 1);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_and_timestamp(
                &transaction,
                user_address,
                access_key_address,
                None,
                current_time,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::KeyAuthorizationExpired { expiry, min_allowed: ct })
                    if expiry == current_time - 1 && ct == current_time + AA_VALID_BEFORE_MIN_SECS
                ),
                "Expired KeyAuthorization should be rejected"
            );
        }

        #[test]
        fn test_key_authorization_expiry_at_current_time_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let current_time = 1000u64;

            // Create KeyAuthorization with expiry == current_time
            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_expiry(current_time);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_and_timestamp(
                &transaction,
                user_address,
                access_key_address,
                None,
                current_time,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::KeyAuthorizationExpired { .. })
                ),
                "KeyAuthorization with expiry == current_time should be rejected"
            );
        }

        #[test]
        fn test_key_authorization_valid_expiry_accepted() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let current_time = 1000u64;

            // Create KeyAuthorization with future expiry
            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_expiry(current_time + 100);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_and_timestamp(
                &transaction,
                user_address,
                access_key_address,
                None,
                current_time,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "KeyAuthorization with future expiry should be accepted, got: {result:?}"
            );
            Ok(())
        }

        #[test]
        fn test_key_authorization_expiry_cached_for_pool_maintenance() -> Result<(), ProviderError>
        {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let current_time = 1000u64;
            let expiry = current_time + 100;

            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address)
                    .with_expiry(expiry);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_and_timestamp(
                &transaction,
                user_address,
                access_key_address,
                None,
                current_time,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(result.is_ok(), "KeyAuthorization should be accepted");
            assert_eq!(
                transaction.key_expiry(),
                Some(expiry),
                "KeyAuthorization expiry should be cached for pool maintenance"
            );
            Ok(())
        }

        #[test]
        fn test_key_authorization_no_expiry_accepted() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();
            let current_time = 1000u64;

            // Create KeyAuthorization with no expiry (None = never expires)
            let key_auth =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, access_key_address);

            let auth_sig_hash = key_auth.signature_hash();
            let auth_signature = user_signer
                .sign_hash_sync(&auth_sig_hash)
                .expect("signing failed");
            let signed_key_auth =
                key_auth.into_signed(PrimitiveSignature::Secp256k1(auth_signature));

            let transaction = create_aa_with_keychain_signature(
                user_address,
                &access_key_signer,
                Some(signed_key_auth),
            );

            let validator = setup_validator_with_keychain_storage_and_timestamp(
                &transaction,
                user_address,
                access_key_address,
                None,
                current_time,
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "KeyAuthorization with no expiry should be accepted, got: {result:?}"
            );
            Ok(())
        }

        /// Setup validator with keychain storage and spending limit for a specific user and key_id.
        fn setup_validator_with_spending_limit(
            transaction: &TempoPooledTransaction,
            user_address: Address,
            key_id: Address,
            enforce_limits: bool,
            spending_limit: Option<(Address, U256)>, // (token, limit)
        ) -> TempoTransactionValidator<MockEthProvider<TempoPrimitives, TempoChainSpec>> {
            let provider =
                MockEthProvider::<TempoPrimitives>::new().with_chain_spec(moderato_with_t1c());

            // Add sender account
            provider.add_account(
                transaction.sender(),
                ExtendedAccount::new(transaction.nonce(), U256::ZERO),
            );
            provider.add_block(B256::random(), Default::default());

            // Setup `AccountKeychain` storage with `AuthorizedKey` and optional spending limit
            provider
                .setup_storage(TempoHardfork::default(), || {
                    let mut keychain = AccountKeychain::new();
                    keychain.keys[user_address][key_id].write(AuthorizedKey {
                        signature_type: 0,
                        expiry: u64::MAX,
                        enforce_limits,
                        is_revoked: false,
                    })?;
                    if let Some((token, limit)) = spending_limit {
                        let limit_key = AccountKeychain::spending_limit_key(user_address, key_id);
                        keychain.spending_limits[limit_key][token].write(SpendingLimitState {
                            remaining: limit,
                            ..Default::default()
                        })?;
                    }
                    Ok::<(), TempoPrecompileError>(())
                })
                .unwrap();

            let inner =
                EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::mainnet())
                    .disable_balance_check()
                    .build(InMemoryBlobStore::default());
            let amm_cache =
                AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
            TempoTransactionValidator::new(
                inner,
                DEFAULT_AA_VALID_AFTER_MAX_SECS,
                DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
                amm_cache,
            )
        }

        #[test]
        fn test_spending_limit_not_enforced_passes() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            // enforce_limits = false, no spending limit set
            let validator = setup_validator_with_spending_limit(
                &transaction,
                user_address,
                access_key_address,
                false, // enforce_limits = false
                None,  // no spending limit
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "Key with enforce_limits=false should pass, got: {result:?}"
            );
            Ok(())
        }

        #[test]
        fn test_spending_limit_sufficient_passes() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            // Get the fee token from the transaction
            let fee_token = transaction
                .inner()
                .fee_token()
                .unwrap_or(tempo_precompiles::DEFAULT_FEE_TOKEN);
            let fee_cost = transaction.fee_token_cost();

            // Set spending limit higher than fee cost
            let validator = setup_validator_with_spending_limit(
                &transaction,
                user_address,
                access_key_address,
                true,                                          // enforce_limits = true
                Some((fee_token, fee_cost + U256::from(100))), // limit > cost
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "Sufficient spending limit should pass, got: {result:?}"
            );
            Ok(())
        }

        #[test]
        fn test_spending_limit_exact_passes() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            let fee_token = transaction
                .inner()
                .fee_token()
                .unwrap_or(tempo_precompiles::DEFAULT_FEE_TOKEN);
            let fee_cost = transaction.fee_token_cost();

            // Set spending limit exactly equal to fee cost
            let validator = setup_validator_with_spending_limit(
                &transaction,
                user_address,
                access_key_address,
                true,                        // enforce_limits = true
                Some((fee_token, fee_cost)), // limit == cost
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "Exact spending limit should pass, got: {result:?}"
            );
            Ok(())
        }

        #[test]
        fn test_spending_limit_exceeded_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            let fee_token = transaction
                .inner()
                .fee_token()
                .unwrap_or(tempo_precompiles::DEFAULT_FEE_TOKEN);
            let fee_cost = transaction.fee_token_cost();

            // Set spending limit lower than fee cost
            let insufficient_limit = fee_cost - U256::from(1);
            let validator = setup_validator_with_spending_limit(
                &transaction,
                user_address,
                access_key_address,
                true,                                  // enforce_limits = true
                Some((fee_token, insufficient_limit)), // limit < cost
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::SpendingLimitExceeded { .. })
                ),
                "Insufficient spending limit should be rejected"
            );
        }

        #[test]
        fn test_spending_limit_zero_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            let fee_token = transaction
                .inner()
                .fee_token()
                .unwrap_or(tempo_precompiles::DEFAULT_FEE_TOKEN);

            // Set spending limit to zero (no spending limit set means zero)
            let validator = setup_validator_with_spending_limit(
                &transaction,
                user_address,
                access_key_address,
                true,                          // enforce_limits = true
                Some((fee_token, U256::ZERO)), // limit = 0
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::SpendingLimitExceeded { .. })
                ),
                "Zero spending limit should be rejected"
            );
        }

        #[test]
        fn test_spending_limit_wrong_token_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            let fee_token = transaction
                .inner()
                .fee_token()
                .unwrap_or(tempo_precompiles::DEFAULT_FEE_TOKEN);

            // Set spending limit for a different token
            let different_token = Address::random();
            assert_ne!(fee_token, different_token); // Ensure they're different

            let validator = setup_validator_with_spending_limit(
                &transaction,
                user_address,
                access_key_address,
                true,                               // enforce_limits = true
                Some((different_token, U256::MAX)), // High limit but for wrong token
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            );
            assert!(
                matches!(
                    result.expect("should not be a provider error"),
                    Err(TempoPoolTransactionError::SpendingLimitExceeded { .. })
                ),
                "Wrong token spending limit should be rejected (fee token has 0 limit)"
            );
        }

        /// Returns a MODERATO chain spec WITHOUT T1C (pre-T1C).
        fn moderato_without_t1c() -> TempoChainSpec {
            Arc::unwrap_or_clone(MODERATO.clone())
        }

        /// Setup a validator with a specific chain spec and tip timestamp.
        fn setup_validator_with_spec(
            transaction: &TempoPooledTransaction,
            chain_spec: TempoChainSpec,
            tip_timestamp: u64,
        ) -> TempoTransactionValidator<MockEthProvider<TempoPrimitives, TempoChainSpec>> {
            let provider = MockEthProvider::<TempoPrimitives>::new().with_chain_spec(chain_spec);
            provider.add_account(
                transaction.sender(),
                ExtendedAccount::new(transaction.nonce(), U256::ZERO),
            );
            provider.add_block(B256::random(), Default::default());

            let inner =
                EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::mainnet())
                    .disable_balance_check()
                    .build(InMemoryBlobStore::default());
            let amm_cache =
                AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
            let validator = TempoTransactionValidator::new(
                inner,
                DEFAULT_AA_VALID_AFTER_MAX_SECS,
                DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
                amm_cache,
            );

            let mock_block = create_mock_block(tip_timestamp);
            validator.on_new_head_block(&mock_block);
            validator
        }

        #[test]
        fn test_legacy_v1_keychain_rejected_post_t1c() {
            let (access_key_signer, _) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_v1_keychain_signature(user_address, &access_key_signer, None);

            let validator = setup_validator_with_spec(&transaction, moderato_with_t1c(), 0);
            let spec = validator
                .inner
                .chain_spec()
                .tempo_hardfork_at(validator.inner.fork_tracker().tip_timestamp());

            let result = validator.validate_keychain_version(&transaction, spec);

            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::LegacyKeychainPostT1C)
                ),
                "V1 keychain should be rejected post-T1C, got: {result:?}"
            );
        }

        #[test]
        fn test_v2_keychain_accepted_post_t1c() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                Some(AuthorizedKey {
                    signature_type: 0,
                    expiry: u64::MAX,
                    enforce_limits: false,
                    is_revoked: false,
                }),
            );
            let mut state_provider = validator.inner.client().latest().unwrap();

            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "V2 keychain should be accepted post-T1C, got: {result:?}"
            );
            Ok(())
        }

        #[test]
        fn test_v2_keychain_rejected_pre_t1c() {
            let (access_key_signer, _) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_keychain_signature(user_address, &access_key_signer, None);

            let validator = setup_validator_with_spec(&transaction, moderato_without_t1c(), 0);
            let spec = validator
                .inner
                .chain_spec()
                .tempo_hardfork_at(validator.inner.fork_tracker().tip_timestamp());

            let result = validator.validate_keychain_version(&transaction, spec);

            assert!(
                matches!(result, Err(TempoPoolTransactionError::V2KeychainPreT1C)),
                "V2 keychain should be rejected pre-T1C, got: {result:?}"
            );
        }

        #[test]
        fn test_v1_keychain_accepted_pre_t1c() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let user_address = Address::random();

            let transaction =
                create_aa_with_v1_keychain_signature(user_address, &access_key_signer, None);

            // Pre-T1C validator with keychain storage
            let provider =
                MockEthProvider::<TempoPrimitives>::new().with_chain_spec(moderato_without_t1c());
            provider.add_account(
                transaction.sender(),
                ExtendedAccount::new(transaction.nonce(), U256::ZERO),
            );
            provider.add_block(B256::random(), Default::default());
            provider
                .setup_storage(TempoHardfork::default(), || {
                    AccountKeychain::new().keys[user_address][access_key_address].write(
                        AuthorizedKey {
                            signature_type: 0,
                            expiry: u64::MAX,
                            enforce_limits: false,
                            is_revoked: false,
                        },
                    )
                })
                .unwrap();
            let inner =
                EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::mainnet())
                    .disable_balance_check()
                    .build(InMemoryBlobStore::default());
            let amm_cache =
                AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
            let validator = TempoTransactionValidator::new(
                inner,
                DEFAULT_AA_VALID_AFTER_MAX_SECS,
                DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
                amm_cache,
            );

            let mut state_provider = validator.inner.client().latest().unwrap();
            let result = validate_against_keychain_default_fee_context(
                &validator,
                &transaction,
                &mut state_provider,
            )?;
            assert!(
                result.is_ok(),
                "V1 keychain should be accepted pre-T1C, got: {result:?}"
            );
            Ok(())
        }

        #[test]
        fn test_legacy_keychain_post_t1c_is_bad_transaction() {
            assert!(
                TempoPoolTransactionError::LegacyKeychainPostT1C.is_bad_transaction(),
                "Post-T1C V1 rejection should be a bad transaction (permanent)"
            );
        }

        #[test]
        fn test_v2_keychain_pre_t1c_is_not_bad_transaction() {
            assert!(
                !TempoPoolTransactionError::V2KeychainPreT1C.is_bad_transaction(),
                "Pre-T1C V2 rejection should NOT be a bad transaction (transient)"
            );
        }

        #[test]
        fn test_expired_access_key_is_not_bad_transaction() {
            assert!(
                !TempoPoolTransactionError::AccessKeyExpired {
                    expiry: 1,
                    min_allowed: 4,
                }
                .is_bad_transaction(),
                "Expired access key rejection should NOT be a bad transaction (timing-sensitive)"
            );
        }

        #[test]
        fn test_expired_key_authorization_is_not_bad_transaction() {
            assert!(
                !TempoPoolTransactionError::KeyAuthorizationExpired {
                    expiry: 1,
                    min_allowed: 4,
                }
                .is_bad_transaction(),
                "Expired key authorization rejection should NOT be a bad transaction (timing-sensitive)"
            );
        }
    }

    // ============================================
    // Authorization list limit tests
    // ============================================

    /// Helper function to create an AA transaction with the given number of authorizations.
    fn create_aa_transaction_with_authorizations(
        authorization_count: usize,
    ) -> TempoPooledTransaction {
        use alloy_eips::eip7702::Authorization;
        use alloy_primitives::{Signature, TxKind, address};
        use tempo_primitives::transaction::{
            TempoSignedAuthorization, TempoTransaction,
            tempo_transaction::Call,
            tt_signature::{PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        };

        // Create dummy authorizations
        let authorizations: Vec<TempoSignedAuthorization> = (0..authorization_count)
            .map(|i| {
                let auth = Authorization {
                    chain_id: U256::from(1),
                    nonce: i as u64,
                    address: address!("0000000000000000000000000000000000000001"),
                };
                TempoSignedAuthorization::new_unchecked(
                    auth,
                    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                        Signature::test_signature(),
                    )),
                )
            })
            .collect();

        let tx_aa = TempoTransaction {
            chain_id: 1,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000, // 20 gwei, above T1's minimum
            gas_limit: 1_000_000,
            calls: vec![Call {
                to: TxKind::Call(address!("0000000000000000000000000000000000000001")),
                value: U256::ZERO,
                input: alloy_primitives::Bytes::new(),
            }],
            nonce_key: U256::ZERO,
            nonce: 0,
            fee_token: Some(address!("0000000000000000000000000000000000000002")),
            fee_payer_signature: None,
            valid_after: None,
            valid_before: None,
            access_list: Default::default(),
            tempo_authorization_list: authorizations,
            key_authorization: None,
        };

        let signed_tx = AASigned::new_unhashed(
            tx_aa,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        );
        let envelope: TempoTxEnvelope = signed_tx.into();
        let recovered = envelope.try_into_recovered().unwrap();
        TempoPooledTransaction::new(recovered)
    }

    #[tokio::test]
    async fn test_aa_too_many_authorizations_rejected() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create transaction with more authorizations than the default limit
        let transaction =
            create_aa_transaction_with_authorizations(DEFAULT_MAX_TEMPO_AUTHORIZATIONS + 1);
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match &outcome {
            TransactionValidationOutcome::Invalid(_, err) => {
                let error_msg = err.to_string();
                assert!(
                    error_msg.contains("Too many authorizations"),
                    "Expected TooManyAuthorizations error, got: {error_msg}"
                );
            }
            other => panic!("Expected Invalid outcome, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_aa_authorization_count_at_limit_accepted() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create transaction with exactly the limit
        let transaction =
            create_aa_transaction_with_authorizations(DEFAULT_MAX_TEMPO_AUTHORIZATIONS);
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        // Should not fail with TooManyAuthorizations (may fail for other reasons)
        if let TransactionValidationOutcome::Invalid(_, err) = &outcome {
            let error_msg = err.to_string();
            assert!(
                !error_msg.contains("Too many authorizations"),
                "Should not fail with TooManyAuthorizations at the limit, got: {error_msg}"
            );
        }
    }

    /// AA transactions must have at least one call.
    #[tokio::test]
    async fn test_aa_no_calls_rejected() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create an AA transaction with no calls
        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .calls(vec![]) // Empty calls
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::NoCalls)
                    ),
                    "Expected NoCalls error, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome with NoCalls error, got: {outcome:?}"),
        }
    }

    /// CREATE calls (contract deployments) must be the first call in an AA transaction.
    #[tokio::test]
    async fn test_aa_create_call_not_first_rejected() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create an AA transaction with a CREATE call as the second call
        let calls = vec![
            Call {
                to: TxKind::Call(Address::random()), // First call is a regular call
                value: U256::ZERO,
                input: Default::default(),
            },
            Call {
                to: TxKind::Create, // Second call is a CREATE - should be rejected
                value: U256::ZERO,
                input: Default::default(),
            },
        ];

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .calls(calls)
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::CreateCallNotFirst)
                    ),
                    "Expected CreateCallNotFirst error, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome with CreateCallNotFirst error, got: {outcome:?}"),
        }
    }

    /// CREATE call as the first call should be accepted.
    #[tokio::test]
    async fn test_aa_create_call_first_accepted() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create an AA transaction with a CREATE call as the first call
        let calls = vec![
            Call {
                to: TxKind::Create, // First call is a CREATE - should be accepted
                value: U256::ZERO,
                input: Default::default(),
            },
            Call {
                to: TxKind::Call(Address::random()), // Second call is a regular call
                value: U256::ZERO,
                input: Default::default(),
            },
        ];

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .calls(calls)
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        // Should NOT fail with CreateCallNotFirst (may fail for other reasons)
        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::CreateCallNotFirst)
                ),
                "CREATE call as first call should be accepted, got: {err:?}"
            );
        }
    }

    /// Multiple CREATE calls in the same transaction should be rejected.
    #[tokio::test]
    async fn test_aa_multiple_creates_rejected() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // calls = [CREATE, CALL, CREATE] -> should reject with CreateCallNotFirst
        let calls = vec![
            Call {
                to: TxKind::Create, // First call is a CREATE - ok
                value: U256::ZERO,
                input: Default::default(),
            },
            Call {
                to: TxKind::Call(Address::random()), // Second call is a regular call
                value: U256::ZERO,
                input: Default::default(),
            },
            Call {
                to: TxKind::Create, // Third call is a CREATE - should be rejected
                value: U256::ZERO,
                input: Default::default(),
            },
        ];

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .calls(calls)
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::CreateCallNotFirst)
                    ),
                    "Expected CreateCallNotFirst error, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome with CreateCallNotFirst error, got: {outcome:?}"),
        }
    }

    /// CREATE calls must not have any entries in the authorization list.
    #[tokio::test]
    async fn test_aa_create_call_with_authorization_list_rejected() {
        use alloy_eips::eip7702::Authorization;
        use alloy_primitives::Signature;
        use tempo_primitives::transaction::{
            TempoSignedAuthorization,
            tt_signature::{PrimitiveSignature, TempoSignature},
        };

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create an AA transaction with a CREATE call and a non-empty authorization list
        let calls = vec![Call {
            to: TxKind::Create, // CREATE call
            value: U256::ZERO,
            input: Default::default(),
        }];

        // Create a single authorization entry
        let auth = Authorization {
            chain_id: U256::from(1),
            nonce: 0,
            address: address!("0000000000000000000000000000000000000001"),
        };
        let authorization = TempoSignedAuthorization::new_unchecked(
            auth,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        );

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .calls(calls)
            .authorization_list(vec![authorization])
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::CreateCallWithAuthorizationList)
                    ),
                    "Expected CreateCallWithAuthorizationList error, got: {err:?}"
                );
            }
            _ => panic!(
                "Expected Invalid outcome with CreateCallWithAuthorizationList error, got: {outcome:?}"
            ),
        }
    }

    /// Paused tokens should be rejected as invalid fee tokens.
    #[test]
    fn test_paused_token_is_invalid_fee_token() {
        let fee_token = address!("20C0000000000000000000000000000000000001");

        // "USD" = 0x555344, stored in high bytes with length 6 (3*2) in LSB
        let usd_currency_value =
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);

        let provider =
            MockEthProvider::default().with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()));
        provider.add_account(
            fee_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (tip20_slots::CURRENCY.into(), usd_currency_value),
                (tip20_slots::PAUSED.into(), U256::from(1)),
            ]),
        );

        let mut state = provider.latest().unwrap();
        let spec = provider.chain_spec().tempo_hardfork_at(0);

        // Test that is_fee_token_paused returns true for paused tokens
        let result = state.is_fee_token_paused(spec, fee_token);
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "Paused tokens should be detected as paused"
        );
    }

    /// Non-AA transaction with insufficient gas should be rejected with Invalid outcome
    /// and IntrinsicGasTooLow error.
    #[tokio::test]
    async fn test_non_aa_intrinsic_gas_insufficient_rejected() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create EIP-1559 transaction with very low gas limit (below intrinsic gas of ~21k)
        let tx = TxBuilder::eip1559(Address::random())
            .gas_limit(1_000) // Way below intrinsic gas
            .build_eip1559();

        let validator = setup_validator(&tx, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(err, InvalidPoolTransactionError::IntrinsicGasTooLow),
                    "Expected IntrinsicGasTooLow error, got: {err:?}"
                );
            }
            TransactionValidationOutcome::Error(_, _) => {
                panic!("Expected Invalid outcome, got Error - this was the bug we fixed!")
            }
            _ => panic!("Expected Invalid outcome with IntrinsicGasTooLow, got: {outcome:?}"),
        }
    }

    /// Non-AA transaction with sufficient gas should pass intrinsic gas validation.
    #[tokio::test]
    async fn test_non_aa_intrinsic_gas_sufficient_passes() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create EIP-1559 transaction with plenty of gas
        let tx = TxBuilder::eip1559(Address::random())
            .gas_limit(100_000) // Well above intrinsic gas
            .build_eip1559();

        let validator = setup_validator(&tx, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        // Should NOT fail with CallGasCostMoreThanGasLimit (intrinsic gas check)
        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(
                matches!(err, InvalidPoolTransactionError::IntrinsicGasTooLow),
                "Non-AA tx with 100k gas should NOT fail intrinsic gas check, got: {err:?}"
            );
        }
    }

    /// Non-AA transaction should NOT trigger AA-specific intrinsic gas error.
    /// This verifies the fix that gates AA intrinsic gas check to only AA transactions.
    #[tokio::test]
    async fn test_non_aa_tx_does_not_trigger_aa_intrinsic_gas_error() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create EIP-1559 transaction with low gas
        let tx = TxBuilder::eip1559(Address::random())
            .gas_limit(1_000)
            .build_eip1559();

        let validator = setup_validator(&tx, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        // Should NOT get AA-specific error
        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost { .. })
                ),
                "Non-AA transaction should NOT trigger AA-specific intrinsic gas error"
            );
        }
    }

    /// Verify intrinsic gas error is returned for insufficient gas.
    #[tokio::test]
    async fn test_intrinsic_gas_error_contains_gas_details() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let gas_limit = 5_000u64;
        let tx = TxBuilder::eip1559(Address::random())
            .gas_limit(gas_limit)
            .build_eip1559();

        let validator = setup_validator(&tx, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(err, InvalidPoolTransactionError::IntrinsicGasTooLow),
                    "Expected IntrinsicGasTooLow error, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome, got: {outcome:?}"),
        }
    }

    /// Paused validator tokens should be rejected even though they would bypass the liquidity check.
    #[test]
    fn test_paused_validator_token_rejected_before_liquidity_bypass() {
        // Use a TIP20-prefixed address for the fee token
        let paused_validator_token = address!("20C0000000000000000000000000000000000001");

        // "USD" = 0x555344, stored in high bytes with length 6 (3*2) in LSB
        let usd_currency_value =
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);

        let provider =
            MockEthProvider::default().with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()));

        // Set up the token as a valid USD token but PAUSED
        provider.add_account(
            paused_validator_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (tip20_slots::CURRENCY.into(), usd_currency_value),
                (tip20_slots::PAUSED.into(), U256::from(1)),
            ]),
        );

        let mut state = provider.latest().unwrap();
        let spec = provider.chain_spec().tempo_hardfork_at(0);

        // Create AMM cache with the paused token in unique_tokens (simulating a validator's
        // preferred token). This would normally cause has_enough_liquidity() to return true
        // immediately at the bypass check.
        let amm_cache = AmmLiquidityCache::with_unique_tokens(vec![paused_validator_token]);

        // Verify the bypass would apply: the token IS in unique_tokens
        assert!(
            amm_cache.is_active_validator_token(&paused_validator_token),
            "Token should be in unique_tokens for this test"
        );

        // Verify has_enough_liquidity would bypass (return true) for this token
        // because it matches a validator token. This confirms the vulnerability we're testing.
        let liquidity_result =
            amm_cache.has_enough_liquidity(paused_validator_token, U256::from(1000), &mut state);
        assert!(
            liquidity_result.is_ok() && liquidity_result.unwrap(),
            "Token in unique_tokens should bypass liquidity check and return true"
        );

        // BUT the pause check in is_fee_token_paused should catch it BEFORE the bypass
        let is_paused = state.is_fee_token_paused(spec, paused_validator_token);
        assert!(is_paused.is_ok());
        assert!(
            is_paused.unwrap(),
            "Paused validator token should be detected by is_fee_token_paused BEFORE reaching has_enough_liquidity"
        );
    }

    #[tokio::test]
    async fn test_aa_exactly_max_calls_accepted() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let calls: Vec<Call> = (0..MAX_AA_CALLS)
            .map(|_| Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: Default::default(),
            })
            .collect();

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .calls(calls)
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::TooManyCalls { .. })
                ),
                "Exactly MAX_AA_CALLS calls should not trigger TooManyCalls, got: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_aa_too_many_calls_rejected() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let calls: Vec<Call> = (0..MAX_AA_CALLS + 1)
            .map(|_| Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: Default::default(),
            })
            .collect();

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .calls(calls)
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::TooManyCalls { .. })
                    ),
                    "Expected TooManyCalls error, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome with TooManyCalls error, got: {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn test_aa_exactly_max_call_input_size_accepted() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let calls = vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: vec![0u8; MAX_CALL_INPUT_SIZE].into(),
        }];

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .calls(calls)
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::CallInputTooLarge { .. })
                ),
                "Exactly MAX_CALL_INPUT_SIZE input should not trigger CallInputTooLarge, got: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_aa_call_input_too_large_rejected() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let calls = vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: vec![0u8; MAX_CALL_INPUT_SIZE + 1].into(),
        }];

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .calls(calls)
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                let is_oversized = matches!(err, InvalidPoolTransactionError::OversizedData { .. });
                let is_call_input_too_large = matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::CallInputTooLarge { .. })
                );
                assert!(
                    is_oversized || is_call_input_too_large,
                    "Expected OversizedData or CallInputTooLarge error, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome, got: {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn test_aa_exactly_max_access_list_accounts_accepted() {
        use alloy_eips::eip2930::{AccessList, AccessListItem};

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let items: Vec<AccessListItem> = (0..MAX_ACCESS_LIST_ACCOUNTS)
            .map(|_| AccessListItem {
                address: Address::random(),
                storage_keys: vec![],
            })
            .collect();

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .access_list(AccessList(items))
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::TooManyAccessListAccounts { .. })
                ),
                "Exactly MAX_ACCESS_LIST_ACCOUNTS should not trigger TooManyAccessListAccounts, got: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_aa_too_many_access_list_accounts_rejected() {
        use alloy_eips::eip2930::{AccessList, AccessListItem};

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let items: Vec<AccessListItem> = (0..MAX_ACCESS_LIST_ACCOUNTS + 1)
            .map(|_| AccessListItem {
                address: Address::random(),
                storage_keys: vec![],
            })
            .collect();

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .access_list(AccessList(items))
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::TooManyAccessListAccounts { .. })
                    ),
                    "Expected TooManyAccessListAccounts error, got: {err:?}"
                );
            }
            _ => panic!(
                "Expected Invalid outcome with TooManyAccessListAccounts error, got: {outcome:?}"
            ),
        }
    }

    #[tokio::test]
    async fn test_aa_exactly_max_storage_keys_per_account_accepted() {
        use alloy_eips::eip2930::{AccessList, AccessListItem};

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let items = vec![AccessListItem {
            address: Address::random(),
            storage_keys: (0..MAX_STORAGE_KEYS_PER_ACCOUNT)
                .map(|_| B256::random())
                .collect(),
        }];

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .access_list(AccessList(items))
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::TooManyStorageKeysPerAccount { .. })
                ),
                "Exactly MAX_STORAGE_KEYS_PER_ACCOUNT should not trigger TooManyStorageKeysPerAccount, got: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_aa_too_many_storage_keys_per_account_rejected() {
        use alloy_eips::eip2930::{AccessList, AccessListItem};

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let items = vec![AccessListItem {
            address: Address::random(),
            storage_keys: (0..MAX_STORAGE_KEYS_PER_ACCOUNT + 1)
                .map(|_| B256::random())
                .collect(),
        }];

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .access_list(AccessList(items))
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::TooManyStorageKeysPerAccount { .. })
                    ),
                    "Expected TooManyStorageKeysPerAccount error, got: {err:?}"
                );
            }
            _ => panic!(
                "Expected Invalid outcome with TooManyStorageKeysPerAccount error, got: {outcome:?}"
            ),
        }
    }

    #[tokio::test]
    async fn test_aa_exactly_max_total_storage_keys_accepted() {
        use alloy_eips::eip2930::{AccessList, AccessListItem};

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let keys_per_account = MAX_STORAGE_KEYS_PER_ACCOUNT;
        let num_accounts = MAX_ACCESS_LIST_STORAGE_KEYS_TOTAL / keys_per_account;
        let items: Vec<AccessListItem> = (0..num_accounts)
            .map(|_| AccessListItem {
                address: Address::random(),
                storage_keys: (0..keys_per_account).map(|_| B256::random()).collect(),
            })
            .collect();
        assert_eq!(
            items.iter().map(|i| i.storage_keys.len()).sum::<usize>(),
            MAX_ACCESS_LIST_STORAGE_KEYS_TOTAL
        );

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .access_list(AccessList(items))
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        if let TransactionValidationOutcome::Invalid(_, ref err) = outcome {
            assert!(
                !matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::TooManyTotalStorageKeys { .. })
                ),
                "Exactly MAX_ACCESS_LIST_STORAGE_KEYS_TOTAL should not trigger TooManyTotalStorageKeys, got: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_aa_too_many_total_storage_keys_rejected() {
        use alloy_eips::eip2930::{AccessList, AccessListItem};

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let keys_per_account = MAX_STORAGE_KEYS_PER_ACCOUNT;
        let num_accounts = MAX_ACCESS_LIST_STORAGE_KEYS_TOTAL / keys_per_account;
        let mut items: Vec<AccessListItem> = (0..num_accounts)
            .map(|_| AccessListItem {
                address: Address::random(),
                storage_keys: (0..keys_per_account).map(|_| B256::random()).collect(),
            })
            .collect();
        items.push(AccessListItem {
            address: Address::random(),
            storage_keys: vec![B256::random()],
        });
        assert_eq!(
            items.iter().map(|i| i.storage_keys.len()).sum::<usize>(),
            MAX_ACCESS_LIST_STORAGE_KEYS_TOTAL + 1
        );

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(address!("0000000000000000000000000000000000000002"))
            .gas_limit(TEMPO_T1_TX_GAS_LIMIT_CAP)
            .access_list(AccessList(items))
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(
                    matches!(
                        err.downcast_other_ref::<TempoPoolTransactionError>(),
                        Some(TempoPoolTransactionError::TooManyTotalStorageKeys { .. })
                    ),
                    "Expected TooManyTotalStorageKeys error, got: {err:?}"
                );
            }
            _ => panic!(
                "Expected Invalid outcome with TooManyTotalStorageKeys error, got: {outcome:?}"
            ),
        }
    }

    #[test]
    fn test_ensure_intrinsic_gas_tempo_tx_below_intrinsic_gas() {
        use tempo_chainspec::hardfork::TempoHardfork;

        let tx = TxBuilder::eip1559(Address::random())
            .gas_limit(1)
            .build_eip1559();

        let result = ensure_intrinsic_gas_tempo_tx(&tx, TempoHardfork::T1);
        assert!(
            matches!(result, Err(InvalidPoolTransactionError::IntrinsicGasTooLow)),
            "Expected IntrinsicGasTooLow, got: {result:?}"
        );
    }

    #[test]
    fn test_ensure_intrinsic_gas_tempo_tx_exactly_at_intrinsic_gas() {
        use tempo_chainspec::hardfork::TempoHardfork;
        use tempo_revm::gas_params::tempo_gas_params;

        let spec = TempoHardfork::T1;
        let tx_probe = TxBuilder::eip1559(Address::random())
            .gas_limit(1_000_000)
            .build_eip1559();

        let gas_params = tempo_gas_params(spec);
        let mut gas = gas_params.initial_tx_gas(
            tx_probe.input(),
            tx_probe.is_create(),
            tx_probe.access_list().map(|l| l.len()).unwrap_or_default() as u64,
            tx_probe
                .access_list()
                .map(|l| l.iter().map(|i| i.storage_keys.len()).sum::<usize>())
                .unwrap_or_default() as u64,
            tx_probe
                .authorization_list()
                .map(|l| l.len())
                .unwrap_or_default() as u64,
        );
        if spec.is_t1() && tx_probe.nonce() == 0 {
            gas.initial_gas += gas_params.get(GasId::new_account_cost());
        }
        let intrinsic = std::cmp::max(gas.initial_gas, gas.floor_gas);

        let tx_exact = TxBuilder::eip1559(Address::random())
            .gas_limit(intrinsic)
            .build_eip1559();

        let result = ensure_intrinsic_gas_tempo_tx(&tx_exact, spec);
        assert!(
            result.is_ok(),
            "Gas limit exactly at intrinsic gas should pass, got: {result:?}"
        );

        let tx_below = TxBuilder::eip1559(Address::random())
            .gas_limit(intrinsic - 1)
            .build_eip1559();

        let result = ensure_intrinsic_gas_tempo_tx(&tx_below, spec);
        assert!(
            matches!(result, Err(InvalidPoolTransactionError::IntrinsicGasTooLow)),
            "Gas limit one below intrinsic gas should fail, got: {result:?}"
        );
    }
}
