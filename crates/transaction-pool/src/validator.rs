use crate::{
    amm::AmmLiquidityCache,
    state_cache::{StateCache, StateCacheDb},
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
};

use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_evm::{Database, EvmEnv};
use alloy_primitives::{Address, B256};
use parking_lot::RwLock;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_evm::ConfigureEvm;
use reth_primitives_traits::{
    Account, Bytecode, SealedBlock, transaction::error::InvalidTransactionError,
};
use reth_provider::BlockReaderIdExt;
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{
    AccountReader, BytecodeReader, StateProvider, StateProviderBox, StateProviderFactory,
    errors::{ProviderError, ProviderResult},
};
use reth_transaction_pool::{
    EthTransactionValidator, PoolTransaction, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidator, error::InvalidPoolTransactionError,
};
use revm::{
    DatabaseRef,
    context::{
        ContextTr, JournalTr,
        result::{EVMError, InvalidTransaction},
    },
};
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};
use tempo_chainspec::hardfork::{TempoHardfork, TempoHardforks};
use tempo_evm::{TempoEvmConfig, evm::TempoEvm};
use tempo_precompiles::{
    nonce::{INonce, NonceManager},
    storage::StorageActions,
};
use tempo_primitives::{
    Block, TempoHeader,
    subblock::has_sub_block_nonce_key_prefix,
    transaction::{TEMPO_EXPIRING_NONCE_KEY, TempoTransaction},
};
use tempo_revm::{
    TempoBlockEnv, TempoInvalidTransaction, TempoStateAccess, error::FeePaymentError,
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
    /// Cached EVM environment from the latest tip block, updated on each `on_new_head_block`.
    cached_evm_env: RwLock<EvmEnv<TempoHardfork, TempoBlockEnv>>,
    /// Tip hash and cache of state reads shared across validation calls, replaced on each
    /// `on_new_head_block`.
    cached_state: RwLock<(B256, Arc<StateCache>)>,
    /// The Tempo hardfork active at the current tip, stored as an index into
    /// [`TempoHardfork::VARIANTS`] and updated on each `on_new_head_block`.
    ///
    /// Cached here so hot paths can resolve the active hardfork with a single atomic load
    /// instead of walking the chain spec's fork schedule.
    active_hardfork: AtomicU8,
}

impl<Client> TempoTransactionValidator<Client>
where
    Client: ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + StateProviderFactory,
{
    pub fn new(
        inner: EthTransactionValidator<Client, TempoPooledTransaction, TempoEvmConfig>,
        aa_valid_after_max_secs: u64,
        max_tempo_authorizations: usize,
        amm_liquidity_cache: AmmLiquidityCache,
    ) -> Self
    where
        Client: BlockReaderIdExt<Header = TempoHeader>,
    {
        let latest_header = inner
            .client()
            .latest_header()
            .expect("failed to fetch latest header")
            .expect("latest header is None");
        let evm_env = inner
            .evm_config()
            .evm_env(latest_header.header())
            .expect("failed constructing EvmEnv from latest header");
        let active_hardfork = AtomicU8::new(evm_env.cfg_env.spec.variant_index());
        Self {
            inner,
            aa_valid_after_max_secs,
            max_tempo_authorizations,
            amm_liquidity_cache,
            cached_evm_env: parking_lot::RwLock::new(evm_env),
            cached_state: RwLock::new((latest_header.hash(), Arc::new(StateCache::default()))),
            active_hardfork,
        }
    }

    /// Returns the Tempo hardfork active at the current tip.
    ///
    /// Updated on each `on_new_head_block`.
    pub fn active_hardfork(&self) -> TempoHardfork {
        TempoHardfork::from_variant_index(self.active_hardfork.load(Ordering::Relaxed))
            .expect("stored hardfork index is valid")
    }

    /// Obtains a clone of the shared [`AmmLiquidityCache`].
    pub fn amm_liquidity_cache(&self) -> AmmLiquidityCache {
        self.amm_liquidity_cache.clone()
    }

    /// Returns the configured client
    pub fn client(&self) -> &Client {
        self.inner.client()
    }

    /// Pool-only time-bound admission checks.
    ///
    /// These enforce propagation-liveness constraints that are stricter than the EVM's
    /// block-timestamp checks:
    /// - `valid_before` must be far enough in the future (propagation buffer)
    /// - `valid_after` must not be too far in the future (wall-clock bound)
    fn ensure_pool_time_bounds(
        &self,
        tx: &TempoTransaction,
    ) -> Result<(), TempoPoolTransactionError> {
        let tip_timestamp = self.inner.fork_tracker().tip_timestamp();

        // Reject AA txs where `valid_before` is too close to current time (or already expired).
        // The EVM checks `valid_before > block_timestamp` but the pool needs an extra
        // propagation buffer to prevent txs from expiring at peers with slightly newer tips.
        if let Some(valid_before) = tx.valid_before {
            let valid_before = valid_before.get();
            let min_allowed = tip_timestamp.saturating_add(AA_VALID_BEFORE_MIN_SECS);
            if valid_before <= min_allowed {
                return Err(TempoPoolTransactionError::InvalidValidBefore {
                    valid_before,
                    min_allowed,
                });
            }
        }

        // Reject AA txs where `valid_after` is too far in the future.
        // Uses wall-clock time to avoid rejecting valid txs when node is lagging.
        if let Some(valid_after) = tx.valid_after {
            let valid_after = valid_after.get();
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

        // Check number of calls
        if tx.calls.len() > MAX_AA_CALLS {
            return Err(TempoPoolTransactionError::TooManyCalls {
                count: tx.calls.len(),
                max_allowed: MAX_AA_CALLS,
            });
        }

        // Check each call's input size
        for (idx, call) in tx.calls.iter().enumerate() {
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

        // Check key_authorization cardinality limits (DoS protection).
        // Semantic validation (duplicates, zero-address, TIP-20, u128 cap) is handled by the
        // EVM precompile via `validate_with_evm`.
        if let Some(ref key_auth) = tx.key_authorization {
            if let Some(limits) = &key_auth.limits
                && limits.len() > MAX_TOKEN_LIMITS
            {
                return Err(TempoPoolTransactionError::TooManyTokenLimits {
                    count: limits.len(),
                    max_allowed: MAX_TOKEN_LIMITS,
                });
            }

            if let Some(scopes) = &key_auth.allowed_calls {
                if scopes.len() > MAX_KEYCHAIN_CALL_SCOPES as usize {
                    return Err(TempoPoolTransactionError::Keychain(
                        "too many call scopes in key authorization",
                    ));
                }

                for scope in scopes {
                    if scope.selector_rules.len() > MAX_KEYCHAIN_SELECTOR_RULES_PER_SCOPE as usize {
                        return Err(TempoPoolTransactionError::Keychain(
                            "too many selector rules in call scope",
                        ));
                    }

                    for rule in &scope.selector_rules {
                        if rule.recipients.len() > MAX_KEYCHAIN_RECIPIENTS_PER_SELECTOR as usize {
                            return Err(TempoPoolTransactionError::Keychain(
                                "too many recipients in selector rule",
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates a batch of transactions against the same state snapshot.
    ///
    /// All transactions share one throwaway [`TempoEvm`] (journaled writes are discarded
    /// after each transaction while loaded state stays warm) and the validator's tip-scoped
    /// [`StateCache`], so repeated state reads are served from memory across transactions
    /// and across concurrent validation calls.
    fn validate_batch<P: StateProvider>(
        &self,
        state_provider: P,
        cached_state: Arc<StateCache>,
        transactions: impl IntoIterator<Item = (TransactionOrigin, TempoPooledTransaction)>,
    ) -> Vec<TransactionValidationOutcome<TempoPooledTransaction>> {
        let mut db = StateCacheDb::new(&cached_state, StateProviderDatabase::new(&state_provider));
        let evm_env = self.cached_evm_env.read().clone();

        // Create a throwaway EVM for the whole batch and run validation, reusing the same
        // validation logic that the block executor uses ([`TempoEvm::validate_transaction`]).
        // - Skip `valid_after` check: the pool intentionally accepts transactions with a
        //   future `valid_after` (queued until executable).
        // - Disable nonce check: the pool accepts future-nonce transactions (queued)
        //   and handles nonce ordering separately.
        // - Skip liquidity check: the pool performs its own liquidity validation against a cached view of the AMM state.
        let mut evm = TempoEvm::new(&mut db, evm_env);
        evm.inner_mut().skip_valid_after_check = true;
        evm.inner_mut().skip_liquidity_check = true;
        evm.ctx_mut().cfg.disable_nonce_check = true;

        transactions
            .into_iter()
            .map(|(origin, transaction)| {
                let outcome = self.validate_one_with_evm(origin, transaction, &mut evm);
                // Discard this transaction's journaled writes (nonce bumps, fee deduction,
                // key authorisation) while keeping loaded accounts and storage warm for the
                // rest of the batch.
                evm.ctx_mut().journal_mut().discard_tx();
                outcome
            })
            .collect()
    }

    /// Returns the latest state provider and a state cache valid for the provider's tip.
    fn latest_state_provider_and_cache(
        &self,
    ) -> ProviderResult<(StateProviderBox, Arc<StateCache>)> {
        let state_provider = self.inner.client().latest()?;
        let latest_hash = self.inner.client().chain_info()?.best_hash;
        Ok((state_provider, self.state_cache_for_tip(latest_hash)))
    }

    /// Returns the shared cache if it matches `tip_hash`, otherwise an empty ephemeral cache.
    ///
    /// A mismatch can happen when `.latest()` observes state for a newer canonical tip before
    /// `on_new_head_block` has refreshed the validator's cached state for that tip.
    fn state_cache_for_tip(&self, tip_hash: B256) -> Arc<StateCache> {
        let (cached_tip_hash, cached_state) = self.cached_state.read().clone();
        if cached_tip_hash == tip_hash {
            cached_state
        } else {
            Arc::new(StateCache::default())
        }
    }

    /// Validates one transaction with the given throwaway EVM.
    ///
    /// The caller is responsible for discarding the journaled writes afterwards.
    fn validate_one_with_evm<DB>(
        &self,
        origin: TransactionOrigin,
        transaction: TempoPooledTransaction,
        evm: &mut TempoEvm<DB>,
    ) -> TransactionValidationOutcome<TempoPooledTransaction>
    where
        DB: Database<Error = ProviderError> + DatabaseRef<Error = ProviderError>,
    {
        // Get the hardfork active at the current tip
        let spec = self.active_hardfork();

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

        // Validate AA transaction authorization list size (pool-only DoS limit).
        if let Err(err) = self.ensure_authorization_list_size(&transaction) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(err),
            );
        }

        // Validate AA transaction field limits (pool-only DoS limits: calls, access list, token limits).
        if let Err(err) = self.ensure_aa_field_limits(&transaction) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(err),
            );
        }

        // Pool-only time-bound checks: valid_before propagation buffer, valid_after max offset.
        if let Some(tx) = transaction.inner().as_aa()
            && let Err(err) = self.ensure_pool_time_bounds(tx.tx())
        {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(err),
            );
        }

        // Run the unified EVM validation pipeline.
        // This covers: non-zero value, keychain version, intrinsic gas, fee payer/token
        // resolution & validation, nonce checks (protocol, 2D, expiring), keychain
        // authorization, and balance checks.
        //
        // Returns resolved fee token and key expiry for pool caching.
        let result = if let Some(tx_env) = transaction.cached_tx_env() {
            evm.validate_transaction(tx_env.clone())
        } else {
            let result = evm.validate_transaction(transaction.tx_env_slow());
            transaction.cache_tx_env(core::mem::take(&mut evm.ctx_mut().tx));
            result
        };
        let validation_ctx = match result {
            Ok(ctx) => ctx,
            Err(err) => match err {
                EVMError::Transaction(err) => {
                    let err = match err {
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::LackOfFundForMaxFee { fee, balance },
                        ) => InvalidPoolTransactionError::Consensus(
                            InvalidTransactionError::InsufficientFunds((*balance, *fee).into()),
                        ),
                        err => {
                            InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(err))
                        }
                    };
                    return TransactionValidationOutcome::Invalid(transaction, err);
                }
                other => {
                    return TransactionValidationOutcome::Error(
                        *transaction.hash(),
                        Box::new(other),
                    );
                }
            },
        };

        // Cache the resolved fee token from EVM validation for pool maintenance.
        transaction.set_resolved_fee_token(validation_ctx.fee_token);

        // Pool-only key-expiry propagation buffer: reject keychain txs whose key
        // expires too soon (within AA_VALID_BEFORE_MIN_SECS of tip timestamp).
        if let Some(key_expiry) = validation_ctx.key_expiry {
            let min_allowed = self
                .inner
                .fork_tracker()
                .tip_timestamp()
                .saturating_add(AA_VALID_BEFORE_MIN_SECS);
            if key_expiry <= min_allowed {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::other(
                        TempoPoolTransactionError::AccessKeyExpired {
                            expiry: key_expiry,
                            min_allowed,
                        },
                    ),
                );
            }

            // Cache the key expiry for pool maintenance eviction.
            transaction.set_key_expiry(Some(key_expiry));
        }

        // Validate that transaction has enough liquidity against at least one of the recent validator tokens.
        let fee = transaction.fee_token_cost();
        match self.amm_liquidity_cache.has_enough_liquidity(
            validation_ctx.fee_token,
            fee,
            evm.db_mut(),
        ) {
            Ok(true) => {}
            Ok(false) => {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::CollectFeePreTx(
                            FeePaymentError::InsufficientAmmLiquidity {
                                user_token: Some(validation_ctx.fee_token),
                                validator_token: None,
                                fee,
                            },
                        ),
                    )),
                );
            }
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        }

        // Delegate to the inner ETH validator for remaining checks
        // (chain_id, EIP-3607 code check, protocol nonce, etc.) and to produce
        // the Valid outcome with state_nonce and balance for pool ordering.
        let inner_validation = {
            let cached_state_provider = CachedAccountInfoReader::new(evm.db_ref());
            self.inner
                .validate_one_with_state_provider(origin, transaction, &cached_state_provider)
        };

        match inner_validation {
            TransactionValidationOutcome::Valid {
                balance,
                mut state_nonce,
                bytecode_hash,
                transaction,
                propagate,
                authorities,
            } => {
                let mut authorities = authorities;
                if let Some(aa_tx) = transaction.transaction().inner().as_aa() {
                    let mut recovered_aa_authorities = aa_tx
                        .tx()
                        .tempo_authorization_list
                        .iter()
                        .filter_map(|authorization| authorization.recover_authority().ok())
                        .collect::<Vec<_>>();

                    if !recovered_aa_authorities.is_empty() {
                        match authorities.as_mut() {
                            Some(existing_authorities) => {
                                existing_authorities.append(&mut recovered_aa_authorities)
                            }
                            None => authorities = Some(recovered_aa_authorities),
                        }
                    }
                }

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
                        // Expiring nonce transactions are validated by the EVM
                    } else {
                        // This is a 2D nonce transaction - validate against 2D nonce
                        state_nonce = match evm.db_mut().with_read_only_storage_ctx(
                            spec,
                            StorageActions::disabled(),
                            || {
                                NonceManager::new().get_nonce(INonce::getNonceCall {
                                    account: transaction.transaction().sender(),
                                    nonceKey: nonce_key,
                                })
                            },
                        ) {
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

                // Precompute the fee balance slot after validation has resolved the fee token.
                transaction.transaction().fee_balance_slot();

                // Precompute nonce storage slots for this transaction.
                let _ = transaction.transaction().expiring_nonce_slot();
                let _ = transaction.transaction().nonce_key_slot();

                // Warm the global keccak cache with storage slot hashes for this transaction.
                transaction.transaction().precalculate_keccak_slots();

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
    Client: ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + StateProviderFactory,
{
    type Transaction = TempoPooledTransaction;
    type Block = Block;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        let (state_provider, cached_state) = match self.latest_state_provider_and_cache() {
            Ok(provider_and_cache) => provider_and_cache,
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        };

        self.validate_batch(
            state_provider,
            cached_state,
            core::iter::once((origin, transaction)),
        )
        .pop()
        .expect("validate_batch returns one outcome per transaction")
    }

    async fn validate_transactions(
        &self,
        transactions: impl IntoIterator<Item = (TransactionOrigin, Self::Transaction), IntoIter: Send>
        + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        let (state_provider, cached_state) = match self.latest_state_provider_and_cache() {
            Ok(provider_and_cache) => provider_and_cache,
            Err(err) => {
                return transactions
                    .into_iter()
                    .map(|(_, tx)| {
                        TransactionValidationOutcome::Error(*tx.hash(), Box::new(err.clone()))
                    })
                    .collect();
            }
        };

        self.validate_batch(state_provider, cached_state, transactions)
    }

    async fn validate_transactions_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: impl IntoIterator<Item = Self::Transaction> + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        let (state_provider, cached_state) = match self.latest_state_provider_and_cache() {
            Ok(provider_and_cache) => provider_and_cache,
            Err(err) => {
                return transactions
                    .into_iter()
                    .map(|tx| {
                        TransactionValidationOutcome::Error(*tx.hash(), Box::new(err.clone()))
                    })
                    .collect();
            }
        };

        self.validate_batch(
            state_provider,
            cached_state,
            transactions.into_iter().map(|tx| (origin, tx)),
        )
    }

    fn on_new_head_block(&self, new_tip_block: &SealedBlock<Self::Block>) {
        self.inner.on_new_head_block(new_tip_block);

        // Cache the EVM environment for the new tip block.
        let evm_env = self
            .inner
            .evm_config()
            .evm_env(new_tip_block.header())
            .expect("invalid block in on_new_head_block");
        self.active_hardfork
            .store(evm_env.cfg_env.spec.variant_index(), Ordering::Relaxed);
        *self.cached_evm_env.write() = evm_env;

        // State changed, drop all cached reads and anchor the new cache to this tip.
        *self.cached_state.write() = (new_tip_block.hash(), Arc::new(StateCache::default()));
    }
}

/// Adapts a cached revm database back into the account info reader interface
/// expected by the inner ETH transaction validator.
struct CachedAccountInfoReader<DB> {
    db: DB,
}

impl<DB> CachedAccountInfoReader<DB> {
    const fn new(db: DB) -> Self {
        Self { db }
    }
}

impl<DB> AccountReader for CachedAccountInfoReader<DB>
where
    DB: DatabaseRef<Error = ProviderError>,
{
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        Ok(self.db.basic_ref(*address)?.map(|account| Account {
            nonce: account.nonce,
            balance: account.balance,
            bytecode_hash: (account.code_hash != KECCAK_EMPTY).then_some(account.code_hash),
        }))
    }
}

impl<DB> BytecodeReader for CachedAccountInfoReader<DB>
where
    DB: DatabaseRef<Error = ProviderError>,
{
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        Ok(Some(Bytecode(self.db.code_by_hash_ref(*code_hash)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::TxBuilder, transaction::TempoPoolTransactionError};
    use alloy_consensus::{Header, Signed, Transaction, TxLegacy};
    use alloy_primitives::{Address, B256, TxKind, U256, address, uint};
    use alloy_signer::Signature;
    use reth_chainspec::EthChainSpec;
    use reth_primitives_traits::{Account, Bytecode, SignedTransaction};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_revm::cached::CachedReads;
    use reth_storage_api::{AccountReader, BlockNumReader, BytecodeReader};
    use reth_transaction_pool::{
        PoolTransaction, blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
    };
    use revm::{DatabaseRef, context::result::InvalidTransaction};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tempo_chainspec::{
        TempoChainSpec,
        spec::{MODERATO, TEMPO_T0_BASE_FEE, TEMPO_T1_BASE_FEE, TEMPO_T1_TX_GAS_LIMIT_CAP},
    };
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        tip20::{TIP20Token, slots as tip20_slots},
    };
    use tempo_primitives::{
        Block, TempoHeader, TempoPrimitives, TempoTxEnvelope, TempoTxType,
        transaction::{
            TempoTransaction,
            envelope::TEMPO_SYSTEM_TX_SIGNATURE,
            tempo_transaction::Call,
            tt_signature::{PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        },
    };

    /// Arbitrary validity window (in seconds) used for expiring-nonce transactions in tests.
    const TEST_VALIDITY_WINDOW: u64 = 25;

    struct CountingDatabaseRef {
        address: Address,
        code_hash: B256,
        account: revm::state::AccountInfo,
        bytecode: revm::bytecode::Bytecode,
        account_reads: Arc<AtomicUsize>,
        bytecode_reads: Arc<AtomicUsize>,
    }

    impl DatabaseRef for CountingDatabaseRef {
        type Error = ProviderError;

        fn basic_ref(
            &self,
            address: Address,
        ) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
            self.account_reads.fetch_add(1, Ordering::Relaxed);
            Ok((address == self.address).then(|| self.account.clone()))
        }

        fn code_by_hash_ref(
            &self,
            code_hash: B256,
        ) -> Result<revm::bytecode::Bytecode, Self::Error> {
            self.bytecode_reads.fetch_add(1, Ordering::Relaxed);
            Ok(if code_hash == self.code_hash {
                self.bytecode.clone()
            } else {
                Default::default()
            })
        }

        fn storage_ref(&self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
            Ok(U256::ZERO)
        }

        fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
    }

    #[test]
    fn cached_account_info_reader_uses_native_cached_reads() {
        let address = Address::random();
        let code_hash = B256::random();
        let account = Account {
            nonce: 7,
            balance: U256::from(42),
            bytecode_hash: Some(code_hash),
        };
        let bytecode = revm::bytecode::Bytecode::default();
        let account_reads = Arc::new(AtomicUsize::new(0));
        let bytecode_reads = Arc::new(AtomicUsize::new(0));
        let provider = CountingDatabaseRef {
            address,
            code_hash,
            account: revm::state::AccountInfo::new(
                account.balance,
                account.nonce,
                code_hash,
                bytecode.clone(),
            ),
            bytecode: bytecode.clone(),
            account_reads: account_reads.clone(),
            bytecode_reads: bytecode_reads.clone(),
        };
        let mut cached_reads = CachedReads::default();
        let cached = CachedAccountInfoReader::new(cached_reads.as_db(provider));

        assert_eq!(cached.basic_account(&address).unwrap(), Some(account));
        assert_eq!(cached.basic_account(&address).unwrap(), Some(account));
        assert_eq!(account_reads.load(Ordering::Relaxed), 1);

        assert_eq!(
            cached.bytecode_by_hash(&code_hash).unwrap(),
            Some(Bytecode(bytecode.clone()))
        );
        assert_eq!(
            cached.bytecode_by_hash(&code_hash).unwrap(),
            Some(Bytecode(bytecode))
        );
        assert_eq!(bytecode_reads.load(Ordering::Relaxed), 1);
    }

    /// Helper to create a mock sealed block with the given timestamp.
    fn create_mock_block(timestamp: u64) -> SealedBlock<Block> {
        let header = TempoHeader {
            inner: Header {
                timestamp,
                gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                excess_blob_gas: Some(0),
                base_fee_per_gas: Some(TEMPO_T0_BASE_FEE),
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
            EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::moderato())
                .with_custom_tx_type(TempoTxType::AA as u8)
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

    #[test]
    fn state_cache_for_tip_reuses_only_matching_tip_cache() {
        let tx = TxBuilder::eip1559(Address::random()).build_eip1559();
        let validator = setup_validator(&tx, 1);
        let (shared_tip_hash, shared_cache) = validator.cached_state.read().clone();

        let matching_cache = validator.state_cache_for_tip(shared_tip_hash);
        assert!(Arc::ptr_eq(&matching_cache, &shared_cache));

        let mismatched_tip_hash = if shared_tip_hash == B256::repeat_byte(0x42) {
            B256::repeat_byte(0x43)
        } else {
            B256::repeat_byte(0x42)
        };
        let ephemeral_cache = validator.state_cache_for_tip(mismatched_tip_hash);
        assert!(!Arc::ptr_eq(&ephemeral_cache, &shared_cache));
    }

    #[test]
    fn latest_state_provider_uses_ephemeral_cache_when_tip_hash_mismatches_latest() {
        let tx = TxBuilder::eip1559(Address::random()).build_eip1559();
        let validator = setup_validator(&tx, 1);
        let latest_hash = validator.client().chain_info().unwrap().best_hash;
        let mismatched_tip_hash = if latest_hash == B256::repeat_byte(0x42) {
            B256::repeat_byte(0x43)
        } else {
            B256::repeat_byte(0x42)
        };
        let shared_cache = Arc::new(StateCache::default());
        *validator.cached_state.write() = (mismatched_tip_hash, shared_cache.clone());

        let (_, validation_cache) = validator.latest_state_provider_and_cache().unwrap();

        assert!(!Arc::ptr_eq(&validation_cache, &shared_cache));
    }

    #[tokio::test]
    async fn test_aa_authorization_list_authorities_tracked() {
        use alloy_eips::eip7702::Authorization;
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;
        use tempo_primitives::transaction::{
            TempoSignedAuthorization,
            tt_signature::{PrimitiveSignature, TempoSignature},
        };

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let authority_signer = PrivateKeySigner::random();
        let expected_authority = authority_signer.address();
        let authorization = Authorization {
            chain_id: U256::from(1),
            nonce: 0,
            address: Address::random(),
        };
        let signature = authority_signer
            .sign_hash_sync(&authorization.signature_hash())
            .expect("authorization signing should succeed");
        let tempo_authorization = TempoSignedAuthorization::new_unchecked(
            authorization,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
        );

        let transaction = TxBuilder::aa(Address::random())
            .fee_token(PATH_USD_ADDRESS)
            .authorization_list(vec![tempo_authorization])
            .build();
        let validator = setup_validator(&transaction, current_time);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Valid { authorities, .. } => {
                let authorities = authorities.expect(
                    "AA transactions with tempo_authorization_list should return authorities",
                );
                assert!(
                    authorities.contains(&expected_authority),
                    "AA authority recovered from tempo_authorization_list must be tracked"
                );
            }
            other => panic!("Expected Valid outcome with recovered authorities, got: {other:?}"),
        }
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::ValueTransferNotAllowed
                    ))
                ));
            }
            _ => panic!("Expected Invalid outcome with Evm error, got: {outcome:?}"),
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::InvalidFeePayerSignature
                    ))
                ));
            }
            _ => panic!("Expected Invalid outcome with Evm error, got: {outcome:?}"),
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
        let validator = setup_validator(&transaction, u64::MAX);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        match outcome {
            TransactionValidationOutcome::Invalid(_, ref err) => {
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::SelfSponsoredFeePayer
                    ))
                ));
            }
            _ => panic!("Expected Invalid outcome with Evm error, got: {outcome:?}"),
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
                chain_id: MODERATO.chain_id(),
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                        )
                    ))
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
                Some(TempoPoolTransactionError::Evm(
                    TempoInvalidTransaction::EthInvalidTransaction(
                        InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                    )
                ))
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
                Some(core::num::NonZeroU64::new(current_time + TEST_VALIDITY_WINDOW).unwrap())
            } else {
                None
            };

            let tx = TempoTransaction {
                chain_id: MODERATO.chain_id(),
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
                        Some(TempoPoolTransactionError::Evm(
                            TempoInvalidTransaction::EthInvalidTransaction(
                                InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                            )
                        ))
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
                        Some(TempoPoolTransactionError::Evm(
                            TempoInvalidTransaction::EthInvalidTransaction(
                                InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                            )
                        ))
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                        )
                    ))
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                        )
                    ))
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
                valid_before: Some(core::num::NonZeroU64::new(current_time + 25).unwrap()), // Valid for 25 seconds
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
                Some(TempoPoolTransactionError::Evm(
                    TempoInvalidTransaction::EthInvalidTransaction(
                        InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                    )
                ))
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
                chain_id: MODERATO.chain_id(),
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
                Some(TempoPoolTransactionError::Evm(
                    TempoInvalidTransaction::EthInvalidTransaction(
                        InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                    )
                ))
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
                Some(TempoPoolTransactionError::Evm(
                    TempoInvalidTransaction::EthInvalidTransaction(
                        InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                    )
                ))
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                        )
                    ))
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
                Some(TempoPoolTransactionError::Evm(
                    TempoInvalidTransaction::EthInvalidTransaction(
                        InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                    )
                ))
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::ValueTransferNotAllowed
                    ))
                ));
            }
            _ => panic!("Expected Invalid outcome with Evm error, got: {outcome:?}"),
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::FeeTokenNotTip20 { .. }
                    ))
                ));
            }
            _ => panic!("Expected Invalid outcome with Evm error, got: {outcome:?}"),
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
                        Some(TempoPoolTransactionError::Evm(
                            TempoInvalidTransaction::EthInvalidTransaction(
                                InvalidTransaction::GasPriceLessThanBasefee
                            )
                        ))
                    ),
                    "Expected Evm error, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome with Evm error, got: {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn test_fee_cap_at_min_base_fee_passes() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create a transaction with max_fee_per_gas exactly at the fixed T1+ minimum.
        let transaction = TxBuilder::aa(Address::random())
            .max_fee(u128::from(TEMPO_T1_BASE_FEE))
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::GasPriceLessThanBasefee
                        )
                    ))
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::GasPriceLessThanBasefee
                        )
                    ))
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
                        Some(TempoPoolTransactionError::Evm(
                            TempoInvalidTransaction::EthInvalidTransaction(
                                InvalidTransaction::GasPriceLessThanBasefee
                            )
                        ))
                    ),
                    "Expected Evm error for EIP-1559 tx, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome with Evm error, got: {outcome:?}"),
        }
    }

    mod keychain_validation {
        use super::*;
        use reth_transaction_pool::error::PoolTransactionError;

        #[test]
        fn test_legacy_keychain_post_t1c_is_bad_transaction() {
            assert!(
                TempoPoolTransactionError::Evm(TempoInvalidTransaction::LegacyKeychainSignature)
                    .is_bad_transaction(),
                "Post-T1C V1 rejection should be a bad transaction (permanent)"
            );
        }

        #[test]
        fn test_v2_keychain_pre_t1c_is_not_bad_transaction() {
            assert!(
                !TempoPoolTransactionError::Evm(
                    TempoInvalidTransaction::V2KeychainBeforeActivation
                )
                .is_bad_transaction(),
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
                        Some(TempoPoolTransactionError::Evm(
                            TempoInvalidTransaction::CallsValidation(_)
                        ))
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
                        Some(TempoPoolTransactionError::Evm(
                            TempoInvalidTransaction::CallsValidation(_)
                        ))
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
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::CallsValidation(_)
                    ))
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
                        Some(TempoPoolTransactionError::Evm(
                            TempoInvalidTransaction::CallsValidation(_)
                        ))
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
                        Some(TempoPoolTransactionError::Evm(
                            TempoInvalidTransaction::CallsValidation(_)
                        ))
                    ),
                    "Expected CreateCallWithAuthorizationList error, got: {err:?}"
                );
            }
            _ => panic!("Expected Invalid outcome, got: {outcome:?}"),
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
        let result = state.is_fee_token_paused(spec, fee_token, StorageActions::disabled());
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
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                        )
                    ))
                ))
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
            .gas_limit(1_000_000) // Well above intrinsic gas
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
                assert!(matches!(
                    err.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                        )
                    ))
                ));
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
            amm_cache.has_enough_liquidity(paused_validator_token, U256::from(1000), &state);
        assert!(
            liquidity_result.is_ok() && liquidity_result.unwrap(),
            "Token in unique_tokens should bypass liquidity check and return true"
        );

        // BUT the pause check in is_fee_token_paused should catch it BEFORE the bypass
        let is_paused =
            state.is_fee_token_paused(spec, paused_validator_token, StorageActions::disabled());
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
}
