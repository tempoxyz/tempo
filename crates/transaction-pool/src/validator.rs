use crate::{
    amm::AmmLiquidityCache,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
};

use alloy_evm::EvmEnv;
use parking_lot::RwLock;
use reth_chainspec::ChainSpecProvider;
use reth_evm::ConfigureEvm;
use reth_primitives_traits::{SealedBlock, transaction::error::InvalidTransactionError};
use reth_provider::BlockReaderIdExt;
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{StateProvider, StateProviderFactory, errors::ProviderError};
use reth_transaction_pool::{
    EthTransactionValidator, PoolTransaction, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidator, error::InvalidPoolTransactionError,
};
use revm::context::result::{EVMError, InvalidTransaction};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
};
use tempo_evm::{TempoEvmConfig, evm::TempoEvm};
use tempo_precompiles::nonce::{INonce, NonceManager};
use tempo_primitives::{
    Block, TempoHeader,
    subblock::has_sub_block_nonce_key_prefix,
    transaction::{TEMPO_EXPIRING_NONCE_KEY, TempoTransaction},
};
use tempo_revm::{
    TempoBlockEnv, TempoInvalidTransaction, TempoStateAccess, ValidationContext,
    error::FeePaymentError,
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
    ) -> Self
    where
        Client: BlockReaderIdExt<Header = TempoHeader>,
    {
        let evm_env = inner
            .evm_config()
            .evm_env(
                inner
                    .client()
                    .latest_header()
                    .expect("failed to fetch latest header")
                    .expect("latest header is None")
                    .header(),
            )
            .expect("failed constructing EvmEnv from latest header");
        Self {
            inner,
            aa_valid_after_max_secs,
            max_tempo_authorizations,
            amm_liquidity_cache,
            cached_evm_env: parking_lot::RwLock::new(evm_env),
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

    /// Runs the Tempo EVM validation pipeline against the given state, reusing the
    /// same validation logic that the block executor uses
    /// ([`TempoEvm::validate_transaction`]).
    ///
    /// A throwaway [`TempoEvm`] is created over a [`StateProviderDatabase`]; all state
    /// mutations (nonce bumps, fee deduction, key authorisation) are applied to the
    /// journal and discarded when the EVM is dropped.
    fn validate_with_evm(
        &self,
        transaction: &TempoPooledTransaction,
        state_provider: impl StateProvider,
    ) -> Result<ValidationContext, EVMError<ProviderError, TempoInvalidTransaction>> {
        let evm_env = self.cached_evm_env.read().clone();

        // Create a throwaway EVM and run validation.
        // - Skip `valid_after` check: the pool intentionally accepts transactions with a
        //   future `valid_after` (queued until executable).
        // - Disable nonce check: the pool accepts future-nonce transactions (queued)
        //   and handles nonce ordering separately.
        // - Skip liquidity check: the pool performs its own liquidity validation against a cached view of the AMM state.
        let mut evm = TempoEvm::new(StateProviderDatabase::new(state_provider), evm_env);
        evm.inner_mut().skip_valid_after_check = true;
        evm.inner_mut().skip_liquidity_check = true;
        evm.ctx_mut().cfg.disable_nonce_check = true;
        evm.validate_transaction(transaction.tx_env().clone())
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
        let validation_ctx = match self.validate_with_evm(&transaction, &state_provider) {
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
            &mut state_provider,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::CollectFeePreTx(
                            FeePaymentError::InsufficientAmmLiquidity { fee },
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
                        // Expiring nonce transactions are validated by the EVM
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
        self.inner.on_new_head_block(new_tip_block);

        // Cache the EVM environment for the new tip block.
        *self.cached_evm_env.write() = self
            .inner
            .evm_config()
            .evm_env(new_tip_block.header())
            .expect("invalid block in on_new_head_block");
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
    use reth_primitives_traits::SignedTransaction;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_transaction_pool::{
        PoolTransaction, blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
    };
    use revm::context::result::InvalidTransaction;
    use std::sync::Arc;
    use tempo_chainspec::spec::{MODERATO, TEMPO_T0_BASE_FEE, TEMPO_T1_TX_GAS_LIMIT_CAP};
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        tip20::{TIP20Token, slots as tip20_slots},
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

    /// Arbitrary validity window (in seconds) used for expiring-nonce transactions in tests.
    const TEST_VALIDITY_WINDOW: u64 = 25;

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
                Some(current_time + TEST_VALIDITY_WINDOW)
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
                        TempoInvalidTransaction::InvalidFeeToken(_)
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
            let key_auth = KeyAuthorization {
                chain_id: 42431, // MODERATO chain_id
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None, // never expires
                limits: None, // unlimited
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: Some(vec![TokenLimit {
                    token: fee_token,
                    limit: U256::ZERO,
                    period: 0,
                }]),
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: Some(vec![]),
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: Some(vec![TokenLimit {
                    token: non_fee_token,
                    limit: U256::MAX,
                    period: 0,
                }]),
                allowed_calls: None,
            };

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
            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: Some(vec![
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
                ]),
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: Some(vec![
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
                ]),
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: Some(vec![TokenLimit {
                    token: resolved_fee_token,
                    limit: U256::MAX,
                    period: 0,
                }]),
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: Some(vec![TokenLimit {
                    token: fee_token,
                    limit: U256::ZERO,
                    period: 0,
                }]),
                allowed_calls: None,
            };

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
            for _ in 0..=MAX_CALL_SCOPES {
                scopes.push(CallScope {
                    target: Address::random(),
                    selector_rules: vec![],
                });
            }

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: Some(scopes),
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: Some(vec![TokenLimit {
                    token: fee_token,
                    limit: U256::from(u128::MAX) + U256::from(1_u8),
                    period: 0,
                }]),
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: Some(vec![
                    CallScope {
                        target: duplicate_target,
                        selector_rules: vec![],
                    },
                    CallScope {
                        target: duplicate_target,
                        selector_rules: vec![],
                    },
                ]),
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: Some(vec![CallScope {
                    target: address!("0000000000000000000000000000000000000001"),
                    selector_rules: vec![],
                }]),
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: Some(vec![CallScope {
                    target: address!("0000000000000000000000000000000000000002"),
                    selector_rules: vec![],
                }]),
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: Some(vec![CallScope {
                    target: address!("0000000000000000000000000000000000000001"),
                    selector_rules: vec![],
                }]),
            };

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
                KeyAuthorization {
                    chain_id: 42431,
                    key_type: SignatureType::Secp256k1,
                    key_id: access_key_address,
                    expiry: None,
                    limits: None,
                    allowed_calls: Some(vec![CallScope {
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
                },
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
                KeyAuthorization {
                    chain_id: 42431,
                    key_type: SignatureType::Secp256k1,
                    key_id: access_key_address,
                    expiry: None,
                    limits: None,
                    allowed_calls: Some(vec![CallScope {
                        target: PATH_USD_ADDRESS,
                        selector_rules: vec![SelectorRule {
                            selector: ITIP20::transferCall::SELECTOR,
                            recipients: vec![allowed_recipient],
                        }],
                    }]),
                },
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
                KeyAuthorization {
                    chain_id: 42431,
                    key_type: SignatureType::Secp256k1,
                    key_id: access_key_address,
                    expiry: None,
                    limits: None,
                    allowed_calls: Some(vec![CallScope {
                        target: PATH_USD_ADDRESS,
                        selector_rules: vec![SelectorRule {
                            selector: ITIP20::transferCall::SELECTOR,
                            recipients: vec![duplicate_recipient, duplicate_recipient],
                        }],
                    }]),
                },
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
                KeyAuthorization {
                    chain_id: 42431,
                    key_type: SignatureType::Secp256k1,
                    key_id: access_key_address,
                    expiry: None,
                    limits: None,
                    allowed_calls: Some(vec![CallScope {
                        target: address!("0000000000000000000000000000000000000042"),
                        selector_rules: vec![SelectorRule {
                            selector: ITIP20::transferCall::SELECTOR,
                            recipients: vec![address!("00000000000000000000000000000000000000aa")],
                        }],
                    }]),
                },
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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: Some(vec![CallScope {
                    target: undeployed_tip20,
                    selector_rules: vec![tempo_primitives::transaction::SelectorRule {
                        selector: [0xa9, 0x05, 0x9c, 0xbb],
                        recipients: vec![address!("00000000000000000000000000000000000000aa")],
                    }],
                }]),
            };

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

        // =====================================================================
        // call_scope_allows_call — pure function, exhaustive branch coverage
        // =====================================================================

        /// Shorthand to build a `CallScope`.
        fn scope(target: Address, rules: Vec<SelectorRule>) -> CallScope {
            CallScope {
                target,
                selector_rules: rules,
            }
        }

        /// Shorthand to build a `SelectorRule`.
        fn rule(sel: [u8; 4], recipients: Vec<Address>) -> SelectorRule {
            SelectorRule {
                selector: sel,
                recipients,
            }
        }

        const SEL_A: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
        const SEL_B: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

        /// Helper: call `call_scope_allows_call` with less boilerplate.
        fn allows(scopes: Option<&[CallScope]>, to: &TxKind, input: &[u8]) -> bool {
            TempoTransactionValidator::<
                MockEthProvider<TempoPrimitives, TempoChainSpec>,
            >::call_scope_allows_call(scopes, to, input)
        }

        /// Helper: build ABI-encoded input with selector + left-padded address.
        fn abi_input(sel: [u8; 4], recipient: Address) -> Vec<u8> {
            let mut input = Vec::from(sel);
            input.extend_from_slice(&[0u8; 12]);
            input.extend_from_slice(recipient.as_slice());
            input
        }

        #[test]
        fn test_call_scope_allows_call_branches() {
            let t = Address::repeat_byte(1);
            let allowed = Address::repeat_byte(0x11);
            let denied = Address::repeat_byte(0x22);

            // None scopes → allow any call
            assert!(allows(None, &TxKind::Call(t), &[]));

            // Empty scopes → deny all
            assert!(!allows(Some(&[]), &TxKind::Call(t), &[]));

            // Create tx → always denied (with and without scopes)
            assert!(!allows(Some(&[scope(t, vec![])]), &TxKind::Create, &[]));
            assert!(!allows(None, &TxKind::Create, &[]));

            // Target mismatch → denied
            assert!(!allows(
                Some(&[scope(t, vec![])]),
                &TxKind::Call(Address::repeat_byte(2)),
                &[],
            ));

            // Empty selector_rules → allow any input
            let s = [scope(t, vec![])];
            assert!(allows(Some(&s), &TxKind::Call(t), &[]));
            assert!(allows(Some(&s), &TxKind::Call(t), &SEL_A));

            // Selector match/mismatch
            let s = [scope(t, vec![rule(SEL_A, vec![])])];
            assert!(allows(Some(&s), &TxKind::Call(t), &SEL_A));
            assert!(!allows(Some(&s), &TxKind::Call(t), &SEL_B));

            // Input too short for selector (< 4 bytes)
            assert!(!allows(Some(&s), &TxKind::Call(t), &[0xaa, 0xbb, 0xcc]));

            // Recipient check: allowed vs denied
            let s = [scope(t, vec![rule(SEL_A, vec![allowed])])];
            assert!(allows(
                Some(&s),
                &TxKind::Call(t),
                &abi_input(SEL_A, allowed)
            ));
            assert!(!allows(
                Some(&s),
                &TxKind::Call(t),
                &abi_input(SEL_A, denied)
            ));

            // Input too short for recipient (< 36 bytes)
            assert!(!allows(Some(&s), &TxKind::Call(t), &SEL_A));

            // Dirty padding in recipient word → denied
            let mut dirty = Vec::from(SEL_A);
            dirty.extend_from_slice(&[0x01; 12]);
            dirty.extend_from_slice(allowed.as_slice());
            assert!(!allows(Some(&s), &TxKind::Call(t), &dirty));
        }

        // =====================================================================
        // validate_t3_key_authorization_restrictions — gap coverage
        // =====================================================================

        /// Helper: build + sign a key auth, submit through T3 validation, return inner result.
        fn t3_validate(
            allowed_calls: Option<Vec<CallScope>>,
            limits: Option<Vec<TokenLimit>>,
            setup_storage: impl FnOnce(&MockEthProvider<TempoPrimitives, TempoChainSpec>),
        ) -> Result<(), TempoPoolTransactionError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            let signed = sign_key_authorization(
                KeyAuthorization {
                    chain_id: 42431,
                    key_type: SignatureType::Secp256k1,
                    key_id: access_key_address,
                    expiry: None,
                    limits,
                    allowed_calls,
                },
                &user_signer,
            );

            let tx =
                create_aa_with_keychain_signature(user_address, &access_key_signer, Some(signed));
            validate_t3_key_authorization_result(
                &tx,
                user_address,
                access_key_address,
                setup_storage,
            )
            .expect("no provider error")
        }

        #[test]
        fn test_t3_key_authorization_restriction_rejections() {
            // Too many selector rules per scope
            let rules: Vec<SelectorRule> = (0..=MAX_SELECTOR_RULES_PER_SCOPE as u32)
                .map(|i| {
                    rule(
                        [(i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8],
                        vec![],
                    )
                })
                .collect();
            assert!(matches!(
                t3_validate(
                    Some(vec![scope(Address::repeat_byte(1), rules)]),
                    None,
                    |_| {}
                ),
                Err(TempoPoolTransactionError::Keychain(
                    "too many selector rules in call scope"
                ))
            ));

            // Duplicate selectors in scope
            assert!(matches!(
                t3_validate(
                    Some(vec![scope(
                        Address::repeat_byte(1),
                        vec![rule(SEL_A, vec![]), rule(SEL_A, vec![])],
                    )]),
                    None,
                    |_| {},
                ),
                Err(TempoPoolTransactionError::Keychain(
                    "duplicate selector rules are not allowed"
                ))
            ));

            // Too many recipients per selector
            let recipients: Vec<Address> = (0..=MAX_RECIPIENTS_PER_SELECTOR as u16)
                .map(|i| Address::repeat_byte(i as u8 + 1))
                .collect();
            assert!(matches!(
                t3_validate(
                    Some(vec![scope(
                        PATH_USD_ADDRESS,
                        vec![rule(ITIP20::transferCall::SELECTOR, recipients)],
                    )]),
                    None,
                    |_| {},
                ),
                Err(TempoPoolTransactionError::Keychain(
                    "too many recipients in selector rule"
                ))
            ));

            // Zero-address recipient
            assert!(matches!(
                t3_validate(
                    Some(vec![scope(
                        PATH_USD_ADDRESS,
                        vec![rule(ITIP20::transferCall::SELECTOR, vec![Address::ZERO])],
                    )]),
                    None,
                    |_| {},
                ),
                Err(TempoPoolTransactionError::Keychain(
                    "selector rule recipients must be non-zero and unique"
                ))
            ));

            // Non-constrained selector with recipients
            assert!(matches!(
                t3_validate(
                    Some(vec![scope(
                        PATH_USD_ADDRESS,
                        vec![rule(
                            [0xde, 0xad, 0xbe, 0xef],
                            vec![Address::repeat_byte(0x11)]
                        )],
                    )]),
                    None,
                    |_| {},
                ),
                Err(TempoPoolTransactionError::Keychain(
                    "recipient-constrained selector rules require TIP-20 target and constrained selector"
                ))
            ));
        }

        // =====================================================================
        // pre-T3 gates: periodic limits and call scopes rejected
        // =====================================================================

        #[test]
        fn test_pre_t3_rejects_tip1011_fields() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            // Periodic limits → rejected pre-T3
            let signed = sign_key_authorization(
                KeyAuthorization {
                    chain_id: 42431,
                    key_type: SignatureType::Secp256k1,
                    key_id: access_key_address,
                    expiry: None,
                    limits: Some(vec![TokenLimit {
                        token: address!("0000000000000000000000000000000000000002"),
                        limit: U256::from(1000),
                        period: 3600,
                    }]),
                    allowed_calls: None,
                },
                &user_signer,
            );
            let tx =
                create_aa_with_keychain_signature(user_address, &access_key_signer, Some(signed));
            let validator =
                setup_validator_with_keychain_storage(&tx, user_address, access_key_address, None);
            let mut sp = validator.inner.client().latest().unwrap();
            let result = validate_against_keychain_default_fee_context(&validator, &tx, &mut sp)
                .expect("no provider error");
            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "periodic token limits are not active before T3"
                    ))
                ),
                "got: {result:?}"
            );

            // Call scopes → rejected pre-T3
            let signed = sign_key_authorization(
                KeyAuthorization {
                    chain_id: 42431,
                    key_type: SignatureType::Secp256k1,
                    key_id: access_key_address,
                    expiry: None,
                    limits: None,
                    allowed_calls: Some(vec![scope(Address::repeat_byte(1), vec![])]),
                },
                &user_signer,
            );
            let tx =
                create_aa_with_keychain_signature(user_address, &access_key_signer, Some(signed));
            let validator =
                setup_validator_with_keychain_storage(&tx, user_address, access_key_address, None);
            let mut sp = validator.inner.client().latest().unwrap();
            let result = validate_against_keychain_default_fee_context(&validator, &tx, &mut sp)
                .expect("no provider error");
            assert!(
                matches!(
                    result,
                    Err(TempoPoolTransactionError::Keychain(
                        "call scopes are not active before T3"
                    ))
                ),
                "got: {result:?}"
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
            let key_auth = KeyAuthorization {
                chain_id,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: None,
            };
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
            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: different_key_id, // Different from access_key_address
                expiry: None,
                limits: None,
                allowed_calls: None,
            };

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
            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 1337,
                key_type: SignatureType::P256,
                key_id: access_key_address,
                expiry: None,
                limits: None,
                allowed_calls: None,
            };

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
            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: Some(current_time - 1), // Expired
                limits: None,
                allowed_calls: None,
            };

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
            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: Some(current_time), // Expired at exactly current time
                limits: None,
                allowed_calls: None,
            };

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
            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: Some(current_time + 100), // Valid (in the future)
                limits: None,
                allowed_calls: None,
            };

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

            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: Some(expiry),
                limits: None,
                allowed_calls: None,
            };

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
            let key_auth = KeyAuthorization {
                chain_id: 42431,
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None, // Never expires
                limits: None,
                allowed_calls: None,
            };

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
}
