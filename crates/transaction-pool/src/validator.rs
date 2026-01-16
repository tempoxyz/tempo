use crate::{
    amm::AmmLiquidityCache,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
};
use alloy_consensus::Transaction;

use alloy_primitives::U256;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_primitives_traits::{
    Block, GotExpected, SealedBlock, transaction::error::InvalidTransactionError,
};
use reth_storage_api::{StateProvider, StateProviderFactory, errors::ProviderError};
use reth_transaction_pool::{
    EthTransactionValidator, PoolTransaction, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidator, error::InvalidPoolTransactionError,
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, NONCE_PRECOMPILE_ADDRESS,
    account_keychain::{AccountKeychain, AuthorizedKey},
};
use tempo_primitives::{
    subblock::has_sub_block_nonce_key_prefix,
    transaction::{RecoveredTempoAuthorization, TempoTransaction},
};
use tempo_revm::{TempoBatchCallEnv, TempoStateAccess, calculate_aa_batch_intrinsic_gas};

// Reject AA txs where `valid_before` is too close to current time (or already expired) to prevent block invalidation.
const AA_VALID_BEFORE_MIN_SECS: u64 = 3;

/// Default maximum number of authorizations allowed in an AA transaction's authorization list.
pub const DEFAULT_MAX_TEMPO_AUTHORIZATIONS: usize = 16;

/// Validator for Tempo transactions.
#[derive(Debug)]
pub struct TempoTransactionValidator<Client> {
    /// Inner validator that performs default Ethereum tx validation.
    pub(crate) inner: EthTransactionValidator<Client, TempoPooledTransaction>,
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
        inner: EthTransactionValidator<Client, TempoPooledTransaction>,
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

    /// Check if a transaction requires keychain validation
    ///
    /// Returns the validation result indicating what action to take:
    /// - ValidateKeychain: Need to validate the keychain authorization
    /// - Skip: No validation needed (not a keychain signature, or same-tx auth is valid)
    /// - Reject: Transaction should be rejected with the given reason
    fn validate_against_keychain(
        &self,
        transaction: &TempoPooledTransaction,
        state_provider: &impl StateProvider,
    ) -> Result<Result<(), &'static str>, ProviderError> {
        let Some(tx) = transaction.inner().as_aa() else {
            return Ok(Ok(()));
        };

        let auth = tx.tx().key_authorization.as_ref();

        // Ensure that key auth is valid if present.
        if let Some(auth) = auth {
            // Validate signature
            if !auth
                .recover_signer()
                .is_ok_and(|signer| signer == transaction.sender())
            {
                return Ok(Err("Invalid KeyAuthorization signature"));
            }

            // Validate chain_id (chain_id == 0 is wildcard, works on any chain)
            let chain_id = self.inner.chain_spec().chain_id();
            if auth.chain_id != 0 && auth.chain_id != chain_id {
                return Ok(Err(
                    "KeyAuthorization chain_id does not match current chain",
                ));
            }
        }

        let Some(sig) = tx.signature().as_keychain() else {
            return Ok(Ok(()));
        };

        // This should never fail because we set sender based on the sig.
        if sig.user_address != transaction.sender() {
            return Ok(Err("Keychain signature user_address does not match sender"));
        }

        // This should fail happen because we validate the signature validity in `recover_signer`.
        let Ok(key_id) = sig.key_id(&tx.signature_hash()) else {
            return Ok(Err(
                "Failed to recover access key ID from Keychain signature",
            ));
        };

        // Ensure that if key auth is present, it is for the same key as the keychain signature.
        if let Some(auth) = auth {
            if auth.key_id != key_id {
                return Ok(Err(
                    "KeyAuthorization key_id does not match Keychain signature key_id",
                ));
            }

            // KeyAuthorization is valid - skip keychain storage check (key will be authorized during execution)
            return Ok(Ok(()));
        }

        // Compute storage slot using helper function
        let storage_slot = AccountKeychain::new().keys[transaction.sender()][key_id].base_slot();

        // Read storage slot from state provider
        let slot_value = state_provider
            .storage(ACCOUNT_KEYCHAIN_ADDRESS, storage_slot.into())?
            .unwrap_or(U256::ZERO);

        // Decode AuthorizedKey using helper
        let authorized_key = AuthorizedKey::decode_from_slot(slot_value);

        // Check if key was revoked (revoked keys cannot be used)
        if authorized_key.is_revoked {
            return Ok(Err("access key has been revoked"));
        }

        // Check if key exists (key exists if expiry > 0)
        if authorized_key.expiry == 0 {
            return Ok(Err("access key does not exist"));
        }

        // Expiry checks are skipped here, they are done in the EVM handler where block timestamp is easily available.
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
        // Reject AA txs where `valid_before` is too close to current time (or already expired).
        if let Some(valid_before) = tx.valid_before {
            // Uses tip_timestamp, as if the node is lagging lagging, the maintenance task will evict expired txs.
            let current_time = self.inner.fork_tracker().tip_timestamp();
            let min_allowed = current_time.saturating_add(AA_VALID_BEFORE_MIN_SECS);
            if valid_before <= min_allowed {
                return Err(TempoPoolTransactionError::InvalidValidBefore {
                    valid_before,
                    min_allowed,
                });
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
    ///
    /// Without this validation, malicious transactions could clog the mempool at zero cost by
    /// passing pool validation (which only sees the first call's input) but failing at execution time.
    fn ensure_aa_intrinsic_gas(
        &self,
        transaction: &TempoPooledTransaction,
    ) -> Result<(), TempoPoolTransactionError> {
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
            override_key_id: None,
        };

        // Calculate the intrinsic gas for the AA transaction
        let mut init_and_floor_gas =
            calculate_aa_batch_intrinsic_gas(&aa_env, Some(tx.access_list.iter()))
                .map_err(|_| TempoPoolTransactionError::NonZeroValue)?;

        // Add 2D nonce gas if nonce_key is non-zero
        // If tx nonce is 0, it's a new key (0 -> 1 transition), otherwise existing key
        if !tx.nonce_key.is_zero() {
            let nonce_gas = if tx.nonce == 0 {
                tempo_revm::NEW_NONCE_KEY_GAS
            } else {
                tempo_revm::EXISTING_NONCE_KEY_GAS
            };
            init_and_floor_gas.initial_gas += nonce_gas;
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

    fn validate_one(
        &self,
        origin: TransactionOrigin,
        transaction: TempoPooledTransaction,
        mut state_provider: impl StateProvider,
    ) -> TransactionValidationOutcome<TempoPooledTransaction> {
        // Reject system transactions, those are never allowed in the pool.
        if transaction.inner().is_system_tx() {
            return TransactionValidationOutcome::Error(
                *transaction.hash(),
                InvalidTransactionError::TxTypeNotSupported.into(),
            );
        }

        // Validate transactions that involve keychain keys
        match self.validate_against_keychain(&transaction, &state_provider) {
            Ok(Ok(())) => {}
            Ok(Err(reason)) => {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::other(TempoPoolTransactionError::Keychain(reason)),
                );
            }
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
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

        // Validate AA transaction intrinsic gas.
        // This ensures the gas limit covers all AA-specific costs (per-call overhead,
        // signature verification, etc.) to prevent mempool DoS attacks where transactions
        // pass pool validation but fail at execution time.
        if let Err(err) = self.ensure_aa_intrinsic_gas(&transaction) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(err),
            );
        }

        let fee_payer = match transaction.inner().fee_payer(transaction.sender()) {
            Ok(fee_payer) => fee_payer,
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        };

        let spec = self
            .inner
            .chain_spec()
            .tempo_hardfork_at(self.inner.fork_tracker().tip_timestamp());

        let fee_token = match state_provider.get_fee_token(transaction.inner(), fee_payer, spec) {
            Ok(fee_token) => fee_token,
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        };

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
            .has_enough_liquidity(fee_token, cost, &state_provider)
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
                // Additional 2D nonce validations
                // Check for 2D nonce validation (nonce_key > 0)
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

                    // This is a 2D nonce transaction - validate against 2D nonce
                    state_nonce = match state_provider.storage(
                        NONCE_PRECOMPILE_ADDRESS,
                        transaction.transaction().nonce_key_slot().unwrap().into(),
                    ) {
                        Ok(nonce) => nonce.unwrap_or_default().saturating_to(),
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
        transactions: Vec<(TransactionOrigin, Self::Transaction)>,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
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

    fn on_new_head_block<B>(&self, new_tip_block: &SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::TxBuilder, transaction::TempoPoolTransactionError};
    use alloy_consensus::{Block, Header, Transaction};
    use alloy_primitives::{Address, B256, U256, address, uint};
    use reth_primitives_traits::SignedTransaction;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_transaction_pool::{
        PoolTransaction, blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
    };
    use std::sync::Arc;
    use tempo_chainspec::spec::MODERATO;
    use tempo_precompiles::{
        PATH_USD_ADDRESS, TIP403_REGISTRY_ADDRESS,
        tip20::{TIP20Token, slots as tip20_slots},
        tip403_registry::{ITIP403Registry, PolicyData, TIP403Registry},
    };
    use tempo_primitives::TempoTxEnvelope;

    /// Helper to create a mock sealed block with the given timestamp.
    fn create_mock_block(timestamp: u64) -> SealedBlock<reth_ethereum_primitives::Block> {
        let header = Header {
            timestamp,
            gas_limit: 30_000_000,
            ..Default::default()
        };
        let block = reth_ethereum_primitives::Block {
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
    ) -> TempoTransactionValidator<
        MockEthProvider<reth_ethereum_primitives::EthPrimitives, TempoChainSpec>,
    > {
        let provider =
            MockEthProvider::default().with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()));
        provider.add_account(
            transaction.sender(),
            ExtendedAccount::new(transaction.nonce(), alloy_primitives::U256::ZERO),
        );
        let block_with_gas = Block {
            header: Header {
                gas_limit: 30_000_000,
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

        let inner = EthTransactionValidatorBuilder::new(provider.clone())
            .disable_balance_check()
            .build(InMemoryBlobStore::default());
        let amm_cache =
            AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
        let validator = TempoTransactionValidator::new(
            inner,
            3600,
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

        // Test case 2: `valid_after` within limit (30 minutes)
        let tx_within_limit = create_aa_transaction(Some(current_time + 1800), None);
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

        // Test case 3: `valid_after` beyond limit (2 hours)
        let tx_too_far = create_aa_transaction(Some(current_time + 7200), None);
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
        let provider =
            MockEthProvider::default().with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()));
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
        provider.add_account(
            fee_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (
                    tip20_slots::TRANSFER_POLICY_ID.into(),
                    U256::from(policy_id),
                ),
                (tip20_slots::CURRENCY.into(), usd_currency_value),
            ]),
        );

        // Add TIP403Registry with blacklist policy containing fee_payer
        let policy_data = PolicyData {
            policy_type: ITIP403Registry::PolicyType::BLACKLIST as u8,
            admin: Address::ZERO,
        };
        let policy_data_slot = TIP403Registry::new().policy_data[policy_id].base_slot();
        let policy_set_slot = TIP403Registry::new().policy_set[policy_id][fee_payer].slot();

        provider.add_account(
            TIP403_REGISTRY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (policy_data_slot.into(), policy_data.encode_to_slot()),
                (policy_set_slot.into(), U256::from(1)), // in blacklist = true
            ]),
        );

        // Create validator and validate
        let inner = EthTransactionValidatorBuilder::new(provider.clone())
            .disable_balance_check()
            .build(InMemoryBlobStore::default());
        let validator = TempoTransactionValidator::new(
            inner,
            3600,
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
                max_fee_per_gas: 2_000_000_000,
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

        // Test 2: 100k gas should pass intrinsic gas check
        let tx_high_gas = create_aa_tx(100_000);
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

    mod keychain_validation {
        use super::*;
        use alloy_primitives::{Signature, TxKind, address};
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;
        use tempo_primitives::transaction::{
            KeyAuthorization, SignatureType, SignedKeyAuthorization, TempoTransaction,
            tempo_transaction::Call,
            tt_signature::{KeychainSignature, PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        };

        /// Generate a secp256k1 keypair for testing
        fn generate_keypair() -> (PrivateKeySigner, Address) {
            let signer = PrivateKeySigner::random();
            let address = signer.address();
            (signer, address)
        }

        /// Create an AA transaction with a keychain signature.
        fn create_aa_with_keychain_signature(
            user_address: Address,
            access_key_signer: &PrivateKeySigner,
            key_authorization: Option<SignedKeyAuthorization>,
        ) -> TempoPooledTransaction {
            let tx_aa = TempoTransaction {
                chain_id: 42431, // MODERATO chain_id
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 2_000_000_000,
                gas_limit: 100_000,
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

            // Sign with the access key
            let signature = access_key_signer
                .sign_hash_sync(&sig_hash)
                .expect("signing failed");

            // Create keychain signature
            let keychain_sig = TempoSignature::Keychain(KeychainSignature::new(
                user_address,
                PrimitiveSignature::Secp256k1(signature),
            ));

            let signed_tx = AASigned::new_unhashed(tx_aa, keychain_sig);
            let envelope: TempoTxEnvelope = signed_tx.into();
            let recovered = envelope.try_into_recovered().unwrap();
            TempoPooledTransaction::new(recovered)
        }

        /// Setup validator with keychain storage for a specific user and key_id.
        fn setup_validator_with_keychain_storage(
            transaction: &TempoPooledTransaction,
            user_address: Address,
            key_id: Address,
            authorized_key_slot_value: Option<U256>,
        ) -> TempoTransactionValidator<
            MockEthProvider<reth_ethereum_primitives::EthPrimitives, TempoChainSpec>,
        > {
            let provider =
                MockEthProvider::default().with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()));

            // Add sender account
            provider.add_account(
                transaction.sender(),
                ExtendedAccount::new(transaction.nonce(), U256::ZERO),
            );
            provider.add_block(B256::random(), Default::default());

            // If slot value provided, setup AccountKeychain storage
            if let Some(slot_value) = authorized_key_slot_value {
                let storage_slot = AccountKeychain::new().keys[user_address][key_id].base_slot();
                provider.add_account(
                    ACCOUNT_KEYCHAIN_ADDRESS,
                    ExtendedAccount::new(0, U256::ZERO)
                        .extend_storage([(storage_slot.into(), slot_value)]),
                );
            }

            let inner = EthTransactionValidatorBuilder::new(provider.clone())
                .disable_balance_check()
                .build(InMemoryBlobStore::default());
            let amm_cache =
                AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
            TempoTransactionValidator::new(inner, 3600, DEFAULT_MAX_TEMPO_AUTHORIZATIONS, amm_cache)
        }

        #[test]
        fn test_non_aa_transaction_skips_keychain_validation() -> Result<(), ProviderError> {
            // Non-AA transaction should return Ok(Ok(())) immediately
            let transaction = TxBuilder::eip1559(Address::random()).build_eip1559();
            let validator = setup_validator(&transaction, 0);
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider)?;
            assert!(result.is_ok(), "Non-AA tx should skip keychain validation");
            Ok(())
        }

        #[test]
        fn test_aa_with_primitive_signature_skips_keychain_validation() -> Result<(), ProviderError>
        {
            // AA transaction with primitive (non-keychain) signature should skip validation
            let transaction = create_aa_transaction(None, None);
            let validator = setup_validator(&transaction, 0);
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider)?;
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
            let slot_value = AuthorizedKey {
                signature_type: 0, // secp256k1
                expiry: u64::MAX,  // never expires
                enforce_limits: false,
                is_revoked: false,
            }
            .encode_to_slot();

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                Some(slot_value),
            );
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider)?;
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
            let slot_value = AuthorizedKey {
                signature_type: 0,
                expiry: 0, // revoked keys have expiry=0
                enforce_limits: false,
                is_revoked: true,
            }
            .encode_to_slot();

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                Some(slot_value),
            );
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider);
            assert_eq!(
                result.expect("should not be a provider error"),
                Err("access key has been revoked"),
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
            let slot_value = AuthorizedKey {
                signature_type: 0,
                expiry: 0, // expiry = 0 means key doesn't exist
                enforce_limits: false,
                is_revoked: false,
            }
            .encode_to_slot();

            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                Some(slot_value),
            );
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider);
            assert_eq!(
                result.expect("should not be a provider error"),
                Err("access key does not exist"),
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
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider);
            assert_eq!(
                result.expect("should not be a provider error"),
                Err("access key does not exist"),
                "Missing storage should result in non-existent key error"
            );
        }

        #[test]
        fn test_key_authorization_skips_storage_check() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            // Create KeyAuthorization signed by the user's main key
            let key_auth = KeyAuthorization {
                chain_id: 42431, // MODERATO chain_id
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None, // never expires
                limits: None, // unlimited
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

            // NO storage setup - KeyAuthorization should skip storage check
            let validator = setup_validator_with_keychain_storage(
                &transaction,
                user_address,
                access_key_address,
                None,
            );
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider)?;
            assert!(
                result.is_ok(),
                "Valid KeyAuthorization should skip storage check, got: {result:?}"
            );
            Ok(())
        }

        #[test]
        fn test_key_authorization_wrong_chain_id_rejected() {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            // Create KeyAuthorization with wrong chain_id (not 0 and not matching)
            let key_auth = KeyAuthorization {
                chain_id: 99999, // Wrong chain_id
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
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
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider);
            assert_eq!(
                result.expect("should not be a provider error"),
                Err("KeyAuthorization chain_id does not match current chain"),
                "Wrong chain_id should be rejected"
            );
        }

        #[test]
        fn test_key_authorization_chain_id_zero_accepted() -> Result<(), ProviderError> {
            let (access_key_signer, access_key_address) = generate_keypair();
            let (user_signer, user_address) = generate_keypair();

            // Create KeyAuthorization with chain_id = 0 (wildcard)
            let key_auth = KeyAuthorization {
                chain_id: 0, // Wildcard - works on any chain
                key_type: SignatureType::Secp256k1,
                key_id: access_key_address,
                expiry: None,
                limits: None,
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
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider)?;
            assert!(
                result.is_ok(),
                "chain_id=0 (wildcard) should be accepted, got: {result:?}"
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
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider);
            assert_eq!(
                result.expect("should not be a provider error"),
                Err("KeyAuthorization key_id does not match Keychain signature key_id"),
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
            let state_provider = validator.inner.client().latest().unwrap();

            let result = validator.validate_against_keychain(&transaction, &state_provider);
            assert_eq!(
                result.expect("should not be a provider error"),
                Err("Invalid KeyAuthorization signature"),
                "Invalid KeyAuthorization signature should be rejected"
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
                max_fee_per_gas: 2_000_000_000,
                gas_limit: 100_000,
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
            let sig_hash = unsigned.signature_hash();
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
            let slot_value = AuthorizedKey {
                signature_type: 0,
                expiry: u64::MAX,
                enforce_limits: false,
                is_revoked: false,
            }
            .encode_to_slot();
            let validator = setup_validator_with_keychain_storage(
                &transaction,
                real_user,
                access_key_address,
                Some(slot_value),
            );
            let state_provider = validator.inner.client().latest().unwrap();

            // This should pass since user_address matches sender by construction
            let result = validator.validate_against_keychain(&transaction, &state_provider)?;
            assert!(
                result.is_ok(),
                "Properly constructed keychain sig should pass, got: {result:?}"
            );
            Ok(())
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
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 100_000,
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
}
