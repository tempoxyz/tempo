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

/// Validator for Tempo transactions.
#[derive(Debug)]
pub struct TempoTransactionValidator<Client> {
    /// Inner validator that performs default Ethereum tx validation.
    pub(crate) inner: EthTransactionValidator<Client, TempoPooledTransaction>,
    /// Maximum allowed `valid_after` offset for AA txs.
    pub(crate) aa_valid_after_max_secs: u64,
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
        amm_liquidity_cache: AmmLiquidityCache,
    ) -> Self {
        Self {
            inner,
            aa_valid_after_max_secs,
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
        let init_and_floor_gas =
            calculate_aa_batch_intrinsic_gas(&aa_env, Some(tx.access_list.iter()))
                .map_err(|_| TempoPoolTransactionError::NonZeroValue)?;

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
    use alloy_consensus::{Block, Transaction};
    use alloy_eips::Decodable2718;
    use alloy_primitives::{Address, B256, U256, hex};
    use reth_primitives_traits::SignedTransaction;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_transaction_pool::{
        PoolTransaction, blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
    };
    use std::sync::Arc;
    use tempo_chainspec::spec::ANDANTINO;
    use tempo_precompiles::tip403_registry::TIP403Registry;
    use tempo_primitives::TempoTxEnvelope;

    /// Helper to create a mock sealed block with the given timestamp.
    fn create_mock_block(timestamp: u64) -> SealedBlock<reth_ethereum_primitives::Block> {
        use alloy_consensus::Header;
        let header = Header {
            timestamp,
            ..Default::default()
        };
        let block = reth_ethereum_primitives::Block {
            header,
            body: Default::default(),
        };
        SealedBlock::seal_slow(block)
    }

    fn get_transaction(with_value: Option<U256>) -> TempoPooledTransaction {
        let raw = "0x02f914950181ad84b2d05e0085117553845b830f7df88080b9143a6040608081523462000414576200133a803803806200001e8162000419565b9283398101608082820312620004145781516001600160401b03908181116200041457826200004f9185016200043f565b92602092838201519083821162000414576200006d9183016200043f565b8186015190946001600160a01b03821692909183900362000414576060015190805193808511620003145760038054956001938488811c9816801562000409575b89891014620003f3578190601f988981116200039d575b50899089831160011462000336576000926200032a575b505060001982841b1c191690841b1781555b8751918211620003145760049788548481811c9116801562000309575b89821014620002f457878111620002a9575b5087908784116001146200023e5793839491849260009562000232575b50501b92600019911b1c19161785555b6005556007805460ff60a01b19169055600880546001600160a01b0319169190911790553015620001f3575060025469d3c21bcecceda100000092838201809211620001de57506000917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9160025530835282815284832084815401905584519384523093a351610e889081620004b28239f35b601190634e487b7160e01b6000525260246000fd5b90606493519262461bcd60e51b845283015260248201527f45524332303a206d696e7420746f20746865207a65726f2061646472657373006044820152fd5b0151935038806200013a565b9190601f198416928a600052848a6000209460005b8c8983831062000291575050501062000276575b50505050811b0185556200014a565b01519060f884600019921b161c191690553880808062000267565b86860151895590970196948501948893500162000253565b89600052886000208880860160051c8201928b8710620002ea575b0160051c019085905b828110620002dd5750506200011d565b60008155018590620002cd565b92508192620002c4565b60228a634e487b7160e01b6000525260246000fd5b90607f16906200010b565b634e487b7160e01b600052604160045260246000fd5b015190503880620000dc565b90869350601f19831691856000528b6000209260005b8d8282106200038657505084116200036d575b505050811b018155620000ee565b015160001983861b60f8161c191690553880806200035f565b8385015186558a979095019493840193016200034c565b90915083600052896000208980850160051c8201928c8610620003e9575b918891869594930160051c01915b828110620003d9575050620000c5565b60008155859450889101620003c9565b92508192620003bb565b634e487b7160e01b600052602260045260246000fd5b97607f1697620000ae565b600080fd5b6040519190601f01601f191682016001600160401b038111838210176200031457604052565b919080601f84011215620004145782516001600160401b038111620003145760209062000475601f8201601f1916830162000419565b92818452828287010111620004145760005b8181106200049d57508260009394955001015290565b85810183015184820184015282016200048756fe608060408181526004918236101561001657600080fd5b600092833560e01c91826306fdde0314610a1c57508163095ea7b3146109f257816318160ddd146109d35781631b4c84d2146109ac57816323b872dd14610833578163313ce5671461081757816339509351146107c357816370a082311461078c578163715018a6146107685781638124f7ac146107495781638da5cb5b1461072057816395d89b411461061d578163a457c2d714610575578163a9059cbb146104e4578163c9567bf914610120575063dd62ed3e146100d557600080fd5b3461011c578060031936011261011c57806020926100f1610b5a565b6100f9610b75565b6001600160a01b0391821683526001865283832091168252845220549051908152f35b5080fd5b905082600319360112610338576008546001600160a01b039190821633036104975760079283549160ff8360a01c1661045557737a250d5630b4cf539739df2c5dacb4c659f2488d92836bffffffffffffffffffffffff60a01b8092161786553087526020938785528388205430156104065730895260018652848920828a52865280858a205584519081527f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925863092a38554835163c45a015560e01b815290861685828581845afa9182156103dd57849187918b946103e7575b5086516315ab88c960e31b815292839182905afa9081156103dd576044879289928c916103c0575b508b83895196879586946364e329cb60e11b8652308c870152166024850152165af19081156103b6579086918991610389575b50169060065416176006558385541660604730895288865260c4858a20548860085416928751958694859363f305d71960e01b8552308a86015260248501528d60448501528d606485015260848401524260a48401525af1801561037f579084929161034c575b50604485600654169587541691888551978894859363095ea7b360e01b855284015260001960248401525af1908115610343575061030c575b5050805460ff60a01b1916600160a01b17905580f35b81813d831161033c575b6103208183610b8b565b8101031261033857518015150361011c5738806102f6565b8280fd5b503d610316565b513d86823e3d90fd5b6060809293503d8111610378575b6103648183610b8b565b81010312610374578290386102bd565b8580fd5b503d61035a565b83513d89823e3d90fd5b6103a99150863d88116103af575b6103a18183610b8b565b810190610e33565b38610256565b503d610397565b84513d8a823e3d90fd5b6103d79150843d86116103af576103a18183610b8b565b38610223565b85513d8b823e3d90fd5b6103ff919450823d84116103af576103a18183610b8b565b92386101fb565b845162461bcd60e51b81528085018790526024808201527f45524332303a20617070726f76652066726f6d20746865207a65726f206164646044820152637265737360e01b6064820152608490fd5b6020606492519162461bcd60e51b8352820152601760248201527f74726164696e6720697320616c7265616479206f70656e0000000000000000006044820152fd5b608490602084519162461bcd60e51b8352820152602160248201527f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6044820152603760f91b6064820152fd5b9050346103385781600319360112610338576104fe610b5a565b9060243593303303610520575b602084610519878633610bc3565b5160018152f35b600594919454808302908382041483151715610562576127109004820391821161054f5750925080602061050b565b634e487b7160e01b815260118552602490fd5b634e487b7160e01b825260118652602482fd5b9050823461061a578260031936011261061a57610590610b5a565b918360243592338152600160205281812060018060a01b03861682526020522054908282106105c9576020856105198585038733610d31565b608490602086519162461bcd60e51b8352820152602560248201527f45524332303a2064656372656173656420616c6c6f77616e63652062656c6f77604482015264207a65726f60d81b6064820152fd5b80fd5b83833461011c578160031936011261011c57805191809380549160019083821c92828516948515610716575b6020958686108114610703578589529081156106df5750600114610687575b6106838787610679828c0383610b8b565b5191829182610b11565b0390f35b81529295507f8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b5b8284106106cc57505050826106839461067992820101948680610668565b80548685018801529286019281016106ae565b60ff19168887015250505050151560051b8301019250610679826106838680610668565b634e487b7160e01b845260228352602484fd5b93607f1693610649565b50503461011c578160031936011261011c5760085490516001600160a01b039091168152602090f35b50503461011c578160031936011261011c576020906005549051908152f35b833461061a578060031936011261061a57600880546001600160a01b031916905580f35b50503461011c57602036600319011261011c5760209181906001600160a01b036107b4610b5a565b16815280845220549051908152f35b82843461061a578160031936011261061a576107dd610b5a565b338252600160209081528383206001600160a01b038316845290528282205460243581019290831061054f57602084610519858533610d31565b50503461011c578160031936011261011c576020905160128152f35b83833461011c57606036600319011261011c5761084e610b5a565b610856610b75565b6044359160018060a01b0381169485815260209560018752858220338352875285822054976000198903610893575b505050906105199291610bc3565b85891061096957811561091a5733156108cc5750948481979861051997845260018a528284203385528a52039120558594938780610885565b865162461bcd60e51b8152908101889052602260248201527f45524332303a20617070726f766520746f20746865207a65726f206164647265604482015261737360f01b6064820152608490fd5b865162461bcd60e51b81529081018890526024808201527f45524332303a20617070726f76652066726f6d20746865207a65726f206164646044820152637265737360e01b6064820152608490fd5b865162461bcd60e51b8152908101889052601d60248201527f45524332303a20696e73756666696369656e7420616c6c6f77616e63650000006044820152606490fd5b50503461011c578160031936011261011c5760209060ff60075460a01c1690519015158152f35b50503461011c578160031936011261011c576020906002549051908152f35b50503461011c578060031936011261011c57602090610519610a12610b5a565b6024359033610d31565b92915034610b0d5783600319360112610b0d57600354600181811c9186908281168015610b03575b6020958686108214610af05750848852908115610ace5750600114610a75575b6106838686610679828b0383610b8b565b929550600383527fc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b5b828410610abb575050508261068394610679928201019438610a64565b8054868501880152928601928101610a9e565b60ff191687860152505050151560051b83010192506106798261068338610a64565b634e487b7160e01b845260229052602483fd5b93607f1693610a44565b8380fd5b6020808252825181830181905290939260005b828110610b4657505060409293506000838284010152601f8019910116010190565b818101860151848201604001528501610b24565b600435906001600160a01b0382168203610b7057565b600080fd5b602435906001600160a01b0382168203610b7057565b90601f8019910116810190811067ffffffffffffffff821117610bad57604052565b634e487b7160e01b600052604160045260246000fd5b6001600160a01b03908116918215610cde5716918215610c8d57600082815280602052604081205491808310610c3957604082827fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef958760209652828652038282205586815220818154019055604051908152a3565b60405162461bcd60e51b815260206004820152602660248201527f45524332303a207472616e7366657220616d6f756e7420657863656564732062604482015265616c616e636560d01b6064820152608490fd5b60405162461bcd60e51b815260206004820152602360248201527f45524332303a207472616e7366657220746f20746865207a65726f206164647260448201526265737360e81b6064820152608490fd5b60405162461bcd60e51b815260206004820152602560248201527f45524332303a207472616e736665722066726f6d20746865207a65726f206164604482015264647265737360d81b6064820152608490fd5b6001600160a01b03908116918215610de25716918215610d925760207f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925918360005260018252604060002085600052825280604060002055604051908152a3565b60405162461bcd60e51b815260206004820152602260248201527f45524332303a20617070726f766520746f20746865207a65726f206164647265604482015261737360f01b6064820152608490fd5b60405162461bcd60e51b8152602060048201526024808201527f45524332303a20617070726f76652066726f6d20746865207a65726f206164646044820152637265737360e01b6064820152608490fd5b90816020910312610b7057516001600160a01b0381168103610b70579056fea2646970667358221220285c200b3978b10818ff576bb83f2dc4a2a7c98dfb6a36ea01170de792aa652764736f6c63430008140033000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000d3fd4f95820a9aa848ce716d6c200eaefb9a2e4900000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000003543131000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000035431310000000000000000000000000000000000000000000000000000000000c001a04e551c75810ffdfe6caff57da9f5a8732449f42f0f4c57f935b05250a76db3b6a046cd47e6d01914270c1ec0d9ac7fae7dfb240ec9a8b6ec7898c4d6aa174388f2";

        let data = hex::decode(raw).unwrap();
        let mut tx = TempoTxEnvelope::decode_2718(&mut data.as_ref()).unwrap();

        if let Some(value) = with_value {
            match &mut tx {
                TempoTxEnvelope::Legacy(tx) => tx.tx_mut().value = value,
                TempoTxEnvelope::Eip2930(tx) => tx.tx_mut().value = value,
                TempoTxEnvelope::Eip1559(tx) => tx.tx_mut().value = value,
                TempoTxEnvelope::Eip7702(tx) => tx.tx_mut().value = value,
                // set value to first call
                TempoTxEnvelope::AA(tx) => {
                    if let Some(first_call) = tx.tx_mut().calls.first_mut() {
                        first_call.value = value;
                    }
                }
            }
        }

        TempoPooledTransaction::new(tx.try_into_recovered().unwrap())
    }

    /// Helper function to create an AA transaction with the given `valid_after` and `valid_before`
    /// timestamps
    fn create_aa_transaction(
        valid_after: Option<u64>,
        valid_before: Option<u64>,
    ) -> TempoPooledTransaction {
        use alloy_primitives::{Signature, TxKind, address};
        use tempo_primitives::transaction::{
            TempoTransaction,
            tempo_transaction::Call,
            tt_signature::{PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        };

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
            valid_after,
            valid_before,
            access_list: Default::default(),
            tempo_authorization_list: vec![],
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

    /// Helper function to setup validator with the given transaction and tip timestamp.
    fn setup_validator(
        transaction: &TempoPooledTransaction,
        tip_timestamp: u64,
    ) -> TempoTransactionValidator<
        MockEthProvider<reth_ethereum_primitives::EthPrimitives, TempoChainSpec>,
    > {
        let provider =
            MockEthProvider::default().with_chain_spec(Arc::unwrap_or_clone(ANDANTINO.clone()));
        provider.add_account(
            transaction.sender(),
            ExtendedAccount::new(transaction.nonce(), alloy_primitives::U256::ZERO),
        );
        provider.add_block(B256::random(), Default::default());

        let inner = EthTransactionValidatorBuilder::new(provider.clone())
            .disable_balance_check()
            .build(InMemoryBlobStore::default());
        let amm_cache =
            AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
        let validator = TempoTransactionValidator::new(inner, 3600, amm_cache);

        // Set the tip timestamp by simulating a new head block
        let mock_block = create_mock_block(tip_timestamp);
        validator.on_new_head_block(&mock_block);

        validator
    }

    #[tokio::test]
    async fn test_some_balance() {
        let transaction = get_transaction(Some(U256::from(1)));
        let validator = setup_validator(&transaction, 0);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction.clone())
            .await;

        if let TransactionValidationOutcome::Invalid(_, err) = outcome {
            assert!(
                err.to_string()
                    .contains("Native transfers are not supported")
            );
        } else {
            panic!("Expected Invalid outcome with InsufficientFunds error");
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

        if let TransactionValidationOutcome::Invalid(_, err) = outcome {
            let error_msg = format!("{err}");
            assert!(!error_msg.contains("valid_before"));
        }

        // Test case 2: `valid_before` too small (at boundary)
        let tx_too_close =
            create_aa_transaction(None, Some(current_time + AA_VALID_BEFORE_MIN_SECS));
        let validator = setup_validator(&tx_too_close, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_too_close)
            .await;

        if let TransactionValidationOutcome::Invalid(_, err) = outcome {
            let error_msg = format!("{err}");
            assert!(
                error_msg.contains("valid_before"),
                "Expected 'valid_before' got: {error_msg}"
            );
        } else {
            panic!("Expected invalid outcome with InvalidValidBefore error");
        }

        // Test case 3: `valid_before` sufficiently in the future
        let tx_valid =
            create_aa_transaction(None, Some(current_time + AA_VALID_BEFORE_MIN_SECS + 1));
        let validator = setup_validator(&tx_valid, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_valid)
            .await;

        if let TransactionValidationOutcome::Invalid(_, err) = outcome {
            let error_msg = format!("{err}");
            assert!(!error_msg.contains("valid_before"));
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

        if let TransactionValidationOutcome::Invalid(_, err) = outcome {
            let error_msg = format!("{err}");
            assert!(!error_msg.contains("valid_after"));
        }

        // Test case 2: `valid_after` within limit (30 minutes)
        let tx_within_limit = create_aa_transaction(Some(current_time + 1800), None);
        let validator = setup_validator(&tx_within_limit, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_within_limit)
            .await;

        if let TransactionValidationOutcome::Invalid(_, err) = outcome {
            let error_msg = format!("{err}");
            assert!(!error_msg.contains("valid_after"));
        }

        // Test case 3: `valid_after` beyond limit (2 hours)
        let tx_too_far = create_aa_transaction(Some(current_time + 7200), None);
        let validator = setup_validator(&tx_too_far, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_too_far)
            .await;

        if let TransactionValidationOutcome::Invalid(_, err) = outcome {
            let error_msg = format!("{err}");
            assert!(error_msg.contains("valid_after"));
        } else {
            panic!("Expected invalid outcome with InvalidValidAfter error");
        }
    }

    #[tokio::test]
    async fn test_blacklisted_fee_payer_rejected() {
        use alloy_primitives::{Signature, TxKind, address, uint};
        use tempo_precompiles::{
            TIP403_REGISTRY_ADDRESS,
            tip20::slots as tip20_slots,
            tip403_registry::{ITIP403Registry, PolicyData},
        };
        use tempo_primitives::transaction::{
            TempoTransaction,
            tempo_transaction::Call,
            tt_signature::{PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        };

        // Use a valid TIP20 token address (PATH_USD with token_id=1)
        let fee_token = address!("20C0000000000000000000000000000000000001");
        let policy_id: u64 = 2;

        // Create AA transaction with valid TIP20 fee_token
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
            fee_token: Some(fee_token),
            fee_payer_signature: None,
            valid_after: None,
            valid_before: None,
            access_list: Default::default(),
            tempo_authorization_list: vec![],
            key_authorization: None,
        };

        let signed_tx = AASigned::new_unhashed(
            tx_aa,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        );
        let envelope: TempoTxEnvelope = signed_tx.into();
        let recovered = envelope.try_into_recovered().unwrap();
        let transaction = TempoPooledTransaction::new(recovered);
        let fee_payer = transaction.sender();

        // Setup provider with storage
        let provider =
            MockEthProvider::default().with_chain_spec(Arc::unwrap_or_clone(ANDANTINO.clone()));
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
        let validator =
            TempoTransactionValidator::new(inner, 3600, AmmLiquidityCache::new(provider).unwrap());

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;

        // Assert BlackListedFeePayer error
        match outcome {
            TransactionValidationOutcome::Invalid(_, err) => {
                let error_msg = err.to_string();
                assert!(
                    error_msg.contains("blacklisted") || error_msg.contains("BlackListed"),
                    "Expected BlackListedFeePayer error, got: {error_msg}"
                );
            }
            other => panic!("Expected Invalid outcome, got: {other:?}"),
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

        match &outcome {
            TransactionValidationOutcome::Invalid(_, err) => {
                assert!(
                    err.to_string()
                        .contains("Insufficient gas for AA transaction"),
                    "Expected InsufficientGasForAAIntrinsicCost, got: {err}"
                );
            }
            other => panic!("Expected Invalid outcome, got: {other:?}"),
        }

        // Test 2: 100k gas should pass intrinsic gas check
        let tx_high_gas = create_aa_tx(100_000);
        let validator = setup_validator(&tx_high_gas, current_time);
        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx_high_gas)
            .await;

        if let TransactionValidationOutcome::Invalid(_, err) = &outcome {
            assert!(
                !err.to_string()
                    .contains("Insufficient gas for AA transaction"),
                "Unexpected InsufficientGasForAAIntrinsicCost: {err}"
            );
        }
    }
}
