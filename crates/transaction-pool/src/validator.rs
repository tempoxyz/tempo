use alloy_primitives::{Address, U256};
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_evm::revm::interpreter::instructions::utility::IntoAddress;
use reth_primitives_traits::{
    Block, GotExpected, SealedBlock, transaction::error::InvalidTransactionError,
};
use reth_storage_api::{StateProvider, StateProviderFactory, errors::ProviderResult};
use reth_transaction_pool::{
    EthPoolTransaction, EthTransactionValidator, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidator,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        provider::TIPFeeStorageProvider,
        storage::slots::mapping_slot,
        tip_fee_manager::{self},
        tip20,
    },
};

/// Validator for Tempo transactions.
#[derive(Debug, Clone)]
pub struct TempoTransactionValidator<Client, Tx> {
    /// The type that performs the actual validation.
    inner: EthTransactionValidator<Client, Tx>,
}

impl<Client, Tx> TempoTransactionValidator<Client, Tx>
where
    Client: StateProviderFactory,
    Tx: EthPoolTransaction,
{
    pub fn new(inner: EthTransactionValidator<Client, Tx>) -> Self {
        Self { inner }
    }
}

impl<Client, Tx> TransactionValidator for TempoTransactionValidator<Client, Tx>
where
    Client: ChainSpecProvider<ChainSpec: EthereumHardforks> + StateProviderFactory,
    Tx: EthPoolTransaction,
{
    type Transaction = Tx;

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

        let balance = match state_provider.get_fee_token_balance(transaction.sender()) {
            Ok(balance) => balance,
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err));
            }
        };

        // Get the tx cost and adjust for fee token decimals
        let cost = transaction.cost().div_ceil(U256::from(1000));
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

        self.inner.validate_one(origin, transaction)
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
            .map(|(origin, tx)| {
                let balance = match state_provider.get_fee_token_balance(tx.sender()) {
                    Ok(balance) => balance,
                    Err(err) => {
                        return TransactionValidationOutcome::Error(*tx.hash(), Box::new(err));
                    }
                };

                // Get the tx cost and adjust for fee token decimals
                let cost = tx.cost().div_ceil(U256::from(1000));
                if balance < cost {
                    return TransactionValidationOutcome::Invalid(
                        tx,
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

                self.inner.validate_one(origin, tx)
            })
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
            .map(|tx| {
                let balance = match state_provider.get_fee_token_balance(tx.sender()) {
                    Ok(balance) => balance,
                    Err(err) => {
                        return TransactionValidationOutcome::Error(*tx.hash(), Box::new(err));
                    }
                };

                // Get the tx cost and adjust for fee token decimals
                let cost = tx.cost().div_ceil(U256::from(1000));
                if balance < cost {
                    return TransactionValidationOutcome::Invalid(
                        tx,
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

                self.inner.validate_one(origin, tx)
            })
            .collect()
    }

    fn on_new_head_block<B>(&self, new_tip_block: &SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block)
    }
}
