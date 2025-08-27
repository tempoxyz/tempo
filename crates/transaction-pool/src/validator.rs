use alloy_primitives::U256;
use futures::future;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_evm::revm::interpreter::instructions::utility::IntoAddress;
use reth_primitives_traits::{
    Block, GotExpected, SealedBlock, transaction::error::InvalidTransactionError,
};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    EthPoolTransaction, EthTransactionValidator, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidator,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{
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

    async fn ensure_sufficient_balance(
        &self,
        transaction: &Tx,
    ) -> Result<(), InvalidTransactionError> {
        let state_provider = self.inner.client().latest().expect("TODO: handle error ");

        let user_token_slot =
            mapping_slot(transaction.sender(), tip_fee_manager::slots::USER_TOKENS);

        let fee_token = state_provider
            .storage(TIP_FEE_MANAGER_ADDRESS, user_token_slot.into())
            .expect("TODO:")
            .unwrap_or_default()
            .into_address();

        if fee_token.is_zero() {
            // TODO: how to handle getting validator fee token? Should we get the next validator or
            // default to some token?
        }

        let balance_slot = mapping_slot(transaction.sender(), tip20::slots::BALANCES);
        let balance = state_provider
            .storage(fee_token, balance_slot.into())
            .expect("TODO:")
            .unwrap_or_default();

        // Get the tx cost and adjust for fee token decimals
        let cost = transaction.cost().div_ceil(U256::from(1000));
        if balance < cost {
            return Err(InvalidTransactionError::InsufficientFunds(
                GotExpected {
                    got: balance,
                    expected: cost,
                }
                .into(),
            ));
        }

        Ok(())
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
        if let Err(err) = self.ensure_sufficient_balance(&transaction).await {
            return TransactionValidationOutcome::Invalid(transaction, err.into());
        }

        self.inner.validate_one(origin, transaction)
    }

    async fn validate_transactions(
        &self,
        transactions: Vec<(TransactionOrigin, Self::Transaction)>,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        let balance_checks = future::join_all(
            transactions
                .iter()
                .map(|(_, tx)| self.ensure_sufficient_balance(tx)),
        )
        .await;

        let num_txs = transactions.len();
        let (valid_txs, invalid_outcomes): (Vec<_>, Vec<_>) =
            transactions.into_iter().zip(balance_checks).fold(
                (Vec::with_capacity(num_txs), Vec::with_capacity(num_txs)),
                |(mut valid, mut invalid), ((origin, tx), result)| {
                    if let Err(err) = result {
                        invalid.push(TransactionValidationOutcome::Invalid(tx, err.into()))
                    } else {
                        valid.push((origin, tx));
                    }

                    (valid, invalid)
                },
            );

        let mut outcomes = self.inner.validate_transactions(valid_txs).await;
        outcomes.extend(invalid_outcomes);
        outcomes
    }

    async fn validate_transactions_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: impl IntoIterator<Item = Self::Transaction> + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        let transactions: Vec<_> = transactions.into_iter().collect();

        let balance_checks = future::join_all(
            transactions
                .iter()
                .map(|tx| self.ensure_sufficient_balance(tx)),
        )
        .await;

        let (valid_txs, invalid_outcomes): (Vec<_>, Vec<_>) =
            transactions.into_iter().zip(balance_checks).fold(
                (Vec::new(), Vec::new()),
                |(mut valid, mut invalid), (tx, result)| {
                    match result {
                        Ok(()) => valid.push(tx),
                        Err(err) => {
                            invalid.push(TransactionValidationOutcome::Invalid(tx, err.into()))
                        }
                    }
                    (valid, invalid)
                },
            );

        let mut outcomes = self
            .inner
            .validate_transactions_with_origin(origin, valid_txs)
            .await;
        outcomes.extend(invalid_outcomes);
        outcomes
    }

    fn on_new_head_block<B>(&self, new_tip_block: &SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block)
    }
}
