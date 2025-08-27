use alloy_primitives::{Address, U256};
use reth_chainspec::{ChainSpecProvider, EthereumHardforks, ValidationError};
use reth_evm::revm::{
    interpreter::instructions::utility::{IntoAddress, IntoU256},
    primitives::hardfork::SpecId::PETERSBURG,
};
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
        tip_fee_manager::{self, TipFeeManager},
        tip20,
        types::IFeeManager,
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
        // TODO: ensure ensure_sufficient_balance
        self.inner.validate_transactions(transactions).await
    }

    async fn validate_transactions_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: impl IntoIterator<Item = Self::Transaction> + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        // TODO: ensure ensure_sufficient_balance
        self.inner
            .validate_transactions_with_origin(origin, transactions)
            .await
    }

    fn on_new_head_block<B>(&self, new_tip_block: &SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block)
    }
}
