use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_primitives::SealedBlock;
use reth_primitives_traits::Block;
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    EthPoolTransaction, EthTransactionValidator, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidator,
};

/// Validator for Tempo transactions.
#[derive(Debug, Clone)]
pub struct TempoTransactionValidator<Client, Tx> {
    /// The type that performs the actual validation.
    inner: EthTransactionValidator<Client, Tx>,
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
        // self.inner.validate_one(origin, transaction)
        todo!()
    }

    async fn validate_transactions(
        &self,
        transactions: Vec<(TransactionOrigin, Self::Transaction)>,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        // self.inner.validate_batch(transactions)
        todo!()
    }

    async fn validate_transactions_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: impl IntoIterator<Item = Self::Transaction> + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        // self.inner.validate_batch_with_origin(origin, transactions)
        todo!()
    }

    fn on_new_head_block<B>(&self, new_tip_block: &SealedBlock<B>)
    where
        B: Block,
    {
        // self.inner.on_new_head_block(new_tip_block.header())
        todo!()
    }
}
