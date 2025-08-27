use reth_transaction_pool::{
    CoinbaseTipOrdering, EthPooledTransaction, Pool, TransactionValidationTaskExecutor,
};

use crate::validator::TempoTransactionValidator;

pub mod transaction;
pub mod validator;

pub type TempoTransactionPool<Client, S, T = EthPooledTransaction> = Pool<
    TransactionValidationTaskExecutor<TempoTransactionValidator<Client, T>>,
    CoinbaseTipOrdering<T>,
    S,
>;
