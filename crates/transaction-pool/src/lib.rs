use reth_transaction_pool::{CoinbaseTipOrdering, Pool, TransactionValidationTaskExecutor};

use crate::{transaction::TempoPooledTransaction, validator::TempoTransactionValidator};

pub mod transaction;
pub mod validator;

pub type TempoTransactionPool<Client, S> = Pool<
    TransactionValidationTaskExecutor<TempoTransactionValidator<Client>>,
    CoinbaseTipOrdering<TempoPooledTransaction>,
    S,
>;
