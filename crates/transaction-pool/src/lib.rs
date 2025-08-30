//! Tempo transaction implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use reth_transaction_pool::{CoinbaseTipOrdering, Pool, TransactionValidationTaskExecutor};

use crate::{transaction::TempoPooledTransaction, validator::TempoTransactionValidator};

pub mod transaction;
pub mod validator;

pub type TempoTransactionPool<Client, S> = Pool<
    TransactionValidationTaskExecutor<TempoTransactionValidator<Client>>,
    CoinbaseTipOrdering<TempoPooledTransaction>,
    S,
>;
