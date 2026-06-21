//! Tempo Node types config.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use tempo_payload_types::{TempoExecutionData, TempoPayloadTypes};
pub use version::{init_version_metadata, version_metadata};

use crate::node::TempoAddOns;
pub use crate::node::{TempoNode, TempoNodeArgs, TempoPayloadBuilderBuilder, TempoPoolBuilder};
use reth_ethereum::provider::db::DatabaseEnv;
use reth_node_builder::{FullNode, NodeAdapter, RethFullAdapter};
pub use reth_storage_api::AccountInfoReader;
pub use reth_transaction_pool::{
    PoolTransaction, StatefulValidationFn, StatelessValidationFn, TransactionOrigin,
    error::{InvalidPoolTransactionError, PoolTransactionError},
};
pub use tempo_transaction_pool::{
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
    validator::DEFAULT_AA_VALID_AFTER_MAX_SECS,
};

pub mod engine;
pub mod node;
pub mod rpc;
pub mod telemetry;
pub use tempo_evm as evm;
pub use tempo_evm::consensus;
pub use tempo_primitives as primitives;

mod version;

type TempoFullNodeTypes = RethFullAdapter<DatabaseEnv, TempoNode>;
type TempoNodeAdapter = NodeAdapter<TempoFullNodeTypes>;

/// Type alias for a launched tempo node.
pub type TempoFullNode = FullNode<TempoNodeAdapter, TempoAddOns<TempoFullNodeTypes>>;
