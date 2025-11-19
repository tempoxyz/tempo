//! Tempo Node types config.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use tempo_payload_types::{TempoExecutionData, TempoPayloadTypes};
pub use version::{init_version_metadata, version_metadata};

use crate::node::{TempoAddOns, TempoNode};
use reth_node_builder::{FullNode, NodeAdapter, RethFullAdapter};

pub mod engine;
pub mod node;
pub mod rpc;
pub use tempo_consensus as consensus;
pub use tempo_evm as evm;
pub use tempo_primitives as primitives;

#[cfg(feature = "weak-db")]
pub mod weak_database;
#[cfg(feature = "weak-db")]
pub use weak_database::WeakDatabase;

mod version;

#[cfg(feature = "weak-db")]
type TempoNodeAdapter = NodeAdapter<RethFullAdapter<WeakDatabase, TempoNode>>;
#[cfg(not(feature = "weak-db"))]
type TempoNodeAdapter = NodeAdapter<RethFullAdapter<std::sync::Arc<reth_db::DatabaseEnv>, TempoNode>>;

/// Type alias for a launched tempo node.
pub type TempoFullNode = FullNode<TempoNodeAdapter, TempoAddOns<TempoNodeAdapter>>;
