//! Tempo Node types config.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use tempo_payload_types::{TempoExecutionData, TempoPayloadTypes};
pub use version::{init_version_metadata, version_metadata};

pub use crate::node::{DEFAULT_AA_VALID_AFTER_MAX_SECS, ValidatorConfig};
use crate::node::{TempoAddOns, TempoNode};
use reth_ethereum::provider::db::DatabaseEnv;
use reth_node_builder::{FullNode, NodeAdapter, RethFullAdapter};
use std::sync::Arc;

pub mod engine;
pub mod node;
pub mod rpc;
pub use tempo_consensus as consensus;
pub use tempo_evm as evm;
pub use tempo_primitives as primitives;

mod version;

type TempoNodeAdapter = NodeAdapter<RethFullAdapter<Arc<DatabaseEnv>, TempoNode>>;

/// Type alias for a launched tempo node.
pub type TempoFullNode = FullNode<TempoNodeAdapter, TempoAddOns<TempoNodeAdapter>>;
