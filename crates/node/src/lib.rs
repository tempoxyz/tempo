//! Tempo Node types config.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use crate::node::{TempoAddOns, TempoNode};
use reth_ethereum::provider::db::DatabaseEnv;
use reth_node_builder::{FullNode, NodeAdapter, RethFullAdapter};
use std::sync::Arc;

pub mod args;
pub mod engine;
pub mod node;
pub mod rpc;

type TempoNodeAdapter = NodeAdapter<RethFullAdapter<Arc<DatabaseEnv>, TempoNode>>;

/// Type alias for a launched tempo node.
pub type TempoFullNode = FullNode<TempoNodeAdapter, TempoAddOns<TempoNodeAdapter>>;
