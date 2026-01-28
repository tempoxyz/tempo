//! Builder for configuring and constructing a [`ConsensusNode`].

use std::path::PathBuf;

use eyre::{ContextCompat, Result};
use reth_ethereum::chainspec::EthChainSpec as _;

use crate::{args::Args as CliArgs, feed::FeedStateHandle};
use tempo_node::TempoFullNode;

use super::ConsensusNode;

/// Builder for configuring and constructing a [`ConsensusNode`].
///
/// # Example
/// ```rust,ignore
/// let handle = ConsensusNode::builder(args.consensus)
///     .with_execution_node(node)
///     .with_feed_state(feed_state)
///     .build()?
///     .spawn();
/// ```
pub struct ConsensusNodeBuilder {
    args: CliArgs,
    execution_node: Option<TempoFullNode>,
    feed_state: Option<FeedStateHandle>,
    storage_directory: Option<PathBuf>,
}

impl ConsensusNodeBuilder {
    /// Create a new builder with the consensus CLI arguments.
    pub(super) fn new(args: CliArgs) -> Self {
        Self {
            args,
            execution_node: None,
            feed_state: None,
            storage_directory: None,
        }
    }

    /// Set the execution node handle (required).
    #[must_use]
    pub fn with_execution_node(mut self, node: TempoFullNode) -> Self {
        self.execution_node = Some(node);
        self
    }

    /// Override the feed state handle for RPC consensus info.
    /// Defaults to a new `FeedStateHandle`.
    #[must_use]
    pub fn with_feed_state(mut self, feed_state: FeedStateHandle) -> Self {
        self.feed_state = Some(feed_state);
        self
    }

    /// Override the storage directory for consensus data.
    /// If not set, derived from the execution node's datadir.
    #[must_use]
    pub fn with_storage_directory(mut self, path: PathBuf) -> Self {
        self.storage_directory = Some(path);
        self
    }

    /// Build the consensus node.
    ///
    /// # Errors
    /// Returns an error if the execution node is not set.
    pub fn build(self) -> Result<ConsensusNode> {
        let execution_node = self
            .execution_node
            .context("execution node is required - call with_execution_node()")?;

        // Resolve storage directory: explicit override > args.storage_dir > derived from datadir
        let storage_directory = self
            .storage_directory
            .or_else(|| self.args.storage_dir.clone())
            .unwrap_or_else(|| {
                execution_node
                    .config
                    .datadir
                    .clone()
                    .resolve_datadir(execution_node.chain_spec().chain())
                    .data_dir()
                    .join("consensus")
            });

        Ok(ConsensusNode {
            args: self.args,
            execution_node,
            feed_state: self
                .feed_state
                .context("feed state is required - call with_feed_state()")?,
            storage_directory,
        })
    }
}
