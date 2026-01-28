//! Builder for configuring and constructing a [`ConsensusNode`].

use eyre::{ContextCompat, Result};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::args::Args;
use crate::feed::FeedStateHandle;

use super::{ConsensusNode, ConsensusNodeConfig, ExecutionNodeInput};

/// Builder for configuring and constructing a [`ConsensusNode`].
///
/// # Example
/// ```rust,ignore
/// let handle = ConsensusNodeBuilder::default()
///     .with_args(args)
///     .with_execution_node_receiver(node_rx)
///     .with_feed_state(feed_state)
///     .with_shutdown_token(shutdown_token)
///     .build()?
///     .spawn();
/// ```
#[derive(Default)]
pub struct ConsensusNodeBuilder {
    args: Option<Args>,
    execution_node_rx: Option<oneshot::Receiver<ExecutionNodeInput>>,
    feed_state: Option<FeedStateHandle>,
    shutdown_token: Option<CancellationToken>,
}

impl ConsensusNodeBuilder {
    /// Set the consensus arguments.
    #[must_use]
    pub fn with_args(mut self, args: Args) -> Self {
        self.args = Some(args);
        self
    }

    /// Set the receiver for the execution node input.
    ///
    /// The consensus node will wait for this receiver to provide the
    /// execution node handle and configuration before starting.
    #[must_use]
    pub fn with_execution_node_receiver(
        mut self,
        rx: oneshot::Receiver<ExecutionNodeInput>,
    ) -> Self {
        self.execution_node_rx = Some(rx);
        self
    }

    /// Set the feed state handle.
    #[must_use]
    pub fn with_feed_state(mut self, feed_state: FeedStateHandle) -> Self {
        self.feed_state = Some(feed_state);
        self
    }

    /// Set the shutdown cancellation token.
    #[must_use]
    pub fn with_shutdown_token(mut self, shutdown_token: CancellationToken) -> Self {
        self.shutdown_token = Some(shutdown_token);
        self
    }

    /// Build the consensus node from this builder.
    ///
    /// Validates all required fields and returns a configured [`ConsensusNode`].
    ///
    /// # Errors
    /// Returns an error if any required field is missing.
    pub fn build(self) -> Result<ConsensusNode> {
        let args = self
            .args
            .context("Args are required - call with_args()")?;

        let execution_node_rx = self
            .execution_node_rx
            .context("Execution node receiver is required - call with_execution_node_receiver()")?;

        let feed_state = self
            .feed_state
            .context("Feed state is required - call with_feed_state()")?;

        let shutdown_token = self
            .shutdown_token
            .context("Shutdown token is required - call with_shutdown_token()")?;

        let config = ConsensusNodeConfig {
            args,
            execution_node_rx,
            feed_state,
            shutdown_token,
        };

        Ok(ConsensusNode::new(config))
    }
}
