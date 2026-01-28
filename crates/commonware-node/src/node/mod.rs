//! Consensus node implementation that can be spawned in a dedicated thread.
//!
//! # Usage
//! ```rust,ignore
//! let handle = ConsensusNode::new(args.consensus, node, feed_state)
//!     .spawn();
//!
//! // Handle can be used to trigger graceful shutdown
//! handle.shutdown();
//! ```

use commonware_runtime::{Metrics, Runner};
use eyre::{WrapErr as _, eyre};
use futures::{FutureExt as _, future::FusedFuture as _};
use reth_ethereum::chainspec::EthChainSpec as _;
use std::{path::PathBuf, thread};
use tracing::{error, info, info_span};

use crate::{args::Args, feed::FeedStateHandle, run_consensus_stack};
use tempo_node::TempoFullNode;

pub(crate) mod handle;

pub use handle::ConsensusNodeHandle;

/// Consensus node that can be spawned in a dedicated thread.
///
/// This encapsulates the commonware runtime and consensus stack setup,
/// providing a clean interface to spawn the consensus layer.
pub struct ConsensusNode {
    args: Args,
    execution_node: TempoFullNode,
    feed_state: FeedStateHandle,
    storage_directory: PathBuf,
}

impl ConsensusNode {
    /// Create a new consensus node.
    ///
    /// The storage directory is derived from the execution node's datadir
    /// unless explicitly set in the CLI args.
    pub fn new(args: Args, execution_node: TempoFullNode, feed_state: FeedStateHandle) -> Self {
        let storage_directory = args.storage_dir.clone().unwrap_or_else(|| {
            execution_node
                .config
                .datadir
                .clone()
                .resolve_datadir(execution_node.chain_spec().chain())
                .data_dir()
                .join("consensus")
        });

        Self {
            args,
            execution_node,
            feed_state,
            storage_directory,
        }
    }

    /// Spawns the consensus node in a dedicated thread and returns a handle.
    ///
    /// The consensus stack runs in its own tokio runtime on a separate thread.
    /// The returned handle can trigger graceful shutdown via [`ConsensusNodeHandle::shutdown`].
    ///
    /// # Panics
    /// The spawned thread will panic if the consensus stack fails.
    pub fn spawn(self) -> ConsensusNodeHandle {
        info_span!("prepare_consensus").in_scope(|| {
            info!(
                path = %self.storage_directory.display(),
                "determined directory for consensus data",
            )
        });

        let Self {
            args,
            execution_node,
            feed_state,
            storage_directory,
        } = self;

        let (handle, shutdown_token) = ConsensusNodeHandle::create();

        let thread_handle = thread::spawn(move || {
            let runtime_config = commonware_runtime::tokio::Config::default()
                .with_tcp_nodelay(Some(true))
                .with_worker_threads(args.worker_threads)
                .with_storage_directory(storage_directory)
                .with_catch_panics(true);

            let runner = commonware_runtime::tokio::Runner::new(runtime_config);

            let result: eyre::Result<()> = runner.start(|ctx| async move {
                // Ensure all consensus metrics are prefixed
                let ctx = ctx.with_label("consensus");

                let mut metrics_server =
                    crate::metrics::install(ctx.with_label("metrics"), args.metrics_address).fuse();

                let consensus_stack = run_consensus_stack(&ctx, args, execution_node, feed_state);
                tokio::pin!(consensus_stack);

                loop {
                    tokio::select!(
                        biased;

                        () = shutdown_token.cancelled() => {
                            info!("consensus received shutdown signal");
                            break Ok(());
                        }

                        ret = &mut consensus_stack => {
                            break ret
                                .and_then(|()| Err(eyre!("consensus stack exited unexpectedly")))
                                .wrap_err("consensus stack failed");
                        }

                        ret = &mut metrics_server, if !metrics_server.is_terminated() => {
                            let reason = match ret.wrap_err::<&str>("task_panicked") {
                                Ok(Ok(())) => "unexpected regular exit".to_string(),
                                Ok(Err(err)) | Err(err) => format!("{err}"),
                            };
                            tracing::warn!(reason, "the metrics server exited");
                        }
                    )
                }
            });

            if let Err(ref e) = result {
                error!("Consensus node failed: {e:?}");
                panic!("Consensus node failed: {e:?}");
            }

            result
        });

        handle.with_thread(thread_handle)
    }
}
