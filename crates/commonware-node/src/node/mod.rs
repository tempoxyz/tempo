//! Consensus node implementation that can be spawned in a dedicated thread.
//!
//! # Usage
//! ```rust,ignore
//! let handle = ConsensusNodeBuilder::default()
//!     .with_args(args.consensus)
//!     .with_execution_node_receiver(node_rx)
//!     .with_feed_state(feed_state)
//!     .with_shutdown_token(shutdown_token)
//!     .build()?
//!     .spawn();
//! ```

use commonware_runtime::{Metrics, Runner};
use eyre::{WrapErr as _, eyre};
use futures::{FutureExt as _, future::FusedFuture as _};
use reth_ethereum::chainspec::EthChainSpec as _;
use std::{path::PathBuf, thread};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, info_span};

use crate::{args::Args, feed::FeedStateHandle, run_consensus_stack};
use tempo_node::TempoFullNode;

pub(crate) mod builder;
pub(crate) mod handle;

pub use builder::ConsensusNodeBuilder;
pub use handle::{ConsensusDeadSignal, ConsensusNodeHandle};

/// Input received from the execution layer to start consensus.
pub struct ExecutionNodeInput {
    /// The execution node handle.
    pub node: TempoFullNode,
    /// Whether the node is in dev mode.
    pub is_dev_mode: bool,
    /// Whether follow mode is enabled (skip consensus).
    pub skip_consensus: bool,
    /// Optional storage directory override. If None, derived from node datadir.
    pub storage_dir_override: Option<PathBuf>,
}

/// Validated consensus node configuration.
pub(crate) struct ConsensusNodeConfig {
    pub(crate) args: Args,
    pub(crate) execution_node_rx: oneshot::Receiver<ExecutionNodeInput>,
    pub(crate) feed_state: FeedStateHandle,
    pub(crate) shutdown_token: CancellationToken,
}

/// Consensus node that can be spawned in a dedicated thread.
///
/// This encapsulates the commonware runtime and consensus stack setup,
/// providing a clean interface to spawn the consensus layer.
pub struct ConsensusNode {
    config: ConsensusNodeConfig,
}

impl ConsensusNode {
    /// Creates a new consensus node with the given configuration.
    pub(crate) fn new(config: ConsensusNodeConfig) -> Self {
        Self { config }
    }

    /// Spawns the consensus node in a dedicated thread and returns a handle.
    ///
    /// The consensus stack runs in its own tokio runtime on a separate thread.
    /// The returned handle can be used to wait for completion or check status.
    ///
    /// All business logic (waiting for execution node, dev mode handling,
    /// storage directory resolution) is encapsulated within this method.
    pub fn spawn(self) -> ConsensusNodeHandle {
        let (dead_tx, dead_rx) = oneshot::channel();

        let config = self.config;

        let thread_handle = thread::spawn(move || {
            let args = config.args;
            let feed_state = config.feed_state;
            let shutdown_token = config.shutdown_token;

            // Wait for the execution node to be ready
            let input = match config.execution_node_rx.blocking_recv() {
                Ok(input) => input,
                Err(_) => {
                    let _ = dead_tx.send(());
                    return Err(eyre!(
                        "channel closed before execution node input could be received"
                    ));
                }
            };

            // Skip consensus in dev mode or follow mode
            if input.is_dev_mode || input.skip_consensus {
                info_span!("consensus").in_scope(|| {
                    info!(
                        dev_mode = input.is_dev_mode,
                        skip_consensus = input.skip_consensus,
                        "skipping consensus stack"
                    );
                });
                let _ = dead_tx.send(());
                futures::executor::block_on(async move {
                    shutdown_token.cancelled().await;
                });
                return Ok(());
            }

            // Resolve storage directory
            let storage_directory = input.storage_dir_override.or_else(|| args.storage_dir.clone()).unwrap_or_else(|| {
                input
                    .node
                    .config
                    .datadir
                    .clone()
                    .resolve_datadir(input.node.chain_spec().chain())
                    .data_dir()
                    .join("consensus")
            });

            info_span!("prepare_consensus").in_scope(|| {
                info!(
                    path = %storage_directory.display(),
                    "determined directory for consensus data",
                )
            });

            let worker_threads = args.worker_threads;
            let runtime_config = commonware_runtime::tokio::Config::default()
                .with_tcp_nodelay(Some(true))
                .with_worker_threads(worker_threads)
                .with_storage_directory(storage_directory)
                .with_catch_panics(true);

            let runner = commonware_runtime::tokio::Runner::new(runtime_config);

            let result: eyre::Result<()> = runner.start(async move |ctx| {
                // Ensure all consensus metrics are prefixed
                let ctx = ctx.with_label("consensus");

                let mut metrics_server =
                    crate::metrics::install(ctx.with_label("metrics"), args.metrics_address).fuse();

                let consensus_stack =
                    run_consensus_stack(&ctx, args, input.node, feed_state);
                tokio::pin!(consensus_stack);

                loop {
                    tokio::select!(
                        biased;

                        () = shutdown_token.cancelled() => {
                            break Ok(());
                        }

                        ret = &mut consensus_stack => {
                            break ret.and_then(|()| Err::<(), eyre::Report>(eyre!(
                                "consensus stack exited unexpectedly"))
                            )
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
                error!("Consensus node runner failed: {e:?}");
            }

            let _ = dead_tx.send(());
            result
        });

        ConsensusNodeHandle::new(thread_handle, dead_rx)
    }
}
