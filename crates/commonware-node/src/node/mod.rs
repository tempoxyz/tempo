//! Consensus node implementation that can be spawned in a dedicated thread.
//!
//! # Usage
//! ```rust,ignore
//! let (handle, exit_future) = ConsensusNode::new(args.consensus, node, feed_state)
//!     .with_telemetry_config(telemetry_config)
//!     .spawn();
//!
//! handle.shutdown()?;   // shutdown (if needed) and wait; propagates panics/errors
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
use tempo_node::{TempoFullNode, telemetry::{PrometheusMetricsConfig, install_prometheus_metrics}};

pub(crate) mod handle;

pub use handle::{ConsensusExitFuture, ConsensusNodeHandle};

/// Consensus node that can be spawned in a dedicated thread.
pub struct ConsensusNode {
    args: Args,
    execution_node: TempoFullNode,
    feed_state: FeedStateHandle,
    storage_directory: PathBuf,
    telemetry_config: Option<PrometheusMetricsConfig>,
}

impl ConsensusNode {
    /// Create a new consensus node.
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
            telemetry_config: None,
        }
    }

    /// Set the telemetry configuration for Prometheus metrics export.
    pub fn with_telemetry_config(mut self, config: Option<PrometheusMetricsConfig>) -> Self {
        self.telemetry_config = config;
        self
    }

    /// Spawns the consensus node in a dedicated thread.
    ///
    /// Returns a handle (for shutdown/join) and an exit future that completes
    /// when the consensus node exits.
    pub fn spawn(self) -> (ConsensusNodeHandle, ConsensusExitFuture) {
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
            telemetry_config,
        } = self;

        let shutdown_token = CancellationToken::new();
        let shutdown_token_for_thread = shutdown_token.clone();
        let (exit_tx, exit_rx) = oneshot::channel();

        let thread_handle = thread::spawn(move || {
            let runtime_config = commonware_runtime::tokio::Config::default()
                .with_tcp_nodelay(Some(true))
                .with_worker_threads(args.worker_threads)
                .with_storage_directory(storage_directory)
                .with_catch_panics(true);

            let runner = commonware_runtime::tokio::Runner::new(runtime_config);

            let result: eyre::Result<()> = runner.start(|ctx| async move {
                let ctx = ctx.with_label("consensus");

                let mut metrics_server =
                    crate::metrics::install(ctx.with_label("metrics"), args.metrics_address).fuse();

                // Start the unified metrics exporter if configured
                if let Some(config) = telemetry_config {
                    install_prometheus_metrics(ctx.with_label("telemetry_metrics"), config)
                        .wrap_err("failed to start Prometheus metrics exporter")?;
                }

                let consensus_stack = run_consensus_stack(&ctx, args, execution_node, feed_state);
                tokio::pin!(consensus_stack);

                loop {
                    tokio::select!(
                        biased;

                        () = shutdown_token_for_thread.cancelled() => {
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
                let _ = exit_tx.send(Err(eyre!("{e}")));
            }
            result
        });

        let handle = ConsensusNodeHandle::new(shutdown_token, thread_handle);
        (handle, exit_rx)
    }
}
