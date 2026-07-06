use futures::StreamExt as _;
use reth_exex::{ExExContext, ExExEvent};
use reth_node_api::FullNodeComponents;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedSender, error::SendError};

use crate::{facts::BlockNumHash, store::MonitorStore};
use tempo_hardfork::TempoHardfork;

use super::{
    AdapterError, AdapterResult, FinalizedLoop, FinalizedLoopConfig, FinishedHeightSink,
    RethFinalizedBlockSource,
};

#[derive(Clone, Debug)]
pub struct RethFinishedHeightSink {
    events: UnboundedSender<ExExEvent>,
}

impl RethFinishedHeightSink {
    pub const fn new(events: UnboundedSender<ExExEvent>) -> Self {
        Self { events }
    }
}

impl FinishedHeightSink for RethFinishedHeightSink {
    fn send_finished_height(&self, block: BlockNumHash) -> AdapterResult<()> {
        self.events
            .send(ExExEvent::FinishedHeight(block))
            .map_err(finished_height_send_error)
    }
}

fn finished_height_send_error(error: SendError<ExExEvent>) -> AdapterError {
    AdapterError::Halt(format!("failed sending FinishedHeight event: {error}"))
}

#[derive(Clone, Debug)]
pub struct ProtocolMonitorExExConfig {
    pub hardfork: TempoHardfork,
    pub retry_interval: Duration,
    pub loop_config: FinalizedLoopConfig,
}

impl Default for ProtocolMonitorExExConfig {
    fn default() -> Self {
        Self {
            hardfork: TempoHardfork::Genesis,
            retry_interval: Duration::from_secs(1),
            loop_config: FinalizedLoopConfig::default(),
        }
    }
}

pub async fn run_protocol_monitor_exex<Node, Store>(
    mut ctx: ExExContext<Node>,
    store: Store,
    config: ProtocolMonitorExExConfig,
) -> AdapterResult<()>
where
    Node: FullNodeComponents,
    Node::Provider: Clone + Send + Sync,
    RethFinalizedBlockSource<Node::Provider>: super::FinalizedBlockSource,
    Store: MonitorStore,
{
    let source = RethFinalizedBlockSource::new(ctx.provider().clone(), config.hardfork);
    let sink = RethFinishedHeightSink::new(ctx.events.clone());
    let mut finalized_loop = FinalizedLoop::with_config(store, source, sink, config.loop_config);
    let mut retry = tokio::time::interval(config.retry_interval);

    finalized_loop.tick()?;

    loop {
        tokio::select! {
            notification = ctx.notifications.next() => {
                let Some(notification) = notification else {
                    return Ok(());
                };
                notification.map_err(|err| {
                    AdapterError::Retry(format!("failed receiving ExEx notification: {err}"))
                })?;
                finalized_loop.tick()?;
            }
            _ = retry.tick() => {
                match finalized_loop.tick() {
                    Ok(_) => {}
                    Err(err) if err.is_retry() => {}
                    Err(err) => return Err(err),
                }
            }
        }
    }
}
