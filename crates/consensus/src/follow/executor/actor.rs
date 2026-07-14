use std::{sync::Arc, time::Duration};

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{marshal::Update, types::Height};
use commonware_runtime::{Clock, ContextCell, FutureExt as _, Handle, Pacer, Spawner, spawn_cell};
use commonware_utils::Acknowledgement as _;
use eyre::{Report, WrapErr as _, ensure};
use futures::{FutureExt as _, StreamExt as _, channel::mpsc, future::BoxFuture};
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_provider::{
    BlockHashReader as _, CanonStateSubscriptions as _, DatabaseProviderFactory as _,
};
use tempo_node::TempoFullNode;
use tracing::{debug, error, info, instrument, warn};

use super::Config;
use crate::{
    consensus::{Digest, block::Block},
    utils::OptionFuture,
};

#[derive(Clone, Copy, Debug)]
struct FinalizedTip {
    height: Height,
    digest: Digest,
}

pub(crate) struct Actor<TContext> {
    context: ContextCell<TContext>,
    execution_node: Arc<TempoFullNode>,
    marshal: crate::alias::marshal::Mailbox,
    mailbox: mpsc::UnboundedReceiver<Update<Block>>,

    tip: FinalizedTip,
    sync_target: Option<FinalizedTip>,
    forkchoice_task: OptionFuture<BoxFuture<'static, (FinalizedTip, eyre::Result<()>)>>,
    fcu_heartbeat_interval: Duration,
    fcu_heartbeat_timer: OptionFuture<BoxFuture<'static, ()>>,
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + Pacer + Spawner,
{
    pub(super) fn new(
        context: TContext,
        config: Config,
        mailbox: mpsc::UnboundedReceiver<Update<Block>>,
    ) -> Self {
        let Config {
            execution_node,
            marshal,
            fcu_heartbeat_interval,
        } = config;

        let tip = execution_node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .map_or_else(
                || FinalizedTip {
                    height: Height::new(0),
                    digest: Digest(execution_node.chain_spec().genesis_hash()),
                },
                |tip| FinalizedTip {
                    height: Height::new(tip.number),
                    digest: Digest(tip.hash),
                },
            );

        Self {
            context: ContextCell::new(context),

            mailbox,
            marshal,
            execution_node,

            tip,
            forkchoice_task: OptionFuture::none(),
            sync_target: None,

            fcu_heartbeat_interval,
            fcu_heartbeat_timer: OptionFuture::none(),
        }
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        let mut canonical_state = self.execution_node.provider.canonical_state_stream();

        loop {
            self.update_fcu_heartbeat_timer();

            tokio::select! {
                biased;

                result = &mut self.forkchoice_task => {
                    let (tip, result) = result;
                    if let Err(error) = result {
                        warn!(%error, height = %tip.height, digest = %tip.digest,
                            "follower forkchoice update failed");
                    }

                    if self.tip.height > tip.height {
                        self.start_forkchoice_task();
                    }
                }

                Some(update) = self.mailbox.next() => {
                    match update {
                        Update::Block(_, ack) => ack.acknowledge(),
                        Update::Tip(_, height, digest) => {
                            let previous_height = self.tip.height;

                            self.observe_tip(FinalizedTip { height, digest });
                            if self.tip.height > previous_height {
                                self.start_forkchoice_task();
                            }

                            if let Err(error) = self.complete_sync_target_if_canonical().await {
                                error!(%error, "failed checking marshal floor advancement");
                                break;
                            }
                        }
                    }
                }

                notification = canonical_state.next() => {
                    let Some(_notification) = notification else {
                        error!("canonical state notification stream ended");
                        break;
                    };

                    if let Err(error) = self.complete_sync_target_if_canonical().await {
                        error!(%error, "failed checking marshal floor advancement");
                        break;
                    }
                }

                _ = (&mut self.fcu_heartbeat_timer).fuse() => {
                    self.send_forkchoice_update_heartbeat();
                }
            }
        }
    }

    fn observe_tip(&mut self, tip: FinalizedTip) {
        if self.sync_target.is_none() {
            debug!(height = %tip.height, digest = %tip.digest, "setting sync target");
            self.sync_target = Some(tip);
        }

        if tip.height > self.tip.height {
            self.tip = tip;
        }
    }

    fn arm_fcu_heartbeat_timer(&mut self) {
        if !self.fcu_heartbeat_timer.is_none() {
            return;
        }

        self.fcu_heartbeat_timer
            .replace(self.context.sleep(self.fcu_heartbeat_interval).boxed());
    }

    fn disarm_fcu_heartbeat_timer(&mut self) {
        self.fcu_heartbeat_timer = OptionFuture::none();
    }

    fn update_fcu_heartbeat_timer(&mut self) {
        if self.forkchoice_task.is_none() {
            self.arm_fcu_heartbeat_timer();
        } else {
            self.disarm_fcu_heartbeat_timer();
        }
    }

    #[instrument(skip_all)]
    fn send_forkchoice_update_heartbeat(&mut self) {
        self.start_forkchoice_task();
    }

    fn start_forkchoice_task(&mut self) {
        if !self.forkchoice_task.is_none() {
            return;
        }

        let tip = self.tip;

        let context = self.context.clone();
        let execution_node = self.execution_node.clone();
        self.forkchoice_task.replace(
            async move {
                let result = submit_forkchoice_update(&context, &execution_node, &tip).await;
                (tip, result)
            }
            .boxed(),
        );
    }

    #[instrument(skip_all, err)]
    async fn complete_sync_target_if_canonical(&mut self) -> eyre::Result<()> {
        let Some(target) = self.sync_target.as_ref() else {
            return Ok(());
        };

        let database = self
            .execution_node
            .provider
            .database_provider_ro()
            .wrap_err("failed opening execution database")?;

        let target_hash = target.digest.0;
        let canonical_hash = database
            .block_hash(target.height.get())
            .wrap_err("failed reading sync target canonical hash")?;

        let Some(canonical_hash) = canonical_hash else {
            return Ok(());
        };

        ensure!(
            canonical_hash == target_hash,
            "sync target canonical hash mismatch: expected {target_hash}, got {canonical_hash}",
        );

        let target = self.sync_target.take().expect("target exists");
        debug!(height = %target.height, digest = %target.digest, "sync target is canonical; advancing marshal floor");

        // The current commonware API accepts a height. Once the certified
        // floor API lands, fetch and pass `finalization` here instead. We set the floor
        // to one-before so that the sync block is replayed (may be a boundary).
        //
        // The finalization is guaranteed to exist as the sync targets come from finalizations
        // observed by the driver, reported to the marshal.
        if let Some(one_before) = target.height.previous() {
            self.marshal.set_floor(one_before).await;
        }

        Ok(())
    }
}

#[instrument(skip_all, fields(height = %tip.height, digest = %tip.digest), err)]
async fn submit_forkchoice_update<TContext: Pacer>(
    context: &TContext,
    execution_node: &TempoFullNode,
    tip: &FinalizedTip,
) -> eyre::Result<()> {
    let hash = tip.digest.0;
    let forkchoice = ForkchoiceState {
        head_block_hash: hash,
        safe_block_hash: hash,
        finalized_block_hash: hash,
    };

    let response = execution_node
        .add_ons_handle
        .beacon_engine_handle
        .fork_choice_updated(forkchoice, None)
        .pace(context, Duration::from_millis(20))
        .await
        .wrap_err("failed requesting follower execution layer to update forkchoice state")?;

    debug!(payload_status = %response.payload_status, "execution layer reported FCU status");
    ensure!(
        !response.is_invalid(),
        Report::msg(response.payload_status).wrap_err("execution layer rejected fcu")
    );

    Ok(())
}
