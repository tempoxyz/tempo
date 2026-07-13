use std::{sync::Arc, time::Duration};

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{
    marshal::Update,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_runtime::{ContextCell, FutureExt as _, Handle, Pacer, Spawner, spawn_cell};
use commonware_utils::Acknowledgement as _;
use eyre::{OptionExt as _, Report, WrapErr as _, ensure};
use futures::{FutureExt as _, StreamExt as _, channel::mpsc, future::BoxFuture};
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
    epoch_strategy: FixedEpocher,
    mailbox: mpsc::UnboundedReceiver<Update<Block>>,

    pending_tip: Option<FinalizedTip>,
    sync_target: Option<FinalizedTip>,
    forkchoice_task: OptionFuture<BoxFuture<'static, (FinalizedTip, eyre::Result<()>)>>,
}

impl<TContext> Actor<TContext>
where
    TContext: Pacer + Spawner,
{
    pub(super) fn new(
        context: TContext,
        config: Config,
        mailbox: mpsc::UnboundedReceiver<Update<Block>>,
    ) -> Self {
        Self {
            context: ContextCell::new(context),

            mailbox,
            marshal: config.marshal,
            execution_node: config.execution_node,
            epoch_strategy: config.epoch_strategy,

            forkchoice_task: OptionFuture::none(),
            pending_tip: None,
            sync_target: None,
        }
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        let mut canonical_state = self.execution_node.provider.canonical_state_stream();

        loop {
            self.start_forkchoice_task();

            tokio::select! {
                biased;

                result = &mut self.forkchoice_task => {
                    let (tip, result) = result;
                    if let Err(error) = result {
                        warn!(%error, height = %tip.height, digest = %tip.digest,
                            "follower forkchoice update failed");
                    }
                }

                Some(update) = self.mailbox.next() => {
                    match update {
                        Update::Block(_, ack) => ack.acknowledge(),
                        Update::Tip(_, height, digest) => {
                            self.observe_tip(FinalizedTip { height, digest });
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
            }
        }
    }

    fn observe_tip(&mut self, tip: FinalizedTip) {
        if self.sync_target.is_none() && self.tip_is_more_than_one_epoch_ahead(&tip) {
            info!(height = %tip.height, digest = %tip.digest, "setting sync target");
            self.sync_target = Some(tip);
        }

        if self
            .pending_tip
            .as_ref()
            .is_none_or(|pending| tip.height > pending.height)
        {
            self.pending_tip = Some(tip);
        }
    }

    fn tip_is_more_than_one_epoch_ahead(&self, tip: &FinalizedTip) -> bool {
        let canonical_height = self
            .execution_node
            .provider
            .canonical_in_memory_state()
            .chain_info()
            .best_number;

        let canonical_epoch = self
            .epoch_strategy
            .containing(commonware_consensus::types::Height::new(canonical_height))
            .expect("epoch strategy is valid for every height")
            .epoch();

        let tip_epoch = self
            .epoch_strategy
            .containing(tip.height)
            .expect("epoch strategy is valid for every height")
            .epoch();

        tip_epoch > canonical_epoch.next()
    }

    fn start_forkchoice_task(&mut self) {
        if !self.forkchoice_task.is_none() {
            return;
        }

        let Some(tip) = self.pending_tip.take() else {
            return;
        };

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
        info!(height = %target.height, digest = %target.digest, "sync target is canonical; advancing marshal floor");

        // The current commonware API accepts a height. Once the certified
        // floor API lands, fetch and pass `finalization` here instead. We set the floor
        // to one-before so that the sync block is replayed (may be a boundary).
        //
        // The finalization is gauranteed to exist as the sync targets come from finalizations
        // observed by the driver, reported to the marshal.:w
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
