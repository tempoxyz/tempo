//! Execution-layer driver for follower nodes.
//!
//! This actor sends verified finalized tips to Reth as head, safe, and finalized forkchoice
//! updates, periodically refreshes that forkchoice with a heartbeat, and advances marshal's floor
//! to one epoch behind the finalized tip when that block is durably canonical in Reth.
//!
//! Unlike the executor used by validator nodes, it does not build payloads, canonicalize proposal
//! heads, or forward finalized blocks into the execution layer. Followers receive complete blocks
//! from their upstream and rely on Reth's sync machinery plus marshal gap repair to fill history.

use std::{sync::Arc, time::Duration};

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{
    marshal::Update,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_runtime::{Clock, ContextCell, FutureExt as _, Handle, Pacer, Spawner, spawn_cell};
use commonware_utils::Acknowledgement as _;
use eyre::{Report, WrapErr as _, ensure};
use futures::{FutureExt as _, StreamExt as _, channel::mpsc, future::BoxFuture};
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_provider::{BlockHashReader as _, DatabaseProviderFactory as _};
use tempo_node::TempoFullNode;
use tracing::{debug, instrument, warn};

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

    tip: FinalizedTip,
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
            epoch_strategy,
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
            epoch_strategy,
            execution_node,

            tip,
            forkchoice_task: OptionFuture::none(),

            fcu_heartbeat_interval,
            fcu_heartbeat_timer: OptionFuture::none(),
        }
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
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
                            if height > self.tip.height {
                                self.tip = FinalizedTip { height, digest };
                                self.start_forkchoice_task();
                                if let Err(error) = self.try_advance_floor().await {
                                    warn!(%error, "failed checking marshal floor advancement");
                                }
                            }
                        }
                    }
                }

                _ = (&mut self.fcu_heartbeat_timer).fuse() => {
                    self.send_forkchoice_update_heartbeat();
                }
            }
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
    async fn try_advance_floor(&mut self) -> eyre::Result<()> {
        let epoch_length = self
            .epoch_strategy
            .containing(self.tip.height)
            .expect("strategy is valid for all heights and epochs")
            .length();

        let database = self
            .execution_node
            .provider
            .database_provider_ro()
            .wrap_err("failed opening execution database")?;

        let floor_height = self.tip.height.saturating_sub(epoch_length.into());
        let floor_digest = database
            .block_hash(floor_height.get())
            .wrap_err("failed reading floor block hash")?;

        let Some(floor_digest) = floor_digest else {
            debug!(tip_height = %self.tip.height, %floor_height, "floor not durable in execution");
            return Ok(());
        };

        debug!(tip_height = %self.tip.height, %floor_height, %floor_digest, "advancing marshal floor");
        self.marshal.set_floor(floor_height).await;

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
