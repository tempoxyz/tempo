//! Owns the strictly sequential finalization-queue.
//!
//! The finalizer is responsible for finalization and backfilling.
//!
//! When serving a request to backfill a given `parent_digest`, the finalizer
//! takes the following steps:
//!
//! 1. find the last available block in the execution layer at block number
//!    `execution_height` with `execution_digest` (or "hash").
//! 2. starting from `parent_digest`, start walking the consensus layer to
//!    get `block(parent_digest)` and its ancestors until `execution_digest` is
//!    reached.
//! 3. replay all blocks by sending them to the execution layer and finalizing
//!    them in inverse direction, starting from `block(execution_height + 1)`
//!    all the way back to `parent_digest`.

use std::sync::Arc;

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::marshal;
use eyre::{OptionExt as _, WrapErr as _, bail, ensure};
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_util::StreamExt as _;
use reth_provider::{BlockNumReader, BlockReaderIdExt};
use tempo_commonware_node_cryptography::{BlsScheme, Digest};
use tempo_node::{TempoExecutionData, TempoFullNode};
use tracing::{Level, info, instrument};

use crate::consensus::block::Block;

pub(super) struct Builder {
    pub(super) execution_node: TempoFullNode,
    pub(super) genesis_block: Arc<Block<tempo_primitives::Block>>,
    pub(super) syncer: marshal::Mailbox<BlsScheme, Block<tempo_primitives::Block>>,
}

impl Builder {
    pub(super) fn build(self) -> Finalizer {
        let Self {
            execution_node,
            genesis_block,
            syncer,
        } = self;
        let (to_me, from_execution_driver) = futures_channel::mpsc::unbounded();
        Finalizer {
            execution_node,
            genesis_block,
            syncer,
            from_execution_driver,
            my_mailbox: Mailbox { inner: to_me },
        }
    }
}

pub(super) struct Finalizer {
    execution_node: TempoFullNode,
    genesis_block: Arc<Block<tempo_primitives::Block>>,
    syncer: marshal::Mailbox<BlsScheme, Block<tempo_primitives::Block>>,

    from_execution_driver: UnboundedReceiver<Message>,

    my_mailbox: Mailbox,
}

impl Finalizer {
    pub(super) fn mailbox(&self) -> &Mailbox {
        &self.my_mailbox
    }

    pub(super) async fn run(mut self) -> eyre::Result<()> {
        while let Some(msg) = self.from_execution_driver.next().await {
            // XXX: finalizations must happen strictly sequentially, so blocking
            // the event loop is desired.
            // TODO: also listen to shutdown signals from the runtime here.
            self.handle_message(msg)
                .await
                .wrap_err("failed handling message from execution driver")?;
        }
        Ok(())
    }

    async fn handle_message(&mut self, message: Message) -> eyre::Result<()> {
        match message {
            Message::Finalize(finalized) => self.finalize(*finalized).await,
            Message::Backfill(digest) => self.backfill(digest).await,
        }
    }

    #[instrument(skip_all, fields(%digest), err)]
    async fn backfill(&mut self, mut digest: Digest) -> eyre::Result<()> {
        // Figure out the last block that the execution layer does have.
        let last_execution_height = self
            .execution_node
            .provider
            .last_block_number()
            .wrap_err("failed to query the execution node for its last block number")?;
        let last_execution_block = self
            .execution_node
            .provider
            .block_by_id(last_execution_height.into())
            .map_err(eyre::Report::new)
            .and_then(|maybe_block| maybe_block.ok_or_eyre("execution node did not know the block"))
            .wrap_err_with(|| format!("failed to query the execution node for block `{last_execution_height}` even though it just returned it as the last available block number"))?;

        info!(
            %last_execution_height,
            last_execution_block_hash = %last_execution_block.hash_slow(),
            "execution layer reported last execution block and height",
        );

        // Consistency check: if this block is in the execution layer but not in
        // the consensus storage, then we have a problem.
        // TODO(janis): That's for the case of killing a node locally and restarting.
        // What if I just copy over the reth db? Should I actually subscribe and
        // wait? When do I stop?
        let digest_of_last = Digest(last_execution_block.hash_slow());
        ensure!(
            digest_of_last == self.genesis_block.digest()
            || self.syncer.get(digest_of_last).await.await.wrap_err_with(||
                format!("syncer closed channel before responding with block for digest `{digest_of_last}`")
            )?.is_some(),
            "consensus does not know about block `{digest}`, even though it exists in the execution layer; this is a problem"
        );
        info!(%digest_of_last, "consensus layer knows about last execution block; good");

        // Next, starting from `digest`, walk backwards until we reach `digest_of_last`
        let mut to_replay = Vec::new();
        while digest_of_last != digest || digest_of_last != self.genesis_block.digest() {
            // TODO: this subscribe can potentially wait a very long time. We
            // don't have a way around this, but we should emit events.
            // TODO: maybe we should just time this out after 5 seconds? The
            // execution driver should push new backill requests anyways.
            info!(%digest, "requesting block from consensus");
            let block = self
                .syncer
                .subscribe(None, digest)
                .await
                .await
                .wrap_err_with(|| {
                    format!(
                        "syncer closed channel before responding with block for digest `{digest}`"
                    )
                })?;
            digest = block.parent_digest();
            to_replay.push(block);
        }

        if digest == self.genesis_block.digest() && digest != digest_of_last {
            bail!(
                "reached consensus layer genesis `{digest}``, but it still does match the latest block of the execution layer `{digest_of_last}`; this is a problem"
            );
        }
        info!(
            amount = to_replay.len(),
            "found blocks to send to the execution layer"
        );
        // Now send the blocks to the execution layer, starting with the last.
        // We will just push all of this into our own mailbox because this is
        // duplicate work otherwise.
        for block in to_replay.into_iter().rev() {
            self.my_mailbox
                .finalize(super::Finalized { block })
                .expect("in a self method; the channel must be alive");
        }

        Ok(())
    }

    #[instrument(
        skip_all,
        fields(finalized_block.digest = %finalized.block.digest()),
        err(level = Level::WARN),
        ret,
    )]
    async fn finalize(
        &mut self,
        finalized: super::Finalized<tempo_primitives::Block>,
    ) -> eyre::Result<()> {
        let super::Finalized { block } = finalized;

        // Check if the execution layer already knows about this block's parent..
        // If it doesn't - start a backfill and push this finalization back
        // into the queue.
        let parent_digest = block.parent_digest();
        let parent_block_hash = parent_digest.0;
        if self.execution_node
            .provider
            .block_by_id(parent_block_hash.into())
            .wrap_err_with(|| format!(
                "failed to query execution node for `{parent_block_hash}`, but need to check if it already knows about it or not"
            ))?
            .is_none()
        {
            self.my_mailbox
                .backfill(parent_digest)
                .expect("in a self method, so my_mailbox must be open");
            self.my_mailbox
                .finalize(super::Finalized { block } )
                .expect("in a self method, so my_mailbox must be open");
            return Ok(());
        }

        let block = block.clone().into_inner();
        let hash = block.hash();
        let payload_status = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(TempoExecutionData(block))
            .await
            .wrap_err(
                "failed sending new-payload request to execution \
                    engine to query payload status of finalized block",
            )?;

        ensure!(
            payload_status.is_valid(),
            "payload status of block-to-be-finalized not valid: \
            `{payload_status}`"
        );

        let fcu_response = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(
                ForkchoiceState {
                    head_block_hash: hash,
                    safe_block_hash: hash,
                    finalized_block_hash: hash,
                },
                None,
                reth_node_builder::EngineApiMessageVersion::V3,
            )
            .await
            .wrap_err(
                "failed running engine_forkchoiceUpdated to set the \
                    finalized block hash",
            )?;

        ensure!(
            fcu_response.is_valid(),
            "payload status of forkchoice update response valid: `{}`",
            fcu_response.payload_status,
        );

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(super) struct Mailbox {
    inner: UnboundedSender<Message>,
}

impl Mailbox {
    // TODO: if there's already a backfill running for a given digest, then
    // don't send another. Sounds like request coalescing?
    pub(super) fn backfill(&self, digest: Digest) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message::Backfill(digest))
            .wrap_err("failed sending backfill request to finalizer, this means it exited")
    }

    pub(super) fn finalize(
        &self,
        finalized: super::Finalized<tempo_primitives::Block>,
    ) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message::Finalize(finalized.into()))
            .wrap_err("failed sending finalization request to finalizer, this means it exited")
    }
}

#[derive(Clone, Debug)]
enum Message {
    Backfill(Digest),
    Finalize(Box<super::Finalized<tempo_primitives::Block>>),
}
