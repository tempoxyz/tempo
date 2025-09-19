//! Owns the strictly sequential finalization-queue.

use alloy_rpc_types_engine::ForkchoiceState;
use eyre::{WrapErr as _, ensure};
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_util::StreamExt as _;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tracing::{Level, instrument};

pub(super) struct Builder {
    pub(super) execution_node: TempoFullNode,
}

impl Builder {
    pub(super) fn build(self) -> Finalizer {
        let Self { execution_node } = self;
        let (to_me, from_execution_driver) = futures_channel::mpsc::unbounded();
        Finalizer {
            execution_node,
            from_execution_driver,
            my_mailbox: Mailbox { inner: to_me },
        }
    }
}

pub(super) struct Finalizer {
    execution_node: TempoFullNode,

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

    async fn handle_message(&self, message: Message) -> eyre::Result<()> {
        match message {
            Message::Finalize(finalized) => self.finalize(finalized).await,
        }
    }

    #[instrument(
        skip_all,
        fields(finalized_block.digest = %finalized.block.digest()),
        err(level = Level::WARN),
        ret,
    )]
    async fn finalize(
        &self,
        finalized: super::Finalized<tempo_primitives::Block>,
    ) -> eyre::Result<()> {
        let super::Finalized { block } = finalized;

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
    pub(super) fn finalize(
        &self,
        finalized: super::Finalized<tempo_primitives::Block>,
    ) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message::Finalize(finalized))
            .wrap_err("failed sending finalization request to finalizer, this means it exited")
    }
}

#[derive(Clone, Debug)]
enum Message {
    Finalize(super::Finalized<tempo_primitives::Block>),
}
