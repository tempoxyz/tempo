//! Owns the strictly sequential finalization-queue.

use eyre::{WrapErr as _, ensure};
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_util::StreamExt as _;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tracing::{Level, instrument, warn};

use super::forkchoice_updater;

pub(super) struct Builder {
    pub(super) execution_node: TempoFullNode,
    pub(super) to_forkchoice_updater: forkchoice_updater::Mailbox,
}

impl Builder {
    pub(super) fn build(self) -> Finalizer {
        let Self {
            execution_node,
            to_forkchoice_updater,
        } = self;
        let (to_me, from_execution_driver) = futures_channel::mpsc::unbounded();
        Finalizer {
            execution_node,
            to_forkchoice_updater,

            from_execution_driver,
            my_mailbox: Mailbox { inner: to_me },
        }
    }
}

pub(super) struct Finalizer {
    execution_node: TempoFullNode,
    to_forkchoice_updater: forkchoice_updater::Mailbox,

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
            Message::Finalize(finalized) => self.finalize(*finalized).await,
        }
    }

    #[instrument(
        skip_all,
        fields(finalized_block.digest = %finalized.block.digest()),
        err(level = Level::WARN),
        ret,
    )]
    async fn finalize(&self, finalized: super::Finalized) -> eyre::Result<()> {
        let super::Finalized { block, response } = finalized;

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

        // TODO(janis): this is basically success-or-die. If we are unable
        // to finalize, then we cannot recover and just exit. Is this the
        // right thing to do? Can we relax this somewhat? Should the
        // forkchoice-update report what went wrong?
        self.to_forkchoice_updater
            .set_finalized(hash)
            .await
            .wrap_err_with(|| {
                format!(
                    "unable to finalize hash `{hash}`; we will not be able to recover form that"
                )
            })?;

        // Acknowledge that the block was finalized.
        if let Err(()) = response.send(()) {
            warn!("tried acknowledging finalization but channel was already closed");
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(super) struct Mailbox {
    inner: UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn finalize(&self, finalized: super::Finalized) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message::Finalize(finalized.into()))
            .wrap_err("failed sending finalization request to finalizer, this means it exited")
    }
}

#[derive(Debug)]
enum Message {
    Finalize(Box<super::Finalized>),
}
