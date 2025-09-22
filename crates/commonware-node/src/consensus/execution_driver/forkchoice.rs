//! Owns forkchoice updates.
//!
//! The forkchoice updater drives the canonical chain by setting forkchoice
//! updates received over [`Mailbox::set_head`] and reading the latest finalized
//! block digest set by [`super::finalizer`].
use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatus};
use eyre::WrapErr as _;
use futures_channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures_util::StreamExt as _;
use tempo_commonware_node_cryptography::Digest;
use tempo_node::TempoFullNode;
use tracing::instrument;

pub(super) struct Builder {
    pub(super) execution_node: TempoFullNode,
    pub(super) finalizer: super::finalizer::Mailbox,
}

impl Builder {
    pub(super) fn build(self) -> Updater {
        let Self {
            execution_node,
            finalizer,
        } = self;

        let (to_me, from_execution_driver) = mpsc::unbounded();
        Updater {
            execution_node,
            finalizer,
            from_execution_driver,
            my_mailbox: Mailbox { inner: to_me },
        }
    }
}

pub(super) struct Updater {
    execution_node: TempoFullNode,
    finalizer: super::finalizer::Mailbox,
    from_execution_driver: UnboundedReceiver<Message>,
    my_mailbox: Mailbox,
}

impl Updater {
    pub(super) fn mailbox(&self) -> &Mailbox {
        &self.my_mailbox
    }

    pub(super) async fn run(mut self) -> eyre::Result<()> {
        while let Some(msg) = self.from_execution_driver.next().await {
            // TODO(janis): does it make sense to abort in-flight fcus? Is there
            // any danger of them slowing down this loop.
            // TODO(janis): also listen to shutdown signals from the runtime here.
            self.update_forkchoice_state(msg.digest, msg.cause)
                .await
                .wrap_err("failed handling message from execution driver")?;
        }
        Ok(())
    }

    #[instrument(skip_all, fields(%digest), follows_from = [cause], ret, err)]
    async fn update_forkchoice_state(
        &self,
        digest: Digest,
        cause: tracing::Span,
    ) -> eyre::Result<PayloadStatus> {
        let finalized_block_hash = self.finalizer.latest_finalized_digest().0;
        let forkchoice_state = ForkchoiceState {
            head_block_hash: digest.0,
            safe_block_hash: finalized_block_hash,
            finalized_block_hash,
        };
        tracing::info!(
            head_block_hash = %forkchoice_state.head_block_hash,
            finalized_block_hash = %forkchoice_state.finalized_block_hash,
            "sending forkchoice-update",
        );
        let fcu_response = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(
                forkchoice_state,
                None,
                reth_node_builder::EngineApiMessageVersion::V3,
            )
            .await
            .wrap_err("failed requesting execution layer to update forkchoice state")?;

        if fcu_response.is_invalid() {
            Err(eyre::Report::msg(fcu_response.payload_status)
                .wrap_err("execution layer responded with error for forkchoice-update"))
        } else {
            Ok(fcu_response.payload_status)
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Mailbox {
    inner: UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn set_head(&self, digest: Digest) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                digest,
                cause: tracing::Span::current(),
            })
            .wrap_err("failed sending set-head request to forkchoice updater this means it exited")
    }
}

#[derive(Debug)]
struct Message {
    digest: Digest,
    cause: tracing::Span,
}
