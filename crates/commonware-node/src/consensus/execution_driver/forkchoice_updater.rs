//! Owns the forkchoice state and is responsible for updating it.
//!
//! Because forkchoice states cannot be updates individually but must be sent
//! all at once (that is, head, safe, and finalized are always sent together),
//! we can run into race conditions in a concurrent setting.

use alloy_primitives::B256;
use alloy_rpc_types_engine::ForkchoiceState;
use eyre::{WrapErr as _, ensure, eyre};
use futures_channel::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};
use futures_util::StreamExt as _;
use tempo_node::TempoFullNode;
use tracing::instrument;

pub(super) struct Builder {
    pub(super) execution_node: TempoFullNode,
    pub(super) initial_block_hash: B256,
}

impl Builder {
    /// Initializes the updater by sending the initial forkchoice state to the execution layer.
    pub(super) async fn try_init(self) -> eyre::Result<ForkchoiceUpdater> {
        let Self {
            execution_node,
            initial_block_hash,
        } = self;
        let initial_forkchoice_state = ForkchoiceState {
            head_block_hash: initial_block_hash,
            safe_block_hash: initial_block_hash,
            finalized_block_hash: initial_block_hash,
        };
        let fcu_response = execution_node
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(
                initial_forkchoice_state,
                None,
                reth_node_builder::EngineApiMessageVersion::V3,
            )
            .await
            .wrap_err("failed sending the initial forkchoice state to the execution layer")?;

        ensure!(
            fcu_response.is_valid() || fcu_response.is_syncing(),
            "status initial forkchoice state was neither syncing nor valid: `{}`",
            fcu_response.payload_status,
        );
        let (to_me, from_execution_driver) = futures_channel::mpsc::unbounded();
        Ok(ForkchoiceUpdater {
            execution_node,
            last_sent_forkchoice_state: initial_forkchoice_state,

            from_execution_driver,
            my_mailbox: Mailbox { inner: to_me },
        })
    }
}

pub(super) struct ForkchoiceUpdater {
    last_sent_forkchoice_state: ForkchoiceState,
    execution_node: TempoFullNode,

    from_execution_driver: UnboundedReceiver<Message>,
    my_mailbox: Mailbox,
}

impl ForkchoiceUpdater {
    pub(super) fn mailbox(&self) -> &Mailbox {
        &self.my_mailbox
    }

    pub(super) async fn run(mut self) {
        while let Some(msg) = self.from_execution_driver.next().await {
            let tracing_id = msg.follows_from().id();
            let _ = self.handle_message(msg, tracing_id).await;
        }
    }

    #[instrument(
        follows_from = [cause],
        skip_all,
        err,
    )]
    async fn handle_message(
        &mut self,
        message: Message,
        cause: Option<tracing::Id>,
    ) -> eyre::Result<()> {
        let (state_to_send, response) = match message {
            Message::SetHead {
                head_block_hash,
                response,
                ..
            } => (
                ForkchoiceState {
                    head_block_hash,
                    ..self.last_sent_forkchoice_state
                },
                response,
            ),
            Message::SetFinalized {
                finalized_block_hash,
                response,
                ..
            } => (
                ForkchoiceState {
                    finalized_block_hash,
                    safe_block_hash: finalized_block_hash,
                    ..self.last_sent_forkchoice_state
                },
                response,
            ),
        };

        // NOTE(janis): if the forkchoice-updated request fails or if the payload
        // was neither valid nor syncing, then the updater will simply drop
        // the response channel and exit. This means it's on the caller to
        // decide if this was bad or not.
        // TODO(janis): should any of this be reported upstream?
        let rsp = self.execution_node
                .add_ons_handle
                .beacon_engine_handle
                .fork_choice_updated(
                    state_to_send,
                    None,
                    reth_node_builder::EngineApiMessageVersion::V3,
                )
                .await
                .wrap_err("failed sending forkchoice state to the execution engine; if we can't, that's a problem")?;

        // TODO(janis): this too seems extremely harsh - what do we do if its invalid?
        eyre::ensure!(
            rsp.is_valid() || rsp.is_syncing(),
            "execution engine reported a forkchoice status that was neither valid nor syncing: `{}`",
            rsp.payload_status
        );
        self.last_sent_forkchoice_state = state_to_send;
        let _ = response.send(());
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(super) struct Mailbox {
    inner: UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) async fn set_finalized(&self, finalized_block_hash: B256) -> eyre::Result<()> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::SetFinalized {
                finalized_block_hash,
                response,
                follows_from: tracing::Span::current(),
            })
            .wrap_err(
                "failed sending set finalized request to forkchoice updater; this means it exited",
            )?;
        rx.await
            .map_err(|_| eyre!("the forkchoice updater task dropped the response channel"))
    }

    pub(super) async fn set_head(&self, head_block_hash: B256) -> eyre::Result<()> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::SetHead {
                head_block_hash,
                response,
                follows_from: tracing::Span::current(),
            })
            .wrap_err(
                "failed sending set head request to forkchoice updater; this means it exited",
            )?;
        rx.await
            .map_err(|_| eyre!("the forkchoice updater task dropped the response channel"))
    }
}

enum Message {
    SetHead {
        head_block_hash: B256,
        response: oneshot::Sender<()>,
        follows_from: tracing::Span,
    },
    SetFinalized {
        finalized_block_hash: B256,
        response: oneshot::Sender<()>,
        follows_from: tracing::Span,
    },
}

impl Message {
    fn follows_from(&self) -> &tracing::Span {
        match self {
            Self::SetHead { follows_from, .. } | Self::SetFinalized { follows_from, .. } => {
                follows_from
            }
        }
    }
}
