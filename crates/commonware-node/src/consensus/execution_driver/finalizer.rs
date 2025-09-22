//! Owns the strictly sequential finalization-queue.
//!
//! The finalizer forwards finalized blocks to the execution layer, and keeps
//! track of its latest finalized digest. This is available through
//! [`Mailbox::latest_finalized_digest`].

use eyre::{WrapErr as _, ensure};
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_util::StreamExt as _;
use tempo_commonware_node_cryptography::Digest;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tokio::sync::watch;
use tracing::{Level, instrument, warn};

pub(super) struct Builder {
    pub(super) execution_node: TempoFullNode,
    pub(super) latest_finalized_digest: Digest,
}

impl Builder {
    pub(super) fn build(self) -> Finalizer {
        let Self {
            execution_node,
            latest_finalized_digest,
        } = self;
        let (to_me, from_execution_driver) = futures_channel::mpsc::unbounded();
        let (latest_finalized_digest, latest_finalized_digest_rx) =
            watch::channel(latest_finalized_digest);
        Finalizer {
            execution_node,
            from_execution_driver,
            latest_finalized_digest,
            my_mailbox: Mailbox {
                inner: to_me,
                latest_finalized_digest: latest_finalized_digest_rx,
            },
        }
    }
}

pub(super) struct Finalizer {
    execution_node: TempoFullNode,

    from_execution_driver: UnboundedReceiver<Message>,
    latest_finalized_digest: watch::Sender<Digest>,

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

        let digest = block.digest();
        let block = block.into_inner();
        let payload_status = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(TempoExecutionData(block))
            .await
            .wrap_err(
                "failed sending new-payload request to execution engine to \
                query payload status of finalized block",
            )?;

        ensure!(
            payload_status.is_valid() || payload_status.is_syncing(),
            "this is a problem: payload status of block-to-be-finalized was \
            neither valid nor syncing: `{payload_status}`"
        );

        let _ = self.latest_finalized_digest.send_replace(digest);

        // Acknowledge that the block was finalized.
        if let Err(()) = response.send(()) {
            warn!("tried acknowledging finalization but channel was already closed");
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(super) struct Mailbox {
    latest_finalized_digest: watch::Receiver<Digest>,
    inner: UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn latest_finalized_digest(&self) -> Digest {
        *self.latest_finalized_digest.borrow()
    }

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
