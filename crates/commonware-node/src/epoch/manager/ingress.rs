use commonware_consensus::{Block as _, Reporter};
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use tempo_commonware_node_cryptography::Digest;
use tracing::{Span, warn};

use crate::consensus::block::Block;

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn new(inner: mpsc::UnboundedSender<Message>) -> Self {
        Self { inner }
    }
}

pub(super) struct Message {
    pub(super) cause: Span,
    pub(super) finalized: Finalized,
}

impl Message {
    fn in_current_span(finalized: Finalized) -> Self {
        Self {
            cause: Span::current(),
            finalized,
        }
    }
}

pub(super) struct Finalized {
    pub(super) digest: Digest,
    pub(super) height: u64,
    pub(super) response: oneshot::Sender<()>,
}

impl Reporter for Mailbox {
    type Activity = Block;

    async fn report(&mut self, block: Self::Activity) {
        let (response, rx) = oneshot::channel();
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        if let Err(error) = self
            .inner
            .unbounded_send(Message::in_current_span(Finalized {
                digest: block.digest(),
                height: block.height(),
                response,
            }))
            .wrap_err("epoch manager no longer running")
        {
            warn!(%error, "failed to report finalized block to epoch manager")
        }
        let _ = rx.await;
    }
}
