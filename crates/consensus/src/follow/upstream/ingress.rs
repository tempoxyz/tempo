use commonware_consensus::types::Height;
use commonware_utils::channel::fallible::FallibleExt as _;
use tempo_node::rpc::consensus::CertifiedBlock;
use tokio::sync::{mpsc, oneshot};

use crate::consensus::{Block, Digest};

pub(super) enum Message {
    /// Request for a finalization of a given height.
    GetFinalization {
        height: Height,
        response: oneshot::Sender<Option<CertifiedBlock>>,
    },
    /// Request a consensus block by digest.
    GetBlock {
        digest: Digest,
        response: oneshot::Sender<Option<Block>>,
    },
}

/// Mailbox to the Upstream actor to issue requests to.
#[derive(Clone)]
pub struct Mailbox(mpsc::UnboundedSender<Message>);

impl Mailbox {
    pub(super) fn new(tx: mpsc::UnboundedSender<Message>) -> Self {
        Self(tx)
    }

    pub(crate) async fn get_finalization(&self, height: Height) -> Option<CertifiedBlock> {
        self.0
            .request(move |response| Message::GetFinalization { height, response })
            .await
            .flatten()
    }

    pub(crate) async fn get_block(&self, digest: Digest) -> Option<Block> {
        self.0
            .request(move |response| Message::GetBlock { digest, response })
            .await
            .flatten()
    }
}
