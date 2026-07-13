use alloy_primitives::B256;
use commonware_consensus::types::Height;
use commonware_utils::channel::fallible::FallibleExt as _;
use reth_primitives_traits::SealedOrRecoveredBlock;
use tempo_node::rpc::consensus::CertifiedBlock;
use tempo_primitives::Block;
use tokio::sync::{mpsc, oneshot};

pub(super) enum Message {
    /// Request for a finalization of a given height.
    GetFinalization {
        height: Height,
        response: oneshot::Sender<Option<CertifiedBlock>>,
    },
    /// Request an execution block by hash.
    GetBlock {
        hash: B256,
        response: oneshot::Sender<Option<SealedOrRecoveredBlock<Block>>>,
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

    pub(crate) async fn get_block(&self, hash: B256) -> Option<SealedOrRecoveredBlock<Block>> {
        self.0
            .request(move |response| Message::GetBlock { hash, response })
            .await
            .flatten()
    }
}
