//! Mailbox for sending marshal updates to the feed actor.

use commonware_consensus::{
    Reporter,
    marshal::Update,
    types::{Height, Round},
};
use commonware_utils::Acknowledgement as _;
use futures::channel::mpsc;
use tracing::error;

use crate::consensus::{Digest, block::Block};

/// A newly observed directly finalized tip.
#[derive(Clone, Copy, Debug)]
pub(super) struct FinalizedTip {
    pub(super) round: Round,
    pub(super) height: Height,
    pub(super) digest: Digest,
}

/// Sender half of the feed channel.
pub(super) type Sender = mpsc::UnboundedSender<FinalizedTip>;

/// Mailbox for sending finalized marshal blocks to the feed actor.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    sender: Sender,
}

impl Mailbox {
    pub(super) fn new(sender: Sender) -> Self {
        Self { sender }
    }
}

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    async fn report(&mut self, update: Self::Activity) {
        let tip = match update {
            Update::Tip(round, height, digest) => FinalizedTip {
                round,
                height,
                digest,
            },
            Update::Block(_, ack) => {
                ack.acknowledge();
                return;
            }
        };

        if self.sender.unbounded_send(tip).is_err() {
            error!("failed sending finalized tip to feed because it is no longer running");
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use commonware_consensus::{
        Heightable as _, Reporter as _,
        marshal::Update,
        types::{Epoch, Round, View},
    };
    use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
    use futures::{FutureExt as _, StreamExt as _, executor::block_on};
    use reth_node_core::primitives::SealedBlock;
    use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader};

    use super::Mailbox;
    use crate::consensus::block::Block;

    #[test]
    fn forwards_tips_and_acknowledges_blocks() {
        block_on(async {
            let (sender, mut receiver) = futures::channel::mpsc::unbounded();
            let mut mailbox = Mailbox::new(sender);
            let block = Block::from_execution_block(
                SealedBlock::seal_slow(TempoBlock {
                    header: TempoHeader {
                        inner: Header {
                            number: 1,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    body: BlockBody::default(),
                }),
                None,
            )
            .expect("test block should not contain BAL side data");

            mailbox
                .report(Update::Tip(
                    Round::new(Epoch::zero(), View::new(1)),
                    block.height(),
                    block.digest(),
                ))
                .await;

            let tip = receiver.next().await.expect("tip should be forwarded");
            assert_eq!(tip.round, Round::new(Epoch::zero(), View::new(1)));
            assert_eq!(tip.height, block.height());
            assert_eq!(tip.digest, block.digest());

            let (acknowledgement, acknowledged) = Exact::handle();
            mailbox.report(Update::Block(block, acknowledgement)).await;

            acknowledged
                .await
                .expect("feed should immediately acknowledge the block");
            assert!(receiver.next().now_or_never().is_none());
        });
    }
}
