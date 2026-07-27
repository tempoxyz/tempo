//! Mailbox for sending marshal updates to the feed actor.

use commonware_consensus::{Reporter, marshal::Update};
use commonware_utils::Acknowledgement as _;
use futures::channel::mpsc;
use tracing::error;

use crate::consensus::block::Block;

/// Sender half of the feed channel.
pub(super) type Sender = mpsc::UnboundedSender<Block>;

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
        let Update::Block(block, acknowledgement) = update else {
            return;
        };

        // The feed is best-effort and must never hold up marshal's durable
        // finalized-block stream.
        acknowledgement.acknowledge();

        if self.sender.unbounded_send(block).is_err() {
            error!("failed sending finalized block to feed because it is no longer running");
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
    fn forwards_only_acknowledged_blocks() {
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

            let (acknowledgement, acknowledged) = Exact::handle();
            mailbox
                .report(Update::Block(block.clone(), acknowledgement))
                .await;

            acknowledged
                .await
                .expect("feed should immediately acknowledge the block");
            assert_eq!(receiver.next().await, Some(block));
            assert!(receiver.next().now_or_never().is_none());
        });
    }
}
