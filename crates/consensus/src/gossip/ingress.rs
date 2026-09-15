//! Marshal reporter for durable certificate publication over `tempo/1`.

use commonware_actor::Feedback;
use commonware_consensus::{
    Heightable as _, Reporter,
    marshal::Update,
    types::{Height, Round},
};
use commonware_utils::Acknowledgement as _;
use tokio::sync::mpsc;
use tracing::debug;

use crate::consensus::Block;

#[derive(Clone, Debug)]
pub(super) enum Message {
    FinalizedTip { round: Round, height: Height },
    FinalizedBlock { height: Height },
}

/// Reports durable marshal tips to the `tempo/1` actor.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    sender: mpsc::UnboundedSender<Message>,
}

pub(super) fn channel() -> (Mailbox, mpsc::UnboundedReceiver<Message>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (Mailbox { sender }, receiver)
}

impl Mailbox {
    fn send(&self, message: Message) -> Feedback {
        if self.sender.send(message).is_err() {
            debug!("dropping gossip message because the actor is no longer running");
            Feedback::Closed
        } else {
            Feedback::Ok
        }
    }
}

/// Marshal tips trigger durable publication. Gap-free block updates expose
/// authenticated epoch boundaries that can release quarantined certificates.
impl Reporter for Mailbox {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        match update {
            Update::Tip(round, height, _) => self.send(Message::FinalizedTip { round, height }),
            Update::Block(block, acknowledgement) => {
                let height = block.height();
                // Gossip only uses the height as an epoch-progress signal. It
                // performs no durability-critical block processing, so do not
                // make marshal wait for the gossip actor to drain its mailbox.
                acknowledgement.acknowledge();
                self.send(Message::FinalizedBlock { height })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use commonware_consensus::{
        Reporter as _,
        marshal::Update,
        types::{Epoch, Height, Round, View},
    };
    use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
    use futures::{FutureExt as _, executor::block_on};

    use super::{Message, channel};
    use crate::{consensus::Digest, follow::test_utils::make_block};

    #[test]
    fn forwards_tips_and_acknowledges_blocks() {
        block_on(async {
            let (mut mailbox, mut receiver) = channel();
            let round = Round::new(Epoch::zero(), View::new(7));

            let _ = mailbox.report(Update::Tip(
                round,
                Height::new(7),
                Digest(B256::with_last_byte(7)),
            ));
            assert!(matches!(
                receiver.recv().await,
                Some(Message::FinalizedTip {
                    round: received,
                    height: received_height,
                }) if received == round && received_height == Height::new(7)
            ));

            let (ack, acknowledged) = Exact::handle();
            let _ = mailbox.report(Update::Block(make_block(1, None).into(), ack));
            acknowledged
                .await
                .expect("gossip should acknowledge blocks eagerly");
            let message = receiver.recv().await.expect("block should be forwarded");
            let Message::FinalizedBlock { height } = message else {
                panic!("expected a finalized block");
            };
            assert_eq!(height, Height::new(1));
            assert!(receiver.recv().now_or_never().is_none());
        });
    }
}
