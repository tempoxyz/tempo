//! Mailbox for the `tempo/1` actor.

use alloy_primitives::Bytes;
use commonware_actor::Feedback;
use commonware_consensus::{
    Reporter,
    marshal::Update,
    types::{Epoch, Round},
};
use commonware_utils::Acknowledgement as _;
use tokio::sync::mpsc;
use tracing::debug;

use crate::consensus::Block;

#[derive(Debug)]
pub(crate) enum Message {
    /// Publish a certificate whose block is available locally.
    Publish { round: Round, frame: Bytes },
    /// Advance the actor's stale-certificate watermark.
    FinalizedTip { round: Round },
    /// Retry quarantines now covered by an authenticated boundary scheme.
    BoundarySchemeInstalled { epoch: Epoch },
}

/// Sends work to the `tempo/1` actor.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    sender: mpsc::UnboundedSender<Message>,
}

/// Creates the actor's mailbox and the receiving half it is started with.
///
/// Marshal and the driver need the mailbox, while the actor needs the driver as
/// its sink. Creating the channel first breaks this initialization cycle.
pub(crate) fn channel() -> (Mailbox, mpsc::UnboundedReceiver<Message>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (Mailbox { sender }, receiver)
}

impl Mailbox {
    /// Publishes a certificate with a block stored locally.
    ///
    /// The node publishes only after it can serve the block to a peer.
    pub(crate) fn publish(&self, round: Round, frame: Bytes) {
        self.send(Message::Publish { round, frame });
    }

    /// Reports that the follower installed an authenticated epoch scheme.
    pub(crate) fn boundary_scheme_installed(&self, epoch: Epoch) {
        self.send(Message::BoundarySchemeInstalled { epoch });
    }

    /// Advances the actor to a finalized marshal tip.
    #[cfg(test)]
    pub(crate) fn finalized_tip(&self, round: Round) {
        self.send(Message::FinalizedTip { round });
    }

    fn send(&self, message: Message) -> Feedback {
        if self.sender.send(message).is_err() {
            debug!("dropping gossip message because the actor is no longer running");
            Feedback::Closed
        } else {
            Feedback::Ok
        }
    }
}

/// Marshal tips drive the actor's watermark. Blocks are irrelevant to gossip,
/// but their acknowledgement must be completed so marshal can keep delivering.
impl Reporter for Mailbox {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        match update {
            Update::Tip(round, _, _) => self.send(Message::FinalizedTip { round }),
            Update::Block(_, ack) => {
                ack.acknowledge();
                Feedback::Ok
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
                Some(Message::FinalizedTip { round: received }) if received == round
            ));

            let (ack, acknowledged) = Exact::handle();
            let _ = mailbox.report(Update::Block(make_block(1, None).into(), ack));
            acknowledged
                .await
                .expect("gossip should immediately acknowledge marshal blocks");
            assert!(receiver.recv().now_or_never().is_none());
        });
    }
}
