//! Mailbox for the `tempo/1` actor.

use commonware_actor::Feedback;
use commonware_consensus::{
    Reporter,
    marshal::Update,
    types::{Epoch, Height, Round},
};
use commonware_utils::Acknowledgement as _;
use tokio::sync::mpsc;
use tracing::debug;

use crate::consensus::Block;

#[derive(Debug)]
pub(crate) enum Message {
    /// Publish the persisted certificate at a finalized marshal tip.
    FinalizedTip { round: Round, height: Height },
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
/// Marshal and the driver need the mailbox, while the actor needs the driver's
/// certificate mailbox. Creating the channel first breaks this initialization cycle.
pub(crate) fn channel() -> (Mailbox, mpsc::UnboundedReceiver<Message>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (Mailbox { sender }, receiver)
}

impl Mailbox {
    /// Reports that the follower installed an authenticated epoch scheme.
    pub(crate) fn boundary_scheme_installed(&self, epoch: Epoch) {
        self.send(Message::BoundarySchemeInstalled { epoch });
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

/// Marshal tips drive publication and the actor's latest verified round. Blocks
/// are irrelevant to gossip, but must be acknowledged so marshal can continue.
impl Reporter for Mailbox {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        match update {
            Update::Tip(round, height, _) => self.send(Message::FinalizedTip { round, height }),
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
                Some(Message::FinalizedTip {
                    round: received,
                    height: received_height,
                }) if received == round && received_height == Height::new(7)
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
