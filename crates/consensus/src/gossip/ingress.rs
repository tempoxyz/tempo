//! Marshal reporter for durable certificate publication over `tempo/1`.

use commonware_actor::Feedback;
use commonware_consensus::{
    Reporter,
    marshal::Update,
    types::{Height, Round},
};
use commonware_utils::Acknowledgement as _;
use tokio::sync::mpsc;
use tracing::debug;

use crate::consensus::Block;

#[derive(Debug)]
pub(super) struct FinalizedTip {
    pub(super) round: Round,
    pub(super) height: Height,
}

/// Reports durable marshal tips to the `tempo/1` actor.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    sender: mpsc::UnboundedSender<FinalizedTip>,
}

pub(super) fn channel() -> (Mailbox, mpsc::UnboundedReceiver<FinalizedTip>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (Mailbox { sender }, receiver)
}

impl Mailbox {
    fn send(&self, tip: FinalizedTip) -> Feedback {
        if self.sender.send(tip).is_err() {
            debug!("dropping gossip message because the actor is no longer running");
            Feedback::Closed
        } else {
            Feedback::Ok
        }
    }
}

/// Validators and followers publish only after marshal reports a durable tip.
/// Block updates are irrelevant to gossip, but must be acknowledged so marshal
/// can continue.
impl Reporter for Mailbox {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        match update {
            Update::Tip(round, height, _) => self.send(FinalizedTip { round, height }),
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

    use super::{FinalizedTip, channel};
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
                Some(FinalizedTip {
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
