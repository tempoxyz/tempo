use commonware_actor::Feedback;
use commonware_consensus::{Reporter, marshal::Update, types::Round};
use futures::channel::mpsc;

use crate::consensus::{Digest, block::Block};

#[derive(Debug)]
pub(super) enum Message {
    /// A finalized block or tip from marshal.
    Update(Update<Block>),
    /// A verified finalized tip whose block has not arrived yet.
    Finalization { round: Round, digest: Digest },
}

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    sender: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::UnboundedSender<Message>) -> Self {
        Self { sender }
    }

    pub(crate) fn finalization(&self, round: Round, digest: Digest) {
        let _ = self.send(Message::Finalization { round, digest });
    }

    fn send(&self, message: Message) -> Feedback {
        if self.sender.unbounded_send(message).is_err() {
            Feedback::Closed
        } else {
            Feedback::Ok
        }
    }
}

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        self.send(Message::Update(update))
    }
}
