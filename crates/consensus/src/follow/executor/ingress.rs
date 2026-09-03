use commonware_actor::Feedback;
use commonware_consensus::{Reporter, marshal::Update};
use futures::channel::mpsc;

use crate::consensus::block::Block;

#[derive(Debug)]
pub(super) enum Message {
    /// A finalized block or tip from marshal.
    Update(Update<Block>),
}

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    sender: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::UnboundedSender<Message>) -> Self {
        Self { sender }
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
