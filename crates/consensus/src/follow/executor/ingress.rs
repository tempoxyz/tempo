use commonware_actor::Feedback;
use commonware_consensus::{Reporter, marshal::Update};
use futures::channel::mpsc;

use crate::consensus::block::Block;

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    sender: mpsc::UnboundedSender<Update<Block>>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::UnboundedSender<Update<Block>>) -> Self {
        Self { sender }
    }
}

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if self.sender.unbounded_send(update).is_err() {
            Feedback::Closed
        } else {
            Feedback::Ok
        }
    }
}
