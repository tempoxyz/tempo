//! Mailbox for the `tempo/1` actor.

use alloy_primitives::Bytes;
use commonware_consensus::types::Round;
use tokio::sync::mpsc;
use tracing::debug;

#[derive(Debug)]
pub(crate) enum Message {
    /// Publish a certificate whose block is available locally.
    Publish { round: Round, frame: Bytes },
}

/// Sends work to the `tempo/1` actor.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    sender: mpsc::UnboundedSender<Message>,
}

/// Creates the actor's mailbox and the receiving half it is started with.
///
/// The feed needs the mailbox before the driver is initialized, while the actor
/// needs the driver as its sink. Creating the channel first breaks this
/// initialization cycle.
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

    fn send(&self, message: Message) {
        if self.sender.send(message).is_err() {
            debug!("dropping gossip message because the actor is no longer running");
        }
    }
}
