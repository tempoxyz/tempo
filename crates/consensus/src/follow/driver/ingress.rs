use commonware_actor::Feedback;
use commonware_consensus::{Reporter, marshal};
use tempo_node::rpc::consensus::Event;
use tokio::sync::{mpsc, oneshot};

use crate::{
    consensus::Block,
    gossip::{Certificate, CertificateError, CertificateMailbox},
};

#[derive(Debug)]
pub(super) enum Message {
    Event(Box<Event>),
    Finalized(marshal::Update<Block>),
    /// A `tempo/1` certificate waiting for verification.
    Certificate {
        certificate: Box<Certificate>,
        response: oneshot::Sender<eyre::Result<(), CertificateError>>,
    },
}

impl From<Event> for Message {
    fn from(value: Event) -> Self {
        Self::Event(Box::new(value))
    }
}

impl From<marshal::Update<Block>> for Message {
    fn from(value: marshal::Update<Block>) -> Self {
        Self::Finalized(value)
    }
}

/// Routes certificates to the driver because it owns the epoch schemes.
impl CertificateMailbox for Mailbox {
    fn process_certificate(
        &self,
        certificate: Certificate,
    ) -> oneshot::Receiver<eyre::Result<(), CertificateError>> {
        let (response, receiver) = oneshot::channel();
        // If the driver has stopped, the response sender is dropped and the
        // caller receives an error.
        let _ = self.0.send(Message::Certificate {
            certificate: Box::new(certificate),
            response,
        });
        receiver
    }
}

#[derive(Clone)]
pub(crate) struct Mailbox(pub(super) mpsc::UnboundedSender<Message>);

impl Mailbox {
    pub(crate) fn to_event_reporter(&self) -> EventReporter {
        EventReporter(self.clone())
    }

    pub(crate) fn to_marshal_reporter(&self) -> MarshalReporter {
        MarshalReporter(self.clone())
    }

    fn send(&self, msg: impl Into<Message>) -> Feedback {
        if self.0.send(msg.into()).is_err() {
            Feedback::Closed
        } else {
            Feedback::Ok
        }
    }
}

#[derive(Clone)]
pub(crate) struct EventReporter(Mailbox);

impl Reporter for EventReporter {
    type Activity = Event;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.0.send(activity)
    }
}

#[derive(Clone)]
pub(crate) struct MarshalReporter(Mailbox);

impl Reporter for MarshalReporter {
    type Activity = marshal::Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.0.send(activity)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use commonware_actor::Feedback;
    use commonware_consensus::{
        Reporter as _,
        marshal::Update,
        types::{Epoch, Height, Round, View},
    };
    use tempo_node::rpc::consensus::Event;

    use super::Mailbox;
    use crate::consensus::Digest;

    #[test]
    fn reporters_return_closed_after_driver_exits() {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let mailbox = Mailbox(sender);
        drop(receiver);

        let mut event_reporter = mailbox.to_event_reporter();
        assert_eq!(
            event_reporter.report(Event::Nullified {
                epoch: 0,
                view: 0,
                seen: 0,
            }),
            Feedback::Closed
        );

        let mut marshal_reporter = mailbox.to_marshal_reporter();
        assert_eq!(
            marshal_reporter.report(Update::Tip(
                Round::new(Epoch::zero(), View::zero()),
                Height::zero(),
                Digest(B256::ZERO),
            )),
            Feedback::Closed
        );
    }
}
