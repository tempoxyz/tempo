use commonware_consensus::{Reporter, marshal};
use tempo_node::rpc::consensus::Event;
use tokio::sync::mpsc;

use crate::consensus::Block;

#[derive(Debug)]
pub(super) enum Message {
    Event(Box<Event>),
    Finalized(marshal::Update<Block>),
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

#[derive(Clone)]
pub(crate) struct Mailbox(pub(super) mpsc::UnboundedSender<Message>);

impl Mailbox {
    pub(crate) fn to_event_reporter(&self) -> EventReporter {
        EventReporter(self.clone())
    }

    pub(crate) fn to_marshal_reporter(&self) -> MarshalReporter {
        MarshalReporter(self.clone())
    }

    fn send(&self, msg: impl Into<Message>) {
        let _ = self.0.send(msg.into());
    }
}

#[derive(Clone)]
pub(crate) struct EventReporter(Mailbox);

impl Reporter for EventReporter {
    type Activity = Event;

    async fn report(&mut self, activity: Self::Activity) {
        self.0.send(activity);
    }
}

#[derive(Clone)]
pub(crate) struct MarshalReporter(Mailbox);

impl Reporter for MarshalReporter {
    type Activity = marshal::Update<Block>;

    async fn report(&mut self, activity: Self::Activity) {
        self.0.send(activity);
    }
}
