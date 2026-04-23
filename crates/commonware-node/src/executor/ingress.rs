use alloy_rpc_types_engine::PayloadId;
use commonware_consensus::{
    Reporter,
    marshal::Update,
    simplex::types::Activity,
    types::{Height, Round},
};
use commonware_utils::acknowledgement::Exact;
use eyre::WrapErr as _;
use futures::{
    SinkExt as _,
    channel::{mpsc, oneshot},
};
use tempo_payload_types::TempoPayloadAttributes;
use tracing::Span;

use crate::{
    alias::simplex::Notarization,
    consensus::{Digest, block::Block},
};

/// An executor mailbox that implements [`Reporter`] with `[Activity]` activity.
#[derive(Clone, Debug)]
pub(crate) struct ConsensusReporter(Mailbox);

/// An executor mailbox that implements [`Reporter`] with `[Update]` activity.
#[derive(Clone, Debug)]
pub(crate) struct MarshalReporter(Mailbox);

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    pub(super) inner: mpsc::UnboundedSender<MessageWithSpan>,
}

impl Mailbox {
    pub(crate) fn to_consensus_reporter(&self) -> ConsensusReporter {
        ConsensusReporter(self.clone())
    }

    pub(crate) fn to_marshal_reporter(&self) -> MarshalReporter {
        MarshalReporter(self.clone())
    }

    /// Canonicalizes the given head and requests a new payload to be built.
    pub(crate) async fn canonicalize_and_build(
        &self,
        height: Height,
        digest: Digest,
        attributes: TempoPayloadAttributes,
    ) -> eyre::Result<PayloadId> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(MessageWithSpan::in_current_span(CanonicalizeAndBuild {
                height,
                digest,
                payload_attributes: Box::new(attributes),
                response,
            }))
            .wrap_err(
                "failed sending canonicalize and build request to agent, this means it exited",
            )?;
        rx.await
            .wrap_err("executor dropped response")
            .and_then(|res| res)
    }
}

#[derive(Debug)]
pub(super) struct MessageWithSpan {
    pub(super) cause: Span,
    pub(super) inner: Message,
}

impl MessageWithSpan {
    fn in_current_span(command: impl Into<Message>) -> Self {
        Self {
            cause: Span::current(),
            inner: command.into(),
        }
    }
}

#[derive(Debug)]
pub(super) enum Message {
    // ===
    // Direct instructions sent to the actor.
    // ===
    /// Requests the agent to canonicalize the head and build a new payload.
    CanonicalizeAndBuild(CanonicalizeAndBuild),

    // ===
    // From the consensus engine.
    // ===
    /// A notarization certificate that has been certified.
    Certification(Notarization),

    /// A notarization certificate that has not been certified.
    ///
    /// These are used as a trigger for backfilling: when operating at the tip,
    /// they have no impact, but if a notarization certificate is received and
    /// its parent determined missing, then a) the parent is implicitly assumed
    /// notarized, and b) a backfill is started
    Notarization(Notarization),

    // ===
    // From the marshal actor.
    // ===
    /// A finalized block received from the marshal actor and waiting to be
    /// executed and acknowledged.
    FinalizedBlock(FinalizedBlock),

    /// The highest finalized tip known to the marshal actor.
    FinalizedTip(FinalizedTip),
}

#[derive(Debug)]
pub(super) struct CanonicalizeAndBuild {
    pub(super) height: Height,
    pub(super) digest: Digest,
    pub(super) payload_attributes: Box<TempoPayloadAttributes>,
    pub(super) response: oneshot::Sender<eyre::Result<PayloadId>>,
}

#[derive(Debug)]
pub(super) struct FinalizedBlock {
    pub(super) block: Block,
    pub(super) acknowledgement: Exact,
}

#[derive(Debug)]
pub(super) struct FinalizedTip {
    pub(super) round: Round,
    pub(super) height: Height,
    pub(super) digest: Digest,
}

impl From<CanonicalizeAndBuild> for Message {
    fn from(value: CanonicalizeAndBuild) -> Self {
        Self::CanonicalizeAndBuild(value)
    }
}

impl From<FinalizedBlock> for Message {
    fn from(value: FinalizedBlock) -> Self {
        Message::FinalizedBlock(value)
    }
}

impl From<FinalizedTip> for Message {
    fn from(value: FinalizedTip) -> Self {
        Message::FinalizedTip(value)
    }
}

impl Reporter for ConsensusReporter {
    type Activity = crate::alias::simplex::Activity;

    async fn report(&mut self, activity: Self::Activity) {
        let msg = match activity {
            Activity::Certification(certification) => Message::Certification(certification),
            Activity::Notarization(notarization) => Message::Notarization(notarization),
            _ => return,
        };
        self.0
            .inner
            .send(MessageWithSpan::in_current_span(msg))
            .await
            .expect("actor is present and ready to receive broadcasts");
    }
}

impl Reporter for MarshalReporter {
    type Activity = Update<Block>;

    async fn report(&mut self, activity: Self::Activity) {
        let msg: Message = match activity {
            Update::Block(block, acknowledgement) => FinalizedBlock {
                block,
                acknowledgement,
            }
            .into(),
            Update::Tip(round, height, digest) => FinalizedTip {
                round,
                height,
                digest,
            }
            .into(),
        };
        self.0
            .inner
            .send(MessageWithSpan::in_current_span(msg))
            .await
            .expect("actor is present and ready to receive broadcasts");
    }
}
