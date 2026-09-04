use super::{durability::Durable as _, Variant};
use crate::{
    marshal::{
        ancestry::{AncestorStream, Ancestry, BlockProvider},
        Identifier,
    },
    simplex::types::{Activity, Finalization, Notarization},
    types::{Height, Round},
    Reporter,
};
use commonware_actor::{
    mailbox::{Overflow, Policy, Sender},
    Feedback,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_p2p::Recipients;
use commonware_runtime::{
    telemetry::{metrics::histogram::Timed, traces::TracedExt as _},
    Clock, Handle,
};
use commonware_utils::{channel::oneshot, vec::NonEmptyVec};
use std::{
    collections::{btree_map::Entry, BTreeMap, VecDeque},
    sync::Arc,
};
use tracing::{info_span, Span};

/// Messages sent to the marshal [Actor](super::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
pub(crate) enum Message<S: Scheme, V: Variant> {
    /// A request to retrieve the `(height, digest)` of a block by its identifier.
    /// The block must be finalized; returns `None` if the block is not finalized.
    GetInfo {
        /// The span carried with this request.
        span: Span,
        /// The identifier of the block to get the information of.
        identifier: Identifier<<V::Block as Digestible>::Digest>,
        /// A channel to send the retrieved `(height, digest)`.
        response: oneshot::Sender<Option<(Height, <V::Block as Digestible>::Digest)>>,
    },
    /// A request to retrieve a block by its identifier.
    ///
    /// Requesting by [Identifier::Height] or [Identifier::Latest] will only return finalized
    /// blocks, whereas requesting by [Identifier::Digest] may return non-finalized
    /// or even unverified blocks.
    GetBlock {
        /// The span carried with this request.
        span: Span,
        /// The identifier of the block to retrieve.
        identifier: Identifier<<V::Block as Digestible>::Digest>,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Option<V::Block>>,
    },
    /// A request to retrieve a finalization by height.
    GetFinalization {
        /// The span carried with this request.
        span: Span,
        /// The height of the finalization to retrieve.
        height: Height,
        /// A channel to send the retrieved finalization.
        response: oneshot::Sender<Option<Finalization<S, V::Commitment>>>,
    },
    /// A request to retrieve the latest processed height.
    GetProcessedHeight {
        /// The span carried with this request.
        span: Span,
        /// A channel to send the latest processed height.
        response: oneshot::Sender<Option<Height>>,
    },
    /// A hint that a finalized block may be available at a given height.
    ///
    /// This triggers a network fetch if the finalization is not available locally.
    /// This is fire-and-forget: the finalization will be stored in marshal and
    /// delivered via the normal finalization flow when available.
    ///
    /// The height must be covered by both the epocher and the provider. If the
    /// epocher cannot map the height to an epoch, or the provider cannot supply
    /// a scheme for that epoch, the hint is silently dropped.
    ///
    /// Targets are required because this is typically called when a peer claims to
    /// be ahead. If a target returns invalid data, the resolver will block them.
    /// Sending this message multiple times with different targets adds to the
    /// target set.
    HintFinalized {
        /// The span carried with this request.
        span: Span,
        /// The height of the finalization to fetch.
        height: Height,
        /// Target peers to fetch from. Added to any existing targets for this height.
        targets: NonEmptyVec<S::PublicKey>,
    },
    /// A request to subscribe to a block by its digest.
    SubscribeByDigest {
        /// The span carried with this request.
        span: Span,
        /// The digest of the block to retrieve.
        digest: <V::Block as Digestible>::Digest,
        /// How marshal should behave if the block is missing locally.
        fallback: DigestFallback,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Arc<V::Block>>,
    },
    /// A request to subscribe to a block by its commitment.
    SubscribeByCommitment {
        /// The span carried with this request.
        span: Span,
        /// The commitment of the block to retrieve.
        commitment: V::Commitment,
        /// How marshal should behave if the block is missing locally.
        fallback: CommitmentFallback,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Arc<V::Block>>,
    },
    /// A hint to fetch a notarized block by round without adding another local subscriber.
    ///
    /// `commitment` is used as a locality check: if the block is already
    /// available locally, the fetch is skipped.
    HintNotarized {
        /// The span carried with this request.
        span: Span,
        /// The notarized round to request.
        round: Round,
        /// The commitment used to short-circuit if the block is already local.
        commitment: V::Commitment,
    },
    /// A request to retrieve the verified block previously persisted for `round`.
    GetVerified {
        /// The span carried with this request.
        span: Span,
        /// The round to query.
        round: Round,
        /// A channel to send the retrieved block, if any.
        response: oneshot::Sender<Option<V::Block>>,
    },
    /// A request to forward a block to a set of recipients.
    Forward {
        /// The span carried with this request.
        span: Span,
        /// The round in which the block was proposed.
        round: Round,
        /// The commitment of the block to forward.
        commitment: V::Commitment,
        /// The recipients to forward the block to.
        recipients: Recipients<S::PublicKey>,
    },
    /// A request to broadcast a locally proposed block and persist it.
    Proposed {
        /// The span carried with this request.
        span: Span,
        /// The round in which the block was proposed.
        round: Round,
        /// The proposed block.
        block: Arc<V::Block>,
        /// The recipients to broadcast the block to.
        recipients: Recipients<S::PublicKey>,
        /// A channel sent once the block sync has started.
        ack: oneshot::Sender<Handle<()>>,
    },
    /// A notification that a block has been verified by the application.
    Verified {
        /// The span carried with this request.
        span: Span,
        /// The round in which the block was verified.
        round: Round,
        /// The verified block.
        block: Arc<V::Block>,
        /// A channel sent once the block sync has started.
        ack: oneshot::Sender<Handle<()>>,
    },
    /// A notification that a block has been certified by the application.
    Certified {
        /// The span carried with this request.
        span: Span,
        /// The round in which the block was certified.
        round: Round,
        /// The certified block.
        block: Arc<V::Block>,
        /// A channel sent once the block and notarization syncs have started; the
        /// handle covers both.
        ack: oneshot::Sender<Handle<()>>,
    },
    /// Attempts to set the sync starting point from a finalized commitment.
    ///
    /// If the verified finalization advances marshal's current floor, marshal
    /// anchors on its block, prunes below it, then syncs and delivers blocks
    /// starting at the floor height. Stale or superseded floors may be ignored.
    ///
    /// To prune data without changing the sync starting point, use
    /// [Message::Prune] instead.
    SetFloor {
        /// The span carried with this request.
        span: Span,
        /// The candidate floor finalization, verified by the actor before use.
        finalization: Finalization<S, V::Commitment>,
    },
    /// Requests pruning finalized blocks and certificates below the given height.
    ///
    /// Unlike [Message::SetFloor], this does not affect the sync starting
    /// point. Requests above marshal's current floor are ignored.
    Prune {
        /// The span carried with this request.
        span: Span,
        /// The minimum height to keep (blocks below this are pruned).
        height: Height,
    },
    /// A notarization from the consensus engine.
    Notarization {
        /// The span carried with this request.
        span: Span,
        /// The notarization.
        notarization: Notarization<S, V::Commitment>,
    },
    /// A finalization from the consensus engine.
    Finalization {
        /// The span carried with this request.
        span: Span,
        /// The finalization.
        finalization: Finalization<S, V::Commitment>,
    },
}

/// How a digest-keyed block subscription should behave when the block is missing locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestFallback {
    /// Wait for local availability only.
    Wait,
    /// Request the notarized proposal for `round` from peers.
    ///
    /// Use this only when the caller has a trusted round for the digest. Digest-keyed
    /// subscriptions intentionally cannot request exact commitment fetches.
    FetchByRound { round: Round },
}

impl From<DigestFallback> for CommitmentFallback {
    fn from(fallback: DigestFallback) -> Self {
        match fallback {
            DigestFallback::Wait => Self::Wait,
            DigestFallback::FetchByRound { round } => Self::FetchByRound { round },
        }
    }
}

/// How a commitment-keyed block subscription should behave when the block is missing locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentFallback {
    /// Wait for local availability only.
    ///
    /// Use this for pending candidate proposal data before notarization.
    Wait,
    /// Request the notarized proposal for `round` from peers.
    ///
    /// Use this when the caller knows a trusted notarized or certified round and
    /// commitment but not the proposal height, such as proposal construction,
    /// verification of a known child, or certification of a notarized candidate. Do not infer
    /// height from the finalized tip or another block: proposals may build on
    /// a certified parent that is not finalized locally yet, and an unverified
    /// child may lie about its height.
    ///
    /// The returned block is heightable once decoded, but that is too late for
    /// the in-flight resolver key or pruning bound.
    FetchByRound { round: Round },
    /// Request the exact commitment from peers and prune the request at
    /// `height`.
    ///
    /// Use this only when no certified parent round is available and the caller
    /// has a locally validated pruning bound, such as repairing a finalized gap
    /// or walking an accepted ancestry stream. Do not use it for a candidate's
    /// immediate parent when the consensus context supplies the parent round.
    ///
    /// The height is not sent to peers. It is a local pruning hint for request
    /// retention, not part of response validity: a fetched block is delivered
    /// if its commitment matches, and certified storage uses the decoded block
    /// height.
    FetchByCommitment { height: Height },
}

impl<S: Scheme, V: Variant> Message<S, V> {
    /// Returns the span carried with this message.
    pub(crate) const fn span(&self) -> &Span {
        match self {
            Self::GetInfo { span, .. }
            | Self::GetBlock { span, .. }
            | Self::GetFinalization { span, .. }
            | Self::GetVerified { span, .. }
            | Self::SubscribeByDigest { span, .. }
            | Self::SubscribeByCommitment { span, .. }
            | Self::Forward { span, .. }
            | Self::Proposed { span, .. }
            | Self::Verified { span, .. }
            | Self::Certified { span, .. }
            | Self::Notarization { span, .. }
            | Self::Finalization { span, .. }
            | Self::GetProcessedHeight { span, .. }
            | Self::HintFinalized { span, .. }
            | Self::HintNotarized { span, .. }
            | Self::SetFloor { span, .. }
            | Self::Prune { span, .. } => span,
        }
    }

    /// Returns the operation name of this message.
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::GetInfo { .. } => "get_info",
            Self::GetBlock { .. } => "get_block",
            Self::GetFinalization { .. } => "get_finalization",
            Self::GetProcessedHeight { .. } => "get_processed_height",
            Self::HintFinalized { .. } => "hint_finalized",
            Self::SubscribeByDigest { .. } => "subscribe_by_digest",
            Self::SubscribeByCommitment { .. } => "subscribe_by_commitment",
            Self::HintNotarized { .. } => "hint_notarized",
            Self::GetVerified { .. } => "get_verified",
            Self::Forward { .. } => "forward",
            Self::Proposed { .. } => "proposed",
            Self::Verified { .. } => "verified",
            Self::Certified { .. } => "certified",
            Self::SetFloor { .. } => "set_floor",
            Self::Prune { .. } => "prune",
            Self::Notarization { .. } => "notarization",
            Self::Finalization { .. } => "finalization",
        }
    }

    fn stale(&self, current: Option<Height>) -> bool {
        match self {
            // Height-targeted reads below the floor can never be served
            Self::GetInfo {
                identifier: Identifier::Height(height),
                ..
            }
            | Self::GetBlock {
                identifier: Identifier::Height(height),
                ..
            }
            | Self::GetFinalization { height, .. } => Some(*height) < current,
            // Hints only inform the actor about heights strictly above the floor
            Self::HintFinalized { height, .. } => Some(*height) <= current,
            // Durability acks cannot be dropped: callers depend on them
            Self::Proposed { .. } | Self::Verified { .. } | Self::Certified { .. } => false,
            // Digest and latest lookups are not bound to a specific height
            Self::GetBlock {
                identifier: Identifier::Digest(_) | Identifier::Latest,
                ..
            }
            | Self::GetInfo {
                identifier: Identifier::Digest(_) | Identifier::Latest,
                ..
            }
            | Self::GetProcessedHeight { .. } => false,
            Self::HintNotarized { .. } => false,
            Self::SubscribeByDigest { .. }
            | Self::SubscribeByCommitment { .. }
            | Self::GetVerified { .. }
            | Self::Forward { .. }
            | Self::SetFloor { .. }
            | Self::Prune { .. }
            | Self::Notarization { .. }
            | Self::Finalization { .. } => false,
        }
    }

    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::GetInfo { response, .. } => response.is_closed(),
            Self::GetBlock { response, .. } | Self::GetVerified { response, .. } => {
                response.is_closed()
            }
            Self::GetFinalization { response, .. } => response.is_closed(),
            Self::GetProcessedHeight { response, .. } => response.is_closed(),
            Self::SubscribeByDigest { response, .. }
            | Self::SubscribeByCommitment { response, .. } => response.is_closed(),
            Self::HintNotarized { .. } => false,
            Self::HintFinalized { .. }
            | Self::Forward { .. }
            | Self::Proposed { .. }
            | Self::Verified { .. }
            | Self::Certified { .. }
            | Self::SetFloor { .. }
            | Self::Prune { .. }
            | Self::Notarization { .. }
            | Self::Finalization { .. } => false,
        }
    }
}

pub(crate) struct Pending<S: Scheme, V: Variant> {
    floor: Option<(Span, Finalization<S, V::Commitment>)>,
    prune: Option<(Span, Height)>,
    hints: BTreeMap<Height, (Span, NonEmptyVec<S::PublicKey>)>,
    messages: VecDeque<PendingMessage<S, V>>,
}

enum PendingMessage<S: Scheme, V: Variant> {
    Message(Message<S, V>),
    HintFinalized(Height),
}

impl<S: Scheme, V: Variant> Default for Pending<S, V> {
    fn default() -> Self {
        Self {
            floor: None,
            prune: None,
            hints: BTreeMap::new(),
            messages: VecDeque::new(),
        }
    }
}

impl<S: Scheme, V: Variant> Pending<S, V> {
    // Only prune advances are usable for height staleness checks. A pending
    // floor finalization does not carry the block height until the block is decoded.
    fn height(&self) -> Option<Height> {
        self.prune.as_ref().map(|(_, height)| *height)
    }

    fn retain(&mut self) {
        let current = self.height();
        self.hints.retain(|height, _| Some(*height) > current);

        let hints = &self.hints;
        self.messages.retain(|message| match message {
            PendingMessage::Message(message) => {
                !message.response_closed() && !message.stale(current)
            }
            PendingMessage::HintFinalized(height) => hints.contains_key(height),
        });
    }

    fn set_floor(&mut self, span: Span, finalization: Finalization<S, V::Commitment>) {
        let round = finalization.round();
        if self
            .floor
            .as_ref()
            .is_some_and(|(_, floor)| floor.round() >= round)
        {
            return;
        }

        self.floor = Some((span, finalization));
    }

    fn prune(&mut self, span: Span, height: Height) {
        let current = self.height();
        if current >= Some(height) {
            return;
        }

        self.prune = Some((span, height));
        self.retain();
    }

    fn extend_hint_targets(
        pending: &mut NonEmptyVec<S::PublicKey>,
        targets: NonEmptyVec<S::PublicKey>,
    ) {
        for target in targets {
            if !pending.contains(&target) {
                pending.push(target);
            }
        }
    }

    fn hint_finalized(&mut self, span: Span, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        // The finalized height is already covered by the floor or prune point.
        let current = self.height();
        if current.is_some_and(|current| height <= current) {
            return;
        }

        match self.hints.entry(height) {
            Entry::Vacant(entry) => {
                entry.insert((span, targets));
                self.messages
                    .push_back(PendingMessage::HintFinalized(height));
            }
            Entry::Occupied(mut entry) => {
                Self::extend_hint_targets(&mut entry.get_mut().1, targets);
            }
        }
    }

    fn restore_hint(&mut self, span: Span, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        match self.hints.entry(height) {
            Entry::Vacant(entry) => {
                entry.insert((span, targets));
            }
            Entry::Occupied(mut entry) => {
                Self::extend_hint_targets(&mut entry.get_mut().1, targets);
            }
        }
        self.messages
            .push_front(PendingMessage::HintFinalized(height));
    }

    fn drain_one<F>(&mut self, message: Message<S, V>, push: &mut F) -> bool
    where
        F: FnMut(Message<S, V>) -> Option<Message<S, V>>,
    {
        // Receiver accepted; the message is consumed
        let Some(message) = push(message) else {
            return true;
        };

        // Receiver rejected; restore so the next drain retries from the same point
        match message {
            Message::SetFloor { span, finalization } => self.set_floor(span, finalization),
            Message::Prune { span, height } => self.prune(span, height),
            Message::HintFinalized {
                span,
                height,
                targets,
            } => self.restore_hint(span, height, targets),
            message => self.messages.push_front(PendingMessage::Message(message)),
        }
        false
    }
}

impl<S: Scheme, V: Variant> Overflow<Message<S, V>> for Pending<S, V> {
    fn is_empty(&self) -> bool {
        self.floor.is_none()
            && self.prune.is_none()
            && self.hints.is_empty()
            && self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<S, V>) -> Option<Message<S, V>>,
    {
        // Drain floor and prune first so the actor advances its floor before
        // it sees the height-bounded reads that follow
        if let Some((span, finalization)) = self.floor.take() {
            if !self.drain_one(Message::SetFloor { span, finalization }, &mut push) {
                return;
            }
        }
        if let Some((span, height)) = self.prune.take() {
            if !self.drain_one(Message::Prune { span, height }, &mut push) {
                return;
            }
        }

        // Drain the remaining queued messages in FIFO order
        while let Some(pending) = self.messages.pop_front() {
            match pending {
                PendingMessage::Message(message) => {
                    if message.response_closed() {
                        continue;
                    }
                    if !self.drain_one(message, &mut push) {
                        break;
                    }
                }
                PendingMessage::HintFinalized(hint_height) => {
                    let Some((span, targets)) = self.hints.remove(&hint_height) else {
                        continue;
                    };
                    let message = Message::HintFinalized {
                        span,
                        height: hint_height,
                        targets,
                    };
                    if !self.drain_one(message, &mut push) {
                        break;
                    }
                }
            }
        }
    }
}

impl<S: Scheme, V: Variant> Policy for Message<S, V> {
    type Overflow = Pending<S, V>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // A closed responder cannot be served
        if message.response_closed() {
            return;
        }
        match message {
            // Coalesce hints: a single entry per height with a unioned target set
            Self::HintFinalized {
                span,
                height,
                targets,
            } => {
                overflow.hint_finalized(span, height, targets);
            }
            // Floors collapse to the highest round seen; prune collapses to
            // the highest height seen.
            Self::SetFloor { span, finalization } => {
                overflow.set_floor(span, finalization);
            }
            Self::Prune { span, height } => {
                overflow.prune(span, height);
            }
            // Queue if the new message is still useful
            message => {
                if message.stale(overflow.height()) {
                    return;
                }
                overflow
                    .messages
                    .push_back(PendingMessage::Message(message));
            }
        }
    }
}

/// A mailbox for sending messages to the marshal [Actor](super::Actor).
#[derive(Clone)]
pub struct Mailbox<S: Scheme, V: Variant> {
    sender: Sender<Message<S, V>>,
}

impl<S: Scheme, V: Variant> Mailbox<S, V> {
    /// Creates a new mailbox.
    pub(crate) const fn new(sender: Sender<Message<S, V>>) -> Self {
        Self { sender }
    }

    /// Create an ancestor stream that fetches missing parents by commitment.
    ///
    /// This stream is always a fetching stream. Callers must only use it after
    /// they already have a block that is safe to verify, certify, build on, or
    /// repair from. From that point, every parent walked by the stream is part of
    /// a certified ancestry chain, and the stream can derive each missing
    /// parent's height from its child before issuing a height-bound request.
    ///
    /// Do not use this to wait for pending candidate proposal data.
    pub(crate) fn ancestor_stream<I, C>(
        &self,
        clock: Arc<C>,
        initial: I,
        fetch_duration: Timed,
    ) -> impl Ancestry<V::ApplicationBlock> + use<S, V, I, C>
    where
        Self: BlockProvider<Block = V::ApplicationBlock>,
        I: IntoIterator<Item = Arc<V::ApplicationBlock>>,
        C: Clock,
    {
        AncestorStream::new(clock, self.clone(), initial, fetch_duration)
    }

    /// Retrieve `(height, digest)` for a finalized block by height, digest, or latest.
    pub async fn get_info(
        &self,
        identifier: impl Into<Identifier<<V::Block as Digestible>::Digest>>,
    ) -> Option<(Height, <V::Block as Digestible>::Digest)> {
        let identifier = identifier.into();
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetInfo {
            span: info_span!("marshal.mailbox.get_info"),
            identifier,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// A best-effort attempt to retrieve a given block from local
    /// storage. It is not an indication to go fetch the block from the network.
    pub async fn get_block(
        &self,
        identifier: impl Into<Identifier<<V::Block as Digestible>::Digest>>,
    ) -> Option<V::Block> {
        let identifier = identifier.into();
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetBlock {
            span: info_span!("marshal.mailbox.get_block"),
            identifier,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// A best-effort attempt to retrieve a given [Finalization] from local
    /// storage. It is not an indication to go fetch the [Finalization] from the network.
    pub async fn get_finalization(&self, height: Height) -> Option<Finalization<S, V::Commitment>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetFinalization {
            span: info_span!("marshal.mailbox.get_finalization", height = height.traced()),
            height,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// Retrieve the latest processed height.
    pub async fn get_processed_height(&self) -> Option<Height> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetProcessedHeight {
            span: info_span!("marshal.mailbox.get_processed_height"),
            response,
        });
        receiver.await.ok().flatten()
    }

    /// Hints that a finalized block may be available at the given height.
    ///
    /// This method will request the finalization from the network via the resolver
    /// if it is not available locally.
    ///
    /// Targets are required because this is typically called when a peer claims to be
    /// ahead. By targeting only those peers, we limit who we ask. If a target returns
    /// invalid data, they will be blocked by the resolver. If targets don't respond
    /// or return "no data", they effectively rate-limit themselves.
    ///
    /// Calling this multiple times for the same height with different targets will
    /// add to the target set if there is an ongoing fetch, allowing more peers to be tried.
    ///
    /// This is fire-and-forget: the finalization will be stored in marshal and delivered
    /// via the normal finalization flow when available.
    ///
    /// The height must be covered by both the epocher and the provider. If the
    /// epocher cannot map the height to an epoch, or the provider cannot supply
    /// a scheme for that epoch, the hint is silently dropped.
    pub fn hint_finalized(&self, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        let _ = self.sender.enqueue(Message::HintFinalized {
            span: info_span!("marshal.mailbox.hint_finalized", height = height.traced()),
            height,
            targets,
        });
    }

    /// Subscribe to a block by its digest.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the subscription will be registered and the caller
    /// will be notified when the block is available. If the block is not finalized, it's possible
    /// that it may never become available.
    ///
    /// The `fallback` parameter controls whether marshal also asks peers for the missing block.
    /// Digest-keyed subscriptions only support waiting locally or fetching by round.
    ///
    /// Delivery makes no durability promise. A delivered block may not have been persisted by
    /// marshal, so it may not be retrievable after an unclean shutdown. Consumers that need
    /// durable height-ordered delivery should rely on application dispatch instead.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub fn subscribe_by_digest(
        &self,
        digest: <V::Block as Digestible>::Digest,
        fallback: DigestFallback,
    ) -> oneshot::Receiver<Arc<V::Block>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::SubscribeByDigest {
            span: info_span!("marshal.mailbox.subscribe_by_digest", digest = %digest),
            digest,
            fallback,
            response: tx,
        });
        rx
    }

    /// Subscribe to a block by its commitment.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the subscription will be registered and the caller
    /// will be notified when the block is available. If the block is not finalized, it's possible
    /// that it may never become available.
    ///
    /// The `fallback` parameter controls whether marshal also asks peers for the missing block.
    ///
    /// Delivery makes no durability promise. A delivered block may not have been persisted by
    /// marshal, so it may not be retrievable after an unclean shutdown. Consumers that need
    /// durable height-ordered delivery should rely on application dispatch instead.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub fn subscribe_by_commitment(
        &self,
        commitment: V::Commitment,
        fallback: CommitmentFallback,
    ) -> oneshot::Receiver<Arc<V::Block>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::SubscribeByCommitment {
            span: info_span!("marshal.mailbox.subscribe_by_commitment", commitment = %commitment),
            fallback,
            commitment,
            response: tx,
        });
        rx
    }

    /// Hint that peers may have the block notarized at `round`.
    ///
    /// This issues a round-bound resolver request without registering a new
    /// block subscriber. The `commitment` is only used to skip the request when
    /// the block is already available locally.
    ///
    /// This is useful when a local-only waiter already exists and later
    /// certification makes a network fetch by notarized round valid.
    pub fn hint_notarized(&self, round: Round, commitment: V::Commitment) {
        let _ = self.sender.enqueue(Message::HintNotarized {
            span: info_span!(
                "marshal.mailbox.hint_notarized",
                round = %round,
                commitment = %commitment
            ),
            round,
            commitment,
        });
    }

    /// Returns a stream over the ancestry of a given block, leading up to genesis.
    ///
    /// This stream may fetch missing parents because callers should only request
    /// ancestry for data they already have locally and are willing to build on,
    /// verify, certify, or repair from. It is not a candidate fetch path.
    ///
    /// If the starting block is not found, `None` is returned.
    pub async fn ancestry<C>(
        &self,
        clock: Arc<C>,
        (fallback, start_digest): (DigestFallback, <V::Block as Digestible>::Digest),
        fetch_duration: Timed,
    ) -> Option<impl Ancestry<V::ApplicationBlock> + use<S, V, C>>
    where
        Self: BlockProvider<Block = V::ApplicationBlock>,
        C: Clock,
    {
        let receiver = self.subscribe_by_digest(start_digest, fallback);
        receiver.await.ok().map(|block| {
            let block = V::into_inner_shared(block);
            self.ancestor_stream(clock, [block], fetch_duration)
        })
    }

    /// Returns the verified block previously persisted for `round`, if any.
    ///
    /// Multiple candidates can exist for one round (an equivocating leader can
    /// land one before a crash and another after), and this returns the first
    /// stored. Callers must not assume it is the most recently verified
    /// candidate: check context/digest before reuse, or look up by digest.
    pub async fn get_verified(&self, round: Round) -> Option<V::Block> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetVerified {
            span: info_span!("marshal.mailbox.get_verified", round = %round),
            round,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// Requests the broadcast of a locally proposed block, persisting it after
    /// the send.
    ///
    /// The actor hands the block to the network before ingesting and persisting
    /// it, so the storage write never delays propagation. `ack` receives the
    /// durable-sync handle once the write's sync has started. The propose path
    /// stages the block (and `ack`) at propose time and calls this when consensus
    /// requests the broadcast via [`crate::Relay::broadcast`], awaiting durability
    /// only at certification so the sync overlaps consensus voting.
    ///
    /// A dropped `ack` (the mailbox is closed) abandons the handshake.
    pub fn proposed(
        &self,
        round: Round,
        block: impl Into<Arc<V::Block>>,
        recipients: Recipients<S::PublicKey>,
        ack: oneshot::Sender<Handle<()>>,
    ) -> Feedback {
        self.sender.enqueue(Message::Proposed {
            span: info_span!("marshal.mailbox.proposed", round = %round),
            round,
            block: block.into(),
            recipients,
            ack,
        })
    }

    /// Notifies the actor that a block should be durably persisted at `round`,
    /// delivering its durable-sync handle through `ack` without awaiting it.
    ///
    /// Takes a sender rather than returning a receiver so certification can
    /// deliver the handle into a handshake staged at propose time. A dropped
    /// `ack` (the mailbox is closed) abandons the handshake.
    pub fn verified_deferred(
        &self,
        round: Round,
        block: impl Into<Arc<V::Block>>,
        ack: oneshot::Sender<Handle<()>>,
    ) {
        let _ = self.sender.enqueue(Message::Verified {
            span: info_span!("marshal.mailbox.verified", round = %round),
            round,
            block: block.into(),
            ack,
        });
    }

    /// Notifies the actor that a block has been verified.
    ///
    /// Returns after the block is durably persisted. Mirrors [Self::certified]: the
    /// durable sync is awaited on the caller's task (off the actor), so the actor
    /// never blocks on fsync.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn verified(&self, round: Round, block: impl Into<Arc<V::Block>>) -> bool {
        let (ack, receiver) = oneshot::channel();
        self.verified_deferred(round, block, ack);
        let Ok(handle) = receiver.await else {
            return false;
        };
        handle.durable(round, "verified").await
    }

    /// Notifies the actor that a block has been certified.
    ///
    /// Returns after the block is durably persisted.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn certified(&self, round: Round, block: impl Into<Arc<V::Block>>) -> bool {
        let (ack, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Certified {
            span: info_span!("marshal.mailbox.certified", round = %round),
            round,
            block: block.into(),
            ack,
        });
        let Ok(handle) = receiver.await else {
            return false;
        };
        handle.durable(round, "certified").await
    }

    /// Attempts to set the sync starting point from a finalized commitment.
    ///
    /// If the verified finalization advances marshal's current floor, marshal
    /// anchors on its block, prunes below it, then syncs and delivers blocks
    /// starting at the floor height. Stale or superseded floors may be ignored.
    ///
    /// To prune data without changing the sync starting point, use
    /// [Self::prune] instead.
    /// Use [`crate::marshal::Config::start`] to provide the startup anchor.
    pub fn set_floor(&self, finalization: Finalization<S, V::Commitment>) {
        let _ = self.sender.enqueue(Message::SetFloor {
            span: info_span!("marshal.mailbox.set_floor", round = %finalization.round()),
            finalization,
        });
    }

    /// Requests pruning finalized blocks and certificates below the given height.
    ///
    /// Unlike [Self::set_floor], this does not affect the sync starting point.
    /// Requests above marshal's current floor are ignored.
    pub fn prune(&self, height: Height) {
        let _ = self.sender.enqueue(Message::Prune {
            span: info_span!("marshal.mailbox.prune", height = height.traced()),
            height,
        });
    }

    /// Forward a locally stored block to a set of recipients.
    pub fn forward(
        &self,
        round: Round,
        commitment: V::Commitment,
        recipients: Recipients<S::PublicKey>,
    ) -> Feedback {
        self.sender.enqueue(Message::Forward {
            span: info_span!("marshal.mailbox.forward", round = %round, commitment = %commitment),
            round,
            commitment,
            recipients,
        })
    }
}

impl<S: Scheme, V: Variant> Reporter for Mailbox<S, V> {
    type Activity = Activity<S, V::Commitment>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let message = match activity {
            Activity::Notarization(notarization) => Message::Notarization {
                span: info_span!("marshal.mailbox.notarization", round = %notarization.round()),
                notarization,
            },
            Activity::Finalization(finalization) => Message::Finalization {
                span: info_span!("marshal.mailbox.finalization", round = %finalization.round()),
                finalization,
            },
            _ => return Feedback::Ok,
        };
        self.sender.enqueue(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{mocks::harness, standard::Standard},
        simplex::{scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Proposal},
        types::{Epoch, View},
        Heightable,
    };
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PrivateKey, Digest as _, Signer as _,
    };
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::{channel::oneshot::error::TryRecvError, NZUsize, TestRng};

    type TestMessage = Message<harness::S, Standard<harness::B>>;
    type TestPending = Pending<harness::S, Standard<harness::B>>;

    fn public_key(seed: u64) -> harness::K {
        PrivateKey::from_seed(seed).public_key()
    }

    fn round(height: u64) -> Round {
        Round::new(Epoch::zero(), View::new(height))
    }

    fn block(height: u64) -> harness::B {
        harness::make_raw_block(harness::D::EMPTY, Height::new(height), height)
    }

    fn commitment(height: u64) -> harness::D {
        <Standard<harness::B> as Variant>::commitment(&block(height))
    }

    fn finalization(height: u64) -> Finalization<harness::S, harness::D> {
        let mut rng = TestRng::new(height);
        let Fixture { schemes, .. } = bls12381_threshold_vrf::fixture::<harness::V, _>(
            &mut rng,
            harness::NAMESPACE,
            harness::NUM_VALIDATORS,
        );
        let proposal = Proposal::new(round(height), View::zero(), commitment(height));
        <harness::StandardHarness as harness::TestHarness>::make_finalization(
            proposal,
            &schemes,
            harness::QUORUM,
        )
    }

    fn get_info(height: u64) -> (TestMessage, oneshot::Receiver<Option<(Height, harness::D)>>) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::GetInfo {
                span: Span::none(),
                identifier: Identifier::Height(Height::new(height)),
                response,
            },
            receiver,
        )
    }

    fn proposed(height: u64) -> (TestMessage, oneshot::Receiver<Handle<()>>) {
        let (ack, receiver) = oneshot::channel();
        (
            TestMessage::Proposed {
                span: Span::none(),
                round: round(height),
                block: block(height).into(),
                recipients: Recipients::All,
                ack,
            },
            receiver,
        )
    }

    fn verified(height: u64) -> (TestMessage, oneshot::Receiver<Handle<()>>) {
        let (ack, receiver) = oneshot::channel();
        (
            TestMessage::Verified {
                span: Span::none(),
                round: round(height),
                block: block(height).into(),
                ack,
            },
            receiver,
        )
    }

    fn certified(height: u64) -> (TestMessage, oneshot::Receiver<Handle<()>>) {
        let (ack, receiver) = oneshot::channel();
        (
            TestMessage::Certified {
                span: Span::none(),
                round: round(height),
                block: block(height).into(),
                ack,
            },
            receiver,
        )
    }

    fn get_block(height: u64) -> (TestMessage, oneshot::Receiver<Option<harness::B>>) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::GetBlock {
                span: Span::none(),
                identifier: Identifier::Height(Height::new(height)),
                response,
            },
            receiver,
        )
    }

    fn get_finalization(
        height: u64,
    ) -> (
        TestMessage,
        oneshot::Receiver<Option<Finalization<harness::S, harness::D>>>,
    ) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::GetFinalization {
                span: Span::none(),
                height: Height::new(height),
                response,
            },
            receiver,
        )
    }

    fn subscribe_by_digest(height: u64) -> (TestMessage, oneshot::Receiver<Arc<harness::B>>) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::SubscribeByDigest {
                span: Span::none(),
                digest: block(height).digest(),
                fallback: DigestFallback::FetchByRound {
                    round: round(height),
                },
                response,
            },
            receiver,
        )
    }

    fn subscribe_by_commitment_message(
        height: u64,
        fallback: CommitmentFallback,
    ) -> (TestMessage, oneshot::Receiver<Arc<harness::B>>) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::SubscribeByCommitment {
                span: Span::none(),
                commitment: commitment(height),
                fallback,
                response,
            },
            receiver,
        )
    }

    fn hint_finalized(height: u64, target: harness::K) -> TestMessage {
        TestMessage::HintFinalized {
            span: Span::none(),
            height: Height::new(height),
            targets: NonEmptyVec::new(target),
        }
    }

    fn set_floor(height: u64) -> TestMessage {
        TestMessage::SetFloor {
            span: Span::none(),
            finalization: finalization(height),
        }
    }

    fn prune(height: u64) -> TestMessage {
        TestMessage::Prune {
            span: Span::none(),
            height: Height::new(height),
        }
    }

    fn pending() -> TestPending {
        TestPending::default()
    }

    fn drain(overflow: &mut TestPending) -> VecDeque<TestMessage> {
        let mut drained = VecDeque::new();
        overflow.drain(|message| {
            drained.push_back(message);
            None
        });
        drained
    }

    fn has_get_info(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                PendingMessage::Message(TestMessage::GetInfo {
                    identifier: Identifier::Height(found),
                    response,
                    ..
                }) if *found == Height::new(height) && !response.is_closed()
            )
        })
    }

    fn has_get_block(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                PendingMessage::Message(TestMessage::GetBlock {
                    identifier: Identifier::Height(found),
                    response,
                    ..
                }) if *found == Height::new(height) && !response.is_closed()
            )
        })
    }

    fn has_get_finalization(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                PendingMessage::Message(TestMessage::GetFinalization {
                    height: found,
                    response,
                    ..
                }) if *found == Height::new(height) && !response.is_closed()
            )
        })
    }

    fn hint_targets(overflow: &TestPending, height: u64) -> Option<&NonEmptyVec<harness::K>> {
        overflow
            .hints
            .get(&Height::new(height))
            .map(|(_, targets)| targets)
    }

    fn has_block_message(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                PendingMessage::Message(
                    TestMessage::Proposed { block, .. }
                        | TestMessage::Verified { block, .. }
                        | TestMessage::Certified { block, .. }
                )
                    if block.height() == Height::new(height)
            )
        })
    }

    fn has_prune(overflow: &TestPending, height: u64) -> bool {
        overflow.prune.as_ref().map(|(_, height)| *height) == Some(Height::new(height))
    }

    fn has_subscription(overflow: &TestPending, height: u64) -> bool {
        let expected_digest = block(height).digest();
        let expected_commitment = commitment(height);
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                PendingMessage::Message(TestMessage::SubscribeByDigest { digest, response, .. })
                    if *digest == expected_digest && !response.is_closed()
            ) || matches!(
                message,
                PendingMessage::Message(TestMessage::SubscribeByCommitment {
                    commitment,
                    response,
                    ..
                }) if *commitment == expected_commitment && !response.is_closed()
            )
        })
    }

    #[test]
    fn durable_methods_report_failure_when_mailbox_closed() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, receiver) =
                commonware_actor::mailbox::new::<TestMessage>(context, NZUsize!(1));
            let mailbox = Mailbox::<harness::S, Standard<harness::B>>::new(sender);
            drop(receiver);

            let (ack, receiver) = oneshot::channel();
            let _ = mailbox.proposed(round(1), block(1), Recipients::All, ack);
            assert!(receiver.await.is_err());
            assert!(!mailbox.verified(round(2), block(2)).await);
            assert!(!mailbox.certified(round(3), block(3)).await);
        });
    }

    #[test]
    fn policy_coalesces_hint_targets() {
        let mut overflow = pending();
        let first = public_key(1);
        let second = public_key(2);

        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(10, first.clone()));
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(10, first.clone()));
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(10, second.clone()));

        assert_eq!(overflow.messages.len(), 1);
        let targets = hint_targets(&overflow, 10).expect("expected hint");
        assert_eq!(targets.len().get(), 2);
        assert!(targets.contains(&first));
        assert!(targets.contains(&second));
    }

    #[test]
    fn policy_preserves_commitment_subscription_fallbacks() {
        let mut overflow = pending();

        let (wait, _wait_rx) = subscribe_by_commitment_message(1, CommitmentFallback::Wait);
        let (by_round, _by_round_rx) = subscribe_by_commitment_message(
            2,
            CommitmentFallback::FetchByRound { round: round(2) },
        );
        let (by_commitment, _by_commitment_rx) = subscribe_by_commitment_message(
            3,
            CommitmentFallback::FetchByCommitment {
                height: Height::new(3),
            },
        );

        <TestMessage as Policy>::handle(&mut overflow, wait);
        <TestMessage as Policy>::handle(&mut overflow, by_round);
        <TestMessage as Policy>::handle(&mut overflow, by_commitment);

        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 3);
        assert!(matches!(
            &drained[0],
            TestMessage::SubscribeByCommitment {
                fallback: CommitmentFallback::Wait,
                ..
            }
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::SubscribeByCommitment {
                fallback: CommitmentFallback::FetchByRound { round: found },
                ..
            } if *found == round(2)
        ));
        assert!(matches!(
            &drained[2],
            TestMessage::SubscribeByCommitment {
                fallback: CommitmentFallback::FetchByCommitment { height },
                ..
            } if *height == Height::new(3)
        ));
    }

    #[test]
    fn policy_handles_closed_subscriptions() {
        let mut overflow = pending();

        let (pending_closed, pending_closed_rx) = subscribe_by_digest(1);
        drop(pending_closed_rx);
        overflow
            .messages
            .push_back(PendingMessage::Message(pending_closed));

        let (pending_open, mut pending_open_rx) = subscribe_by_commitment_message(
            2,
            CommitmentFallback::FetchByRound { round: round(2) },
        );
        overflow
            .messages
            .push_back(PendingMessage::Message(pending_open));

        let (current_closed, current_closed_rx) = subscribe_by_digest(3);
        drop(current_closed_rx);
        <TestMessage as Policy>::handle(&mut overflow, current_closed);

        assert!(!has_subscription(&overflow, 1));
        assert!(has_subscription(&overflow, 2));
        assert!(!has_subscription(&overflow, 3));
        assert!(matches!(
            pending_open_rx.try_recv(),
            Err(TryRecvError::Empty)
        ));
    }

    #[test]
    fn policy_handles_closed_responses() {
        let mut overflow = pending();

        let (pending_closed, pending_closed_rx) = get_block(1);
        drop(pending_closed_rx);
        overflow
            .messages
            .push_back(PendingMessage::Message(pending_closed));

        let (pending_open, mut pending_open_rx) = get_info(2);
        overflow
            .messages
            .push_back(PendingMessage::Message(pending_open));

        let (current_closed, current_closed_rx) = get_finalization(3);
        drop(current_closed_rx);
        <TestMessage as Policy>::handle(&mut overflow, current_closed);

        assert!(!has_get_block(&overflow, 1));
        assert!(has_get_info(&overflow, 2));
        assert!(!has_get_finalization(&overflow, 3));
        assert!(matches!(
            pending_open_rx.try_recv(),
            Err(TryRecvError::Empty)
        ));
    }

    #[test]
    fn policy_drain_stops_after_returned_response_closes() {
        let mut overflow = pending();
        let (first, first_rx) = get_block(1);
        let (second, mut second_rx) = get_info(2);
        overflow.messages.push_back(PendingMessage::Message(first));
        overflow.messages.push_back(PendingMessage::Message(second));

        let mut first_rx = Some(first_rx);
        let mut attempts = 0;
        overflow.drain(|message| {
            attempts += 1;
            drop(first_rx.take());
            Some(message)
        });
        assert_eq!(attempts, 1);

        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 1);
        assert!(matches!(
            &drained[0],
            TestMessage::GetInfo {
                identifier: Identifier::Height(height),
                response,
                ..
            } if *height == Height::new(2) && !response.is_closed()
        ));
        assert!(matches!(second_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn policy_keeps_coalesced_hints_in_fifo_position() {
        let mut overflow = pending();
        let first = public_key(1);
        let second = public_key(2);
        let (get_block_9, _get_block_9_rx) = get_block(9);
        let (get_info_11, _get_info_11_rx) = get_info(11);

        <TestMessage as Policy>::handle(&mut overflow, get_block_9);
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(10, first.clone()));
        <TestMessage as Policy>::handle(&mut overflow, get_info_11);
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(10, second.clone()));

        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 3);
        assert!(matches!(
            &drained[0],
            TestMessage::GetBlock {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(9)
        ));
        assert!(matches!(
            &drained[2],
            TestMessage::GetInfo {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(11)
        ));
        let TestMessage::HintFinalized {
            height, targets, ..
        } = &drained[1]
        else {
            panic!("expected hint");
        };
        assert_eq!(*height, Height::new(10));
        assert_eq!(targets.len().get(), 2);
        assert!(targets.contains(&first));
        assert!(targets.contains(&second));
    }

    #[test]
    fn policy_keeps_highest_floor_and_prune() {
        let mut overflow = pending();

        <TestMessage as Policy>::handle(&mut overflow, set_floor(5));
        <TestMessage as Policy>::handle(&mut overflow, set_floor(3));
        <TestMessage as Policy>::handle(&mut overflow, set_floor(8));
        <TestMessage as Policy>::handle(&mut overflow, prune(4));
        <TestMessage as Policy>::handle(&mut overflow, prune(2));
        <TestMessage as Policy>::handle(&mut overflow, prune(7));

        assert_eq!(
            overflow.floor.as_ref().map(|(_, floor)| floor.round()),
            Some(round(8))
        );
        assert_eq!(
            overflow.prune.as_ref().map(|(_, height)| *height),
            Some(Height::new(7))
        );
        assert!(overflow.messages.is_empty());

        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 2);
        assert!(matches!(
            &drained[0],
            TestMessage::SetFloor { finalization, .. } if finalization.round() == round(8)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::Prune { height, .. } if *height == Height::new(7)
        ));
    }

    #[test]
    fn policy_replaces_floor_and_prune_and_drops_stale_pending_on_drain() {
        let mut overflow = pending();

        overflow.floor = Some((Span::none(), finalization(5)));
        let (get_info_4, _get_info_4_rx) = get_info(4);
        let (get_block_7, _get_block_7_rx) = get_block(7);
        let (get_block_8, _get_block_8_rx) = get_block(8);
        overflow
            .messages
            .push_back(PendingMessage::Message(get_info_4));
        overflow
            .messages
            .push_back(PendingMessage::Message(get_block_7));
        overflow.hint_finalized(
            Span::none(),
            Height::new(8),
            NonEmptyVec::new(public_key(1)),
        );
        overflow
            .messages
            .push_back(PendingMessage::Message(get_block_8));
        <TestMessage as Policy>::handle(&mut overflow, set_floor(8));
        <TestMessage as Policy>::handle(&mut overflow, prune(8));
        assert_eq!(
            overflow.floor.as_ref().map(|(_, floor)| floor.round()),
            Some(round(8))
        );
        assert_eq!(overflow.messages.len(), 1);
        assert!(!has_get_info(&overflow, 4));
        assert!(!has_get_block(&overflow, 7));
        assert!(has_get_block(&overflow, 8));
        assert!(hint_targets(&overflow, 8).is_none());
        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 3);
        assert!(matches!(
            &drained[0],
            TestMessage::SetFloor { finalization, .. } if finalization.round() == round(8)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::Prune { height, .. } if *height == Height::new(8)
        ));
        assert!(matches!(
            &drained[2],
            TestMessage::GetBlock {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(8)
        ));

        let mut overflow = pending();
        overflow.prune = Some((Span::none(), Height::new(5)));
        let (get_finalization_4, _get_finalization_4_rx) = get_finalization(4);
        let (get_block_6, _get_block_6_rx) = get_block(6);
        let (get_block_7, _get_block_7_rx) = get_block(7);
        overflow
            .messages
            .push_back(PendingMessage::Message(get_finalization_4));
        overflow
            .messages
            .push_back(PendingMessage::Message(get_block_6));
        overflow.hint_finalized(
            Span::none(),
            Height::new(6),
            NonEmptyVec::new(public_key(2)),
        );
        overflow
            .messages
            .push_back(PendingMessage::Message(get_block_7));
        <TestMessage as Policy>::handle(&mut overflow, prune(7));
        assert_eq!(
            overflow.prune.as_ref().map(|(_, height)| *height),
            Some(Height::new(7))
        );
        assert_eq!(overflow.messages.len(), 1);
        assert!(!has_get_finalization(&overflow, 4));
        assert!(!has_get_block(&overflow, 6));
        assert!(has_get_block(&overflow, 7));
        assert!(hint_targets(&overflow, 6).is_none());
        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 2);
        assert!(matches!(
            &drained[0],
            TestMessage::Prune { height, .. } if *height == Height::new(7)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::GetBlock {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(7)
        ));
    }

    #[test]
    fn policy_prune_drops_closed_pending() {
        let mut overflow = pending();
        let (closed_message, closed_rx) = get_block(8);
        drop(closed_rx);
        let (open_message, mut open_rx) = get_block(8);

        overflow
            .messages
            .push_back(PendingMessage::Message(closed_message));
        overflow
            .messages
            .push_back(PendingMessage::Message(open_message));

        <TestMessage as Policy>::handle(&mut overflow, prune(7));
        assert_eq!(overflow.messages.len(), 1);
        assert!(has_get_block(&overflow, 8));
        assert!(matches!(open_rx.try_recv(), Err(TryRecvError::Empty)));

        let mut overflow = pending();
        let (closed_message, closed_rx) = get_finalization(8);
        drop(closed_rx);
        let (open_message, mut open_rx) = get_finalization(8);

        overflow
            .messages
            .push_back(PendingMessage::Message(closed_message));
        overflow
            .messages
            .push_back(PendingMessage::Message(open_message));

        <TestMessage as Policy>::handle(&mut overflow, prune(7));
        assert_eq!(overflow.messages.len(), 1);
        assert!(has_get_finalization(&overflow, 8));
        assert!(matches!(open_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn policy_skips_retain_when_prune_height_does_not_increase() {
        let mut overflow = pending();
        <TestMessage as Policy>::handle(&mut overflow, prune(10));

        let (closed_message, closed_rx) = get_block(11);
        drop(closed_rx);
        overflow
            .messages
            .push_back(PendingMessage::Message(closed_message));

        <TestMessage as Policy>::handle(&mut overflow, set_floor(9));
        assert_eq!(overflow.messages.len(), 1);

        <TestMessage as Policy>::handle(&mut overflow, prune(9));
        assert_eq!(overflow.messages.len(), 1);

        <TestMessage as Policy>::handle(&mut overflow, prune(12));
        assert!(overflow.messages.is_empty());
    }

    #[test]
    fn policy_drops_stale_requests_against_pending_floor_and_prune() {
        let mut overflow = pending();
        let (get_info_4, _get_info_4_rx) = get_info(4);
        let (get_info_5, _get_info_5_rx) = get_info(5);
        let (get_info_6, _get_info_6_rx) = get_info(6);
        let (get_info_7, _get_info_7_rx) = get_info(7);
        let (get_block_4, _get_block_4_rx) = get_block(4);
        let (get_block_5, _get_block_5_rx) = get_block(5);
        let (get_block_6, _get_block_6_rx) = get_block(6);
        let (get_block_7, _get_block_7_rx) = get_block(7);
        let (get_finalization_4, _get_finalization_4_rx) = get_finalization(4);
        let (get_finalization_6, _get_finalization_6_rx) = get_finalization(6);

        <TestMessage as Policy>::handle(&mut overflow, set_floor(5));
        <TestMessage as Policy>::handle(&mut overflow, get_info_4);
        <TestMessage as Policy>::handle(&mut overflow, get_info_5);
        <TestMessage as Policy>::handle(&mut overflow, get_block_4);
        <TestMessage as Policy>::handle(&mut overflow, get_block_5);
        <TestMessage as Policy>::handle(&mut overflow, get_finalization_4);
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(5, public_key(1)));
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(6, public_key(2)));

        <TestMessage as Policy>::handle(&mut overflow, prune(7));
        assert!(has_prune(&overflow, 7));
        <TestMessage as Policy>::handle(&mut overflow, get_info_6);
        <TestMessage as Policy>::handle(&mut overflow, get_finalization_6);
        assert!(!has_get_finalization(&overflow, 6));
        <TestMessage as Policy>::handle(&mut overflow, get_block_6);
        <TestMessage as Policy>::handle(&mut overflow, get_info_7);
        assert!(has_get_info(&overflow, 7));
        <TestMessage as Policy>::handle(&mut overflow, get_block_7);
        assert!(has_get_block(&overflow, 7));

        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 4);
        assert!(matches!(
            &drained[0],
            TestMessage::SetFloor { finalization, .. } if finalization.round() == round(5)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::Prune { height, .. } if *height == Height::new(7)
        ));
        assert!(matches!(
            &drained[2],
            TestMessage::GetInfo {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(7)
        ));
        assert!(matches!(
            &drained[3],
            TestMessage::GetBlock {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(7)
        ));
    }

    #[test]
    fn policy_keeps_block_messages_and_waiters() {
        let mut overflow = pending();

        let (proposed_message, mut proposed_ack) = proposed(4);
        let (verified_message, mut verified_ack) = verified(6);
        let (certified_message, mut certified_ack) = certified(8);
        overflow
            .messages
            .push_back(PendingMessage::Message(proposed_message));
        overflow
            .messages
            .push_back(PendingMessage::Message(verified_message));
        overflow
            .messages
            .push_back(PendingMessage::Message(certified_message));

        <TestMessage as Policy>::handle(&mut overflow, set_floor(7));
        assert!(has_block_message(&overflow, 4));
        assert!(has_block_message(&overflow, 6));
        assert!(has_block_message(&overflow, 8));
        assert!(matches!(proposed_ack.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(verified_ack.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(certified_ack.try_recv(), Err(TryRecvError::Empty)));

        <TestMessage as Policy>::handle(&mut overflow, prune(9));
        assert!(has_block_message(&overflow, 8));
        assert!(matches!(certified_ack.try_recv(), Err(TryRecvError::Empty)));

        let (stale, mut stale_ack) = proposed(8);
        <TestMessage as Policy>::handle(&mut overflow, stale);
        assert!(has_block_message(&overflow, 8));
        assert!(matches!(stale_ack.try_recv(), Err(TryRecvError::Empty)));

        let (current, mut current_ack) = verified(9);
        <TestMessage as Policy>::handle(&mut overflow, current);
        assert!(has_block_message(&overflow, 9));
        assert!(matches!(current_ack.try_recv(), Err(TryRecvError::Empty)));

        let drained = drain(&mut overflow);
        assert!(matches!(drained[0], TestMessage::SetFloor { .. }));
        assert!(matches!(drained[1], TestMessage::Prune { .. }));
    }
}
