use crate::{
    Epochable, Viewable,
    simplex::{
        actors::{Ask, Kind},
        types::Certificate,
    },
    types::View,
};
use bytes::Bytes;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_resolver::{Consumer, Delivery, Outcome, p2p::Producer};
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{channel::oneshot, sequence::U64, vec::NonEmptyVec};
use std::collections::VecDeque;
use tracing::{Span, info_span};

/// Messages sent to the resolver actor from the voter.
pub enum MailboxMessage<S: Scheme, D: Digest> {
    /// A certificate was received or produced.
    Certificate {
        /// The span carried with this message.
        span: Span,
        /// The certificate.
        certificate: Certificate<S, D>,
    },
    /// Certification result for a view.
    Certified {
        /// The span carried with this message.
        span: Span,
        /// The certified view.
        view: View,
        /// Whether certification succeeded.
        success: bool,
    },
    /// Fetch missing proposal ancestry.
    Resolve {
        /// The span carried with this message.
        span: Span,
        /// View of the proposal that exposed the missing ancestry.
        proposal: View,
        /// View whose certificate is needed.
        view: View,
        /// The certificate that is needed.
        kind: Kind,
        /// When set, the resolver queries only this peer.
        target: Option<S::PublicKey>,
    },
}

impl<S: Scheme, D: Digest> MailboxMessage<S, D> {
    /// Returns the message view used for pruning and deduplication.
    pub(crate) fn view(&self) -> View {
        match self {
            Self::Certificate { certificate, .. } => certificate.view(),
            Self::Certified { view, .. } => *view,
            Self::Resolve { view, .. } => *view,
        }
    }

    /// Returns the span carried with this message.
    pub(crate) const fn span(&self) -> &Span {
        match self {
            Self::Certificate { span, .. }
            | Self::Certified { span, .. }
            | Self::Resolve { span, .. } => span,
        }
    }

    /// Returns the operation name of this message.
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::Certificate { .. } => "certificate",
            Self::Certified { .. } => "certified",
            Self::Resolve { .. } => "resolve",
        }
    }
}

/// Pending resolver messages retained after the mailbox fills.
pub struct Pending<S: Scheme, D: Digest> {
    finalization: Option<MailboxMessage<S, D>>,
    messages: VecDeque<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Default for Pending<S, D> {
    fn default() -> Self {
        Self {
            finalization: None,
            messages: VecDeque::new(),
        }
    }
}

impl<S: Scheme, D: Digest> Overflow<MailboxMessage<S, D>> for Pending<S, D> {
    fn is_empty(&self) -> bool {
        self.finalization.is_none() && self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(MailboxMessage<S, D>) -> Option<MailboxMessage<S, D>>,
    {
        if let Some(finalization) = self.finalization.take()
            && let Some(finalization) = push(finalization)
        {
            self.finalization = Some(finalization);
            return;
        }

        while let Some(message) = self.messages.pop_front() {
            if let Some(message) = push(message) {
                self.messages.push_front(message);
                break;
            }
        }
    }
}

impl<S: Scheme, D: Digest> Policy for MailboxMessage<S, D> {
    type Overflow = Pending<S, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Ignore the message if there exists a queued finalization
        // with a view greater than or equal to the new view
        let new_view = message.view();
        if matches!(
            overflow.finalization.as_ref(),
            Some(Self::Certificate { certificate: Certificate::Finalization(old_finalized), .. })
                if old_finalized.view() >= new_view
        ) {
            return;
        }

        // Retain only the highest-view finalization and any messages with a view greater than the new view
        if matches!(
            &message,
            Self::Certificate {
                certificate: Certificate::Finalization(_),
                ..
            }
        ) {
            overflow
                .messages
                .retain(|old_message| old_message.view() > new_view);
            overflow.finalization = Some(message);
            return;
        }

        // Ignore duplicate work. Resolve requests with the same proposal,
        // requested view, and kind share one network fetch. An unrestricted
        // duplicate removes the target. Different kinds remain distinct
        // because their certificates are not interchangeable.
        if overflow
            .messages
            .iter_mut()
            .any(|old_message| match (&message, old_message) {
                (
                    Self::Certificate {
                        certificate: new_certificate,
                        ..
                    },
                    Self::Certificate {
                        certificate: old_certificate,
                        ..
                    },
                ) => {
                    new_certificate.view() == old_certificate.view()
                        && matches!(
                            (new_certificate, old_certificate),
                            (Certificate::Notarization(_), Certificate::Notarization(_))
                                | (Certificate::Nullification(_), Certificate::Nullification(_))
                                | (Certificate::Finalization(_), Certificate::Finalization(_))
                        )
                }
                (
                    Self::Certified { view: new_view, .. },
                    Self::Certified { view: old_view, .. },
                ) => new_view == old_view,
                (
                    Self::Resolve {
                        proposal: new_proposal,
                        view: new_view,
                        kind: new_kind,
                        target: new_target,
                        ..
                    },
                    Self::Resolve {
                        proposal: old_proposal,
                        view: old_view,
                        kind: old_kind,
                        target: old_target,
                        ..
                    },
                ) if new_proposal == old_proposal
                    && new_view == old_view
                    && new_kind == old_kind =>
                {
                    if new_target.is_none() {
                        *old_target = None;
                    }
                    true
                }
                _ => false,
            })
        {
            return;
        }
        overflow.messages.push_back(message);
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: Sender<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: Sender<MailboxMessage<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a certificate.
    pub fn updated(&mut self, certificate: Certificate<S, D>) {
        let _ = self.sender.enqueue(MailboxMessage::Certificate {
            span: info_span!(
                "simplex.resolver.mailbox.updated",
                epoch = certificate.epoch().traced(),
                view = certificate.view().traced()
            ),
            certificate,
        });
    }

    /// Notify the resolver of a certification result.
    pub fn certified(&mut self, view: View, success: bool) {
        let _ = self.sender.enqueue(MailboxMessage::Certified {
            span: info_span!(
                "simplex.resolver.mailbox.certified",
                view = view.traced(),
                success
            ),
            view,
            success,
        });
    }

    /// Requests missing proposal ancestry. If `target` is provided, the
    /// resolver queries only that peer.
    pub(crate) fn resolve(
        &mut self,
        proposal: View,
        view: View,
        kind: Kind,
        target: Option<S::PublicKey>,
    ) {
        let _ = self.sender.enqueue(MailboxMessage::Resolve {
            span: info_span!(
                "simplex.resolver.mailbox.resolve",
                proposal = proposal.traced(),
                view = view.traced(),
                kind = kind.as_str()
            ),
            proposal,
            view,
            kind,
            target,
        });
    }
}

#[derive(Debug)]
pub(crate) enum HandlerMessage {
    Deliver {
        span: Span,
        view: View,
        data: Bytes,
        asks: NonEmptyVec<Ask>,
        response: oneshot::Sender<Outcome>,
    },
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

impl HandlerMessage {
    /// Returns true if the requester stopped waiting for this response.
    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

/// Deliveries retained while the ready queue is full.
#[derive(Default)]
pub(crate) struct HandlerPending(VecDeque<HandlerMessage>);

impl Overflow<HandlerMessage> for HandlerPending {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(HandlerMessage) -> Option<HandlerMessage>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }

            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl Policy for HandlerMessage {
    type Overflow = HandlerPending;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Drop produce requests so the serve backlog stays bounded by the ready
        // queue. We prefer handling our own responses over serving peers, who can
        // ask a less loaded peer instead.
        if matches!(message, Self::Produce { .. }) {
            return;
        }

        // Retain deliveries that still have a waiting requester.
        if message.response_closed() {
            return;
        }
        overflow.0.push_back(message);
    }
}

#[derive(Clone)]
pub(crate) struct Handler {
    sender: Sender<HandlerMessage>,
}

impl Handler {
    pub(crate) const fn new(sender: Sender<HandlerMessage>) -> Self {
        Self { sender }
    }
}

impl Consumer for Handler {
    type Key = U64;
    type Value = Bytes;
    type Subscriber = Ask;
    type Outcome = Outcome;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<Self::Outcome> {
        let (response, receiver) = oneshot::channel();
        let (_, span) = delivery.subscribers.first().clone();
        let asks = delivery.subscribers.map_into(|(ask, _)| ask);
        let _ = self.sender.enqueue(HandlerMessage::Deliver {
            span,
            view: View::new(delivery.key.into()),
            data: value,
            asks,
            response,
        });
        receiver
    }
}

impl Producer for Handler {
    type Key = U64;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(HandlerMessage::Produce {
            view: View::new(key.into()),
            response,
        });
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{Certificate, Finalization, Finalize, Nullification, Nullify, Proposal},
        },
        types::{Epoch, Round},
    };
    use commonware_actor::mailbox::Policy;
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_utils::{non_empty, test_rng};
    use std::collections::VecDeque;

    type TestScheme = ed25519::Scheme;
    const EPOCH: Epoch = Epoch::new(1);

    fn fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, b"resolver-policy", 5);
        (schemes, verifier)
    }

    fn proposal(view: View) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(EPOCH, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        )
    }

    fn nullification(view: View) -> Certificate<TestScheme, Sha256Digest> {
        let (schemes, verifier) = fixture();
        let round = Round::new(EPOCH, view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).expect("nullify"))
            .collect();
        Certificate::Nullification(
            Nullification::from_nullifies(&verifier, non_empty![@&votes], &Sequential)
                .expect("nullification"),
        )
    }

    fn finalization(view: View) -> Certificate<TestScheme, Sha256Digest> {
        let (schemes, verifier) = fixture();
        let proposal = proposal(view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize"))
            .collect();
        Certificate::Finalization(
            Finalization::from_finalizes(&verifier, non_empty![@&votes], &Sequential)
                .expect("finalization"),
        )
    }

    fn drain(
        mut overflow: Pending<TestScheme, Sha256Digest>,
    ) -> VecDeque<MailboxMessage<TestScheme, Sha256Digest>> {
        let mut messages = VecDeque::new();
        Overflow::drain(&mut overflow, |message| {
            messages.push_back(message);
            None
        });
        messages
    }

    fn certificate_msg(
        certificate: Certificate<TestScheme, Sha256Digest>,
    ) -> MailboxMessage<TestScheme, Sha256Digest> {
        MailboxMessage::Certificate {
            span: Span::none(),
            certificate,
        }
    }

    fn certified_msg(view: View, success: bool) -> MailboxMessage<TestScheme, Sha256Digest> {
        MailboxMessage::Certified {
            span: Span::none(),
            view,
            success,
        }
    }

    fn resolve_msg(
        proposal: View,
        view: View,
        kind: Kind,
    ) -> MailboxMessage<TestScheme, Sha256Digest> {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, b"resolver-policy-target", 5);
        MailboxMessage::Resolve {
            span: Span::none(),
            proposal,
            view,
            kind,
            target: Some(participants[0].clone()),
        }
    }

    fn unrestricted_resolve_msg(
        proposal: View,
        view: View,
        kind: Kind,
    ) -> MailboxMessage<TestScheme, Sha256Digest> {
        MailboxMessage::Resolve {
            span: Span::none(),
            proposal,
            view,
            kind,
            target: None,
        }
    }

    #[test]
    fn handle_retains_open_deliveries_only() {
        let mut overflow = HandlerPending::default();
        let deliver = |view: u64, response| HandlerMessage::Deliver {
            span: Span::none(),
            view: View::new(view),
            data: Bytes::new(),
            asks: NonEmptyVec::new(Ask::backfill()),
            response,
        };

        // An overflowed produce request is dropped and its requester sees the
        // closed response.
        let (response, mut produce) = oneshot::channel();
        HandlerMessage::handle(
            &mut overflow,
            HandlerMessage::Produce {
                view: View::new(1),
                response,
            },
        );
        assert!(matches!(
            produce.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));

        // Deliveries are retained, and drain skips one whose requester left.
        let (response, closed) = oneshot::channel();
        HandlerMessage::handle(&mut overflow, deliver(2, response));
        let (response, _open) = oneshot::channel();
        HandlerMessage::handle(&mut overflow, deliver(3, response));
        drop(closed);

        let mut messages = Vec::new();
        Overflow::drain(&mut overflow, |message| {
            messages.push(message);
            None
        });
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            messages.pop(),
            Some(HandlerMessage::Deliver { view, .. }) if view == View::new(3)
        ));
    }

    #[test]
    fn finalization_prunes_stale_certificates_and_results() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(2))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(2), false));
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(5))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(5), false));
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 3);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Nullification(n), .. })
                if n.view() == View::new(5)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                view,
                success: false,
                ..
            }) if view == View::new(5)
        ));
    }

    #[test]
    fn finalization_prunes_resolve_by_requested_view() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(View::new(10), View::new(2), Kind::Nullification),
        );
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(View::new(10), View::new(5), Kind::Notarization),
        );
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Resolve {
                proposal,
                view,
                kind: Kind::Notarization,
                ..
            }) if proposal == View::new(10) && view == View::new(5)
        ));
    }

    #[test]
    fn resolve_deduplicates_by_proposal_view_and_kind() {
        let mut overflow = Pending::default();
        for kind in [Kind::Nullification, Kind::Nullification, Kind::Notarization] {
            MailboxMessage::handle(
                &mut overflow,
                resolve_msg(View::new(10), View::new(3), kind),
            );
        }

        let overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            MailboxMessage::Resolve {
                kind: Kind::Nullification,
                ..
            }
        ));
        assert!(matches!(
            &overflow[1],
            MailboxMessage::Resolve {
                kind: Kind::Notarization,
                ..
            }
        ));
    }

    /// An unrestricted request must not modify a pending request for another
    /// certificate kind.
    #[test]
    fn resolve_retains_target_across_kinds() {
        let proposal = View::new(10);
        let view = View::new(3);
        let mut overflow = Pending::default();
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(proposal, view, Kind::Nullification),
        );
        MailboxMessage::handle(
            &mut overflow,
            unrestricted_resolve_msg(proposal, view, Kind::Notarization),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Resolve {
                kind: Kind::Nullification,
                target: Some(_),
                ..
            })
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Resolve {
                kind: Kind::Notarization,
                target: None,
                ..
            })
        ));
    }

    /// An unrestricted duplicate must widen the pending request regardless of
    /// arrival order.
    #[test]
    fn resolve_widens_duplicate_to_unrestricted() {
        let proposal = View::new(10);
        let view = View::new(3);
        for unrestricted_first in [false, true] {
            let messages = if unrestricted_first {
                [
                    unrestricted_resolve_msg(proposal, view, Kind::Notarization),
                    resolve_msg(proposal, view, Kind::Notarization),
                ]
            } else {
                [
                    resolve_msg(proposal, view, Kind::Notarization),
                    unrestricted_resolve_msg(proposal, view, Kind::Notarization),
                ]
            };
            let mut overflow = Pending::default();
            for message in messages {
                MailboxMessage::handle(&mut overflow, message);
            }

            let mut overflow = drain(overflow);
            assert_eq!(overflow.len(), 1);
            assert!(matches!(
                overflow.pop_front(),
                Some(MailboxMessage::Resolve {
                    proposal: actual_proposal,
                    view: actual_view,
                    kind: Kind::Notarization,
                    target: None,
                    ..
                }) if actual_proposal == proposal && actual_view == view
            ));
        }
    }

    #[test]
    fn duplicate_certified_result_is_ignored() {
        let mut overflow = Pending::<TestScheme, Sha256Digest>::default();
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(4), false));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(4), true));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                view,
                success: false,
                ..
            }) if view == View::new(4)
        ));
    }

    #[test]
    fn queued_finalization_rejects_covered_messages() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));

        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(2))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(2), false));
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(2))));
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(View::new(10), View::new(2), Kind::Nullification),
        );
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(4))));
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(View::new(10), View::new(4), Kind::Notarization),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 3);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Nullification(n), .. })
                if n.view() == View::new(4)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Resolve {
                view,
                kind: Kind::Notarization,
                ..
            }) if view == View::new(4)
        ));
    }

    #[test]
    fn duplicate_finalization_is_dropped() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
    }

    #[test]
    fn newer_finalization_replaces_older_pruning_floor() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(4))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(4), false));
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(5))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(5)
        ));
    }

    #[test]
    fn duplicate_certificate_is_ignored() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(4))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(4), true));
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(4))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Nullification(n), .. })
                if n.view() == View::new(4)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                view,
                success: true,
                ..
            }) if view == View::new(4)
        ));
    }
}
