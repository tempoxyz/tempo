use crate::{
    simplex::{
        metrics::TimeoutReason,
        types::{Certificate, Proposal},
    },
    types::{Round as Rnd, View},
    Epochable, Viewable,
};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_runtime::telemetry::traces::TracedExt as _;
use std::collections::VecDeque;
use tracing::{info_span, Span};

/// Messages sent to the [super::actor::Actor].
pub enum Message<S: Scheme, D: Digest> {
    /// Leader's proposal from batcher.
    Proposal {
        /// The span carried with this message.
        span: Span,
        /// The leader's proposal.
        proposal: Proposal<D>,
    },
    /// Signal that the current view should timeout (if not already).
    Timeout {
        /// The span carried with this message.
        span: Span,
        /// The round to timeout.
        round: Rnd,
        /// The reason for the timeout.
        reason: TimeoutReason,
    },
    /// Certificate from batcher or resolver.
    Verified {
        /// The span carried with this message.
        span: Span,
        /// The verified certificate.
        certificate: Certificate<S, D>,
        /// Whether the certificate came from the resolver. When true, the voter
        /// will not send it back to the resolver (to avoid "boomerang").
        from_resolver: bool,
    },
}

impl<S: Scheme, D: Digest> Message<S, D> {
    /// Returns the message view used for pruning and deduplication.
    pub(crate) fn view(&self) -> View {
        match self {
            Self::Proposal { proposal, .. } => proposal.view(),
            Self::Timeout { round, .. } => round.view(),
            Self::Verified { certificate, .. } => certificate.view(),
        }
    }

    /// Returns the span carried with this message.
    pub(crate) const fn span(&self) -> &Span {
        match self {
            Self::Proposal { span, .. }
            | Self::Timeout { span, .. }
            | Self::Verified { span, .. } => span,
        }
    }

    /// Returns the operation name of this message.
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::Proposal { .. } => "proposal",
            Self::Timeout { .. } => "timeout",
            Self::Verified { .. } => "verified",
        }
    }
}

/// Pending voter messages retained after the mailbox fills.
pub struct Pending<S: Scheme, D: Digest> {
    finalization: Option<Message<S, D>>,
    messages: VecDeque<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Default for Pending<S, D> {
    fn default() -> Self {
        Self {
            finalization: None,
            messages: VecDeque::new(),
        }
    }
}

impl<S: Scheme, D: Digest> Overflow<Message<S, D>> for Pending<S, D> {
    fn is_empty(&self) -> bool {
        self.finalization.is_none() && self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<S, D>) -> Option<Message<S, D>>,
    {
        if let Some(finalization) = self.finalization.take() {
            if let Some(finalization) = push(finalization) {
                self.finalization = Some(finalization);
                return;
            }
        }

        while let Some(message) = self.messages.pop_front() {
            if let Some(message) = push(message) {
                self.messages.push_front(message);
                break;
            }
        }
    }
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    type Overflow = Pending<S, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Ignore the message if there exists a queued finalization
        // with a view greater than or equal to the new view
        let new_view = message.view();
        if matches!(
            overflow.finalization.as_ref(),
            Some(Self::Verified { certificate: Certificate::Finalization(old_finalized), .. })
                if old_finalized.view() >= new_view
        ) {
            return;
        }

        // Retain only the highest-view finalization and any messages with a view greater than the new view
        if matches!(
            &message,
            Self::Verified {
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

        // Ignore the message if it is a duplicate
        if overflow
            .messages
            .iter()
            .any(|old_message| match (&message, old_message) {
                (
                    Self::Proposal {
                        proposal: new_proposal,
                        ..
                    },
                    Self::Proposal {
                        proposal: old_proposal,
                        ..
                    },
                ) => new_proposal.view() == old_proposal.view(),
                (
                    Self::Timeout {
                        round: new_round, ..
                    },
                    Self::Timeout {
                        round: old_round, ..
                    },
                ) => {
                    new_round.view() == old_round.view() // only retain the first queued timeout reason
                }
                (
                    Self::Verified {
                        certificate: new_certificate,
                        ..
                    },
                    Self::Verified {
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
    sender: Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a leader's proposal.
    pub fn proposal(&mut self, proposal: Proposal<D>) {
        let _ = self.sender.enqueue(Message::Proposal {
            span: info_span!(
                "simplex.voter.mailbox.proposal",
                epoch = proposal.epoch().traced(),
                view = proposal.view().traced()
            ),
            proposal,
        });
    }

    /// Signal that the given round should timeout (if not already).
    pub fn timeout(&mut self, round: Rnd, reason: TimeoutReason) {
        let _ = self.sender.enqueue(Message::Timeout {
            span: info_span!(
                "simplex.voter.mailbox.timeout",
                epoch = round.epoch().traced(),
                view = round.view().traced(),
                reason = reason.as_str()
            ),
            round,
            reason,
        });
    }

    /// Send a recovered certificate.
    pub fn recovered(&mut self, certificate: Certificate<S, D>) {
        let _ = self.sender.enqueue(Message::Verified {
            span: info_span!(
                "simplex.voter.mailbox.recovered",
                epoch = certificate.epoch().traced(),
                view = certificate.view().traced(),
                certificate = certificate.kind()
            ),
            certificate,
            from_resolver: false,
        });
    }

    /// Send a resolved certificate.
    pub fn resolved(&mut self, certificate: Certificate<S, D>) {
        let _ = self.sender.enqueue(Message::Verified {
            span: info_span!(
                "simplex.voter.mailbox.resolved",
                epoch = certificate.epoch().traced(),
                view = certificate.view().traced(),
                certificate = certificate.kind()
            ),
            certificate,
            from_resolver: true,
        });
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
    use commonware_utils::test_rng;
    use std::collections::VecDeque;

    type TestScheme = ed25519::Scheme;
    const EPOCH: Epoch = Epoch::new(1);

    fn fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, b"voter-policy", 5);
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
            Nullification::from_nullifies(&verifier, &votes, &Sequential).expect("nullification"),
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
            Finalization::from_finalizes(&verifier, &votes, &Sequential).expect("finalization"),
        )
    }

    fn proposal_msg(view: View) -> Message<TestScheme, Sha256Digest> {
        Message::Proposal {
            span: Span::none(),
            proposal: proposal(view),
        }
    }

    fn timeout_msg(view: View, reason: TimeoutReason) -> Message<TestScheme, Sha256Digest> {
        Message::Timeout {
            span: Span::none(),
            round: Round::new(EPOCH, view),
            reason,
        }
    }

    fn verified_msg(
        certificate: Certificate<TestScheme, Sha256Digest>,
        from_resolver: bool,
    ) -> Message<TestScheme, Sha256Digest> {
        Message::Verified {
            span: Span::none(),
            certificate,
            from_resolver,
        }
    }

    fn drain(
        mut overflow: Pending<TestScheme, Sha256Digest>,
    ) -> VecDeque<Message<TestScheme, Sha256Digest>> {
        let mut messages = VecDeque::new();
        Overflow::drain(&mut overflow, |message| {
            messages.push_back(message);
            None
        });
        messages
    }

    #[test]
    fn finalization_prunes_stale_overflow() {
        let mut overflow = Pending::default();
        Message::handle(&mut overflow, proposal_msg(View::new(2)));
        Message::handle(
            &mut overflow,
            timeout_msg(View::new(2), TimeoutReason::LeaderTimeout),
        );
        Message::handle(
            &mut overflow,
            verified_msg(nullification(View::new(2)), false),
        );
        Message::handle(&mut overflow, proposal_msg(View::new(4)));
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(3)), false),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified { certificate: Certificate::Finalization(f), from_resolver: false, .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Proposal { proposal: p, .. }) if p.view() == View::new(4)
        ));
    }

    #[test]
    fn duplicate_certificate_is_ignored() {
        let mut overflow = Pending::default();
        let certificate = nullification(View::new(5));
        Message::handle(&mut overflow, verified_msg(certificate.clone(), false));
        Message::handle(&mut overflow, verified_msg(certificate, true));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified { certificate: Certificate::Nullification(n), from_resolver: false, .. })
                if n.view() == View::new(5)
        ));
    }

    #[test]
    fn queued_finalization_rejects_covered_messages() {
        let mut overflow = Pending::default();
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(3)), false),
        );

        Message::handle(&mut overflow, proposal_msg(View::new(3)));
        Message::handle(
            &mut overflow,
            timeout_msg(View::new(2), TimeoutReason::LeaderTimeout),
        );
        Message::handle(
            &mut overflow,
            verified_msg(nullification(View::new(2)), false),
        );
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(2)), false),
        );
        Message::handle(&mut overflow, proposal_msg(View::new(4)));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified { certificate: Certificate::Finalization(f), from_resolver: false, .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Proposal { proposal: p, .. }) if p.view() == View::new(4)
        ));
    }

    #[test]
    fn duplicate_finalization_is_dropped() {
        let mut overflow = Pending::default();
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(3)), false),
        );
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(3)), true),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified { certificate: Certificate::Finalization(f), from_resolver: false, .. })
                if f.view() == View::new(3)
        ));
    }

    #[test]
    fn newer_finalization_replaces_older_pruning_floor() {
        let mut overflow = Pending::default();
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(3)), false),
        );
        Message::handle(&mut overflow, proposal_msg(View::new(4)));
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(5)), false),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified { certificate: Certificate::Finalization(f), from_resolver: false, .. })
                if f.view() == View::new(5)
        ));
    }

    #[test]
    fn duplicate_proposals_and_timeouts_are_deduplicated() {
        let mut overflow = Pending::<TestScheme, Sha256Digest>::default();
        Message::handle(&mut overflow, proposal_msg(View::new(4)));
        Message::handle(&mut overflow, proposal_msg(View::new(4)));
        Message::handle(
            &mut overflow,
            timeout_msg(View::new(4), TimeoutReason::LeaderTimeout),
        );
        Message::handle(
            &mut overflow,
            timeout_msg(View::new(4), TimeoutReason::Inactivity),
        );

        let overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
    }
}
