//! Wrapper for scheme-dependent activity filtering and verification.
//!
//! # Overview
//!
//! The [`AttributableReporter`] provides a composable wrapper around consensus reporters
//! that automatically filters and verifies activities based on scheme attributability.
//! This ensures that:
//!
//! 1. **Peer activities are cryptographically verified** before being reported
//! 2. **Non-attributable schemes** suppress per-validator activities from peers to prevent
//!    signature forgery attacks
//! 3. **Certificates** are always reported as they contain valid quorum proofs
//!
//! # Security Rationale
//!
//! With [`super::bls12381_threshold`], any `t` valid partial signatures
//! can be used to forge a partial signature for any participant. If per-validator activities
//! were exposed for such schemes, adversaries could fabricate evidence of either liveness or of committing a fault.
//! This wrapper prevents that attack by suppressing peer activities for non-attributable schemes.

use crate::{
    simplex::{scheme::Scheme, types::Activity},
    Reporter,
};
use commonware_actor::Feedback;
use commonware_cryptography::{certificate, Digest};
use commonware_parallel::Strategy;
use commonware_utils::sync::Mutex;
use rand_core::CryptoRng;
use std::sync::Arc;

/// Reporter wrapper that filters and verifies activities based on scheme attributability.
///
/// This wrapper provides scheme-aware activity filtering with automatic verification of peer
/// activities. It prevents signature forgery attacks on non-attributable schemes while ensuring
/// all activities are cryptographically valid before reporting.
pub struct AttributableReporter<
    E: CryptoRng + Send + 'static,
    S: certificate::Scheme,
    D: Digest,
    T: Strategy,
    R: Reporter<Activity = Activity<S, D>>,
> {
    /// RNG for certificate verification
    rng: Arc<Mutex<E>>,
    /// Signing scheme for verification
    scheme: S,
    /// Inner reporter that receives filtered activities
    reporter: R,
    /// Strategy for parallel operations.
    strategy: T,
    /// Whether to always verify peer activities
    verify: bool,
}

impl<
        E: CryptoRng + Send + 'static,
        S: certificate::Scheme + Clone,
        D: Digest,
        T: Strategy,
        R: Reporter<Activity = Activity<S, D>>,
    > Clone for AttributableReporter<E, S, D, T, R>
{
    fn clone(&self) -> Self {
        Self {
            rng: self.rng.clone(),
            scheme: self.scheme.clone(),
            reporter: self.reporter.clone(),
            strategy: self.strategy.clone(),
            verify: self.verify,
        }
    }
}

impl<
        E: CryptoRng + Send + 'static,
        S: certificate::Scheme,
        D: Digest,
        T: Strategy,
        R: Reporter<Activity = Activity<S, D>>,
    > AttributableReporter<E, S, D, T, R>
{
    /// Creates a new `AttributableReporter` that wraps an inner reporter.
    pub fn new(rng: E, scheme: S, reporter: R, strategy: T, verify: bool) -> Self {
        Self {
            rng: Arc::new(Mutex::new(rng)),
            scheme,
            reporter,
            strategy,
            verify,
        }
    }
}

impl<
        E: CryptoRng + Send + 'static,
        S: Scheme<D>,
        D: Digest,
        T: Strategy,
        R: Reporter<Activity = Activity<S, D>>,
    > Reporter for AttributableReporter<E, S, D, T, R>
{
    type Activity = Activity<S, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // Verify peer activities if verification is enabled
        if self.verify
            && !activity.verified()
            && !activity.verify(&mut *self.rng.lock(), &self.scheme, &self.strategy)
        {
            // Ignore unverified peer activity.
            return Feedback::Ok;
        }

        // Filter based on scheme attributability
        if !S::is_attributable() {
            match activity {
                Activity::Notarize(_)
                | Activity::Nullify(_)
                | Activity::Finalize(_)
                | Activity::ConflictingNotarize(_)
                | Activity::ConflictingFinalize(_)
                | Activity::NullifyFinalize(_) => {
                    // Ignore per-validator peer activity for non-attributable schemes.
                    return Feedback::Ok;
                }
                Activity::Notarization(_)
                | Activity::Certification(_)
                | Activity::Nullification(_)
                | Activity::Finalization(_) => {
                    // Always report certificates
                }
            }
        }

        self.reporter.report(activity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::{bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519},
            types::{Notarization, Notarize, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk,
        certificate::{self, mocks::Fixture, Scheme as _},
        ed25519::PublicKey as Ed25519PublicKey,
        sha256::Digest as Sha256Digest,
        Hasher, Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{sync::Mutex, test_rng, N3f1};
    use std::sync::Arc;

    const NAMESPACE: &[u8] = b"test-reporter";

    #[derive(Clone)]
    struct MockReporter<S: certificate::Scheme, D: Digest> {
        activities: Arc<Mutex<Vec<Activity<S, D>>>>,
    }

    impl<S: certificate::Scheme, D: Digest> MockReporter<S, D> {
        fn new() -> Self {
            Self {
                activities: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn reported(&self) -> Vec<Activity<S, D>> {
            self.activities.lock().clone()
        }

        fn count(&self) -> usize {
            self.activities.lock().len()
        }
    }

    impl<S: certificate::Scheme, D: Digest> Reporter for MockReporter<S, D> {
        type Activity = Activity<S, D>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            self.activities.lock().push(activity);
            Feedback::Ok
        }
    }

    fn create_proposal(epoch: u64, view: u64) -> Proposal<Sha256Digest> {
        let data = format!("proposal-{epoch}-{view}");
        let hash = Sha256::hash(data.as_bytes());
        let epoch = Epoch::new(epoch);
        let view = View::new(view);
        Proposal::new(Round::new(epoch, view), view, hash)
    }

    #[test]
    fn test_invalid_peer_activity_ignored() {
        // Invalid peer activities should be ignored when verification is enabled.
        let mut rng = test_rng();
        let Fixture { verifier, .. } = ed25519::fixture(&mut rng, NAMESPACE, 4);

        // Create a scheme with wrong namespace to generate invalid signatures
        let Fixture {
            schemes: wrong_schemes,
            ..
        } = ed25519::fixture(&mut rng, b"wrong-namespace", 4);

        assert!(
            ed25519::Scheme::is_attributable(),
            "Ed25519 must be attributable"
        );

        let mock = MockReporter::new();
        let mut reporter = AttributableReporter::new(rng, verifier, mock.clone(), Sequential, true);

        // Create an invalid activity (signed with wrong namespace scheme)
        let proposal = create_proposal(0, 1);
        let attestation = wrong_schemes[1]
            .sign::<Sha256Digest>(Subject::Notarize {
                proposal: &proposal,
            })
            .expect("signing failed");
        let notarize = Notarize {
            proposal,
            attestation,
        };

        // Report it.
        assert_eq!(reporter.report(Activity::Notarize(notarize)), Feedback::Ok);

        // Should be ignored.
        assert_eq!(mock.count(), 0);
    }

    #[test]
    fn test_skip_verification() {
        // When verification is disabled, invalid activities pass through
        let mut rng = test_rng();
        let Fixture { verifier, .. } = ed25519::fixture(&mut rng, NAMESPACE, 4);

        // Create a scheme with wrong namespace to generate invalid signatures
        let Fixture {
            schemes: wrong_schemes,
            ..
        } = ed25519::fixture(&mut rng, b"wrong-namespace", 4);

        assert!(
            ed25519::Scheme::is_attributable(),
            "Ed25519 must be attributable"
        );

        let mock = MockReporter::new();
        let mut reporter = AttributableReporter::new(
            rng,
            verifier,
            mock.clone(),
            Sequential,
            false, // Disable verification
        );

        // Create an invalid activity (signed with wrong namespace scheme)
        let proposal = create_proposal(0, 1);
        let attestation = wrong_schemes[1]
            .sign::<Sha256Digest>(Subject::Notarize {
                proposal: &proposal,
            })
            .expect("signing failed");
        let notarize = Notarize {
            proposal,
            attestation,
        };

        // Report it
        assert_eq!(reporter.report(Activity::Notarize(notarize)), Feedback::Ok);

        // Should be reported even though it's invalid
        assert_eq!(mock.count(), 1);
        let reported = mock.reported();
        assert!(matches!(reported[0], Activity::Notarize(_)));
    }

    #[test]
    fn test_certificates_always_reported() {
        // Certificates should always be reported, even for non-attributable schemes
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 4);

        assert!(
            !bls12381_threshold_vrf::Scheme::<Ed25519PublicKey, MinPk>::is_attributable(),
            "BLS threshold must be non-attributable"
        );

        let mock = MockReporter::new();
        let mut reporter = AttributableReporter::new(rng, verifier, mock.clone(), Sequential, true);

        // Create a certificate from multiple validators
        let proposal = create_proposal(0, 1);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| {
                scheme
                    .sign::<Sha256Digest>(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .expect("signing failed")
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("failed to assemble certificate");

        let notarization = Notarization {
            proposal,
            certificate,
        };

        // Report it
        assert_eq!(
            reporter.report(Activity::Notarization(notarization)),
            Feedback::Ok
        );

        // Should be reported even though scheme is non-attributable (certificates are quorum proofs)
        assert_eq!(mock.count(), 1);
        let reported = mock.reported();
        assert!(matches!(reported[0], Activity::Notarization(_)));
    }

    #[test]
    fn test_non_attributable_filters_peer_activities() {
        // Non-attributable schemes (like BLS threshold) must filter peer per-validator activities
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 4);

        assert!(
            !bls12381_threshold_vrf::Scheme::<Ed25519PublicKey, MinPk>::is_attributable(),
            "BLS threshold must be non-attributable"
        );

        let mock = MockReporter::new();
        let mut reporter = AttributableReporter::new(rng, verifier, mock.clone(), Sequential, true);

        // Create peer activity (from validator 1)
        let proposal = create_proposal(0, 1);
        let attestation = schemes[1]
            .sign::<Sha256Digest>(Subject::Notarize {
                proposal: &proposal,
            })
            .expect("signing failed");

        let notarize = Notarize {
            proposal,
            attestation,
        };

        // Report peer per-validator activity
        assert_eq!(reporter.report(Activity::Notarize(notarize)), Feedback::Ok);

        // Must be filtered
        assert_eq!(mock.count(), 0);
    }

    #[test]
    fn test_attributable_scheme_reports_peer_activities() {
        // Ed25519 (attributable) should report peer per-validator activities
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, NAMESPACE, 4);

        assert!(
            ed25519::Scheme::is_attributable(),
            "Ed25519 must be attributable"
        );

        let mock = MockReporter::new();
        let mut reporter = AttributableReporter::new(rng, verifier, mock.clone(), Sequential, true);

        // Create a peer activity (from validator 1)
        let proposal = create_proposal(0, 1);
        let attestation = schemes[1]
            .sign::<Sha256Digest>(Subject::Notarize {
                proposal: &proposal,
            })
            .expect("signing failed");

        let notarize = Notarize {
            proposal,
            attestation,
        };

        // Report the peer per-validator activity
        assert_eq!(reporter.report(Activity::Notarize(notarize)), Feedback::Ok);

        // Should be reported since scheme is attributable
        assert_eq!(mock.count(), 1);
        let reported = mock.reported();
        assert!(matches!(reported[0], Activity::Notarize(_)));
    }
}
