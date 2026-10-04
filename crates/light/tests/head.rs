use std::num::NonZeroU64;

use alloy_consensus::{Header, Sealable as _};
use alloy_primitives::{B256, hex};
use commonware_codec::Encode as _;
use commonware_consensus::types::Epoch;
use rand::{SeedableRng as _, rngs::StdRng};
use tempo_finality::{
    NetworkIdentity,
    test_utils::{DkgFixture, dkg_fixture, make_certificate},
};
use tempo_light::{CertifiedHeader, HeadTracker, head::Error};
use tempo_primitives::TempoHeader;

const EPOCH_LENGTH: NonZeroU64 = NonZeroU64::new(10).unwrap();

fn evidence(dkg: &DkgFixture, height: u64, root: B256, extra: Vec<u8>) -> CertifiedHeader {
    let header = TempoHeader {
        inner: Header {
            number: height,
            state_root: root,
            extra_data: extra.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let digest = header.hash_slow();
    let epoch = height / EPOCH_LENGTH.get();
    let certificate = make_certificate(
        tempo_finality::Digest(digest),
        Epoch::new(epoch),
        height,
        &dkg.schemes,
    );
    CertifiedHeader {
        header,
        digest,
        epoch,
        view: height,
        certificate: hex::encode(certificate.encode()),
    }
}

fn fixture() -> (StdRng, DkgFixture, HeadTracker) {
    let mut rng = StdRng::seed_from_u64(987);
    let dkg = dkg_fixture(&mut rng, Epoch::zero());
    let tracker = HeadTracker::new(
        NetworkIdentity {
            from_epoch: 0,
            identity: *dkg.outcome.network_identity(),
        },
        EPOCH_LENGTH,
    );
    (rng, dkg, tracker)
}

#[test]
fn skipped_heads_do_not_regress_or_invalidate_in_flight_snapshots() {
    let (mut rng, dkg, mut tracker) = fixture();
    assert!(tracker.snapshot().is_none());
    let root_a = B256::with_last_byte(1);
    let root_b = B256::with_last_byte(2);
    let old = tracker
        .accept(&mut rng, evidence(&dkg, 1, root_a, vec![]))
        .unwrap();
    tracker
        .accept(&mut rng, evidence(&dkg, 400, root_b, vec![]))
        .unwrap();
    assert_eq!(
        tracker.snapshot().unwrap().evidence().header.inner.number,
        400
    );
    assert_eq!(old.header().inner.number, 1);
    assert_eq!(old.header().inner.state_root, root_a);
    assert_eq!(
        tracker.snapshot().unwrap().header().inner.state_root,
        root_b
    );
    assert!(matches!(
        tracker.accept(&mut rng, evidence(&dkg, 2, root_a, vec![])),
        Err(Error::Regression)
    ));
}

#[test]
fn invalid_candidates_and_authenticated_conflicts_do_not_mutate_progress() {
    let (mut rng, dkg, mut tracker) = fixture();
    let first = evidence(&dkg, 1, B256::ZERO, vec![]);
    tracker.accept(&mut rng, first.clone()).unwrap();
    tracker.accept(&mut rng, first.clone()).unwrap();
    let mut altered = evidence(&dkg, 2, B256::ZERO, vec![]);
    altered.header.inner.state_root = B256::with_last_byte(1);
    assert!(tracker.accept(&mut rng, altered).is_err());
    assert!(matches!(
        tracker.accept(&mut rng, evidence(&dkg, 1, B256::with_last_byte(1), vec![])),
        Err(Error::ConflictingHead)
    ));
    assert_eq!(tracker.snapshot().unwrap().evidence(), &first);
}

#[test]
fn rotated_keys_require_previously_authenticated_transition_evidence() {
    let (mut rng, dkg, mut tracker) = fixture();
    let next = dkg_fixture(&mut rng, Epoch::new(1));
    let next_head = evidence(&next, 10, B256::ZERO, vec![]);
    assert!(tracker.accept(&mut rng, next_head.clone()).is_err());
    assert_eq!(tracker.identity().identity, *dkg.outcome.network_identity());
    assert!(tracker.snapshot().is_none());
    let fake_boundary = evidence(&next, 9, B256::ZERO, next.outcome.encode().to_vec());
    assert!(
        tracker
            .authenticate_transition(&mut rng, &fake_boundary)
            .is_err()
    );
    assert_eq!(tracker.identity().identity, *dkg.outcome.network_identity());
    let boundary = evidence(&dkg, 9, B256::ZERO, next.outcome.encode().to_vec());
    tracker
        .authenticate_transition(&mut rng, &boundary)
        .unwrap();
    assert_eq!(tracker.identity().from_epoch, 1);
    assert_eq!(
        tracker.identity().identity,
        *next.outcome.network_identity()
    );
    tracker.accept(&mut rng, next_head).unwrap();
    assert!(
        tracker
            .authenticate_transition(&mut rng, &boundary)
            .is_err()
    );
}

#[test]
fn malformed_wrong_epoch_and_non_boundary_transitions_do_not_change_identity() {
    let (mut rng, dkg, mut tracker) = fixture();
    let wrong = dkg_fixture(&mut rng, Epoch::new(2));
    assert!(matches!(
        tracker.authenticate_transition(
            &mut rng,
            &evidence(&dkg, 8, B256::ZERO, wrong.outcome.encode().to_vec())
        ),
        Err(Error::NotBoundary)
    ));
    assert!(matches!(
        tracker.authenticate_transition(
            &mut rng,
            &evidence(&dkg, 9, B256::ZERO, wrong.outcome.encode().to_vec())
        ),
        Err(Error::TransitionEpoch)
    ));
    assert!(matches!(
        tracker.authenticate_transition(&mut rng, &evidence(&dkg, 9, B256::ZERO, vec![0xff])),
        Err(Error::MalformedBoundary(_))
    ));
    assert_eq!(tracker.identity().identity, *dkg.outcome.network_identity());
}

#[test]
fn a_transition_cannot_rewrite_identity_for_an_already_accepted_epoch() {
    let (mut rng, dkg, mut tracker) = fixture();
    let next = dkg_fixture(&mut rng, Epoch::new(1));
    tracker
        .accept(&mut rng, evidence(&dkg, 12, B256::ZERO, vec![]))
        .unwrap();
    assert!(matches!(
        tracker.authenticate_transition(
            &mut rng,
            &evidence(&dkg, 9, B256::ZERO, next.outcome.encode().to_vec())
        ),
        Err(Error::ConflictingIdentity)
    ));
    assert_eq!(tracker.identity().identity, *dkg.outcome.network_identity());
    assert_eq!(tracker.snapshot().unwrap().header().inner.number, 12);
}

#[test]
fn oversized_evidence_fails_before_decode_without_advancing() {
    let (mut rng, dkg, mut tracker) = fixture();
    let mut huge = evidence(&dkg, 1, B256::ZERO, vec![]);
    huge.certificate = "0".repeat(16 * 1024 + 1);
    assert!(matches!(
        tracker.accept(&mut rng, huge),
        Err(Error::EvidenceSize)
    ));
    let huge = evidence(&dkg, 1, B256::ZERO, vec![0; 1024 * 1024 + 1]);
    assert!(matches!(
        tracker.accept(&mut rng, huge),
        Err(Error::EvidenceSize)
    ));
    assert!(tracker.snapshot().is_none());
}
