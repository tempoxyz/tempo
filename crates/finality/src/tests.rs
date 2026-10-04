use std::num::NonZeroU64;

use alloy_consensus::{Header, Sealable as _};
use alloy_primitives::{B256, hex};
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::types::{Notarization, Notarize},
    types::{Epoch, FixedEpocher},
};
use commonware_parallel::Sequential;
use rand::{SeedableRng as _, rngs::StdRng};
use tempo_primitives::TempoHeader;

use crate::{
    CertifiedHeader, Digest, Error, FinalizationVerifier, NetworkIdentity,
    test_utils::{dkg_fixture, make_certificate},
};

const EPOCH_LENGTH: NonZeroU64 = NonZeroU64::new(10).unwrap();

fn fixture() -> (StdRng, FinalizationVerifier, CertifiedHeader) {
    let mut rng = StdRng::seed_from_u64(123);
    let dkg = dkg_fixture(&mut rng, Epoch::zero());
    let verifier = FinalizationVerifier::new(
        NetworkIdentity {
            from_epoch: 0,
            identity: *dkg.outcome.network_identity(),
        },
        FixedEpocher::new(EPOCH_LENGTH),
    );
    let header = TempoHeader {
        inner: Header {
            number: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let digest = header.hash_slow();
    let finalization = make_certificate(Digest(digest), Epoch::zero(), 42, &dkg.schemes);
    (
        rng,
        verifier,
        CertifiedHeader {
            epoch: 0,
            view: 42,
            digest,
            certificate: hex::encode(finalization.encode()),
            header,
        },
    )
}

#[test]
fn real_threshold_finalization_authenticates_canonical_header() {
    let (mut rng, verifier, evidence) = fixture();
    verifier
        .decode_and_verify_header(&mut rng, &evidence)
        .unwrap();
    let json = serde_json::to_string(&evidence).unwrap();
    let decoded = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, decoded);
    verifier
        .decode_and_verify_header(&mut rng, &decoded)
        .unwrap();
}

#[test]
fn altered_tempo_fields_root_and_remote_digest_fail() {
    let (mut rng, verifier, evidence) = fixture();
    for kind in 0..4 {
        let mut changed = evidence.clone();
        match kind {
            0 => changed.header.inner.state_root = B256::with_last_byte(1),
            1 => changed.header.timestamp_millis_part = 123,
            2 => changed.digest = B256::ZERO,
            _ => changed.header.inner.extra_data = vec![1].into(),
        }
        assert!(matches!(
            verifier.decode_and_verify_header(&mut rng, &changed),
            Err(Error::BlockDigestMismatch)
        ));
    }
}

#[test]
fn fork_activated_consensus_context_is_in_the_signed_header_hash() {
    let (mut rng, verifier, mut evidence) = fixture();
    let mut signer_rng = StdRng::seed_from_u64(123);
    let dkg = dkg_fixture(&mut signer_rng, Epoch::zero());
    evidence.header.consensus_context = Some(tempo_primitives::TempoConsensusContext {
        epoch: 0,
        view: 42,
        parent_view: 0,
        proposer: alloy_primitives::b256!(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        .try_into()
        .unwrap(),
    });
    evidence.digest = evidence.header.hash_slow();
    evidence.certificate = hex::encode(
        make_certificate(Digest(evidence.digest), Epoch::zero(), 42, &dkg.schemes).encode(),
    );
    verifier
        .decode_and_verify_header(&mut rng, &evidence)
        .unwrap();
    evidence.header.consensus_context.as_mut().unwrap().view += 1;
    assert!(matches!(
        verifier.decode_and_verify_header(&mut rng, &evidence),
        Err(Error::BlockDigestMismatch)
    ));
}

#[test]
fn metadata_and_epoch_binding_are_checked() {
    let (mut rng, verifier, mut evidence) = fixture();
    evidence.epoch = 1;
    assert!(matches!(
        verifier.decode_and_verify_header(&mut rng, &evidence),
        Err(Error::MetadataMismatch)
    ));
    evidence.epoch = 0;
    evidence.view += 1;
    assert!(matches!(
        verifier.decode_and_verify_header(&mut rng, &evidence),
        Err(Error::MetadataMismatch)
    ));

    let mut rng = StdRng::seed_from_u64(123);
    let dkg = dkg_fixture(&mut rng, Epoch::zero());
    evidence.header.inner.number = 10;
    evidence.digest = evidence.header.hash_slow();
    evidence.view = 42;
    evidence.certificate = hex::encode(
        make_certificate(Digest(evidence.digest), Epoch::zero(), 42, &dkg.schemes).encode(),
    );
    assert!(matches!(
        verifier.decode_and_verify_header(&mut rng, &evidence),
        Err(Error::EpochMismatch {
            height: 10,
            expected: 1,
            actual: 0
        })
    ));
}

#[test]
fn notarizations_truncation_trailing_bytes_and_substituted_identity_fail() {
    let (mut rng, verifier, evidence) = fixture();
    let dkg = dkg_fixture(&mut rng, Epoch::zero());
    let proposal =
        make_certificate(Digest(evidence.digest), Epoch::zero(), 42, &dkg.schemes).proposal;
    let votes = dkg
        .schemes
        .iter()
        .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
        .collect::<Vec<_>>();
    let notarization = Notarization::from_notarizes(
        &dkg.schemes[0],
        commonware_utils::non_empty![@&votes],
        &Sequential,
    )
    .unwrap();
    let mut changed = evidence.clone();
    changed.certificate = hex::encode(notarization.encode());
    assert!(
        verifier
            .decode_and_verify_header(&mut rng, &changed)
            .is_err()
    );
    changed.certificate = evidence.certificate[..20].to_owned();
    assert!(matches!(
        verifier.decode_and_verify_header(&mut rng, &changed),
        Err(Error::MalformedCertificate(_))
    ));
    changed.certificate = format!("{}00", evidence.certificate);
    assert!(matches!(
        verifier.decode_and_verify_header(&mut rng, &changed),
        Err(Error::MalformedCertificate(_))
    ));
    let other = FinalizationVerifier::new(
        NetworkIdentity {
            from_epoch: 0,
            identity: *dkg.outcome.network_identity(),
        },
        FixedEpocher::new(EPOCH_LENGTH),
    );
    assert!(other.decode_and_verify_header(&mut rng, &evidence).is_err());
}

#[test]
fn authenticated_boundary_installs_rotated_identity() {
    let (mut rng, verifier, _) = fixture();
    let current = {
        let mut rng = StdRng::seed_from_u64(123);
        dkg_fixture(&mut rng, Epoch::zero())
    };
    let next = dkg_fixture(&mut rng, Epoch::new(1));
    let header = TempoHeader {
        inner: Header {
            number: 9,
            extra_data: next.outcome.encode().into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let digest = header.hash_slow();
    let evidence = CertifiedHeader {
        epoch: 0,
        view: 9,
        digest,
        certificate: hex::encode(
            make_certificate(Digest(digest), Epoch::zero(), 9, &current.schemes).encode(),
        ),
        header,
    };
    verifier
        .decode_and_verify_header(&mut rng, &evidence)
        .unwrap();
    verifier
        .decode_dkg_outcome_and_register_boundary(&evidence.header.inner.extra_data)
        .unwrap();
    let header = TempoHeader {
        inner: Header {
            number: 10,
            ..Default::default()
        },
        ..Default::default()
    };
    let digest = header.hash_slow();
    let evidence = CertifiedHeader {
        epoch: 1,
        view: 10,
        digest,
        certificate: hex::encode(
            make_certificate(Digest(digest), Epoch::new(1), 10, &next.schemes).encode(),
        ),
        header,
    };
    verifier
        .decode_and_verify_header(&mut rng, &evidence)
        .unwrap();
}
