//! Shared test fixtures.
//!
//! Threshold certificates need a dealt DKG output, which is expensive to
//! reproduce and easy to get subtly wrong. Both the follower driver and the
//! `tempo/1` actor need one, so it lives here rather than in either.

use std::iter::repeat_with;

use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf::Scheme,
        types::{Finalization, Finalize, Proposal},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt as dkg,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random as _;
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, TryFromIterator as _, ordered};
use rand_core::CryptoRng;
use tempo_dkg_onchain_artifacts::{
    DkgCeremony, OnchainDkgOutcome, OnchainDkgOutcomeV1, OnchainDkgOutcomeV2,
};

use crate::consensus::Digest;

/// A dealt DKG output together with signers able to form a quorum over it.
pub(crate) struct DkgFixture {
    pub(crate) outcome: OnchainDkgOutcome,
    pub(crate) schemes: Vec<Scheme<PublicKey, MinSig>>,
}

pub(crate) fn dkg_fixture(rng: &mut impl CryptoRng, epoch: Epoch) -> DkgFixture {
    let player_keys = repeat_with(|| PrivateKey::random(&mut *rng))
        .take(4)
        .collect::<Vec<_>>();
    let players = ordered::Set::try_from_iter(
        player_keys
            .iter()
            .map(|private_key| private_key.public_key()),
    )
    .expect("test players should be unique");

    let (output, shares) =
        dkg::deal::<_, _, N3f1>(&mut *rng, Mode::NonZeroCounter, players).expect("test DKG");

    let schemes = shares
        .into_iter()
        .map(|(_, share)| {
            Scheme::signer(
                crate::config::NAMESPACE,
                output.players().clone(),
                output.public().clone(),
                share,
            )
            .expect("test share should match the public polynomial")
        })
        .collect();

    let outcome = OnchainDkgOutcomeV1 {
        epoch: epoch.get(),
        next_ceremony: DkgCeremony {
            players: output.players().clone(),
            is_full_dkg: false,
        },
        output,
    }
    .into();

    DkgFixture { outcome, schemes }
}

/// Returns `outcome` for `epoch` instead.
pub(crate) fn with_epoch(mut outcome: OnchainDkgOutcome, epoch: u64) -> OnchainDkgOutcome {
    match &mut outcome {
        OnchainDkgOutcome::V1(outcome) => outcome.epoch = epoch,
        OnchainDkgOutcome::V2(outcome) => outcome.epoch = epoch,
    }
    outcome
}

/// Returns `outcome` as a TIP-1123 boundary block writes it, without a ceremony.
pub(crate) fn without_ceremony(outcome: &OnchainDkgOutcome) -> OnchainDkgOutcome {
    OnchainDkgOutcomeV2 {
        epoch: outcome.raw_epoch(),
        output: outcome.output().clone(),
    }
    .into()
}

/// Builds a finalization certificate over an arbitrary payload.
pub(crate) fn make_certificate(
    payload: Digest,
    epoch: Epoch,
    view: u64,
    schemes: &[Scheme<PublicKey, MinSig>],
) -> Finalization<Scheme<PublicKey, MinSig>, Digest> {
    let proposal = Proposal::new(Round::new(epoch, View::new(view)), View::zero(), payload);
    let votes = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("signer should sign"))
        .collect::<Vec<_>>();

    Finalization::from_finalizes(
        &schemes[0],
        commonware_utils::non_empty![@&votes],
        &Sequential,
    )
    .expect("all test signers form a quorum")
}
