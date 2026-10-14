//! Derives upcoming leaders from consensus certificates.
//!
//! Validators broadcast their certificates to every connected peer, operators
//! included. The leader of view `v + 1` is elected from the VRF seed carried by
//! any certificate of view `v`: notarization, nullification and finalization
//! of a view sign the same seed. An operator that verifies the certificate
//! knows the next leader as early as the validators do.

use commonware_codec::Read as _;
use commonware_consensus::{
    Epochable as _, Viewable as _,
    simplex::{
        elector::{Config as _, Elector as _, Random, RandomElector, RandomVersion},
        scheme::bls12381_threshold::vrf::Scheme,
        types,
    },
    types::{Epoch, Round},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_parallel::Sequential;
use commonware_runtime::IoBuf;
use commonware_utils::ordered;
use rand_core::CryptoRng;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

use crate::consensus::Digest;

/// A consensus certificate as sent on the certificates channel.
pub type Certificate = types::Certificate<Scheme<PublicKey, MinSig>, Digest>;

/// Decodes a message received on the consensus certificates channel.
///
/// The channel is multiplexed by epoch; a certificate whose epoch disagrees
/// with its subchannel is rejected.
pub fn decode_certificate(message: IoBuf) -> Option<Certificate> {
    let (subchannel, mut payload) = commonware_p2p::utils::mux::parse(message).ok()?;
    let certificate = Certificate::read_cfg(&mut payload, &()).ok()?;
    (certificate.epoch().get() == subchannel).then_some(certificate)
}

/// Elects the leaders of one epoch.
pub struct EpochLeaders {
    epoch: Epoch,
    participants: ordered::Set<PublicKey>,
    scheme: Scheme<PublicKey, MinSig>,
    elector: RandomElector<Scheme<PublicKey, MinSig>, Sha256>,
}

impl EpochLeaders {
    /// Builds the elector of the epoch whose DKG outcome is `outcome`.
    ///
    /// `outcome` is read from the `extraData` of the epoch's boundary block
    /// (the last block of the previous epoch, or genesis). `t12` is whether
    /// T12 is active at that block's timestamp: it selects the elector
    /// version, as in the epoch manager.
    pub fn new(outcome: &OnchainDkgOutcome, t12: bool) -> Self {
        let participants = outcome.players().clone();
        #[expect(deprecated, reason = "retain the pre-T12 leader schedule")]
        let version = if t12 {
            RandomVersion::V1
        } else {
            RandomVersion::V0
        };
        Self {
            epoch: outcome.epoch(),
            scheme: Scheme::verifier(
                crate::config::NAMESPACE,
                participants.clone(),
                outcome.sharing().clone(),
            ),
            elector: Random::<Sha256>::new(version).build(&participants),
            participants,
        }
    }

    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Verifies `certificate` and returns the round after it with its leader.
    ///
    /// Returns `None` for certificates of other epochs or with invalid
    /// signatures.
    pub fn next_leader(
        &self,
        rng: &mut impl CryptoRng,
        certificate: &Certificate,
    ) -> Option<(Round, PublicKey)> {
        if certificate.epoch() != self.epoch || !certificate.verify(rng, &self.scheme, &Sequential)
        {
            return None;
        }
        let seed = match certificate {
            types::Certificate::Notarization(notarization) => &notarization.certificate,
            types::Certificate::Nullification(nullification) => &nullification.certificate,
            types::Certificate::Finalization(finalization) => &finalization.certificate,
        };
        let round = Round::new(self.epoch, certificate.view().next());
        let leader = self.elector.elect(round, Some(seed));
        Some((round, self.participants.get(leader.get() as usize)?.clone()))
    }
}

#[cfg(test)]
mod tests {
    use commonware_codec::{Encode as _, Write as _, varint::UInt};
    use commonware_consensus::{
        simplex::types::{Notarization, Notarize, Proposal},
        types::View,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::IoBuf;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::test_utils::{dkg_fixture, make_certificate};

    fn framed(certificate: &Certificate, subchannel: u64) -> IoBuf {
        let mut buf = Vec::new();
        UInt(subchannel).write(&mut buf);
        buf.extend_from_slice(&certificate.encode());
        IoBuf::from(buf)
    }

    #[test]
    fn every_certificate_of_a_view_elects_the_same_next_leader() {
        let mut rng = StdRng::seed_from_u64(0);
        let epoch = Epoch::new(3);
        let fixture = dkg_fixture(&mut rng, epoch);
        let leaders = EpochLeaders::new(&fixture.outcome, true);
        let payload = Digest(alloy_primitives::B256::repeat_byte(1));

        let finalization =
            Certificate::Finalization(make_certificate(payload, epoch, 7, &fixture.schemes));
        let proposal = Proposal::new(Round::new(epoch, View::new(7)), View::new(6), payload);
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization = Certificate::Notarization(
            Notarization::from_notarizes(
                &fixture.schemes[0],
                commonware_utils::non_empty![@&notarizes],
                &Sequential,
            )
            .unwrap(),
        );

        let decoded = decode_certificate(framed(&finalization, 3)).unwrap();
        let (round, leader) = leaders.next_leader(&mut rng, &decoded).unwrap();
        assert_eq!(round, Round::new(epoch, View::new(8)));
        assert!(fixture.outcome.players().position(&leader).is_some());
        assert_eq!(
            leaders.next_leader(&mut rng, &notarization),
            Some((round, leader))
        );

        // The subchannel must match the certificate's epoch.
        assert!(decode_certificate(framed(&finalization, 4)).is_none());
    }

    #[test]
    fn rejects_certificates_of_another_dkg() {
        let mut rng = StdRng::seed_from_u64(1);
        let epoch = Epoch::new(3);
        let ours = dkg_fixture(&mut rng, epoch);
        let theirs = dkg_fixture(&mut rng, epoch);
        let leaders = EpochLeaders::new(&ours.outcome, true);
        let payload = Digest(alloy_primitives::B256::repeat_byte(1));

        let forged =
            Certificate::Finalization(make_certificate(payload, epoch, 7, &theirs.schemes));
        assert_eq!(leaders.next_leader(&mut rng, &forged), None);

        let other_epoch =
            Certificate::Finalization(make_certificate(payload, Epoch::new(4), 7, &ours.schemes));
        assert_eq!(leaders.next_leader(&mut rng, &other_epoch), None);
    }
}
