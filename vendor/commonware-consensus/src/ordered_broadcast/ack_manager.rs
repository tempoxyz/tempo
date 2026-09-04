use super::types::Ack;
use crate::types::{Epoch, Height, Participant};
use commonware_cryptography::{
    certificate::{Attestation, Scheme},
    Digest, PublicKey,
};
use commonware_parallel::Strategy;
use commonware_utils::N3f1;
use std::collections::{BTreeMap, HashMap, HashSet};

/// A struct representing a set of votes for a payload digest.
#[derive(Default)]
struct Partials<S: Scheme, D: Digest> {
    // The set of signer indices that have voted for the payload.
    pub signers: HashSet<Participant>,

    // A map from payload digest to attestations.
    // Each signer should only vote once for each sequencer/height/epoch.
    pub attestations: HashMap<D, Vec<Attestation<S>>>,
}

/// Evidence for a chunk.
/// This is either a set of votes or a certificate.
enum Evidence<S: Scheme, D: Digest> {
    Partials(Partials<S, D>),
    Certificate(S::Certificate),
}

impl<S: Scheme, D: Digest> Default for Evidence<S, D> {
    fn default() -> Self {
        Self::Partials(Partials {
            signers: HashSet::new(),
            attestations: HashMap::new(),
        })
    }
}

/// Manages acknowledgements for chunks.
#[derive(Default)]
pub struct AckManager<P: PublicKey, S: Scheme, D: Digest> {
    // Acknowledgements for digests.
    //
    // Map from Sequencer => Height => Epoch => Evidence
    //
    // Evidence may be votes or certificates.
    //
    // The BTreeMaps are sorted by key, so we can prune old entries. In particular, we can prune
    // entries where the height is less than the height of the highest chunk for the sequencer.
    // We can often prune entries for old epochs as well.
    #[allow(clippy::type_complexity)]
    acks: HashMap<P, BTreeMap<Height, BTreeMap<Epoch, Evidence<S, D>>>>,
}

impl<P: PublicKey, S: Scheme, D: Digest> AckManager<P, S, D> {
    /// Creates a new `AckManager`.
    pub fn new() -> Self {
        Self {
            acks: HashMap::new(),
        }
    }

    /// Adds a vote to the evidence.
    ///
    /// If-and-only-if the quorum is newly-reached, the certificate is returned.
    pub fn add_ack(
        &mut self,
        ack: &Ack<P, S, D>,
        scheme: &S,
        strategy: &impl Strategy,
    ) -> Option<S::Certificate> {
        let evidence = self
            .acks
            .entry(ack.chunk.sequencer.clone())
            .or_default()
            .entry(ack.chunk.height)
            .or_default()
            .entry(ack.epoch)
            .or_default();

        match evidence {
            Evidence::Certificate(_) => None,
            Evidence::Partials(p) => {
                if !p.signers.insert(ack.attestation.signer) {
                    // Validator already signed
                    return None;
                }

                // Add the vote
                let attestations = p.attestations.entry(ack.chunk.payload).or_default();
                attestations.push(ack.attestation.clone());

                // Try to assemble certificate
                let certificate =
                    scheme.assemble::<_, N3f1>(attestations.iter().cloned(), strategy)?;

                // Take ownership of the votes, which must exist
                p.attestations.remove(&ack.chunk.payload);

                Some(certificate)
            }
        }
    }

    /// Returns a tuple of (Epoch, Certificate), if it exists, for the given sequencer and height.
    ///
    /// If multiple epochs have certificates, the highest epoch is returned.
    pub fn get_certificate(
        &self,
        sequencer: &P,
        height: Height,
    ) -> Option<(Epoch, &S::Certificate)> {
        self.acks
            .get(sequencer)
            .and_then(|m| m.get(&height))
            .and_then(|m| {
                // Reverse iterator to get the highest epoch first
                m.iter().rev().find_map(|(epoch, evidence)| match evidence {
                    Evidence::Certificate(c) => Some((*epoch, c)),
                    _ => None,
                })
            })
    }

    /// Sets the certificate for the given sequencer, height, and epoch.
    /// Returns `true` if the certificate was newly set, `false` if it already existed.
    pub fn add_certificate(
        &mut self,
        sequencer: &P,
        height: Height,
        epoch: Epoch,
        certificate: S::Certificate,
    ) -> bool {
        // Set the certificate.
        // If the certificate already existed, return false
        if let Some(Evidence::Certificate(_)) = self
            .acks
            .entry(sequencer.clone())
            .or_default()
            .entry(height)
            .or_default()
            .insert(epoch, Evidence::Certificate(certificate))
        {
            return false;
        }

        // Prune all entries with height less than the parent
        //
        // This approach ensures we don't accidentally notify the application of a certificate multiple
        // times (which could otherwise occur if we recover the certificate for some chunk at tip and then
        // receive a duplicate broadcast of said chunk before a sequencer sends one at a new height).
        if let Some(m) = self.acks.get_mut(sequencer) {
            let min_height = height.previous().unwrap_or(Height::zero());
            m.retain(|&h, _| h >= min_height);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ordered_broadcast::{
        scheme::{bls12381_multisig, bls12381_threshold, ed25519, secp256r1, Scheme},
        types::Chunk,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        Hasher, Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, TestRng};
    use helpers::Sha256Digest;

    const NAMESPACE: &[u8] = b"1234";

    /// Aggregated helper functions to reduce duplication in tests.
    mod helpers {
        use super::*;
        use crate::ordered_broadcast::types::{AckSubject, Chunk};
        use commonware_cryptography::Hasher;

        pub type Sha256Digest = <Sha256 as Hasher>::Digest;

        /// Create an Ack by signing with the provided scheme.
        pub fn create_ack<S>(
            scheme: &S,
            chunk: Chunk<PublicKey, <Sha256 as Hasher>::Digest>,
            epoch: Epoch,
        ) -> Ack<PublicKey, S, <Sha256 as Hasher>::Digest>
        where
            S: Scheme<PublicKey, Sha256Digest>,
        {
            let context = AckSubject {
                chunk: &chunk,
                epoch,
            };
            let attestation = scheme
                .sign::<Sha256Digest>(context)
                .expect("Failed to sign vote");
            Ack {
                chunk,
                epoch,
                attestation,
            }
        }

        /// Create a vector of acks for the given scheme indices.
        pub fn create_acks_for_indices<S>(
            schemes: &[S],
            chunk: Chunk<PublicKey, <Sha256 as Hasher>::Digest>,
            epoch: Epoch,
            indices: &[usize],
        ) -> Vec<Ack<PublicKey, S, <Sha256 as Hasher>::Digest>>
        where
            S: Scheme<PublicKey, Sha256Digest>,
        {
            indices
                .iter()
                .map(|&i| create_ack(&schemes[i], chunk.clone(), epoch))
                .collect()
        }

        /// Add acks (generated from the provided scheme indices) to the manager.
        /// Returns the certificate if produced.
        pub fn add_acks_for_indices<S>(
            manager: &mut AckManager<PublicKey, S, <Sha256 as Hasher>::Digest>,
            schemes: &[S],
            chunk: Chunk<PublicKey, <Sha256 as Hasher>::Digest>,
            epoch: Epoch,
            indices: &[usize],
        ) -> Option<S::Certificate>
        where
            S: Scheme<PublicKey, Sha256Digest>,
        {
            let acks = create_acks_for_indices(schemes, chunk, epoch, indices);
            let mut certificate = None;
            for ack in acks {
                if let Some(cert) = manager.add_ack(&ack, &schemes[0], &Sequential) {
                    certificate = Some(cert);
                }
            }
            certificate
        }
    }

    /// Different payloads for the same chunk produce distinct certificates.
    fn chunk_different_payloads<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        // Use 8 validators so quorum is 6
        let num_validators = 8;
        let fixture = fixture(&mut test_rng(), NAMESPACE, num_validators);
        let mut acks = AckManager::<PublicKey, S, <Sha256 as Hasher>::Digest>::new();
        let sequencer = fixture.participants[1].clone();
        let height = Height::new(10);

        // Use different epochs so validators can vote for both chunks
        let epoch1 = Epoch::new(5);
        let epoch2 = Epoch::new(6);

        let chunk1 = Chunk::new(sequencer.clone(), height, Sha256::hash(b"payload1"));
        let chunk2 = Chunk::new(sequencer, height, Sha256::hash(b"payload2"));

        let cert1 = helpers::add_acks_for_indices(
            &mut acks,
            &fixture.schemes,
            chunk1,
            epoch1,
            &[0, 1, 2, 3, 4, 5],
        );
        let cert2 = helpers::add_acks_for_indices(
            &mut acks,
            &fixture.schemes,
            chunk2,
            epoch2,
            &[0, 1, 2, 3, 4, 5],
        );

        let c1 = cert1.expect("Expected certificate for payload1");
        let c2 = cert2.expect("Expected certificate for payload2");
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_chunk_different_payloads() {
        chunk_different_payloads(ed25519::fixture);
        chunk_different_payloads(secp256r1::fixture);
        chunk_different_payloads(bls12381_multisig::fixture::<MinPk, _>);
        chunk_different_payloads(bls12381_multisig::fixture::<MinSig, _>);
        chunk_different_payloads(bls12381_threshold::fixture::<MinPk, _>);
        chunk_different_payloads(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Adding certificates for different heights prunes older entries.
    fn sequencer_different_heights<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let fixture = fixture(&mut test_rng(), NAMESPACE, num_validators);
        let mut acks = AckManager::<PublicKey, S, <Sha256 as Hasher>::Digest>::new();
        let sequencer = fixture.participants[1].clone();
        let epoch = Epoch::new(10);
        let height1 = Height::new(10);
        let height2 = Height::new(20);

        let chunk1 = Chunk::new(sequencer.clone(), height1, Sha256::hash(b"chunk1"));
        let cert1 =
            helpers::add_acks_for_indices(&mut acks, &fixture.schemes, chunk1, epoch, &[0, 1, 2])
                .expect("Should produce certificate");
        assert!(acks.add_certificate(&sequencer, height1, epoch, cert1.clone()));
        assert_eq!(
            acks.get_certificate(&sequencer, height1),
            Some((epoch, &cert1))
        );

        let chunk2 = Chunk::new(sequencer.clone(), height2, Sha256::hash(b"chunk2"));
        let cert2 =
            helpers::add_acks_for_indices(&mut acks, &fixture.schemes, chunk2, epoch, &[0, 1, 2])
                .expect("Should produce certificate");
        assert!(acks.add_certificate(&sequencer, height2, epoch, cert2.clone()));

        assert_eq!(acks.get_certificate(&sequencer, height1), None);
        assert_eq!(
            acks.get_certificate(&sequencer, height2),
            Some((epoch, &cert2))
        );
    }

    #[test]
    fn test_sequencer_different_heights() {
        sequencer_different_heights(ed25519::fixture);
        sequencer_different_heights(secp256r1::fixture);
        sequencer_different_heights(bls12381_multisig::fixture::<MinPk, _>);
        sequencer_different_heights(bls12381_multisig::fixture::<MinSig, _>);
        sequencer_different_heights(bls12381_threshold::fixture::<MinPk, _>);
        sequencer_different_heights(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Adding certificates for contiguous heights prunes entries older than the immediate parent.
    fn sequencer_contiguous_heights<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let fixture = fixture(&mut test_rng(), NAMESPACE, num_validators);
        let mut acks = AckManager::<PublicKey, S, <Sha256 as Hasher>::Digest>::new();
        let sequencer = fixture.participants[1].clone();
        let epoch = Epoch::new(10);

        let chunk1 = Chunk::new(sequencer.clone(), Height::new(10), Sha256::hash(b"chunk1"));
        let cert1 =
            helpers::add_acks_for_indices(&mut acks, &fixture.schemes, chunk1, epoch, &[0, 1, 2])
                .expect("Should produce certificate");
        assert!(acks.add_certificate(&sequencer, Height::new(10), epoch, cert1.clone()));
        assert_eq!(
            acks.get_certificate(&sequencer, Height::new(10)),
            Some((epoch, &cert1))
        );

        let chunk2 = Chunk::new(sequencer.clone(), Height::new(11), Sha256::hash(b"chunk2"));
        let cert2 =
            helpers::add_acks_for_indices(&mut acks, &fixture.schemes, chunk2, epoch, &[0, 1, 2])
                .expect("Should produce certificate");
        assert!(acks.add_certificate(&sequencer, Height::new(11), epoch, cert2.clone()));

        assert_eq!(
            acks.get_certificate(&sequencer, Height::new(10)),
            Some((epoch, &cert1))
        );
        assert_eq!(
            acks.get_certificate(&sequencer, Height::new(11)),
            Some((epoch, &cert2))
        );

        let chunk3 = Chunk::new(sequencer.clone(), Height::new(12), Sha256::hash(b"chunk3"));
        let cert3 =
            helpers::add_acks_for_indices(&mut acks, &fixture.schemes, chunk3, epoch, &[0, 1, 2])
                .expect("Should produce certificate");
        assert!(acks.add_certificate(&sequencer, Height::new(12), epoch, cert3.clone()));

        assert_eq!(acks.get_certificate(&sequencer, Height::new(10)), None);
        assert_eq!(
            acks.get_certificate(&sequencer, Height::new(11)),
            Some((epoch, &cert2))
        );
        assert_eq!(
            acks.get_certificate(&sequencer, Height::new(12)),
            Some((epoch, &cert3))
        );
    }

    #[test]
    fn test_sequencer_contiguous_heights() {
        sequencer_contiguous_heights(ed25519::fixture);
        sequencer_contiguous_heights(secp256r1::fixture);
        sequencer_contiguous_heights(bls12381_multisig::fixture::<MinPk, _>);
        sequencer_contiguous_heights(bls12381_multisig::fixture::<MinSig, _>);
        sequencer_contiguous_heights(bls12381_threshold::fixture::<MinPk, _>);
        sequencer_contiguous_heights(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// For the same sequencer and height, the highest epoch's certificate is returned.
    fn chunk_different_epochs<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let fixture = fixture(&mut test_rng(), NAMESPACE, num_validators);
        let mut acks = AckManager::<PublicKey, S, <Sha256 as Hasher>::Digest>::new();
        let sequencer = fixture.participants[1].clone();
        let height = Height::new(30);
        let epoch1 = Epoch::new(1);
        let epoch2 = Epoch::new(2);

        let chunk = Chunk::new(sequencer.clone(), height, Sha256::hash(b"chunk"));

        let cert1 = helpers::add_acks_for_indices(
            &mut acks,
            &fixture.schemes,
            chunk.clone(),
            epoch1,
            &[0, 1, 2],
        )
        .expect("Should produce certificate");
        assert!(acks.add_certificate(&sequencer, height, epoch1, cert1));

        let cert2 =
            helpers::add_acks_for_indices(&mut acks, &fixture.schemes, chunk, epoch2, &[0, 1, 2])
                .expect("Should produce certificate");
        assert!(acks.add_certificate(&sequencer, height, epoch2, cert2.clone()));

        assert_eq!(
            acks.get_certificate(&sequencer, height),
            Some((epoch2, &cert2))
        );
    }

    #[test]
    fn test_chunk_different_epochs() {
        chunk_different_epochs(ed25519::fixture);
        chunk_different_epochs(secp256r1::fixture);
        chunk_different_epochs(bls12381_multisig::fixture::<MinPk, _>);
        chunk_different_epochs(bls12381_multisig::fixture::<MinSig, _>);
        chunk_different_epochs(bls12381_threshold::fixture::<MinPk, _>);
        chunk_different_epochs(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Adding the same certificate twice returns false.
    fn add_certificate<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let fixture = fixture(&mut test_rng(), NAMESPACE, num_validators);
        let mut acks = AckManager::<PublicKey, S, <Sha256 as Hasher>::Digest>::new();
        let epoch = Epoch::new(99);
        let sequencer = fixture.participants[1].clone();
        let height = Height::new(42);
        let chunk = Chunk::new(sequencer.clone(), height, Sha256::hash(&sequencer));

        let cert =
            helpers::add_acks_for_indices(&mut acks, &fixture.schemes, chunk, epoch, &[0, 1, 2])
                .expect("Should produce certificate");

        assert_eq!(acks.get_certificate(&sequencer, height), None);
        assert!(acks.add_certificate(&sequencer, height, epoch, cert.clone()));
        assert_eq!(
            acks.get_certificate(&sequencer, height),
            Some((epoch, &cert))
        );
        assert!(!acks.add_certificate(&sequencer, height, epoch, cert.clone()));
        assert_eq!(
            acks.get_certificate(&sequencer, height),
            Some((epoch, &cert))
        );
    }

    #[test]
    fn test_add_certificate() {
        add_certificate(ed25519::fixture);
        add_certificate(secp256r1::fixture);
        add_certificate(bls12381_multisig::fixture::<MinPk, _>);
        add_certificate(bls12381_multisig::fixture::<MinSig, _>);
        add_certificate(bls12381_threshold::fixture::<MinPk, _>);
        add_certificate(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Duplicate attestation submissions are ignored.
    fn duplicate_attestation_submission<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let fixture = fixture(&mut test_rng(), NAMESPACE, num_validators);
        let mut acks = AckManager::<PublicKey, S, <Sha256 as Hasher>::Digest>::new();
        let sequencer = fixture.participants[1].clone();
        let epoch = Epoch::new(1);
        let height = Height::new(10);
        let chunk = Chunk::new(sequencer, height, Sha256::hash(b"payload"));

        let ack = helpers::create_ack(&fixture.schemes[0], chunk, epoch);
        assert!(acks
            .add_ack(&ack, &fixture.schemes[0], &Sequential)
            .is_none());
        assert!(acks
            .add_ack(&ack, &fixture.schemes[0], &Sequential)
            .is_none());
    }

    #[test]
    fn test_duplicate_attestation_submission() {
        duplicate_attestation_submission(ed25519::fixture);
        duplicate_attestation_submission(secp256r1::fixture);
        duplicate_attestation_submission(bls12381_multisig::fixture::<MinPk, _>);
        duplicate_attestation_submission(bls12381_multisig::fixture::<MinSig, _>);
        duplicate_attestation_submission(bls12381_threshold::fixture::<MinPk, _>);
        duplicate_attestation_submission(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Once a certificate is reached, further acks are ignored.
    fn subsequent_acks_after_certificate_reached<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let fixture = fixture(&mut test_rng(), NAMESPACE, num_validators);
        let mut acks = AckManager::<PublicKey, S, <Sha256 as Hasher>::Digest>::new();
        let sequencer = fixture.participants[1].clone();
        let epoch = Epoch::new(1);
        let height = Height::new(10);
        let chunk = Chunk::new(sequencer, height, Sha256::hash(b"payload"));

        let acks_vec =
            helpers::create_acks_for_indices(&fixture.schemes, chunk.clone(), epoch, &[0, 1, 2]);
        let mut produced = None;
        for ack in acks_vec {
            if let Some(cert) = acks.add_ack(&ack, &fixture.schemes[0], &Sequential) {
                produced = Some(cert);
            }
        }
        assert!(produced.is_some());

        let ack = helpers::create_ack(&fixture.schemes[3], chunk, epoch);
        assert!(acks
            .add_ack(&ack, &fixture.schemes[0], &Sequential)
            .is_none());
    }

    #[test]
    fn test_subsequent_acks_after_certificate_reached() {
        subsequent_acks_after_certificate_reached(ed25519::fixture);
        subsequent_acks_after_certificate_reached(secp256r1::fixture);
        subsequent_acks_after_certificate_reached(bls12381_multisig::fixture::<MinPk, _>);
        subsequent_acks_after_certificate_reached(bls12381_multisig::fixture::<MinSig, _>);
        subsequent_acks_after_certificate_reached(bls12381_threshold::fixture::<MinPk, _>);
        subsequent_acks_after_certificate_reached(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Acks for different sequencers are managed separately.
    fn multiple_sequencers<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let fixture = fixture(&mut test_rng(), NAMESPACE, num_validators);
        let mut acks = AckManager::<PublicKey, S, <Sha256 as Hasher>::Digest>::new();

        let sequencer1 = fixture.participants[1].clone();
        let sequencer2 = fixture.participants[3].clone();
        let epoch = Epoch::new(1);
        let height = Height::new(10);

        let chunk1 = Chunk::new(sequencer1.clone(), height, Sha256::hash(b"payload1"));
        let chunk2 = Chunk::new(sequencer2.clone(), height, Sha256::hash(b"payload2"));

        let cert1 =
            helpers::add_acks_for_indices(&mut acks, &fixture.schemes, chunk1, epoch, &[0, 1, 2])
                .expect("Should produce certificate");
        let cert2 =
            helpers::add_acks_for_indices(&mut acks, &fixture.schemes, chunk2, epoch, &[0, 1, 2])
                .expect("Should produce certificate");

        assert_ne!(cert1, cert2);
        assert!(acks.add_certificate(&sequencer1, height, epoch, cert1));
        assert!(acks.add_certificate(&sequencer2, height, epoch, cert2));
    }

    #[test]
    fn test_multiple_sequencers() {
        multiple_sequencers(ed25519::fixture);
        multiple_sequencers(secp256r1::fixture);
        multiple_sequencers(bls12381_multisig::fixture::<MinPk, _>);
        multiple_sequencers(bls12381_multisig::fixture::<MinSig, _>);
        multiple_sequencers(bls12381_threshold::fixture::<MinPk, _>);
        multiple_sequencers(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// If quorum is never reached, no certificate is produced.
    fn incomplete_quorum<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let fixture = fixture(&mut test_rng(), NAMESPACE, num_validators);
        let mut acks = AckManager::<PublicKey, S, <Sha256 as Hasher>::Digest>::new();
        let sequencer = fixture.participants[1].clone();
        let epoch = Epoch::new(1);
        let height = Height::new(10);
        let chunk = Chunk::new(sequencer.clone(), height, Sha256::hash(b"payload"));

        let acks_vec = helpers::create_acks_for_indices(&fixture.schemes, chunk, epoch, &[0, 1]);
        for ack in acks_vec {
            assert!(acks
                .add_ack(&ack, &fixture.schemes[0], &Sequential)
                .is_none());
        }
        assert_eq!(acks.get_certificate(&sequencer, height), None);
    }

    #[test]
    fn test_incomplete_quorum() {
        incomplete_quorum(ed25519::fixture);
        incomplete_quorum(secp256r1::fixture);
        incomplete_quorum(bls12381_multisig::fixture::<MinPk, _>);
        incomplete_quorum(bls12381_multisig::fixture::<MinSig, _>);
        incomplete_quorum(bls12381_threshold::fixture::<MinPk, _>);
        incomplete_quorum(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Interleaved acks for different payloads are aggregated separately.
    fn interleaved_payloads<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        // Use 20 validators so quorum is 14
        // We'll have validators [0-13] vote for payload1 and [6-19] vote for payload2
        // This gives us overlapping sets but each reaches quorum
        let num_validators = 20;
        let fixture = fixture(&mut test_rng(), NAMESPACE, num_validators);
        let mut acks = AckManager::<PublicKey, S, <Sha256 as Hasher>::Digest>::new();
        let sequencer = fixture.participants[1].clone();
        let epoch = Epoch::new(1);
        let height = Height::new(10);

        let payload1 = Sha256::hash(b"payload1");
        let payload2 = Sha256::hash(b"payload2");

        let chunk1 = Chunk::new(sequencer.clone(), height, payload1);
        let chunk2 = Chunk::new(sequencer, height, payload2);

        // Interleave submissions to show they're tracked separately
        let mut certificates = Vec::new();

        // Add acks in interleaved fashion
        for i in 0..14 {
            // Add payload1 ack
            let ack1 = helpers::create_ack(&fixture.schemes[i], chunk1.clone(), epoch);
            if let Some(cert) = acks.add_ack(&ack1, &fixture.schemes[0], &Sequential) {
                certificates.push((chunk1.payload, cert));
            }

            // Add payload2 ack (from validators 6-19)
            if i + 6 < 20 {
                let ack2 = helpers::create_ack(&fixture.schemes[i + 6], chunk2.clone(), epoch);
                if let Some(cert) = acks.add_ack(&ack2, &fixture.schemes[0], &Sequential) {
                    certificates.push((chunk2.payload, cert));
                }
            }
        }

        assert!(!certificates.is_empty());
        for (p, _) in certificates {
            assert!(p == payload1 || p == payload2);
        }
    }

    #[test]
    fn test_interleaved_payloads() {
        interleaved_payloads(ed25519::fixture);
        interleaved_payloads(secp256r1::fixture);
        interleaved_payloads(bls12381_multisig::fixture::<MinPk, _>);
        interleaved_payloads(bls12381_multisig::fixture::<MinSig, _>);
        interleaved_payloads(bls12381_threshold::fixture::<MinPk, _>);
        interleaved_payloads(bls12381_threshold::fixture::<MinSig, _>);
    }
}
