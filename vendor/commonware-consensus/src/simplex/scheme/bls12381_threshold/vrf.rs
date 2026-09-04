//! BLS12-381 threshold VRF implementation of the [`Scheme`] trait for `simplex`.
//!
//! Certificates contain a vote signature and a round signature (a seed that can be used
//! as a VRF).
//!
//! # Using the VRF
//!
//! A malicious leader (colluding with at least 1 Byzantine validator) can observe the output of the
//! VRF before deciding whether to publish their block to all participants (they uniquely see `2f` other
//! partial signatures and can recover the seed by combining their own partial signature). As a result,
//! it is **not safe** to use a round's randomness to affect execution in that same round (as the leader can
//! bias execution to their advantage by deciding whether or not to publish their block).
//!
//! Applications that want to incorporate this embedded VRF into execution should employ a "commit-then-reveal" pattern
//! and require users to bind to the output of randomness in advance (i.e. `draw(view+k)` means execution uses VRF output
//! `k` views later). The larger `k`, the more likely that the transaction is finalized before the randomness is revealed (recall, Simplex
//! is streamlined). The safest approach (if you're willing to wait) is to bound the outcome to a future epoch (which ensures a
//! transaction is finalized before the VRF it relies on is revealed).
//!
//! _For applications willing to accept additional overhead, a more robust (and instant) VRF can be implemented
//! by requiring validators to emit their contribution to the seed for some height `h` only after they have observed `h` is finalized.
//! This permits transactions to use the VRF output immediately but requires an extra message broadcast per finalized height._
//!
//! # Non-Attributable Signatures
//!
//! [`Scheme`] is **non-attributable**: exposing partial signatures as evidence of
//! either liveness or of committing a fault is not safe. With threshold signatures,
//! any `t` valid partial signatures can be used to forge a partial signature for any
//! other player, enabling equivocation attacks. Because peer connections are
//! authenticated, evidence can be used locally (as it must be sent by said participant)
//! but can't be used by an external observer.

#[commonware_macros::stability(ALPHA)]
use crate::simplex::scheme::seed_namespace;
use crate::{
    simplex::{
        scheme::Namespace,
        types::{Finalization, Notarization, Subject},
    },
    types::{Epoch, Participant, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    types::lazy::Lazy, Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write,
};
#[commonware_macros::stability(ALPHA)]
use commonware_cryptography::bls12381::tle;
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        ops::{self, batch, threshold},
        sharing::Sharing,
        variant::{PartialSignature, Variant},
    },
    certificate::{self, Attestation, Subject as CertificateSubject, Verification},
    Digest, PublicKey,
};
use commonware_macros::stability;
use commonware_parallel::Strategy;
use commonware_utils::{ordered::Set, Faults};
use rand::rngs::StdRng;
use rand_core::{CryptoRng, SeedableRng};
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
};

/// The role-specific data for a BLS12-381 threshold scheme participant.
#[derive(Clone, Debug)]
enum Role<P: PublicKey, V: Variant> {
    Signer {
        /// Participants in the committee.
        participants: Set<P>,
        /// The public polynomial, used for the group identity, and partial signatures.
        polynomial: Sharing<V>,
        /// Local share used to generate partial signatures.
        share: Share,
        /// Pre-computed namespaces for domain separation.
        namespace: Namespace,
    },
    Verifier {
        /// Participants in the committee.
        participants: Set<P>,
        /// The public polynomial, used for the group identity, and partial signatures.
        polynomial: Sharing<V>,
        /// Pre-computed namespaces for domain separation.
        namespace: Namespace,
    },
    CertificateVerifier {
        /// Public identity of the committee (constant across reshares).
        identity: V::Public,
        /// Pre-computed namespaces for domain separation.
        namespace: Namespace,
    },
}

/// BLS12-381 threshold VRF implementation of the [`certificate::Scheme`] trait.
///
/// This scheme produces both vote signatures and per-round seed signatures.
/// The seed can be extracted from certificates using the [`Seedable`] trait.
///
/// It is possible for a node to play one of the following roles: a signer (with its share),
/// a verifier (with evaluated public polynomial), or an external verifier that
/// only checks recovered certificates.
#[derive(Clone, Debug)]
pub struct Scheme<P: PublicKey, V: Variant> {
    role: Role<P, V>,
}

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Constructs a signer instance with a private share and evaluated public polynomial.
    ///
    /// The participant identity keys are used for committee ordering and indexing.
    /// The polynomial can be evaluated to obtain public verification keys for partial
    /// signatures produced by committee members.
    ///
    /// Returns `None` if the share's public key does not match any participant.
    ///
    /// * `namespace` - base namespace for domain separation
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    /// * `share` - local threshold share for signing
    pub fn signer(
        namespace: &[u8],
        participants: Set<P>,
        polynomial: Sharing<V>,
        share: Share,
    ) -> Option<Self> {
        assert_eq!(
            polynomial.total().get() as usize,
            participants.len(),
            "polynomial total must equal participant len"
        );
        polynomial.precompute_partial_publics();
        let partial_public = polynomial
            .partial_public(share.index)
            .expect("share index must match participant indices");
        if partial_public == share.public::<V>() {
            Some(Self {
                role: Role::Signer {
                    participants,
                    polynomial,
                    share,
                    namespace: Namespace::new(namespace),
                },
            })
        } else {
            None
        }
    }

    /// Produces a verifier that can authenticate votes but does not hold signing state.
    ///
    /// The participant identity keys are used for committee ordering and indexing.
    /// The polynomial can be evaluated to obtain public verification keys for partial
    /// signatures produced by committee members.
    ///
    /// * `namespace` - base namespace for domain separation
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    pub fn verifier(namespace: &[u8], participants: Set<P>, polynomial: Sharing<V>) -> Self {
        assert_eq!(
            polynomial.total().get() as usize,
            participants.len(),
            "polynomial total must equal participant len"
        );
        polynomial.precompute_partial_publics();

        Self {
            role: Role::Verifier {
                participants,
                polynomial,
                namespace: Namespace::new(namespace),
            },
        }
    }

    /// Creates a verifier that only checks recovered certificates.
    ///
    /// This lightweight verifier can authenticate recovered threshold certificates but cannot
    /// verify individual votes or partial signatures.
    ///
    /// * `namespace` - base namespace for domain separation
    /// * `identity` - public identity of the committee (constant across reshares)
    pub fn certificate_verifier(namespace: &[u8], identity: V::Public) -> Self {
        Self {
            role: Role::CertificateVerifier {
                identity,
                namespace: Namespace::new(namespace),
            },
        }
    }

    /// Returns the ordered set of participant public identity keys in the committee.
    pub fn participants(&self) -> &Set<P> {
        match &self.role {
            Role::Signer { participants, .. } => participants,
            Role::Verifier { participants, .. } => participants,
            Role::CertificateVerifier { .. } => {
                panic!("can only be called for signer and verifier")
            }
        }
    }

    /// Returns the public identity of the committee (constant across reshares).
    pub fn identity(&self) -> &V::Public {
        match &self.role {
            Role::Signer { polynomial, .. } => polynomial.public(),
            Role::Verifier { polynomial, .. } => polynomial.public(),
            Role::CertificateVerifier { identity, .. } => identity,
        }
    }

    /// Returns the local share if this instance can generate partial signatures.
    pub const fn share(&self) -> Option<&Share> {
        match &self.role {
            Role::Signer { share, .. } => Some(share),
            _ => None,
        }
    }

    /// Returns the evaluated public polynomial for validating partial signatures produced by committee members.
    pub fn polynomial(&self) -> &Sharing<V> {
        match &self.role {
            Role::Signer { polynomial, .. } => polynomial,
            Role::Verifier { polynomial, .. } => polynomial,
            Role::CertificateVerifier { .. } => {
                panic!("can only be called for signer and verifier")
            }
        }
    }

    /// Returns the pre-computed namespaces.
    const fn namespace(&self) -> &Namespace {
        match &self.role {
            Role::Signer { namespace, .. } => namespace,
            Role::Verifier { namespace, .. } => namespace,
            Role::CertificateVerifier { namespace, .. } => namespace,
        }
    }

    /// Encrypts a message for a target round using Timelock Encryption ([TLE](tle)).
    ///
    /// The encrypted message can only be decrypted using the seed signature
    /// from a certificate of the target round (i.e. notarization, finalization,
    /// or nullification).
    #[stability(ALPHA)]
    pub fn encrypt<R: CryptoRng>(
        &self,
        rng: &mut R,
        target: Round,
        message: impl Into<tle::Block>,
    ) -> tle::Ciphertext<V> {
        let block = message.into();
        let target_message = target.encode();
        tle::encrypt(
            rng,
            *self.identity(),
            (&self.namespace().seed, &target_message),
            &block,
        )
    }
}

/// Encrypts a message for a future round using Timelock Encryption ([TLE](tle)).
///
/// The encrypted message can only be decrypted using the seed signature
/// from a certificate of the target round (i.e. notarization, finalization,
/// or nullification).
#[stability(ALPHA)]
pub fn encrypt<R: CryptoRng, V: Variant>(
    rng: &mut R,
    identity: V::Public,
    namespace: &[u8],
    target: Round,
    message: impl Into<tle::Block>,
) -> tle::Ciphertext<V> {
    let block = message.into();
    let seed_ns = seed_namespace(namespace);
    let target_message = target.encode();
    tle::encrypt(rng, identity, (&seed_ns, &target_message), &block)
}

/// Generates a test fixture with Ed25519 identities and BLS12-381 threshold schemes.
///
/// Returns a [`commonware_cryptography::certificate::mocks::Fixture`] whose keys and
/// scheme instances share a consistent ordering.
#[cfg(feature = "mocks")]
pub fn fixture<V, R>(
    rng: &mut R,
    namespace: &[u8],
    n: u32,
) -> commonware_cryptography::certificate::mocks::Fixture<
    Scheme<commonware_cryptography::ed25519::PublicKey, V>,
>
where
    V: Variant,
    R: rand_core::CryptoRng,
{
    commonware_cryptography::bls12381::certificate::threshold::mocks::fixture::<_, V, _>(
        rng,
        namespace,
        n,
        |namespace, participants, polynomial, share| {
            Scheme::signer(namespace, participants, polynomial, share)
        },
        |namespace, participants, polynomial| Scheme::verifier(namespace, participants, polynomial),
    )
}

/// Combined vote/seed signature pair emitted by the BLS12-381 threshold VRF scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature<V: Variant> {
    /// Signature over the consensus vote message (partial or recovered aggregate).
    pub vote_signature: V::Signature,
    /// Signature over the per-round seed (partial or recovered aggregate).
    pub seed_signature: V::Signature,
}

impl<V: Variant> Write for Signature<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.vote_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl<V: Variant> Read for Signature<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let vote_signature = V::Signature::read(reader)?;
        let seed_signature = V::Signature::read(reader)?;

        Ok(Self {
            vote_signature,
            seed_signature,
        })
    }
}

impl<V: Variant> FixedSize for Signature<V> {
    const SIZE: usize = V::Signature::SIZE * 2;
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for Signature<V>
where
    V::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            vote_signature: u.arbitrary()?,
            seed_signature: u.arbitrary()?,
        })
    }
}

/// Certificate for BLS12-381 threshold VRF signatures.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<V: Variant> {
    /// The recovered threshold signature pair.
    pub signature: Lazy<Signature<V>>,
}

impl<V: Variant> Certificate<V> {
    /// Attempts to get the decoded signature.
    ///
    /// Returns `None` if the signature fails to decode.
    pub fn get(&self) -> Option<&Signature<V>> {
        self.signature.get()
    }
}

impl<V: Variant> From<Signature<V>> for Certificate<V> {
    fn from(signature: Signature<V>) -> Self {
        Self {
            signature: Lazy::from(signature),
        }
    }
}

impl<V: Variant> Write for Certificate<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signature.write(writer);
    }
}

impl<V: Variant> Read for Certificate<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let signature = Lazy::<Signature<V>>::read(reader)?;
        Ok(Self { signature })
    }
}

impl<V: Variant> FixedSize for Certificate<V> {
    const SIZE: usize = Signature::<V>::SIZE;
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for Certificate<V>
where
    V::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            signature: Lazy::from(u.arbitrary::<Signature<V>>()?),
        })
    }
}

/// Seed represents a threshold signature over the current view.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Seed<V: Variant> {
    /// The round for which this seed is generated
    pub round: Round,
    /// The threshold signature on the seed.
    pub signature: V::Signature,
}

impl<V: Variant> Seed<V> {
    /// Creates a new seed with the given view and signature.
    pub const fn new(round: Round, signature: V::Signature) -> Self {
        Self { round, signature }
    }

    /// Verifies the threshold signature on this [Seed].
    pub fn verify<P: PublicKey>(&self, scheme: &Scheme<P, V>) -> bool {
        let seed_message = self.round.encode();

        ops::verify_message::<V>(
            scheme.identity(),
            &scheme.namespace().seed,
            &seed_message,
            &self.signature,
        )
        .is_ok()
    }

    /// Returns the round associated with this seed.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Decrypts a [TLE](tle) ciphertext using this seed.
    ///
    /// Returns `None` if the ciphertext is invalid or encrypted for a different
    /// round than this seed.
    #[stability(ALPHA)]
    pub fn decrypt(&self, ciphertext: &tle::Ciphertext<V>) -> Option<tle::Block> {
        decrypt(self, ciphertext)
    }
}

/// Decrypts a [TLE](tle) ciphertext using the seed from a certificate (i.e.
/// notarization, finalization, or nullification).
///
/// Returns `None` if the ciphertext is invalid or encrypted for a different
/// round than the given seed.
#[stability(ALPHA)]
pub fn decrypt<V: Variant>(seed: &Seed<V>, ciphertext: &tle::Ciphertext<V>) -> Option<tle::Block> {
    tle::decrypt(&seed.signature, ciphertext)
}

impl<V: Variant> Epochable for Seed<V> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant> Viewable for Seed<V> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant> Write for Seed<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant> Read for Seed<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let signature = V::Signature::read(reader)?;

        Ok(Self { round, signature })
    }
}

impl<V: Variant> EncodeSize for Seed<V> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.signature.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for Seed<V>
where
    V::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            round: u.arbitrary()?,
            signature: u.arbitrary()?,
        })
    }
}

/// Seedable is a trait that provides access to the seed associated with a message.
pub trait Seedable<V: Variant> {
    /// Returns the seed associated with this object.
    fn seed(&self) -> Seed<V>;
}

impl<P: PublicKey, V: Variant, D: Digest> Seedable<V> for Notarization<Scheme<P, V>, D> {
    fn seed(&self) -> Seed<V> {
        let cert = self
            .certificate
            .get()
            .expect("verified certificate must decode");
        Seed::new(self.proposal.round, cert.seed_signature)
    }
}

impl<P: PublicKey, V: Variant, D: Digest> Seedable<V> for Finalization<Scheme<P, V>, D> {
    fn seed(&self) -> Seed<V> {
        let cert = self
            .certificate
            .get()
            .expect("verified certificate must decode");
        Seed::new(self.proposal.round, cert.seed_signature)
    }
}

/// Extracts the seed message bytes from a Subject.
///
/// The seed message is the round encoded as bytes, used for per-view randomness.
fn seed_message_from_subject<D: Digest>(subject: &Subject<'_, D>) -> bytes::Bytes {
    match subject {
        Subject::Notarize { proposal } | Subject::Finalize { proposal } => proposal.round.encode(),
        Subject::Nullify { round } => round.encode(),
    }
}

impl<P: PublicKey, V: Variant> certificate::Verifier for Scheme<P, V> {
    type Subject<'a, D: Digest> = Subject<'a, D>;
    type PublicKey = P;
    type Certificate = Certificate<V>;

    fn verify_certificate<R, D, M>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        certificate: &Self::Certificate,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
        M: Faults,
    {
        let Some(cert) = certificate.get() else {
            return false;
        };

        let identity = self.identity();
        let namespace = self.namespace();

        let vote_namespace = subject.namespace(namespace);
        let vote_message = subject.message();
        let seed_message = seed_message_from_subject(&subject);

        let entries = &[
            (vote_namespace, vote_message.as_ref(), cert.vote_signature),
            (&namespace.seed, seed_message.as_ref(), cert.seed_signature),
        ];
        batch::verify_same_signer::<_, V, _>(rng, identity, entries, strategy).is_ok()
    }

    fn verify_certificates<'a, R, D, I, M>(
        &self,
        rng: &mut R,
        certificates: I,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
        I: Iterator<Item = (Subject<'a, D>, &'a Self::Certificate)>,
        M: Faults,
    {
        let identity = self.identity();
        let namespace = self.namespace();

        let mut seeds = HashMap::new();
        let mut entries: Vec<_> = Vec::new();

        for (context, certificate) in certificates {
            let Some(cert) = certificate.get() else {
                return false;
            };

            // Prepare vote message with context-specific namespace
            let vote_namespace = context.namespace(namespace);
            let vote_message = context.message();
            entries.push((vote_namespace, vote_message, cert.vote_signature));

            // Seed signatures are per-round, so multiple certificates for the same round
            // (e.g., notarization and finalization) share the same seed. We only include
            // each unique seed once in the aggregate, but verify all certificates for a
            // round have matching seeds.
            let seed_message = seed_message_from_subject(&context);
            if let Some(previous) = seeds.get(&seed_message) {
                if *previous != cert.seed_signature {
                    return false;
                }
            } else {
                entries.push((&namespace.seed, seed_message.clone(), cert.seed_signature));
                seeds.insert(seed_message, cert.seed_signature);
            }
        }

        // We care about the correctness of each signature, so we use batch verification rather
        // than computing the aggregate signature and verifying it.
        let entries_refs: Vec<_> = entries
            .iter()
            .map(|(ns, msg, sig)| (*ns, msg.as_ref(), *sig))
            .collect();
        batch::verify_same_signer::<_, V, _>(rng, identity, &entries_refs, strategy).is_ok()
    }

    fn is_batchable() -> bool {
        true
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {}

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {}
}

impl<P: PublicKey, V: Variant> certificate::Scheme for Scheme<P, V> {
    type Signature = Signature<V>;

    fn me(&self) -> Option<Participant> {
        match &self.role {
            Role::Signer { share, .. } => Some(share.index),
            _ => None,
        }
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        self.participants()
    }

    fn sign<D: Digest>(&self, subject: Subject<'_, D>) -> Option<Attestation<Self>> {
        let share = self.share()?;

        let namespace = self.namespace();
        let vote_namespace = subject.namespace(namespace);
        let vote_message = subject.message();
        let vote_signature =
            threshold::sign_message::<V>(share, vote_namespace, &vote_message).value;

        let seed_message = seed_message_from_subject(&subject);
        let seed_signature =
            threshold::sign_message::<V>(share, &namespace.seed, &seed_message).value;

        let signature = Signature {
            vote_signature,
            seed_signature,
        };

        Some(Attestation {
            signer: share.index,
            signature: signature.into(),
        })
    }

    fn verify_attestation<R, D>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        attestation: &Attestation<Self>,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
    {
        let Ok(evaluated) = self.polynomial().partial_public(attestation.signer) else {
            return false;
        };

        let namespace = self.namespace();
        let vote_namespace = subject.namespace(namespace);
        let vote_message = subject.message();
        let seed_message = seed_message_from_subject(&subject);

        let Some(signature) = attestation.signature.get() else {
            return false;
        };

        let entries = &[
            (
                vote_namespace,
                vote_message.as_ref(),
                signature.vote_signature,
            ),
            (
                &namespace.seed,
                seed_message.as_ref(),
                signature.seed_signature,
            ),
        ];
        batch::verify_same_signer::<_, V, _>(rng, &evaluated, entries, strategy).is_ok()
    }

    fn verify_attestations<R, D, I>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        attestations: I,
        strategy: &impl Strategy,
    ) -> Verification<Self>
    where
        R: CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
    {
        let namespace = self.namespace();
        let (partials, failures) =
            strategy.map_partition_collect_vec(attestations.into_iter(), |attestation| {
                let index = attestation.signer;
                let value = attestation.signature.get().map(|sig| {
                    (
                        PartialSignature::<V> {
                            index,
                            value: sig.vote_signature,
                        },
                        PartialSignature::<V> {
                            index,
                            value: sig.seed_signature,
                        },
                    )
                });
                (index, value)
            });

        let polynomial = self.polynomial();
        let vote_namespace = subject.namespace(namespace);
        let vote_message = subject.message();
        let seed_message = seed_message_from_subject(&subject);

        // Generate independent RNG seeds for concurrent verification
        let mut vote_rng_seed = [0u8; 32];
        let mut seed_rng_seed = [0u8; 32];
        rng.fill_bytes(&mut vote_rng_seed);
        rng.fill_bytes(&mut seed_rng_seed);

        // Verify vote and seed signatures concurrently.
        let (vote_invalid, seed_invalid) = strategy.join(
            || {
                let mut vote_rng = StdRng::from_seed(vote_rng_seed);
                match threshold::batch_verify_same_message::<_, V, _>(
                    &mut vote_rng,
                    polynomial,
                    vote_namespace,
                    &vote_message,
                    partials.iter().map(|(vote, _)| vote),
                    strategy,
                ) {
                    Ok(()) => BTreeSet::new(),
                    Err(errs) => errs.into_iter().map(|p| p.index).collect(),
                }
            },
            || {
                let mut seed_rng = StdRng::from_seed(seed_rng_seed);
                match threshold::batch_verify_same_message::<_, V, _>(
                    &mut seed_rng,
                    polynomial,
                    &namespace.seed,
                    &seed_message,
                    partials.iter().map(|(_, seed)| seed),
                    strategy,
                ) {
                    Ok(()) => BTreeSet::new(),
                    Err(errs) => errs.into_iter().map(|p| p.index).collect(),
                }
            },
        );

        // Merge invalid sets and add decode failures
        let mut invalid: BTreeSet<_> = vote_invalid.union(&seed_invalid).copied().collect();
        invalid.extend(failures);

        // Filter out cryptographically invalid signatures (partials only excludes decode failures)
        let verified = partials
            .into_iter()
            .filter(|(vote, _)| !invalid.contains(&vote.index))
            .map(|(vote, seed)| Attestation {
                signer: vote.index,
                signature: Signature {
                    vote_signature: vote.value,
                    seed_signature: seed.value,
                }
                .into(),
            })
            .collect();

        Verification::new(verified, invalid.into_iter().collect())
    }

    fn assemble<I, M>(&self, attestations: I, strategy: &impl Strategy) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
        M: Faults,
    {
        let (partials, failures) =
            strategy.map_partition_collect_vec(attestations.into_iter(), |attestation| {
                let index = attestation.signer;
                let value = attestation.signature.get().map(|sig| {
                    (
                        PartialSignature::<V> {
                            index,
                            value: sig.vote_signature,
                        },
                        PartialSignature::<V> {
                            index,
                            value: sig.seed_signature,
                        },
                    )
                });
                (index, value)
            });
        if !failures.is_empty() {
            return None;
        }
        let (vote_partials, seed_partials): (Vec<_>, Vec<_>) = partials.into_iter().unzip();

        let quorum = self.polynomial();
        if vote_partials.len() < quorum.required::<M>() as usize {
            return None;
        }

        let (vote_signature, seed_signature) = threshold::recover_pair::<V, _, M>(
            quorum,
            vote_partials.iter(),
            seed_partials.iter(),
            strategy,
        )
        .ok()?;

        Some(
            Signature {
                vote_signature,
                seed_signature,
            }
            .into(),
        )
    }

    fn is_attributable() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::{notarize_namespace, seed_namespace},
            types::{Finalization, Finalize, Notarization, Notarize, Proposal, Subject},
        },
        types::{Round, View},
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg::feldman_desmedt as dkg,
            primitives::{
                group::Scalar,
                ops::threshold,
                variant::{MinPk, MinSig, Variant},
            },
        },
        certificate::{mocks::Fixture, Scheme as _, Verifier as _},
        ed25519,
        ed25519::certificate::mocks::participants as ed25519_participants,
        sha256::Digest as Sha256Digest,
        Hasher, Sha256,
    };
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, Faults, N3f1, NZU32};
    use rand::{rngs::StdRng, SeedableRng};

    const NAMESPACE: &[u8] = b"bls-threshold-signing-scheme";

    type Scheme<V> = super::Scheme<ed25519::PublicKey, V>;
    type Signature<V> = super::Signature<V>;

    fn setup_signers<V: Variant>(n: u32, seed: u64) -> (Vec<Scheme<V>>, Scheme<V>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let Fixture {
            schemes, verifier, ..
        } = fixture::<V, _>(&mut rng, NAMESPACE, n);

        (schemes, verifier)
    }

    fn sample_proposal(epoch: Epoch, view: View, tag: u8) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(epoch, view),
            view.previous().unwrap(),
            Sha256::hash(&[tag]),
        )
    }

    fn signer_shares_must_match_participant_indices<V: Variant>() {
        let mut rng = test_rng();
        let participants = ed25519_participants(&mut rng, 4);
        let (polynomial, mut shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(4));
        shares[0].index = Participant::new(999);
        Scheme::<V>::signer(
            NAMESPACE,
            participants.keys().clone(),
            polynomial,
            shares[0].clone(),
        );
    }

    #[test]
    #[should_panic(expected = "share index must match participant indices")]
    fn test_signer_shares_must_match_participant_indices_min_pk() {
        signer_shares_must_match_participant_indices::<MinPk>();
    }

    #[test]
    #[should_panic(expected = "share index must match participant indices")]
    fn test_signer_shares_must_match_participant_indices_min_sig() {
        signer_shares_must_match_participant_indices::<MinSig>();
    }
    fn scheme_polynomial_threshold_must_equal_quorum<V: Variant>() {
        let mut rng = test_rng();
        let participants = ed25519_participants(&mut rng, 5);
        let (polynomial, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(4));
        Scheme::<V>::signer(
            NAMESPACE,
            participants.keys().clone(),
            polynomial,
            shares[0].clone(),
        );
    }

    #[test]
    #[should_panic(expected = "polynomial total must equal participant len")]
    fn test_scheme_polynomial_threshold_must_equal_quorum_min_pk() {
        scheme_polynomial_threshold_must_equal_quorum::<MinPk>();
    }

    #[test]
    #[should_panic(expected = "polynomial total must equal participant len")]
    fn test_scheme_polynomial_threshold_must_equal_quorum_min_sig() {
        scheme_polynomial_threshold_must_equal_quorum::<MinSig>();
    }

    fn verifier_polynomial_threshold_must_equal_quorum<V: Variant>() {
        let mut rng = test_rng();
        let participants = ed25519_participants(&mut rng, 5);
        let (polynomial, _) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(4));
        Scheme::<V>::verifier(NAMESPACE, participants.keys().clone(), polynomial);
    }

    #[test]
    #[should_panic(expected = "polynomial total must equal participant len")]
    fn test_verifier_polynomial_threshold_must_equal_quorum_min_pk() {
        verifier_polynomial_threshold_must_equal_quorum::<MinPk>();
    }

    #[test]
    #[should_panic(expected = "polynomial total must equal participant len")]
    fn test_verifier_polynomial_threshold_must_equal_quorum_min_sig() {
        verifier_polynomial_threshold_must_equal_quorum::<MinSig>();
    }

    #[test]
    fn test_is_not_attributable() {
        assert!(!Scheme::<MinPk>::is_attributable());
        assert!(!Scheme::<MinSig>::is_attributable());
    }

    #[test]
    fn test_is_batchable() {
        assert!(Scheme::<MinPk>::is_batchable());
        assert!(Scheme::<MinSig>::is_batchable());
    }

    fn sign_vote_roundtrip_for_each_context<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 7);
        let scheme = &schemes[0];
        let mut rng = test_rng();

        let proposal = sample_proposal(Epoch::new(0), View::new(2), 1);
        let notarize_vote = scheme
            .sign(Subject::Notarize {
                proposal: &proposal,
            })
            .unwrap();
        assert!(scheme.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal,
            },
            &notarize_vote,
            &Sequential,
        ));

        let nullify_vote = scheme
            .sign::<Sha256Digest>(Subject::Nullify {
                round: proposal.round,
            })
            .unwrap();
        assert!(scheme.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            Subject::Nullify {
                round: proposal.round,
            },
            &nullify_vote,
            &Sequential,
        ));

        let finalize_vote = scheme
            .sign(Subject::Finalize {
                proposal: &proposal,
            })
            .unwrap();
        assert!(scheme.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            Subject::Finalize {
                proposal: &proposal,
            },
            &finalize_vote,
            &Sequential,
        ));
    }

    #[test]
    fn test_sign_vote_roundtrip_for_each_context() {
        sign_vote_roundtrip_for_each_context::<MinPk>();
        sign_vote_roundtrip_for_each_context::<MinSig>();
    }

    fn verifier_cannot_sign<V: Variant>() {
        let (_, verifier) = setup_signers::<V>(4, 11);

        let proposal = sample_proposal(Epoch::new(0), View::new(3), 2);
        assert!(
            verifier
                .sign(Subject::Notarize {
                    proposal: &proposal,
                })
                .is_none(),
            "verifier should not produce signatures"
        );
    }

    #[test]
    fn test_verifier_cannot_sign() {
        verifier_cannot_sign::<MinPk>();
        verifier_cannot_sign::<MinSig>();
    }

    fn verifier_accepts_votes<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 11);
        let proposal = sample_proposal(Epoch::new(0), View::new(3), 2);
        let vote = schemes[1]
            .sign(Subject::Notarize {
                proposal: &proposal,
            })
            .unwrap();
        assert!(verifier.verify_attestation::<_, Sha256Digest>(
            &mut test_rng(),
            Subject::Notarize {
                proposal: &proposal,
            },
            &vote,
            &Sequential,
        ));
    }

    #[test]
    fn test_verifier_accepts_votes() {
        verifier_accepts_votes::<MinPk>();
        verifier_accepts_votes::<MinSig>();
    }

    fn verify_votes_filters_bad_signers<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(5, 13);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(5), 3);

        let mut votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let verification = schemes[0].verify_attestations(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal,
            },
            votes.clone(),
            &Sequential,
        );
        assert!(verification.invalid.is_empty());
        assert_eq!(verification.verified.len(), quorum);

        votes[0].signer = Participant::new(999);
        let verification = schemes[0].verify_attestations(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal,
            },
            votes,
            &Sequential,
        );
        assert_eq!(verification.invalid, vec![Participant::new(999)]);
        assert_eq!(verification.verified.len(), quorum - 1);
    }

    #[test]
    fn test_verify_votes_filters_bad_signers() {
        verify_votes_filters_bad_signers::<MinPk>();
        verify_votes_filters_bad_signers::<MinSig>();
    }

    fn assemble_certificate_requires_quorum<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 17);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(7), 4);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum - 1)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        assert!(schemes[0].assemble::<_, N3f1>(votes, &Sequential).is_none());
    }

    #[test]
    fn test_assemble_certificate_requires_quorum() {
        assemble_certificate_requires_quorum::<MinPk>();
        assemble_certificate_requires_quorum::<MinSig>();
    }

    fn verify_certificate<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 19);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(9), 5);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Finalize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble certificate");

        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut test_rng(),
            Subject::Finalize {
                proposal: &proposal,
            },
            &certificate,
            &Sequential,
        ));
    }

    #[test]
    fn test_verify_certificate() {
        verify_certificate::<MinPk>();
        verify_certificate::<MinSig>();
    }

    fn verify_certificate_detects_corruption<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(4, 23);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(11), 6);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble certificate");

        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal,
            },
            &certificate,
            &Sequential,
        ));

        let cert = certificate.get().unwrap();
        let corrupted: Certificate<V> = Signature {
            vote_signature: cert.seed_signature,
            seed_signature: cert.seed_signature,
        }
        .into();
        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal,
            },
            &corrupted,
            &Sequential,
        ));
    }

    #[test]
    fn test_verify_certificate_detects_corruption() {
        verify_certificate_detects_corruption::<MinPk>();
        verify_certificate_detects_corruption::<MinSig>();
    }

    fn certificate_codec_roundtrip<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(5, 29);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(13), 7);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble certificate");

        let encoded = certificate.encode();
        let decoded = Certificate::<V>::decode_cfg(encoded, &()).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_codec_roundtrip() {
        certificate_codec_roundtrip::<MinPk>();
        certificate_codec_roundtrip::<MinSig>();
    }

    fn seed_codec_roundtrip<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 5);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(1), 0);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Finalize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble certificate");
        let cert = certificate.get().unwrap();

        let seed = Seed::new(proposal.round, cert.seed_signature);

        let encoded = seed.encode();
        let decoded = Seed::<V>::decode_cfg(encoded, &()).expect("decode seed");
        assert_eq!(decoded, seed);
    }

    #[test]
    fn test_seed_codec_roundtrip() {
        seed_codec_roundtrip::<MinPk>();
        seed_codec_roundtrip::<MinSig>();
    }

    fn seed_verify<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 5);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(1), 0);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Finalize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble certificate");
        let cert = certificate.get().unwrap();

        let seed = Seed::new(proposal.round, cert.seed_signature);

        assert!(seed.verify(&schemes[0]));

        // Create an invalid seed with a mismatched round
        let invalid_seed = Seed::new(
            Round::new(proposal.epoch(), proposal.view().next()),
            cert.seed_signature,
        );

        assert!(!invalid_seed.verify(&schemes[0]));
    }

    #[test]
    fn test_seed_verify() {
        seed_verify::<MinPk>();
        seed_verify::<MinSig>();
    }

    fn seedable<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 5);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(1), 0);

        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let notarization =
            Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap();

        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let finalization =
            Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap();

        assert_eq!(notarization.seed(), finalization.seed());
        assert!(notarization.seed().verify(&schemes[0]));
    }

    #[test]
    fn test_seedable() {
        seedable::<MinPk>();
        seedable::<MinSig>();
    }

    fn scheme_clone_and_verifier<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 31);
        let signer = schemes[0].clone();
        let proposal = sample_proposal(Epoch::new(0), View::new(21), 9);

        assert!(
            signer
                .sign(Subject::Notarize {
                    proposal: &proposal,
                })
                .is_some(),
            "signer should produce votes"
        );

        assert!(
            verifier
                .sign(Subject::Notarize {
                    proposal: &proposal,
                })
                .is_none(),
            "verifier should not produce votes"
        );
    }

    #[test]
    fn test_scheme_clone_and_verifier() {
        scheme_clone_and_verifier::<MinPk>();
        scheme_clone_and_verifier::<MinSig>();
    }

    fn certificate_verifier_accepts_certificates<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 37);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(15), 8);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Finalize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble certificate");

        let certificate_verifier =
            Scheme::<V>::certificate_verifier(NAMESPACE, *schemes[0].identity());
        assert!(
            certificate_verifier
                .sign(Subject::Finalize {
                    proposal: &proposal,
                })
                .is_none(),
            "certificate verifier should not produce votes"
        );
        assert!(
            certificate_verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                &mut test_rng(),
                Subject::Finalize {
                    proposal: &proposal,
                },
                &certificate,
                &Sequential,
            )
        );
    }

    #[test]
    fn test_certificate_verifier_accepts_certificates() {
        certificate_verifier_accepts_certificates::<MinPk>();
        certificate_verifier_accepts_certificates::<MinSig>();
    }

    fn certificate_verifier_panics_on_vote<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 37);
        let certificate_verifier =
            Scheme::<V>::certificate_verifier(NAMESPACE, *schemes[0].identity());
        let proposal = sample_proposal(Epoch::new(0), View::new(15), 8);
        let vote = schemes[1]
            .sign(Subject::Finalize {
                proposal: &proposal,
            })
            .unwrap();

        certificate_verifier.verify_attestation::<_, Sha256Digest>(
            &mut test_rng(),
            Subject::Finalize {
                proposal: &proposal,
            },
            &vote,
            &Sequential,
        );
    }

    #[test]
    #[should_panic(expected = "can only be called for signer and verifier")]
    fn test_certificate_verifier_panics_on_vote_min_pk() {
        certificate_verifier_panics_on_vote::<MinPk>();
    }

    #[test]
    #[should_panic(expected = "can only be called for signer and verifier")]
    fn test_certificate_verifier_panics_on_vote_min_sig() {
        certificate_verifier_panics_on_vote::<MinSig>();
    }

    fn verify_certificate_returns_seed_randomness<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 43);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(19), 10);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble certificate");
        let cert = certificate.get().unwrap();

        let seed = Seed::<V>::new(proposal.round, cert.seed_signature);
        assert_eq!(seed.signature, cert.seed_signature);
    }

    #[test]
    fn test_verify_certificate_returns_seed_randomness() {
        verify_certificate_returns_seed_randomness::<MinPk>();
        verify_certificate_returns_seed_randomness::<MinSig>();
    }

    fn certificate_decode_rejects_length_mismatch<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 47);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(21), 11);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign::<Sha256Digest>(Subject::Nullify {
                        round: proposal.round,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble certificate");

        let mut encoded = certificate.encode();
        let truncated = encoded.split_to(encoded.len() - 1);
        assert!(Signature::<V>::decode_cfg(truncated, &()).is_err());
    }

    #[test]
    fn test_certificate_decode_rejects_length_mismatch() {
        certificate_decode_rejects_length_mismatch::<MinPk>();
        certificate_decode_rejects_length_mismatch::<MinSig>();
    }

    fn sign_vote_partial_matches_share<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 53);
        let scheme = &schemes[0];
        let share = scheme.share().expect("has share");

        let proposal = sample_proposal(Epoch::new(0), View::new(23), 12);
        let vote = scheme
            .sign(Subject::Notarize {
                proposal: &proposal,
            })
            .unwrap();

        let notarize_namespace = notarize_namespace(NAMESPACE);
        let notarize_message = proposal.encode();
        let expected_message = threshold::sign_message::<V>(
            share,
            notarize_namespace.as_ref(),
            notarize_message.as_ref(),
        )
        .value;

        let seed_namespace = seed_namespace(NAMESPACE);
        let seed_message = proposal.round.encode();
        let expected_seed =
            threshold::sign_message::<V>(share, seed_namespace.as_ref(), seed_message.as_ref())
                .value;

        assert_eq!(vote.signer, share.index);
        let sig = vote.signature.get().unwrap();
        assert_eq!(sig.vote_signature, expected_message);
        assert_eq!(sig.seed_signature, expected_seed);
    }

    #[test]
    fn test_sign_vote_partial_matches_share() {
        sign_vote_partial_matches_share::<MinPk>();
        sign_vote_partial_matches_share::<MinSig>();
    }

    fn verify_certificate_detects_seed_corruption<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(4, 59);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(25), 13);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign::<Sha256Digest>(Subject::Nullify {
                        round: proposal.round,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble certificate");

        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            Subject::Nullify {
                round: proposal.round,
            },
            &certificate,
            &Sequential,
        ));

        let cert = certificate.get().unwrap();
        let corrupted: Certificate<V> = Signature {
            vote_signature: cert.vote_signature,
            seed_signature: cert.vote_signature,
        }
        .into();
        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            Subject::Nullify {
                round: proposal.round,
            },
            &corrupted,
            &Sequential,
        ));
    }

    #[test]
    fn test_verify_certificate_detects_seed_corruption() {
        verify_certificate_detects_seed_corruption::<MinPk>();
        verify_certificate_detects_seed_corruption::<MinSig>();
    }

    fn encrypt_decrypt<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(4, 61);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        // Prepare a message to encrypt
        let message = b"Secret message for future view10";

        // Target round for encryption
        let target = Round::new(Epoch::new(333), View::new(10));

        // Encrypt using the scheme
        let ciphertext = schemes[0].encrypt(&mut rng, target, *message);

        // Can also encrypt with the verifier scheme
        let ciphertext_verifier = verifier.encrypt(&mut rng, target, *message);

        // Generate notarization for the target round to get the seed
        let proposal = sample_proposal(target.epoch(), target.view(), 14);
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let notarization =
            Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap();

        // Decrypt using the seed
        let seed = notarization.seed();
        let decrypted = seed.decrypt(&ciphertext).unwrap();
        assert_eq!(message, decrypted.as_ref());

        let decrypted_verifier = seed.decrypt(&ciphertext_verifier).unwrap();
        assert_eq!(message, decrypted_verifier.as_ref());
    }

    #[test]
    fn test_encrypt_decrypt() {
        encrypt_decrypt::<MinPk>();
        encrypt_decrypt::<MinSig>();
    }

    fn verify_attestation_rejects_malleability<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(4, 67);
        let proposal = sample_proposal(Epoch::new(0), View::new(27), 14);

        let attestation = schemes[0]
            .sign(Subject::Notarize {
                proposal: &proposal,
            })
            .unwrap();

        assert!(schemes[0].verify_attestation::<_, Sha256Digest>(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal,
            },
            &attestation,
            &Sequential,
        ));

        let random_scalar = Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let att_sig = attestation.signature.get().unwrap();
        let forged_attestation: Attestation<Scheme<V>> = Attestation {
            signer: attestation.signer,
            signature: Signature {
                vote_signature: att_sig.vote_signature - &delta,
                seed_signature: att_sig.seed_signature + &delta,
            }
            .into(),
        };

        let forged_sig = forged_attestation.signature.get().unwrap();
        let forged_sum = forged_sig.vote_signature + &forged_sig.seed_signature;
        let valid_sum = att_sig.vote_signature + &att_sig.seed_signature;
        assert_eq!(forged_sum, valid_sum, "signature sums should be equal");

        assert!(
            !schemes[0].verify_attestation::<_, Sha256Digest>(
                &mut rng,
                Subject::Notarize {
                    proposal: &proposal,
                },
                &forged_attestation,
                &Sequential,
            ),
            "forged attestation should be rejected"
        );
    }

    #[test]
    fn test_verify_attestation_rejects_malleability() {
        verify_attestation_rejects_malleability::<MinPk>();
        verify_attestation_rejects_malleability::<MinSig>();
    }

    fn verify_attestations_rejects_malleability<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(4, 71);
        let proposal = sample_proposal(Epoch::new(0), View::new(29), 15);

        let attestation1 = schemes[0]
            .sign(Subject::Notarize {
                proposal: &proposal,
            })
            .unwrap();
        let attestation2 = schemes[1]
            .sign(Subject::Notarize {
                proposal: &proposal,
            })
            .unwrap();

        let verification = schemes[0].verify_attestations(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal,
            },
            vec![attestation1.clone(), attestation2.clone()],
            &Sequential,
        );
        assert!(verification.invalid.is_empty());
        assert_eq!(verification.verified.len(), 2);

        let random_scalar = Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let att1_sig = attestation1.signature.get().unwrap();
        let att2_sig = attestation2.signature.get().unwrap();
        let forged_attestation1: Attestation<Scheme<V>> = Attestation {
            signer: attestation1.signer,
            signature: Signature {
                vote_signature: att1_sig.vote_signature - &delta,
                seed_signature: att1_sig.seed_signature,
            }
            .into(),
        };
        let forged_attestation2: Attestation<Scheme<V>> = Attestation {
            signer: attestation2.signer,
            signature: Signature {
                vote_signature: att2_sig.vote_signature + &delta,
                seed_signature: att2_sig.seed_signature,
            }
            .into(),
        };

        let forged1_sig = forged_attestation1.signature.get().unwrap();
        let forged2_sig = forged_attestation2.signature.get().unwrap();
        let forged_vote_sum = forged1_sig.vote_signature + &forged2_sig.vote_signature;
        let valid_vote_sum = att1_sig.vote_signature + &att2_sig.vote_signature;
        assert_eq!(
            forged_vote_sum, valid_vote_sum,
            "vote signature sums should be equal"
        );

        let verification = schemes[0].verify_attestations(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal,
            },
            vec![forged_attestation1, forged_attestation2],
            &Sequential,
        );
        assert!(
            !verification.invalid.is_empty(),
            "forged attestations should be detected"
        );
    }

    #[test]
    fn test_verify_attestations_rejects_malleability() {
        verify_attestations_rejects_malleability::<MinPk>();
        verify_attestations_rejects_malleability::<MinSig>();
    }

    fn verify_certificate_rejects_malleability<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(4, 73);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(31), 16);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble certificate");

        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal,
            },
            &certificate,
            &Sequential,
        ));

        let cert = certificate.get().unwrap();
        let random_scalar = Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let forged_certificate: Certificate<V> = Signature {
            vote_signature: cert.vote_signature - &delta,
            seed_signature: cert.seed_signature + &delta,
        }
        .into();

        let forged_cert = forged_certificate.get().unwrap();
        let forged_sum = forged_cert.vote_signature + &forged_cert.seed_signature;
        let valid_sum = cert.vote_signature + &cert.seed_signature;
        assert_eq!(forged_sum, valid_sum, "signature sums should be equal");

        assert!(
            !verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                &mut rng,
                Subject::Notarize {
                    proposal: &proposal,
                },
                &forged_certificate,
                &Sequential,
            ),
            "forged certificate should be rejected"
        );
    }

    #[test]
    fn test_verify_certificate_rejects_malleability() {
        verify_certificate_rejects_malleability::<MinPk>();
        verify_certificate_rejects_malleability::<MinSig>();
    }

    fn verify_certificates_rejects_malleability<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(4, 79);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let proposal1 = sample_proposal(Epoch::new(0), View::new(33), 17);
        let proposal2 = sample_proposal(Epoch::new(0), View::new(34), 18);

        let votes1: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal1,
                    })
                    .unwrap()
            })
            .collect();
        let votes2: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal2,
                    })
                    .unwrap()
            })
            .collect();

        let certificate1 = schemes[0]
            .assemble::<_, N3f1>(votes1, &Sequential)
            .expect("assemble certificate1");
        let certificate2 = schemes[0]
            .assemble::<_, N3f1>(votes2, &Sequential)
            .expect("assemble certificate2");

        assert!(verifier.verify_certificates::<_, Sha256Digest, _, N3f1>(
            &mut rng,
            [
                (
                    Subject::Notarize {
                        proposal: &proposal1,
                    },
                    &certificate1
                ),
                (
                    Subject::Notarize {
                        proposal: &proposal2,
                    },
                    &certificate2
                ),
            ]
            .into_iter(),
            &Sequential,
        ));

        let cert1 = certificate1.get().unwrap();
        let cert2 = certificate2.get().unwrap();
        let random_scalar = Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let forged_certificate1: Certificate<V> = Signature {
            vote_signature: cert1.vote_signature - &delta,
            seed_signature: cert1.seed_signature,
        }
        .into();
        let forged_certificate2: Certificate<V> = Signature {
            vote_signature: cert2.vote_signature + &delta,
            seed_signature: cert2.seed_signature,
        }
        .into();

        let forged1 = forged_certificate1.get().unwrap();
        let forged2 = forged_certificate2.get().unwrap();
        let forged_vote_sum = forged1.vote_signature + &forged2.vote_signature;
        let valid_vote_sum = cert1.vote_signature + &cert2.vote_signature;
        assert_eq!(
            forged_vote_sum, valid_vote_sum,
            "vote signature sums should be equal"
        );

        assert!(
            !verifier.verify_certificates::<_, Sha256Digest, _, N3f1>(
                &mut rng,
                [
                    (
                        Subject::Notarize {
                            proposal: &proposal1,
                        },
                        &forged_certificate1
                    ),
                    (
                        Subject::Notarize {
                            proposal: &proposal2,
                        },
                        &forged_certificate2
                    ),
                ]
                .into_iter(),
                &Sequential,
            ),
            "forged certificates should be rejected"
        );
    }

    #[test]
    fn test_verify_certificates_rejects_malleability() {
        verify_certificates_rejects_malleability::<MinPk>();
        verify_certificates_rejects_malleability::<MinSig>();
    }

    fn assemble_notarization_certificate<V: Variant>(
        schemes: &[Scheme<V>],
        proposal: &Proposal<Sha256Digest>,
    ) -> Certificate<V> {
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| scheme.sign(Subject::Notarize { proposal }).unwrap())
            .collect();

        schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble notarization certificate")
    }

    fn assemble_finalization_certificate<V: Variant>(
        schemes: &[Scheme<V>],
        proposal: &Proposal<Sha256Digest>,
    ) -> Certificate<V> {
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let votes: Vec<_> = schemes
            .iter()
            .skip(schemes.len() - quorum)
            .map(|scheme| scheme.sign(Subject::Finalize { proposal }).unwrap())
            .collect();

        schemes[0]
            .assemble::<_, N3f1>(votes, &Sequential)
            .expect("assemble finalization certificate")
    }

    fn verify_certificates_accepts_shared_round_seed<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(4, 81);
        let proposal = sample_proposal(Epoch::new(1), View::new(35), 19);
        let notarization_certificate = assemble_notarization_certificate(&schemes, &proposal);
        let finalization_certificate = assemble_finalization_certificate(&schemes, &proposal);

        assert!(verifier.verify_certificates::<_, Sha256Digest, _, N3f1>(
            &mut rng,
            [
                (
                    Subject::Notarize {
                        proposal: &proposal,
                    },
                    &notarization_certificate,
                ),
                (
                    Subject::Finalize {
                        proposal: &proposal,
                    },
                    &finalization_certificate,
                ),
            ]
            .into_iter(),
            &Sequential,
        ));
    }

    #[test]
    fn test_verify_certificates_accepts_shared_round_seed() {
        verify_certificates_accepts_shared_round_seed::<MinPk>();
        verify_certificates_accepts_shared_round_seed::<MinSig>();
    }

    fn verify_certificates_rejects_cross_epoch_seed_replay<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(4, 83);
        let view = View::new(35);
        let proposal1 = sample_proposal(Epoch::new(1), view, 19);
        let proposal2 = sample_proposal(Epoch::new(2), view, 20);
        let certificate1 = assemble_notarization_certificate(&schemes, &proposal1);
        let certificate2 = assemble_notarization_certificate(&schemes, &proposal2);

        assert!(verifier.verify_certificates::<_, Sha256Digest, _, N3f1>(
            &mut rng,
            [
                (
                    Subject::Notarize {
                        proposal: &proposal1,
                    },
                    &certificate1,
                ),
                (
                    Subject::Notarize {
                        proposal: &proposal2,
                    },
                    &certificate2,
                ),
            ]
            .into_iter(),
            &Sequential,
        ));

        let cert1 = certificate1.get().unwrap();
        let cert2 = certificate2.get().unwrap();
        let forged_certificate2: Certificate<V> = Signature {
            vote_signature: cert2.vote_signature,
            seed_signature: cert1.seed_signature,
        }
        .into();

        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal2,
            },
            &forged_certificate2,
            &Sequential,
        ));

        let batch = [
            (
                Subject::Notarize {
                    proposal: &proposal1,
                },
                &certificate1,
            ),
            (
                Subject::Notarize {
                    proposal: &proposal2,
                },
                &forged_certificate2,
            ),
        ];

        assert!(!verifier.verify_certificates::<_, Sha256Digest, _, N3f1>(
            &mut rng,
            batch.iter().copied(),
            &Sequential,
        ));
        assert_eq!(
            verifier.verify_certificates_bisect::<_, Sha256Digest, N3f1>(
                &mut rng,
                &batch,
                &Sequential,
            ),
            vec![true, false],
        );
    }

    #[test]
    fn test_verify_certificates_rejects_cross_epoch_seed_replay() {
        verify_certificates_rejects_cross_epoch_seed_replay::<MinPk>();
        verify_certificates_rejects_cross_epoch_seed_replay::<MinSig>();
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Signature<MinSig>>,
            CodecConformance<Certificate<MinSig>>,
            CodecConformance<Seed<MinSig>>,
        }
    }
}
