//! Signing scheme implementations for `simplex`.
//!
//! # Attributable Schemes and Fault Evidence
//!
//! Signing schemes differ in whether per-validator activities can be used as evidence of either
//! liveness or of committing a fault:
//!
//! - **Attributable Schemes** ([`ed25519`], [`bls12381_multisig`], [`secp256r1`]): Individual signatures can be
//!   presented to some third party as evidence of either liveness or of committing a fault. Certificates contain signer
//!   indices alongside individual signatures, enabling secure per-validator activity tracking and conflict detection.
//!
//! - **Non-Attributable schemes** ([`bls12381_threshold`]): Individual signatures cannot be presented
//!   to some third party as evidence of either liveness or of committing a fault because they can be forged
//!   by other players (often after some quorum of partial signatures are collected). With [`bls12381_threshold`],
//!   possession of any `t` valid partial signatures can be used to forge a partial signature for any other player.
//!   Because peer connections are authenticated, evidence can be used locally (as it must be sent by said participant)
//!   but can't be used by an external observer.
//!
//! The [`CertificateScheme::is_attributable()`] associated function signals whether evidence can be safely
//! exposed. For applications only interested in collecting evidence for liveness/faults, use [`reporter::AttributableReporter`]
//! which automatically handles filtering and verification based on scheme (hiding votes/proofs that are not attributable). To
//! observe all exported activity, process all messages passed through the [`crate::Reporter`] interface (note that reports
//! are not exhaustive: votes below the activity window are dropped without being reported, see
//! [`crate::simplex::types::Activity`]).
//!
//! # BLS12-381 Threshold Variants
//!
//! The [`bls12381_threshold`] module provides two variants:
//!
//! - [`bls12381_threshold::standard`]: Standard threshold signatures. Certificates contain only a
//!   vote signature recovered from partial signatures.
//!
//! - [`bls12381_threshold::vrf`]: Threshold VRF (Verifiable Random Function) that produces both
//!   vote signatures and per-round seed signatures. The seed can be used for randomness (e.g.,
//!   leader election, timelock encryption).
//!
//! **Security Warning for VRF Usage**: Each round's seed partial signs only the round and is
//! carried by every vote type, so the `f` Byzantine participants of a `3f+1` committee can recover
//! the seed once any `f+1` honest participants have voted (even for conflicting proposals), before
//! the round resolves and without any certificate forming. A malicious leader can use this early
//! knowledge to front-run the outcome. Applications should employ a "commit-then-reveal" pattern
//! by binding randomness requests in finalized blocks **before** the reveal occurs (e.g.,
//! `draw(view+100)`). See [`bls12381_threshold::vrf`] for details.

use crate::simplex::types::Subject;
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{
    Digest,
    certificate::{
        Namespace as CertificateNamespace, Scheme as CertificateScheme,
        Subject as CertificateSubject, Verifier,
    },
};
use commonware_utils::{N3f1, union};

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;
commonware_macros::stability_mod!(ALPHA, pub mod secp256r1);

#[cfg(not(target_arch = "wasm32"))]
pub mod reporter;

/// Pre-computed namespaces for simplex voting subjects.
///
/// This struct holds the pre-computed namespace bytes for each vote type.
#[derive(Clone, Debug)]
pub struct Namespace {
    /// Namespace for notarize votes/certificates.
    pub notarize: Vec<u8>,
    /// Namespace for nullify votes/certificates.
    pub nullify: Vec<u8>,
    /// Namespace for finalize votes/certificates.
    pub finalize: Vec<u8>,
    /// Namespace for seed signatures (used by threshold schemes).
    pub seed: Vec<u8>,
}

impl Namespace {
    /// Creates a new SimplexNamespace from a base namespace.
    pub fn new(namespace: &[u8]) -> Self {
        Self {
            notarize: notarize_namespace(namespace),
            nullify: nullify_namespace(namespace),
            finalize: finalize_namespace(namespace),
            seed: seed_namespace(namespace),
        }
    }
}

impl CertificateNamespace for Namespace {
    fn derive(namespace: &[u8]) -> Self {
        Self::new(namespace)
    }
}

impl<'a, D: Digest> CertificateSubject for Subject<'a, D> {
    type Namespace = Namespace;

    fn namespace<'b>(&self, derived: &'b Self::Namespace) -> &'b [u8] {
        match self {
            Self::Notarize { .. } => &derived.notarize,
            Self::Nullify { .. } => &derived.nullify,
            Self::Finalize { .. } => &derived.finalize,
        }
    }

    fn message(&self) -> Bytes {
        match self {
            Self::Notarize { proposal } => proposal.encode(),
            Self::Nullify { round } => round.encode(),
            Self::Finalize { proposal } => proposal.encode(),
        }
    }
}

/// Marker trait for certificate verifiers compatible with `simplex`.
///
/// This trait binds a [`Verifier`] to the [`Subject`] subject type and [`N3f1`]
/// fault model used by the simplex protocol. It is automatically implemented
/// for any compatible verifier.
pub trait CertificateVerifier<D: Digest>:
    for<'a> Verifier<Subject<'a, D> = Subject<'a, D>, Faults = N3f1>
{
}

impl<D: Digest, S> CertificateVerifier<D> for S where
    S: for<'a> Verifier<Subject<'a, D> = Subject<'a, D>, Faults = N3f1>
{
}

/// Marker trait for signing schemes compatible with `simplex`.
///
/// This trait binds a [`CertificateScheme`] to the [`Subject`] subject type and
/// [`N3f1`] fault model used by the simplex protocol. It is automatically
/// implemented for any compatible scheme.
pub trait Scheme<D: Digest>:
    CertificateVerifier<D> + for<'a> CertificateScheme<Subject<'a, D> = Subject<'a, D>>
{
}

impl<D: Digest, S> Scheme<D> for S where
    S: CertificateVerifier<D> + for<'a> CertificateScheme<Subject<'a, D> = Subject<'a, D>>
{
}

// Constants for domain separation in signature verification
// These are used to prevent cross-protocol attacks and message-type confusion
const SEED_SUFFIX: &[u8] = b"_SEED";
const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

/// Creates a namespace for seed messages by appending the SEED_SUFFIX
/// The seed is used for leader election and randomness generation
#[inline]
pub(crate) fn seed_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, SEED_SUFFIX)
}

/// Creates a namespace for notarize messages by appending the NOTARIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

/// Creates a namespace for nullify messages by appending the NULLIFY_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

/// Creates a namespace for finalize messages by appending the FINALIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}
