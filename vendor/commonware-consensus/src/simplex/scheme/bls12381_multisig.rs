//! BLS12-381 multi-signature implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be
//! used by an external observer as evidence of either liveness or of committing a fault.
//! Certificates contain signer indices alongside an aggregated signature,
//! enabling secure per-validator activity tracking and conflict detection.

use crate::simplex::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_bls12381_multisig;

impl_certificate_bls12381_multisig!(Subject<'a, D>, Namespace);
