//! Secp256r1 implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault.
//! Certificates contain signer indices alongside individual signatures,
//! enabling secure per-validator activity tracking and fault detection.
//!
//! Unlike Ed25519 and BLS12-381, Secp256r1 does not benefit from batch verification,
//! so the batcher will verify signatures immediately as they arrive rather than
//! waiting to batch them.

use crate::simplex::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_secp256r1;

impl_certificate_secp256r1!(Subject<'a, D>, Namespace);
