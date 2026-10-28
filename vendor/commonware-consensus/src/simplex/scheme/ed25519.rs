//! Ed25519 implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault. Certificates
//! contain signer indices alongside individual signatures, enabling secure
//! per-validator activity tracking and fault detection.

use crate::simplex::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_ed25519;
use commonware_utils::N3f1;

impl_certificate_ed25519!(Subject<'a, D>, Namespace, N3f1);
