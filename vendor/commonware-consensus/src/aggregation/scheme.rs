//! Signing scheme implementations for `aggregation`.
//!
//! This module provides protocol-specific wrappers around the generic signing schemes
//! in [`commonware_cryptography::certificate`]. Each wrapper binds the scheme's subject type to
//! [`Item`], which represents the data being aggregated and signed.
//!
//! # Available Schemes
//!
//! - [`ed25519`]: Attributable signatures with individual verification. HSM-friendly,
//!   no trusted setup required.
//! - [`secp256r1`]: Attributable signatures with individual verification. HSM-friendly,
//!   no trusted setup required.
//! - [`bls12381_multisig`]: Attributable signatures with aggregated verification.
//!   Compact certificates while preserving attribution.
//! - [`bls12381_threshold`]: Non-attributable threshold signatures. Constant-size
//!   certificates regardless of committee size.

use super::types::Item;
use commonware_cryptography::{certificate, Digest};

/// Marker trait for signing schemes compatible with `aggregation`.
///
/// This trait binds a [`certificate::Scheme`] to the [`Item`] subject type used
/// by the aggregation protocol. It is automatically implemented for any scheme
/// whose subject type matches `&'a Item<D>`.
pub trait Scheme<D: Digest>: for<'a> certificate::Scheme<Subject<'a, D> = &'a Item<D>> {}

impl<D: Digest, S> Scheme<D> for S where S: for<'a> certificate::Scheme<Subject<'a, D> = &'a Item<D>>
{}

pub mod bls12381_multisig {
    //! BLS12-381 multi-signature implementation of the
    //! [`Scheme`](commonware_cryptography::certificate::Scheme) trait for `aggregation`.
    //!
    //! This scheme is attributable: certificates are compact while still preserving
    //! per-validator attribution.

    use crate::aggregation::types::{Item, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_multisig;

    impl_certificate_bls12381_multisig!(&'a Item<D>, Namespace);
}

pub mod bls12381_threshold {
    //! BLS12-381 threshold implementation of the [`Scheme`](commonware_cryptography::certificate::Scheme)
    //! trait for `aggregation`.
    //!
    //! This scheme is non-attributable: partial signatures should not be exposed as
    //! third-party evidence.

    use crate::aggregation::types::{Item, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_threshold;

    impl_certificate_bls12381_threshold!(&'a Item<D>, Namespace);
}

pub mod ed25519 {
    //! Ed25519 implementation of the [`Scheme`](commonware_cryptography::certificate::Scheme) trait
    //! for `aggregation`.
    //!
    //! This scheme is attributable: individual signatures can be safely exposed as
    //! evidence of liveness or faults.

    use crate::aggregation::types::{Item, Namespace};
    use commonware_cryptography::impl_certificate_ed25519;

    impl_certificate_ed25519!(&'a Item<D>, Namespace);
}

pub mod secp256r1 {
    //! Secp256r1 implementation of the [`Scheme`](commonware_cryptography::certificate::Scheme) trait
    //! for `aggregation`.
    //!
    //! This scheme is attributable: individual signatures can be safely exposed as
    //! evidence of liveness or faults.

    use crate::aggregation::types::{Item, Namespace};
    use commonware_cryptography::impl_certificate_secp256r1;

    impl_certificate_secp256r1!(&'a Item<D>, Namespace);
}
