//!  A collection of various aliases of cryptography primitives that are used
//! throughout the node.
//!
//! These are primarily type aliases to make working with commonware types
//! easier. But there is also [`Digest`], which is a thin wrapper around
//! [`alloy_primitives::B256`] and used as the atom over which consensus is
//! established.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use std::ops::Deref;

use alloy_primitives::B256;
use commonware_codec::{FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{bls12381, bls12381::primitives::variant::Variant, ed25519};
use commonware_utils::{Array, Span};

// pub type Digest = sha256::Digest;
pub type Identity = <BlsScheme as Variant>::Public;
pub type GroupShare = bls12381::primitives::group::Share;
pub type PublicPolynomial = bls12381::primitives::poly::Poly<Identity>;

pub type PrivateKey = ed25519::PrivateKey;
pub type PublicKey = ed25519::PublicKey;

pub type BlsScheme = bls12381::primitives::variant::MinSig;
pub type BlsSignature = <BlsScheme as Variant>::Signature;
pub type BlsPublicKey = <BlsScheme as Variant>::Public;

/// Wrapper around [`B256`] to use it in places requiring [`commonware_cryptography::Digest`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Digest(pub B256);

impl Array for Digest {}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for Digest {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl commonware_cryptography::Digest for Digest {
    /// Generate a random digest.
    ///
    /// # Note
    ///
    /// One-to-one copy of [`commonware_cryptography::Digest`]
    /// for [`commonware_cryptography::sha256::Digest`].
    fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut array = B256::ZERO;
        rng.fill_bytes(&mut *array);
        Self(array)
    }
}

impl FixedSize for Digest {
    const SIZE: usize = 32;
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Read for Digest {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let array = <[u8; 32]>::read(buf)?;
        Ok(Self(B256::new(array)))
    }
}

impl Write for Digest {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf)
    }
}

impl Span for Digest {}
