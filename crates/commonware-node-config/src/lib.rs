//! Definitions to read and write a tempo consensus configuration.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{fmt::Display, path::Path};

use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use commonware_codec::{DecodeExt as _, Encode, ReadExt};
use commonware_cryptography::{
    Signer,
    bls12381::primitives::group::Share,
    ed25519::{PrivateKey, PublicKey},
};
use crypto_common::generic_array::typenum::Unsigned as _;
use crypto_common::rand_core::CryptoRngCore;

#[cfg(test)]
mod tests;

const SIGNING_SHARE_ENV: &str = "TEMPO_SIGNING_SHARE_SECRET";

/// The share used to encrypt the signing share at rest.
#[derive(Clone)]
pub struct SigningShareSecret(ChaCha20Poly1305);

impl SigningShareSecret {
    /// Generates a random secret.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(ChaCha20Poly1305::new(&ChaCha20Poly1305::generate_key(rng)))
    }

    pub fn from_env() -> Result<Self, SigningShareSecretError> {
        let hex = std::env::var(SIGNING_SHARE_ENV).map_err(SigningShareSecretErrorKind::EnvVar)?;
        let bytes = const_hex::decode(&hex).map_err(SigningShareSecretErrorKind::Hex)?;
        let key = ChaCha20Poly1305::new_from_slice(&bytes)
            .map_err(SigningShareSecretErrorKind::Invalid)?;
        Ok(Self(key))
    }

    pub fn encrypt_encodable(
        &self,
        encodable: &impl Encode,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<u8> {
        let nonce = ChaCha20Poly1305::generate_nonce(rng);
        let ciphertext = self
            .0
            .encrypt(&nonce, encodable.encode().as_ref())
            .expect("an encoded share should always fit into the maximum AEAD blocks");
        let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ciphertext);
        buf
    }

    pub fn decrypt(&self, encoded: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let Some((nonce, ciphertext)) =
            encoded.split_at_checked(<ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE)
        else {
            return Err(DecryptErrorKind::InvalidLength.into());
        };
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = self.0.decrypt(&nonce, ciphertext).unwrap();
        Ok(plaintext)
    }

    pub fn decrypt_decodable<T: ReadExt>(&self, encoded: &[u8]) -> Result<T, DecryptError> {
        let plaintext = self.decrypt(encoded)?;
        let this = ReadExt::read(&mut &plaintext[..]).map_err(DecryptErrorKind::Decode)?;
        Ok(this)
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct DecryptError(DecryptErrorKind);

impl From<DecryptErrorKind> for DecryptError {
    fn from(value: DecryptErrorKind) -> Self {
        Self(value)
    }
}

#[derive(Debug, thiserror::Error)]
enum DecryptErrorKind {
    #[error("the encoded input lenght was invalid")]
    InvalidLength,
    #[error("failed decoding decrypted bytes into target type")]
    Decode(commonware_codec::Error),
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SigningShareSecretError(SigningShareSecretErrorKind);

impl From<SigningShareSecretErrorKind> for SigningShareSecretError {
    fn from(value: SigningShareSecretErrorKind) -> Self {
        Self(value)
    }
}

#[derive(Debug, thiserror::Error)]
enum SigningShareSecretErrorKind {
    #[error("failed reading env var `{SIGNING_SHARE_ENV}`")]
    EnvVar(#[source] std::env::VarError),
    #[error("env var `{SIGNING_SHARE_ENV}` was not hex encoded")]
    Hex(#[source] const_hex::FromHexError),
    #[error("key contained in env var `{SIGNING_SHARE_ENV}` was invalid")]
    Invalid(#[source] crypto_common::InvalidLength),
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct SigningKey {
    #[debug(skip)]
    inner: PrivateKey,
}

impl SigningKey {
    pub fn into_inner(self) -> PrivateKey {
        self.inner
    }

    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Self, SigningKeyError> {
        let hex = std::fs::read_to_string(path).map_err(SigningKeyErrorKind::Read)?;
        Self::try_from_hex(&hex)
    }

    pub fn try_from_hex(hex: &str) -> Result<Self, SigningKeyError> {
        let bytes = const_hex::decode(hex).map_err(SigningKeyErrorKind::Hex)?;
        let inner = PrivateKey::decode(&bytes[..]).map_err(SigningKeyErrorKind::Parse)?;
        Ok(Self { inner })
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), SigningKeyError> {
        std::fs::write(path, self.to_string()).map_err(SigningKeyErrorKind::Write)?;
        Ok(())
    }

    pub fn public_key(&self) -> PublicKey {
        self.inner.public_key()
    }
}

impl Display for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&const_hex::encode_prefixed(self.inner.encode().as_ref()))
    }
}

impl From<PrivateKey> for SigningKey {
    fn from(inner: PrivateKey) -> Self {
        Self { inner }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SigningKeyError {
    #[from]
    inner: SigningKeyErrorKind,
}

#[derive(Debug, thiserror::Error)]
enum SigningKeyErrorKind {
    #[error("failed decoding file contents as hex-encoded bytes")]
    Hex(#[source] const_hex::FromHexError),
    #[error("failed parsing hex-decoded bytes as ed25519 private key")]
    Parse(#[source] commonware_codec::Error),
    #[error("failed reading file")]
    Read(#[source] std::io::Error),
    #[error("failed writing to file")]
    Write(#[source] std::io::Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningShare {
    inner: Share,
}

impl SigningShare {
    pub fn into_inner(self) -> Share {
        self.inner
    }

    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Self, SigningShareError> {
        let hex = std::fs::read_to_string(path).map_err(SigningShareErrorKind::Read)?;
        Self::try_from_hex(&hex)
    }

    pub fn try_from_hex(hex: &str) -> Result<Self, SigningShareError> {
        let bytes = const_hex::decode(hex).map_err(SigningShareErrorKind::Hex)?;
        let inner = Share::decode(&bytes[..]).map_err(SigningShareErrorKind::Parse)?;
        Ok(Self { inner })
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), SigningShareError> {
        std::fs::write(path, self.to_string()).map_err(SigningShareErrorKind::Write)?;
        Ok(())
    }
}

impl Display for SigningShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&const_hex::encode_prefixed(self.inner.encode().as_ref()))
    }
}

impl From<Share> for SigningShare {
    fn from(inner: Share) -> Self {
        Self { inner }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SigningShareError {
    #[from]
    inner: SigningShareErrorKind,
}

#[derive(Debug, thiserror::Error)]
enum SigningShareErrorKind {
    #[error("failed decoding file contents as hex-encoded bytes")]
    Hex(#[source] const_hex::FromHexError),
    #[error("failed parsing hex-decoded bytes as bls12381 private share")]
    Parse(#[source] commonware_codec::Error),
    #[error("failed reading file")]
    Read(#[source] std::io::Error),
    #[error("failed writing to file")]
    Write(#[source] std::io::Error),
}
