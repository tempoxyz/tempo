//! Definitions to read and write a tempo consensus configuration.
//!
//! Key material can optionally be encrypted at rest using AES-256-GCM with
//! PBKDF2-derived keys. See the [`encrypted`] module for format details.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{fmt::Display, path::Path};

use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{
    bls12381::primitives::group::Share,
    ed25519::{PrivateKey, PublicKey},
    Signer,
};

pub mod encrypted;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct SigningKey {
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

    /// Reads a signing key from a file that may be either plaintext hex or an
    /// encrypted envelope. When `passphrase` is `Some`, encrypted files are
    /// decrypted transparently; plaintext files are still accepted regardless,
    /// which allows operators to migrate incrementally.
    pub fn read_maybe_encrypted<P: AsRef<Path>>(
        path: P,
        passphrase: Option<&[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let bytes = encrypted::read_maybe_encrypted(path.as_ref(), passphrase)
            .map_err(SigningKeyErrorKind::Encryption)?;
        let hex = String::from_utf8(bytes)
            .map_err(|_| SigningKeyErrorKind::Hex(const_hex::FromHexError::InvalidStringLength))?;
        Self::try_from_hex(hex.trim())
    }

    pub fn try_from_hex(hex: &str) -> Result<Self, SigningKeyError> {
        let bytes = const_hex::decode(hex).map_err(SigningKeyErrorKind::Hex)?;
        let inner = PrivateKey::decode(&bytes[..]).map_err(SigningKeyErrorKind::Parse)?;
        Ok(Self { inner })
    }

    /// Writes the signing key to `writer`.
    pub fn to_writer<W: std::io::Write>(&self, mut writer: W) -> Result<(), SigningKeyError> {
        writer
            .write_all(self.to_string().as_bytes())
            .map_err(SigningKeyErrorKind::Write)?;
        Ok(())
    }

    /// Writes the signing key to `path`, encrypted with `passphrase`.
    pub fn write_encrypted<P: AsRef<Path>>(
        &self,
        path: P,
        passphrase: &[u8],
    ) -> Result<(), SigningKeyError> {
        encrypted::write_encrypted(path.as_ref(), self.to_string().as_bytes(), passphrase)
            .map_err(SigningKeyErrorKind::Encryption)?;
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
    #[error("encryption/decryption failed")]
    Encryption(#[source] encrypted::EncryptionError),
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

    /// Reads a signing share from a file that may be either plaintext hex or
    /// an encrypted envelope (see [`SigningKey::read_maybe_encrypted`]).
    pub fn read_maybe_encrypted<P: AsRef<Path>>(
        path: P,
        passphrase: Option<&[u8]>,
    ) -> Result<Self, SigningShareError> {
        let bytes = encrypted::read_maybe_encrypted(path.as_ref(), passphrase)
            .map_err(SigningShareErrorKind::Encryption)?;
        let hex = String::from_utf8(bytes).map_err(|_| {
            SigningShareErrorKind::Hex(const_hex::FromHexError::InvalidStringLength)
        })?;
        Self::try_from_hex(hex.trim())
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

    /// Writes the signing share to `path`, encrypted with `passphrase`.
    pub fn write_encrypted<P: AsRef<Path>>(
        &self,
        path: P,
        passphrase: &[u8],
    ) -> Result<(), SigningShareError> {
        encrypted::write_encrypted(path.as_ref(), self.to_string().as_bytes(), passphrase)
            .map_err(SigningShareErrorKind::Encryption)?;
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
    #[error("encryption/decryption failed")]
    Encryption(#[source] encrypted::EncryptionError),
}
