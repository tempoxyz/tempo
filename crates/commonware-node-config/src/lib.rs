//! Definitions to read and write a tempo consensus configuration.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{fmt::Display, path::Path};

use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use commonware_codec::{DecodeExt as _, Encode, ReadExt};
use commonware_cryptography::{
    Signer,
    bls12381::primitives::group::Share,
    ed25519::{PrivateKey, PublicKey},
};
use crypto_common::{KeySizeUser, generic_array::typenum::Unsigned as _, rand_core::CryptoRngCore};

#[cfg(test)]
mod tests;

const SIGNING_SHARE_KEY_ENV: &str = "TEMPO_SIGNING_SHARE_KEY";

pub fn sining_share_key_from_env() -> Result<Cipher, EncryptionKeyError> {
    Cipher::from_env(SIGNING_SHARE_KEY_ENV)
}

#[derive(Clone)]
pub struct EncryptionKey(Key);

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EncryptionKey").field(&"<REDACTED>").finish()
    }
}

impl EncryptionKey {
    /// Generates a random secret.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        EncryptionKey(ChaCha20Poly1305::generate_key(rng))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionKeyError> {
        if bytes.len() != ChaCha20Poly1305::key_size() {
            return Err(EncryptionKeyErrorKind::Invalid(crypto_common::InvalidLength).into());
        }
        Ok(Self(Key::clone_from_slice(bytes)))
    }

    pub fn from_hex(hex: &[u8]) -> Result<Self, EncryptionKeyError> {
        let bytes = const_hex::decode(hex).map_err(EncryptionKeyErrorKind::Hex)?;
        Self::from_bytes(&bytes)
    }

    /// Generates a random secret.
    pub fn to_hex(&self) -> String {
        const_hex::encode(self.0.as_slice())
    }

    pub fn to_cipher(&self) -> Cipher {
        Cipher::from_key(self)
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), EncryptionKeyError> {
        std::fs::write(path, self.to_hex()).map_err(EncryptionKeyErrorKind::Write)?;
        Ok(())
    }
}

/// The share used to encrypt the signing share at rest.
#[derive(Clone)]
pub struct Cipher(ChaCha20Poly1305);

impl Cipher {
    pub fn from_key(key: &EncryptionKey) -> Self {
        Self(ChaCha20Poly1305::new(&key.0))
    }

    /// Convenience method to construct a cipher directly from `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionKeyError> {
        let key =
            ChaCha20Poly1305::new_from_slice(&bytes).map_err(EncryptionKeyErrorKind::Invalid)?;
        Ok(Self(key))
    }

    /// Convenience method to construct a cipher directly from `[hex]`.
    pub fn from_hex(hex: &[u8]) -> Result<Self, EncryptionKeyError> {
        let bytes = const_hex::decode(hex).map_err(EncryptionKeyErrorKind::Hex)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_env(name: &'static str) -> Result<Self, EncryptionKeyError> {
        let hex = std::env::var(name)
            .map_err(|source| EncryptionKeyErrorKind::EnvVar { source, name })?;
        Self::from_bytes(hex.as_bytes())
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
    #[error("the encoded input length was invalid")]
    InvalidLength,
    #[error("failed decoding decrypted bytes into target type")]
    Decode(commonware_codec::Error),
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct EncryptionKeyError(EncryptionKeyErrorKind);

impl From<EncryptionKeyErrorKind> for EncryptionKeyError {
    fn from(value: EncryptionKeyErrorKind) -> Self {
        Self(value)
    }
}

#[derive(Debug, thiserror::Error)]
enum EncryptionKeyErrorKind {
    #[error("failed reading env var `{name}`")]
    EnvVar {
        name: &'static str,
        source: std::env::VarError,
    },
    #[error("env var was not hex encoded")]
    Hex(#[source] const_hex::FromHexError),
    #[error("key contained in env var was invalid")]
    Invalid(#[source] crypto_common::InvalidLength),
    #[error("failed to write encryption key to file")]
    Write(#[source] std::io::Error),
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

    fn try_from_hex(hex: &str) -> Result<Self, SigningKeyError> {
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

    pub fn read_from_file<P: AsRef<Path>>(
        path: P,
        key: &Cipher,
    ) -> Result<Self, SigningShareError> {
        let bytes = std::fs::read(path).map_err(SigningShareErrorKind::Read)?;
        Self::try_from_hex(&bytes, key)
    }

    pub fn try_from_hex(hex: &[u8], key: &Cipher) -> Result<Self, SigningShareError> {
        let bytes = const_hex::decode(hex).map_err(SigningShareErrorKind::Hex)?;
        let inner = key
            .decrypt_decodable::<Share>(&bytes)
            .map_err(SigningShareErrorKind::Decrypt)?;
        Ok(Self { inner })
    }

    pub fn write_to_file<P: AsRef<Path>>(
        &self,
        path: P,
        key: &Cipher,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), SigningShareError> {
        std::fs::write(path, self.to_hex(key, rng)).map_err(SigningShareErrorKind::Write)?;
        Ok(())
    }

    pub fn to_hex(&self, key: &Cipher, rng: &mut impl CryptoRngCore) -> String {
        const_hex::encode(key.encrypt_encodable(&self.inner, rng))
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
    #[error("failed decrypting bls12381 private share")]
    Decrypt(#[source] DecryptError),
    #[error("failed reading file")]
    Read(#[source] std::io::Error),
    #[error("failed writing to file")]
    Write(#[source] std::io::Error),
}
