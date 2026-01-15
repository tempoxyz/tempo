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
use zeroize::{Zeroize as _, ZeroizeOnDrop, Zeroizing};

#[cfg(test)]
mod tests;

pub const DKG_ENCRYPTION_KEY: &str = "TEMPO_DKG_ENCRYPTION_KEY";

pub fn dkg_encryption_key_from_env() -> Result<EncryptionKey, EncryptionKeyError> {
    EncryptionKey::from_env(DKG_ENCRYPTION_KEY)
}

#[derive(Clone)]
pub struct EncryptionKey {
    // The cipher used for encryption/decryption.
    cipher: ChaCha20Poly1305,

    // The key to construct the cipher. This is actually included in
    // ChaCha20Poly1305, but not exposed in any way. We put the key next to the
    // cipher for ux reasons.
    key: Key,
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

impl ZeroizeOnDrop for EncryptionKey {}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("cipher", &"[REDACTED]")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl EncryptionKey {
    /// Generates a random secret.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let key = ChaCha20Poly1305::generate_key(rng);
        Self {
            cipher: ChaCha20Poly1305::new(&key),
            key,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionKeyError> {
        if bytes.len() != ChaCha20Poly1305::key_size() {
            return Err(EncryptionKeyErrorKind::Invalid(crypto_common::InvalidLength).into());
        }
        let key = Key::clone_from_slice(bytes);
        let cipher = ChaCha20Poly1305::new(&key);
        Ok(Self { cipher, key })
    }

    pub fn from_hex(hex: &[u8]) -> Result<Self, EncryptionKeyError> {
        let bytes = Zeroizing::new(const_hex::decode(hex).map_err(EncryptionKeyErrorKind::Hex)?);
        Self::from_bytes(&bytes)
    }

    /// Converts the encryption to a hex-encoded byte slice.
    pub fn to_hex(&self) -> String {
        const_hex::encode(self.key.as_slice())
    }

    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Self, EncryptionKeyError> {
        let bytes = Zeroizing::new(std::fs::read(path).map_err(EncryptionKeyErrorKind::Read)?);
        Self::from_hex(&bytes)
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), EncryptionKeyError> {
        let hexed = Zeroizing::new(self.to_hex());
        std::fs::write(path, hexed).map_err(EncryptionKeyErrorKind::Write)?;
        Ok(())
    }

    pub fn from_env(name: &'static str) -> Result<Self, EncryptionKeyError> {
        let hex = Zeroizing::new(
            std::env::var(name)
                .map_err(|source| EncryptionKeyErrorKind::EnvVar { source, name })?,
        );
        Self::from_hex(hex.as_bytes())
    }

    pub fn encrypt_encodable(
        &self,
        encodable: &impl Encode,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<u8> {
        struct Z(bytes::BytesMut);
        impl Drop for Z {
            fn drop(&mut self) {
                self.0.iter_mut().zeroize();
            }
        }
        impl ZeroizeOnDrop for Z {}
        let bytes = Z(encodable.encode_mut());
        self.encrypt(bytes.0.as_ref(), rng)
    }

    /// Encrypts `bytes` using the key.
    ///
    /// Encryption should only fail if
    pub fn encrypt(&self, bytes: &[u8], rng: &mut impl CryptoRngCore) -> Vec<u8> {
        let nonce = ChaCha20Poly1305::generate_nonce(rng);
        let ciphertext = self.cipher.encrypt(&nonce, bytes).expect(
            "this method should only be used with reasonably sized payloads \
                payloads should be well below 2^36 bytes, which is the maximum \
                permitted bytes size",
        );
        // .expect("an encoded share should always fit into the maximum AEAD blocks");
        let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ciphertext);
        buf
    }

    fn decrypt(&self, encoded: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let Some((nonce, ciphertext)) =
            encoded.split_at_checked(<ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE)
        else {
            return Err(DecryptErrorKind::InvalidLength.into());
        };
        let nonce = Nonce::from_slice(nonce);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(DecryptErrorKind::BadCipherText)?;
        Ok(plaintext)
    }

    pub fn decrypt_decodable<T: ReadExt>(&self, encoded: &[u8]) -> Result<T, DecryptError> {
        let plaintext = Zeroizing::new(self.decrypt(encoded)?);
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
    #[error("failed decrypting ciphertext")]
    BadCipherText(#[source] chacha20poly1305::Error),
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
    #[error("failed reading the key from the provided file")]
    Read(#[source] std::io::Error),
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
        key: &EncryptionKey,
    ) -> Result<Self, SigningShareError> {
        let bytes = std::fs::read(path).map_err(SigningShareErrorKind::Read)?;
        Self::try_from_hex(&bytes, key)
    }

    pub fn try_from_hex(hex: &[u8], key: &EncryptionKey) -> Result<Self, SigningShareError> {
        let bytes = const_hex::decode(hex).map_err(SigningShareErrorKind::Hex)?;
        let inner = key
            .decrypt_decodable::<Share>(&bytes)
            .map_err(SigningShareErrorKind::Decrypt)?;
        Ok(Self { inner })
    }

    pub fn write_to_file<P: AsRef<Path>>(
        &self,
        path: P,
        key: &EncryptionKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), SigningShareError> {
        std::fs::write(path, self.to_hex(key, rng)).map_err(SigningShareErrorKind::Write)?;
        Ok(())
    }

    pub fn to_hex(&self, key: &EncryptionKey, rng: &mut impl CryptoRngCore) -> String {
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
