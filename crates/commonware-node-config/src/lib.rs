//! Definitions to read and write a tempo consensus configuration.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{
    fmt::Display,
    io::{Read as _, Write as _},
    path::Path,
};

use commonware_codec::{DecodeExt as _, Encode as _, FixedSize as _, Write as CodecWrite};
use commonware_cryptography::{
    Signer,
    bls12381::primitives::group::Share,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random as _;
use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret as _, ExposeSecretMut as _, SecretBox, SecretString};

#[cfg(test)]
mod tests;

pub type SigningKeyPassphrase = SecretString;

pub const MAX_SIGNING_KEY_PASSPHRASE_BYTES: u64 = 1024;

/// Reads a signing-key passphrase from `path`.
///
/// The returned boolean reports whether the opened handle is a FIFO.
pub fn read_secret<P: AsRef<Path>>(path: P) -> std::io::Result<(SigningKeyPassphrase, bool)> {
    use std::os::unix::fs::FileTypeExt as _;

    let file = std::fs::File::open(path)?;
    let is_fifo = file.metadata()?.file_type().is_fifo();

    Ok((read_secret_inner(file)?, is_fifo))
}

fn read_secret_inner<R: std::io::Read>(reader: R) -> std::io::Result<SigningKeyPassphrase> {
    let mut reader = reader;
    let mut read_result = Ok(());
    let mut passphrase = SecretBox::init_with_mut(|buf: &mut String| {
        buf.reserve_exact((MAX_SIGNING_KEY_PASSPHRASE_BYTES + 1) as usize);

        let mut reader =
            std::io::BufReader::new(&mut reader).take(MAX_SIGNING_KEY_PASSPHRASE_BYTES + 1);
        read_result = reader.read_to_string(buf).map(|_| ());
        if read_result.is_err() {
            return;
        }

        if buf.len() as u64 > MAX_SIGNING_KEY_PASSPHRASE_BYTES {
            read_result = Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("passphrase exceeds {MAX_SIGNING_KEY_PASSPHRASE_BYTES} byte limit"),
            ));
            return;
        }

        while matches!(buf.as_bytes().last(), Some(b'\r' | b'\n')) {
            buf.pop();
        }
    });

    read_result?;

    // TODO: `SecretString::from(String)` uses `String::into_boxed_str`, which
    // can reallocate and leave secret bytes behind in the old allocation.
    Ok(SecretString::from(std::mem::take(
        passphrase.expose_secret_mut(),
    )))
}

#[derive(Clone, Debug)]
pub struct SigningKey {
    inner: PrivateKey,
}

impl SigningKey {
    pub fn into_inner(self) -> PrivateKey {
        self.inner
    }

    /// Generates a fresh, cryptographically random signing key using `rng`.
    pub fn random<R: CryptoRngCore>(rng: R) -> Self {
        Self {
            inner: PrivateKey::random(rng),
        }
    }

    pub fn read_from_file_unencrypted<P: AsRef<Path>>(path: P) -> Result<Self, SigningKeyError> {
        let hex = std::fs::read_to_string(path).map_err(SigningKeyErrorKind::Read)?;
        Self::try_from_hex(hex.trim())
    }

    /// Reads a passphrase-encrypted signing key from `path`.
    ///
    /// The file is expected to be an [age](https://age-encryption.org/v1)
    /// payload produced via passphrase encryption (e.g. `age -p`) whose
    /// plaintext is the raw encoded ed25519 private key (as produced by
    /// commonware-codec's `Encode` impl on [`PrivateKey`]).
    ///
    /// After decryption the plaintext buffer is zeroized.
    pub fn read_from_file_encrypted<P: AsRef<Path>>(
        path: P,
        passphrase: SecretString,
    ) -> Result<Self, SigningKeyError> {
        let file = std::fs::File::open(path).map_err(SigningKeyErrorKind::Read)?;
        Self::read_encrypted(std::io::BufReader::new(file), passphrase)
    }

    /// Reads a passphrase-encrypted signing key from an arbitrary
    /// [`std::io::Read`].
    pub fn read_encrypted<R: std::io::BufRead>(
        ciphertext: R,
        passphrase: SecretString,
    ) -> Result<Self, SigningKeyError> {
        let decryptor =
            age::Decryptor::new_buffered(ciphertext).map_err(SigningKeyErrorKind::Decrypt)?;
        let identity = age::scrypt::Identity::new(passphrase);

        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(SigningKeyErrorKind::Decrypt)?;

        let mut io_err: Option<std::io::Error> = None;
        let plaintext: SecretBox<[u8; PrivateKey::SIZE]> =
            SecretBox::init_with_mut(|buf: &mut [u8; PrivateKey::SIZE]| {
                io_err = reader.read_exact(buf).err()
            });
        if let Some(err) = io_err {
            return Err(SigningKeyErrorKind::Read(err).into());
        }

        let inner = PrivateKey::decode(plaintext.expose_secret().as_ref())
            .map_err(SigningKeyErrorKind::Parse)?;
        Ok(Self { inner })
    }

    /// Writes the signing key to `path` as a passphrase-encrypted age payload.
    pub fn write_to_file_encrypted<P: AsRef<Path>>(
        &self,
        path: P,
        passphrase: SecretString,
    ) -> Result<(), SigningKeyError> {
        let file = std::fs::File::create(path).map_err(SigningKeyErrorKind::Write)?;
        self.write_encrypted(file, passphrase)
    }

    /// Writes the signing key to an arbitrary [`std::io::Write`] as a
    /// passphrase-encrypted age payload. See [`Self::write_to_file_encrypted`].
    pub fn write_encrypted<W: std::io::Write>(
        &self,
        writer: W,
        passphrase: SecretString,
    ) -> Result<(), SigningKeyError> {
        // Serialize the private key bytes directly into a fixed-size,
        // auto-zeroizing buffer - no transient `Bytes`/`Vec` on the heap.
        let plaintext: SecretBox<[u8; PrivateKey::SIZE]> =
            SecretBox::init_with_mut(|buf: &mut [u8; PrivateKey::SIZE]| {
                let mut tail: &mut [u8] = buf;
                CodecWrite::write(&self.inner, &mut tail);
            });

        let mut age_writer = age::Encryptor::with_user_passphrase(passphrase)
            .wrap_output(writer)
            .map_err(SigningKeyErrorKind::Write)?;
        age_writer
            .write_all(plaintext.expose_secret())
            .map_err(SigningKeyErrorKind::Write)?;
        age_writer.finish().map_err(SigningKeyErrorKind::Write)?;

        Ok(())
    }

    pub fn try_from_hex(hex: &str) -> Result<Self, SigningKeyError> {
        let bytes = const_hex::decode(hex).map_err(SigningKeyErrorKind::Hex)?;
        let inner = PrivateKey::decode(&bytes[..]).map_err(SigningKeyErrorKind::Parse)?;
        Ok(Self { inner })
    }

    /// Writes the signing key to `writer` as `0x`-prefixed hex of the
    /// raw encoded ed25519 private key bytes.
    pub fn to_writer_unencrypted<W: std::io::Write>(
        &self,
        mut writer: W,
    ) -> Result<(), SigningKeyError> {
        let hex = const_hex::encode_prefixed(self.inner.encode().as_ref());
        writer
            .write_all(hex.as_bytes())
            .map_err(SigningKeyErrorKind::Write)?;
        Ok(())
    }

    pub fn public_key(&self) -> PublicKey {
        self.inner.public_key()
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
    #[error("failed decrypting age payload (wrong passphrase or malformed file?)")]
    Decrypt(#[source] age::DecryptError),
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
