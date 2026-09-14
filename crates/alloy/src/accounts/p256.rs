//! Local P-256 signing for Tempo primitive signatures.

use std::fmt;

use alloy_primitives::{Address, B256, ChainId};
use alloy_signer::{Signer, SignerSync};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use serde::{Deserialize, Deserializer, de};
use sha2::{Digest, Sha256};
use tempo_primitives::transaction::{
    PrimitiveSignature, derive_p256_address, tt_signature::P256SignatureWithPreHash,
};

/// An extractable P-256 JSON Web Key as persisted by Tempo Accounts.
///
/// The encoded JWK strings are validated and decoded at deserialization. The
/// in-memory representation contains only fixed-size curve coordinates and a
/// private scalar.
#[derive(Clone)]
pub(super) struct P256Jwk {
    x: [u8; 32],
    y: [u8; 32],
    d: [u8; 32],
}

impl fmt::Debug for P256Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("P256Jwk")
            .field("curve", &"P-256")
            .field("public_key", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for P256Jwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct EncodedJwk {
            kty: String,
            crv: String,
            x: String,
            y: String,
            d: String,
        }

        let encoded = EncodedJwk::deserialize(deserializer)?;
        Self::from_base64url(
            &encoded.kty,
            &encoded.crv,
            &encoded.x,
            &encoded.y,
            &encoded.d,
        )
        .map_err(de::Error::custom)
    }
}

/// Errors returned while materializing a Tempo Accounts P-256 access key.
#[derive(Debug, thiserror::Error)]
pub(super) enum P256SignerError {
    /// The JWK does not describe a P-256 elliptic-curve key.
    #[error("expected an EC P-256 JWK")]
    UnsupportedJwk,
    /// A JWK coordinate or private scalar is not valid base64url.
    #[error("invalid base64url in P-256 JWK field {field}: {source}")]
    InvalidBase64 {
        /// JWK field name.
        field: &'static str,
        /// Decode error.
        source: base64::DecodeError,
    },
    /// The decoded field was not exactly 32 bytes.
    #[error("P-256 JWK field {field} must decode to 32 bytes")]
    InvalidLength {
        /// JWK field name.
        field: &'static str,
    },
    /// The private scalar is not a valid P-256 key.
    #[error("invalid P-256 private key")]
    InvalidPrivateKey,
    /// The JWK public coordinates do not match its private scalar.
    #[error("P-256 JWK public key does not match its private key")]
    PublicKeyMismatch,
}

/// A local P-256 signer producing canonical Tempo primitive signatures.
///
/// This uses Alloy's generic [`Signer`] and [`SignerSync`] traits with
/// [`PrimitiveSignature`] as the signature type.
#[derive(Clone)]
pub(super) struct TempoP256Signer {
    signing_key: SigningKey,
    pub_key_x: B256,
    pub_key_y: B256,
    address: Address,
    chain_id: Option<ChainId>,
    pre_hash: bool,
}

impl fmt::Debug for TempoP256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempoP256Signer")
            .field("address", &self.address)
            .field("chain_id", &self.chain_id)
            .field("pre_hash", &self.pre_hash)
            .finish_non_exhaustive()
    }
}

impl TempoP256Signer {
    /// Create a signer from a raw private scalar.
    ///
    /// The resulting signatures cover the supplied digest directly, matching
    /// `TempoAccount.fromP256`.
    pub(super) fn from_slice(private_key: &[u8]) -> Result<Self, P256SignerError> {
        Self::from_slice_with_pre_hash(private_key, false)
    }

    /// Create a signer from an Accounts WebCrypto JWK.
    ///
    /// WebCrypto ECDSA applies SHA-256 internally, so signatures produced from
    /// this key set the Tempo `preHash` flag and sign `SHA-256(digest)`.
    pub(super) fn from_webcrypto_jwk(jwk: &P256Jwk) -> Result<Self, P256SignerError> {
        let signer = Self::from_slice_with_pre_hash(&jwk.d, true)?;

        if signer.pub_key_x.as_slice() != jwk.x || signer.pub_key_y.as_slice() != jwk.y {
            return Err(P256SignerError::PublicKeyMismatch);
        }
        Ok(signer)
    }

    fn from_slice_with_pre_hash(
        private_key: &[u8],
        pre_hash: bool,
    ) -> Result<Self, P256SignerError> {
        let signing_key =
            SigningKey::from_slice(private_key).map_err(|_| P256SignerError::InvalidPrivateKey)?;
        let point = signing_key.verifying_key().to_encoded_point(false);
        let pub_key_x = point.x().ok_or(P256SignerError::InvalidPrivateKey)?;
        let pub_key_y = point.y().ok_or(P256SignerError::InvalidPrivateKey)?;
        let pub_key_x = B256::from_slice(pub_key_x);
        let pub_key_y = B256::from_slice(pub_key_y);
        let address = derive_p256_address(&pub_key_x, &pub_key_y);

        Ok(Self {
            signing_key,
            pub_key_x,
            pub_key_y,
            address,
            chain_id: None,
            pre_hash,
        })
    }

    /// Return whether this signer applies SHA-256 before ECDSA.
    #[cfg(test)]
    const fn pre_hash(&self) -> bool {
        self.pre_hash
    }

    fn sign_primitive(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        let digest = if self.pre_hash {
            B256::from_slice(&Sha256::digest(hash.as_slice()))
        } else {
            *hash
        };
        let signature: Signature = self
            .signing_key
            .sign_prehash(digest.as_slice())
            .map_err(alloy_signer::Error::other)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let bytes = signature.to_bytes();

        Ok(PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::from_slice(&bytes[..32]),
            s: B256::from_slice(&bytes[32..]),
            pub_key_x: self.pub_key_x,
            pub_key_y: self.pub_key_y,
            pre_hash: self.pre_hash,
        }))
    }
}

impl P256Jwk {
    /// Decode and validate an extractable WebCrypto P-256 JWK.
    fn from_base64url(
        key_type: &str,
        curve: &str,
        x: &str,
        y: &str,
        private_scalar: &str,
    ) -> Result<Self, P256SignerError> {
        if key_type != "EC" || curve != "P-256" {
            return Err(P256SignerError::UnsupportedJwk);
        }
        Ok(Self {
            x: decode_jwk_field("x", x)?,
            y: decode_jwk_field("y", y)?,
            d: decode_jwk_field("d", private_scalar)?,
        })
    }
}

#[async_trait::async_trait]
impl Signer<PrimitiveSignature> for TempoP256Signer {
    async fn sign_hash(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        self.sign_primitive(hash)
    }

    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}

impl SignerSync<PrimitiveSignature> for TempoP256Signer {
    fn sign_hash_sync(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        self.sign_primitive(hash)
    }

    fn chain_id_sync(&self) -> Option<ChainId> {
        self.chain_id
    }
}

fn decode_jwk_field(field: &'static str, value: &str) -> Result<[u8; 32], P256SignerError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|source| P256SignerError::InvalidBase64 { field, source })?;
    decoded
        .try_into()
        .map_err(|_| P256SignerError::InvalidLength { field })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn webcrypto_vector_jwk() -> P256Jwk {
        P256Jwk::from_base64url(
            "EC",
            "P-256",
            "OtOGGpViE5JRa7WT7wVYPtLlhm9ctiYKMBcjf9ibkK8",
            "0JYcfjcHWmeRo5xh9WKVsCttJlZ7YV5gqkHuHI6DOI0",
            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI",
        )
        .unwrap()
    }

    #[test]
    fn imports_accounts_webcrypto_jwk() {
        let signer = TempoP256Signer::from_webcrypto_jwk(&webcrypto_vector_jwk()).unwrap();
        assert_eq!(
            signer.address(),
            "0xf0159a522607cd6ab1097204c9fafb7bbe6afb6c"
                .parse::<Address>()
                .unwrap()
        );
        assert!(signer.pre_hash());
    }

    #[test]
    fn rejects_mismatched_public_coordinates() {
        let mut jwk = webcrypto_vector_jwk();
        jwk.x = [0u8; 32];
        assert!(matches!(
            TempoP256Signer::from_webcrypto_jwk(&jwk),
            Err(P256SignerError::PublicKeyMismatch)
        ));
    }
}
