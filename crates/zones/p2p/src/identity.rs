use std::path::Path;

use alloy_primitives::Address;
use alloy_signer_local::PrivateKeySigner;
use commonware_codec::DecodeExt as _;
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};

/// An Ed25519 private key loaded as a node's Commonware identity.
#[derive(Clone, Debug)]
pub(crate) struct Ed25519Identity(PrivateKey);

impl Ed25519Identity {
    /// Reads an unencrypted, hex-encoded identity from `path`.
    pub(crate) fn read_from_file(path: impl AsRef<Path>) -> Result<Self, Ed25519IdentityError> {
        let path = path.as_ref();
        let encoded =
            std::fs::read_to_string(path).map_err(|source| Ed25519IdentityError::Read {
                path: path.to_owned(),
                source,
            })?;
        Self::from_hex(encoded.trim())
    }

    /// Parses an unencrypted, hex-encoded identity.
    pub(crate) fn from_hex(encoded: &str) -> Result<Self, Ed25519IdentityError> {
        let bytes = const_hex::decode(encoded).map_err(Ed25519IdentityError::Hex)?;
        let key = PrivateKey::decode(&bytes[..]).map_err(Ed25519IdentityError::Decode)?;
        Ok(Self(key))
    }

    /// Returns the Ed25519 public key corresponding to this private key.
    pub(crate) fn ed25519_public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    pub(crate) fn into_private_key(self) -> PrivateKey {
        self.0
    }
}

/// A node's individual secp256k1 key.
#[derive(Clone, Debug)]
pub(crate) struct Secp256k1Identity(PrivateKeySigner);

impl Secp256k1Identity {
    /// Reads an unencrypted, hex-encoded private key from `path`.
    pub(crate) fn read_from_file(path: impl AsRef<Path>) -> Result<Self, Secp256k1IdentityError> {
        let path = path.as_ref();
        let encoded =
            std::fs::read_to_string(path).map_err(|source| Secp256k1IdentityError::Read {
                path: path.to_owned(),
                source,
            })?;
        Self::from_hex(encoded.trim())
    }

    /// Parses an unencrypted, hex-encoded secp256k1 private key.
    pub(crate) fn from_hex(encoded: &str) -> Result<Self, Secp256k1IdentityError> {
        encoded
            .parse::<PrivateKeySigner>()
            .map(Self)
            .map_err(|source| Secp256k1IdentityError::Invalid(source.to_string()))
    }

    /// Returns the address corresponding to this private key.
    pub(crate) fn address(&self) -> Address {
        self.0.address()
    }

    pub(crate) fn signer(&self) -> PrivateKeySigner {
        self.0.clone()
    }
}

/// Errors produced while loading a Commonware Ed25519 identity.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Ed25519IdentityError {
    #[error("failed reading Commonware Ed25519 identity `{path}`")]
    Read {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Commonware Ed25519 identity is not valid hex")]
    Hex(#[source] const_hex::FromHexError),

    #[error("Commonware identity is not a valid Ed25519 private key")]
    Decode(#[source] commonware_codec::Error),
}

/// Errors produced while loading a node's individual secp256k1 identity.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Secp256k1IdentityError {
    #[error("failed reading secp256k1 identity `{path}`")]
    Read {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid secp256k1 private key: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::{Ed25519Identity, Secp256k1Identity};

    #[test]
    fn parses_hex_identity() {
        let key = PrivateKey::from_seed(7);
        let identity =
            Ed25519Identity::from_hex(&const_hex::encode_prefixed(key.encode().as_ref())).unwrap();

        assert_eq!(identity.ed25519_public_key(), key.public_key());
    }

    #[test]
    fn parses_secp256k1_identity_without_exposing_the_key() {
        let identity = Secp256k1Identity::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        assert_eq!(
            identity.address().to_string(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
        assert!(!format!("{identity:?}").contains("0000000000000001"));
    }
}
