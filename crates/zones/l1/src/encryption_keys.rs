use alloy_primitives::{B256, U256};
use parking_lot::RwLock;
use std::{collections::BTreeMap, sync::Arc};
use tracing::warn;

use crate::EncryptionKeyRotation;

/// Private keys available for decrypting finalized deposits.
///
/// Keys are configured by their private material and bound to Portal indexes when the
/// corresponding finalized registration is observed. The Portal remains authoritative for key
/// validity; this ring only ensures deposits are decrypted with the key named by `keyIndex`.
#[derive(Clone, Default)]
pub struct EncryptionKeyRing {
    inner: Arc<RwLock<EncryptionKeys>>,
}

#[derive(Default)]
struct EncryptionKeys {
    candidates: BTreeMap<(B256, u8), k256::SecretKey>,
    by_index: BTreeMap<U256, k256::SecretKey>,
    /// Finalized Portal key indexes whose public key has no private material on this node.
    unbound: BTreeMap<U256, (B256, u8)>,
}

/// Public fingerprint of locally configured decryption-key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyFingerprint {
    pub x: B256,
    pub y_parity: u8,
}

/// Public fingerprint associated with a finalized Portal key index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundPublicKeyFingerprint {
    pub key_index: U256,
    pub x: B256,
    pub y_parity: u8,
}

/// Public-only status of a node's decryption-key ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKeyPublicStatus {
    pub candidates: Vec<PublicKeyFingerprint>,
    pub bound: Vec<BoundPublicKeyFingerprint>,
}

impl std::fmt::Debug for EncryptionKeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys = self.inner.read();
        f.debug_struct("EncryptionKeyRing")
            .field("candidate_count", &keys.candidates.len())
            .field("bound_count", &keys.by_index.len())
            .field("unbound_count", &keys.unbound.len())
            .finish()
    }
}

impl EncryptionKeyRing {
    /// Create a ring from private keys that may appear in the Portal's append-only key history.
    pub fn new(keys: impl IntoIterator<Item = k256::SecretKey>) -> Self {
        let ring = Self::default();
        for key in keys {
            ring.add_candidate(key);
        }
        ring
    }

    /// Add private key material before its Portal registration is observed.
    pub fn add_candidate(&self, key: k256::SecretKey) {
        self.inner.write().candidates.insert(public_key(&key), key);
    }

    /// Bind a finalized Portal key registration to matching configured private material.
    ///
    /// A registration without configured private material is recorded by its public key only, so
    /// L1 ingestion continues and [`Self::key`] fails for that index. Errors only when the index
    /// was already recorded with a different public key.
    pub fn apply_rotation(&self, rotation: &EncryptionKeyRotation) -> eyre::Result<()> {
        let mut keys = self.inner.write();
        let public = (rotation.x, rotation.y_parity);
        let existing = keys
            .by_index
            .get(&rotation.key_index)
            .map(public_key)
            .or_else(|| keys.unbound.get(&rotation.key_index).copied());
        if let Some(existing) = existing {
            eyre::ensure!(
                existing == public,
                "Portal key index {} was already bound to a different key",
                rotation.key_index
            );
            return Ok(());
        }

        if let Some(key) = keys.candidates.get(&public).cloned() {
            keys.by_index.insert(rotation.key_index, key);
        } else {
            warn!(
                key_index = %rotation.key_index,
                activation_block = rotation.activation_block,
                "No private decryption key is configured for finalized Portal key index; \
                 deposits encrypted to it cannot be decrypted by this node"
            );
            keys.unbound.insert(rotation.key_index, public);
        }
        Ok(())
    }

    /// Return the private key registered at `key_index`.
    ///
    /// Errors when the index is unknown or its key has no private material on this node.
    pub fn key(&self, key_index: U256) -> eyre::Result<k256::SecretKey> {
        let keys = self.inner.read();
        if let Some(key) = keys.by_index.get(&key_index) {
            return Ok(key.clone());
        }
        eyre::ensure!(
            !keys.unbound.contains_key(&key_index),
            "missing private decryption key for finalized Portal key index {key_index}"
        );
        eyre::bail!("no private decryption key is bound to Portal key index {key_index}")
    }

    /// Return only public fingerprints and Portal bindings for operator observability.
    ///
    /// Private keys and their source paths are intentionally not exposed.
    pub fn public_status(&self) -> EncryptionKeyPublicStatus {
        let keys = self.inner.read();
        let candidates = keys
            .candidates
            .keys()
            .map(|(x, y_parity)| PublicKeyFingerprint {
                x: *x,
                y_parity: *y_parity,
            })
            .collect();
        let bound = keys
            .by_index
            .iter()
            .map(|(index, key)| {
                let (x, y_parity) = public_key(key);
                BoundPublicKeyFingerprint {
                    key_index: *index,
                    x,
                    y_parity,
                }
            })
            .collect();
        EncryptionKeyPublicStatus { candidates, bound }
    }
}

fn public_key(key: &k256::SecretKey) -> (B256, u8) {
    crate::precompiles::ecies::compressed_x_and_parity(key.public_key().as_affine())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rotation(
        key: &k256::SecretKey,
        key_index: u64,
        activation_block: u64,
    ) -> EncryptionKeyRotation {
        let (x, y_parity) = public_key(key);
        EncryptionKeyRotation {
            x,
            y_parity,
            pubkey: crate::encryption_key_address(x, y_parity).unwrap(),
            key_index: U256::from(key_index),
            activation_block,
        }
    }

    #[test]
    fn binds_configured_keys_to_their_portal_indexes() {
        let old = k256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let current = k256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let ring = EncryptionKeyRing::new([old.clone(), current.clone()]);

        ring.apply_rotation(&rotation(&old, 0, 10)).unwrap();
        ring.apply_rotation(&rotation(&current, 1, 20)).unwrap();

        assert_eq!(ring.key(U256::ZERO).unwrap().to_bytes(), old.to_bytes());
        assert_eq!(ring.key(U256::ONE).unwrap().to_bytes(), current.to_bytes());
    }

    #[test]
    fn records_a_rotation_without_its_private_key() {
        let configured = k256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let missing = k256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let ring = EncryptionKeyRing::new([configured.clone()]);

        ring.apply_rotation(&rotation(&missing, 1, 20)).unwrap();
        ring.apply_rotation(&rotation(&missing, 1, 20)).unwrap();
        assert_eq!(
            ring.key(U256::ONE).unwrap_err().to_string(),
            "missing private decryption key for finalized Portal key index 1"
        );
        assert_eq!(
            ring.key(U256::from(2)).unwrap_err().to_string(),
            "no private decryption key is bound to Portal key index 2"
        );

        let err = ring
            .apply_rotation(&rotation(&configured, 1, 20))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Portal key index 1 was already bound to a different key"
        );
    }

    #[test]
    fn rejects_a_bound_index_rebound_to_an_unknown_key() {
        let configured = k256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let missing = k256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let ring = EncryptionKeyRing::new([configured.clone()]);
        ring.apply_rotation(&rotation(&configured, 0, 10)).unwrap();

        let err = ring.apply_rotation(&rotation(&missing, 0, 10)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Portal key index 0 was already bound to a different key"
        );
        assert_eq!(
            ring.key(U256::ZERO).unwrap().to_bytes(),
            configured.to_bytes()
        );
    }

    #[test]
    fn public_status_contains_no_secret_material() {
        let key = k256::SecretKey::from_slice(&[0x33; 32]).unwrap();
        let ring = EncryptionKeyRing::new([key.clone()]);
        ring.apply_rotation(&rotation(&key, 4, 20)).unwrap();

        let status = ring.public_status();
        let (x, y_parity) = public_key(&key);
        assert_eq!(
            status.candidates,
            vec![PublicKeyFingerprint { x, y_parity }]
        );
        assert_eq!(
            status.bound,
            vec![BoundPublicKeyFingerprint {
                key_index: U256::from(4),
                x,
                y_parity,
            }]
        );
    }
}
