use alloy_primitives::{B256, U256};
use parking_lot::RwLock;
use std::{
    collections::{BTreeMap, btree_map::Entry},
    sync::Arc,
};

use crate::EncryptionKeyRotation;

/// Private keys available for decrypting finalized deposits.
///
/// Keys are configured by their private material and bound to Portal indexes when the
/// corresponding finalized registration is observed. The Portal remains authoritative for key
/// validity; this ring only ensures deposits are decrypted with the key named by `keyIndex`.
///
/// Every registration is recorded, including keys this node has no private material for, which
/// another sequencer may register. Deposits to such a key fail in [`Self::key`] instead of
/// halting L1 ingestion.
#[derive(Clone, Default)]
pub struct EncryptionKeyRing {
    inner: Arc<RwLock<EncryptionKeys>>,
}

#[derive(Default)]
struct EncryptionKeys {
    candidates: BTreeMap<(B256, u8), k256::SecretKey>,
    /// Public key registered at each finalized Portal key index.
    by_index: BTreeMap<U256, (B256, u8)>,
}

impl EncryptionKeys {
    /// Portal key indexes whose private key is configured.
    fn bound(&self) -> impl Iterator<Item = (&U256, &(B256, u8))> {
        self.by_index
            .iter()
            .filter(|(_, public)| self.candidates.contains_key(public))
    }
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
            .field("registered_count", &keys.by_index.len())
            .field("bound_count", &keys.bound().count())
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

    /// Record a finalized Portal key registration.
    ///
    /// Returns whether private material for the registered key is configured.
    pub fn apply_rotation(&self, rotation: &EncryptionKeyRotation) -> eyre::Result<bool> {
        let mut keys = self.inner.write();
        let public = (rotation.x, rotation.y_parity);
        match keys.by_index.entry(rotation.key_index) {
            Entry::Occupied(entry) => eyre::ensure!(
                *entry.get() == public,
                "Portal key index {} was already bound to a different key",
                rotation.key_index
            ),
            Entry::Vacant(entry) => {
                entry.insert(public);
            }
        }
        Ok(keys.candidates.contains_key(&public))
    }

    /// Return the private key registered at `key_index`.
    pub fn key(&self, key_index: U256) -> eyre::Result<k256::SecretKey> {
        let keys = self.inner.read();
        let public = keys.by_index.get(&key_index).ok_or_else(|| {
            eyre::eyre!("no finalized Portal key registration at key index {key_index}")
        })?;
        keys.candidates.get(public).cloned().ok_or_else(|| {
            eyre::eyre!("missing private decryption key for Portal key index {key_index}")
        })
    }

    /// Whether private material for the given public key is configured.
    pub fn has_candidate(&self, x: B256, y_parity: u8) -> bool {
        self.inner.read().candidates.contains_key(&(x, y_parity))
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
            .bound()
            .map(|(index, (x, y_parity))| BoundPublicKeyFingerprint {
                key_index: *index,
                x: *x,
                y_parity: *y_parity,
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
        let ring = EncryptionKeyRing::new([configured]);

        assert!(!ring.apply_rotation(&rotation(&missing, 1, 20)).unwrap());
        let err = ring.key(U256::ONE).unwrap_err();
        assert!(err.to_string().contains("missing private decryption key"));
        assert!(ring.public_status().bound.is_empty());

        // Configuring the key later makes the registration usable.
        ring.add_candidate(missing.clone());
        assert_eq!(ring.key(U256::ONE).unwrap().to_bytes(), missing.to_bytes());
    }

    #[test]
    fn rejects_a_different_key_at_a_registered_index() {
        let first = k256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let second = k256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let ring = EncryptionKeyRing::new([first.clone()]);

        ring.apply_rotation(&rotation(&second, 1, 20)).unwrap();
        ring.apply_rotation(&rotation(&second, 1, 20)).unwrap();
        let err = ring.apply_rotation(&rotation(&first, 1, 20)).unwrap_err();
        assert!(err.to_string().contains("already bound to a different key"));
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
