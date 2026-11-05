//! Threshold-encrypted transaction payloads.
//!
//! A sender encrypts a transaction body to the network's long-lived BLS12-381 identity (the
//! constant term of the DKG polynomial, unchanged across reshares) under an identity bound to the
//! plaintext envelope that carries it. Validators release a partial signature over that identity
//! only after the block that includes the envelope is finalized, so contents stay hidden until
//! their position in the chain can no longer change, and envelopes that are never included are
//! never decrypted.
//!
//! The body is sealed with ChaCha20-Poly1305 under a fresh 32-byte key, and only that key is
//! timelock-encrypted ([`tle`]), so the pairing cost per transaction is constant in body size.

use alloy_primitives::{Address, B256, ChainId, U256, keccak256};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use commonware_cryptography::bls12381::{
    primitives::{
        group::Share,
        ops::{self, threshold},
        sharing::Sharing,
        variant::{MinSig, PartialSignature, Variant},
    },
    tle,
};
use commonware_parallel::Strategy;
use commonware_utils::{Participant, iter::NonEmpty};
use rand_core::CryptoRng;

/// Namespace for decryption-key signatures. Distinct from every consensus namespace, so a key
/// share can never be replayed as a vote or seed partial and vice versa.
pub const NAMESPACE: &[u8] = b"TEMPO_ENCRYPTED_TX_V1";

/// A key that decrypts exactly one [`EncryptedBody`]: the threshold signature over its identity.
pub type DecryptionKey = <MinSig as Variant>::Signature;

/// The network identity bodies are encrypted to.
pub type NetworkIdentity = <MinSig as Variant>::Public;

/// A validator's share of one [`DecryptionKey`].
pub type KeyShare = PartialSignature<MinSig>;

/// Errors from building or opening an encrypted body.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The network identity is the group identity element.
    #[error("timelock encryption failed")]
    Encrypt(#[from] tle::Error),
    /// The key does not open this body: wrong identity, wrong key or a tampered ciphertext.
    #[error("decryption key does not open this body")]
    Decrypt,
    /// Threshold recovery failed, or a share or key is invalid for its identity.
    #[error("threshold signature check failed")]
    Threshold(#[from] commonware_cryptography::bls12381::primitives::Error),
    /// A point failed to decode or is outside the prime-order subgroup.
    #[error("invalid curve point")]
    InvalidPoint,
    /// Recovered keys failed batched verification against the network identity.
    #[error("recovered keys do not verify against the network identity")]
    InvalidKey,
    /// A batch has a different number of signatures than identities.
    #[error("expected {expected} signatures, got {actual}")]
    LengthMismatch {
        /// Number of identities.
        expected: usize,
        /// Number of signatures supplied.
        actual: usize,
    },
}

/// The plaintext fields of an encrypted transaction that the pool validates and the block commits
/// to before contents are known: who pays, which nonce it consumes and how much gas it may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Chain the transaction is valid on.
    pub chain_id: ChainId,
    /// Account whose nonce is consumed and whose fee is charged at inclusion.
    pub sender: Address,
    /// 2D nonce key.
    pub nonce_key: U256,
    /// Nonce for `nonce_key`.
    pub nonce: u64,
    /// Gas reserved at inclusion and made available to the decrypted calls.
    pub gas_limit: u64,
}

impl Envelope {
    /// The identity a body is encrypted to: the envelope's fields and the hash of the sealed body.
    /// Copying a ciphertext into another envelope changes the identity, so its key never opens
    /// the copy.
    pub fn identity(&self, sealed_body_hash: B256) -> B256 {
        let mut buf = [0u8; 8 + 20 + 32 + 8 + 8 + 32];
        buf[..8].copy_from_slice(&self.chain_id.to_be_bytes());
        buf[8..28].copy_from_slice(self.sender.as_slice());
        buf[28..60].copy_from_slice(&self.nonce_key.to_be_bytes::<32>());
        buf[60..68].copy_from_slice(&self.nonce.to_be_bytes());
        buf[68..76].copy_from_slice(&self.gas_limit.to_be_bytes());
        buf[76..].copy_from_slice(sealed_body_hash.as_slice());
        keccak256(buf)
    }
}

/// A transaction body encrypted to an envelope's identity.
///
/// The identity cannot commit to [`Self::key`]: anyone can encrypt another key to the same
/// identity, which then fails to decrypt. The sender's signature and the transaction hash must
/// therefore cover both fields, not just the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedBody {
    /// The body key, timelock-encrypted to [`Envelope::identity`].
    pub key: tle::Ciphertext<MinSig>,
    /// The body sealed with ChaCha20-Poly1305 under that key, with a zero nonce: each key seals
    /// exactly one body.
    pub sealed: Vec<u8>,
}

impl EncryptedBody {
    /// Encrypts `body` for `envelope`, returning the ciphertext and its identity.
    pub fn encrypt(
        rng: &mut impl CryptoRng,
        network: NetworkIdentity,
        envelope: &Envelope,
        body: &[u8],
    ) -> Result<(Self, B256), Error> {
        let mut body_key = [0u8; 32];
        rng.fill_bytes(&mut body_key);
        let sealed = ChaCha20Poly1305::new(&body_key.into())
            .encrypt(&Default::default(), body)
            .expect("ChaCha20-Poly1305 encryption into a Vec cannot fail");
        let identity = envelope.identity(keccak256(&sealed));
        let key = tle::encrypt::<_, MinSig>(
            rng,
            network,
            (NAMESPACE, identity.as_slice()),
            &tle::Block::new(body_key),
        )?;
        Ok((Self { key, sealed }, identity))
    }

    /// Opens the body with the recovered key for its identity.
    pub fn decrypt(&self, key: &DecryptionKey) -> Result<Vec<u8>, Error> {
        let body_key = tle::decrypt::<MinSig>(key, &self.key).ok_or(Error::Decrypt)?;
        let body_key: [u8; 32] = body_key
            .as_ref()
            .try_into()
            .expect("tle blocks are 32 bytes");
        ChaCha20Poly1305::new(&body_key.into())
            .decrypt(&Default::default(), self.sealed.as_slice())
            .map_err(|_| Error::Decrypt)
    }
}

/// Signs every identity of a finalized block with this validator's share.
pub fn key_shares(share: &Share, identities: &[B256], strategy: &impl Strategy) -> Vec<KeyShare> {
    strategy.map_collect_vec(identities, |id| {
        threshold::sign_message::<MinSig>(share, NAMESPACE, id.as_slice())
    })
}

/// Checks one validator's shares for a block's identities with one batched pairing check.
pub fn verify_key_shares(
    rng: &mut impl CryptoRng,
    sharing: &Sharing<MinSig>,
    signer: Participant,
    identities: &[B256],
    shares: &[KeyShare],
    strategy: &impl Strategy,
) -> Result<(), Error> {
    ensure_same_len(identities, shares.len())?;
    let entries: Vec<_> = identities
        .iter()
        .zip(shares)
        .map(|(id, share)| (NAMESPACE, id.as_slice(), share.clone()))
        .collect();
    let Some(entries) = NonEmpty::try_new(entries.iter()) else {
        return Ok(());
    };
    Ok(threshold::batch_verify_same_signer::<_, MinSig, _>(
        rng, sharing, signer, entries, strategy,
    )?)
}

/// Recovers every identity's key from the same quorum of validators' verified shares.
///
/// `shares_by_validator[v][i]` is validator `v`'s share for identity `i`.
pub fn recover_keys(
    sharing: &Sharing<MinSig>,
    shares_by_validator: &[Vec<KeyShare>],
    strategy: &impl Strategy,
) -> Result<Vec<DecryptionKey>, Error> {
    let count = shares_by_validator.first().map_or(0, Vec::len);
    for shares in shares_by_validator {
        if shares.len() != count {
            return Err(Error::LengthMismatch {
                expected: count,
                actual: shares.len(),
            });
        }
    }
    let per_identity = (0..count)
        .map(|i| shares_by_validator.iter().map(move |shares| &shares[i]))
        .collect();
    Ok(threshold::recover_multiple::<MinSig, _>(
        sharing,
        per_identity,
        strategy,
    )?)
}

/// Checks the keys a block publishes against the network identity in one batched pairing check,
/// so a verifier never has to trust a proposer's claim that a body failed to decrypt.
pub fn verify_keys(
    rng: &mut impl CryptoRng,
    network: &NetworkIdentity,
    identities: &[B256],
    keys: &[DecryptionKey],
    strategy: &impl Strategy,
) -> Result<(), Error> {
    ensure_same_len(identities, keys.len())?;
    let entries = identities
        .iter()
        .zip(keys)
        .map(|(id, key)| (NAMESPACE, id.as_slice(), *key));
    let Some(entries) = NonEmpty::try_new(entries) else {
        return Ok(());
    };
    Ok(ops::batch::verify_same_signer::<_, MinSig, _>(
        rng, network, entries, strategy,
    )?)
}

fn ensure_same_len(identities: &[B256], actual: usize) -> Result<(), Error> {
    if identities.len() == actual {
        Ok(())
    } else {
        Err(Error::LengthMismatch {
            expected: identities.len(),
            actual,
        })
    }
}

pub mod fast;

#[cfg(test)]
mod tests;
