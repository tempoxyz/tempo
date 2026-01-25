//! BLS threshold signing for bridge attestations.
//!
//! Uses the MinSig variant (G2 public keys, G1 signatures) to match consensus
//! signing, allowing reuse of the same DKG shares for both consensus and bridge.

use alloy_primitives::B256;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::bls12381::primitives::{
    group::{G1, G2, Private, Share},
    ops::sign,
    variant::MinSig,
};
use commonware_utils::Participant;

use crate::{
    attestation::PartialSignature,
    error::{BridgeError, Result},
    message::{BLS_DST, G1_COMPRESSED_LEN},
};

/// BLS threshold signer using a validator's key share.
///
/// The bridge uses the MinSig variant (same as consensus):
/// - Public keys on G2 (96 bytes compressed, 256 bytes uncompressed)
/// - Signatures on G1 (48 bytes compressed, 128 bytes uncompressed)
///
/// This allows reusing the same DKG shares from consensus for bridge signing.
/// The on-chain verification uses:
/// - DST: "TEMPO_BRIDGE_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_"
/// - hash_to_curve targeting G1
/// - Pairing check: e(H(m), pk) * e(sig, -G2) == 1
pub struct BLSSigner {
    /// The validator's share index (used in Lagrange interpolation).
    validator_index: u32,
    /// The validator's private key share from DKG (same as consensus share).
    share: Share,
}

impl BLSSigner {
    /// Create a new signer with a key share.
    pub fn new(share: Share) -> Self {
        Self {
            validator_index: share.index.get(),
            share,
        }
    }

    /// Create a signer from a validator index and private key.
    ///
    /// The share should come from the consensus DKG ceremony.
    /// The same share works for both consensus and bridge signing.
    pub fn from_index_and_private(index: u32, private: Private) -> Self {
        let share = Share::new(Participant::new(index), private);
        Self::new(share)
    }

    /// Load a signer from a hex-encoded key share file.
    ///
    /// File format: hex-encoded bytes of a commonware Share.
    pub fn from_file(path: &str) -> Result<Self> {
        let hex_content = std::fs::read_to_string(path).map_err(|e| {
            BridgeError::Config(format!("failed to read key share file {path}: {e}"))
        })?;

        let hex_trimmed = hex_content.trim().trim_start_matches("0x");
        let bytes = const_hex::decode(hex_trimmed)
            .map_err(|e| BridgeError::Config(format!("invalid hex in key share file: {e}")))?;

        let share = Share::decode(&bytes[..])
            .map_err(|e| BridgeError::Config(format!("failed to parse key share: {e}")))?;

        Ok(Self::new(share))
    }

    /// Sign an attestation hash, returning a partial signature.
    ///
    /// The attestation hash is signed directly using the bridge's DST,
    /// which causes the hash to be mapped to a G1 point via RFC 9380
    /// hash-to-curve before signing.
    pub fn sign_partial(&self, attestation_hash: B256) -> Result<PartialSignature> {
        // Sign using the low-level sign function with our custom DST.
        // This hashes the attestation_hash to G1 using the DST, then
        // multiplies by the private key share.
        let signature: G1 =
            sign::<MinSig>(&self.share.private, BLS_DST, attestation_hash.as_slice());

        // Serialize the G1 signature (48 bytes compressed)
        let sig_bytes = serialize_g1(&signature)?;

        Ok(PartialSignature::new(self.validator_index, sig_bytes))
    }

    /// Get the validator index for this signer.
    pub fn validator_index(&self) -> u32 {
        self.validator_index
    }

    /// Get the public key corresponding to this share (G2 point).
    pub fn public_key(&self) -> G2 {
        self.share.public::<MinSig>()
    }
}

/// Serialize a G1 point to compressed bytes (48 bytes).
fn serialize_g1(point: &G1) -> Result<[u8; G1_COMPRESSED_LEN]> {
    let bytes = point.encode();
    if bytes.len() != G1_COMPRESSED_LEN {
        return Err(BridgeError::InvalidSignatureLength {
            expected: G1_COMPRESSED_LEN,
            actual: bytes.len(),
        });
    }

    let mut result = [0u8; G1_COMPRESSED_LEN];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Deserialize a G1 point from compressed bytes (48 bytes).
pub fn deserialize_g1(bytes: &[u8; G1_COMPRESSED_LEN]) -> Result<G1> {
    G1::decode(&bytes[..])
        .map_err(|e| BridgeError::Signing(format!("failed to deserialize G1 signature: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::bls12381::{
        dkg,
        primitives::{ops::verify, sharing::Mode},
    };
    use commonware_utils::{N3f1, NZU32};
    use rand::{SeedableRng, rngs::StdRng};

    /// Create test shares using DKG (MinSig variant, same as consensus).
    fn test_shares() -> Vec<Share> {
        let mut rng = StdRng::seed_from_u64(12345);
        let n = NZU32!(5);
        let (_sharing, shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::default(), n);
        shares
    }

    #[test]
    fn test_sign_partial_produces_valid_g1_signature() {
        let shares = test_shares();
        let share = shares[0].clone();
        let signer = BLSSigner::new(share.clone());

        let attestation_hash = B256::repeat_byte(0x42);
        let partial = signer.sign_partial(attestation_hash).unwrap();

        assert_eq!(partial.index, share.index.get());
        assert_eq!(partial.signature.len(), 48); // G1 compressed

        // Verify we can deserialize the signature
        let g1_sig = deserialize_g1(&partial.signature).unwrap();

        // Verify the signature against the share's public key (G2)
        let public_key = share.public::<MinSig>();
        let result = verify::<MinSig>(&public_key, BLS_DST, attestation_hash.as_slice(), &g1_sig);
        assert!(result.is_ok(), "signature should verify: {result:?}");
    }

    #[test]
    fn test_sign_partial_different_hashes_produce_different_sigs() {
        let shares = test_shares();
        let signer = BLSSigner::new(shares[1].clone());

        let hash1 = B256::repeat_byte(0x11);
        let hash2 = B256::repeat_byte(0x22);

        let partial1 = signer.sign_partial(hash1).unwrap();
        let partial2 = signer.sign_partial(hash2).unwrap();

        assert_ne!(partial1.signature, partial2.signature);
    }

    #[test]
    fn test_sign_partial_deterministic() {
        let shares = test_shares();
        let signer = BLSSigner::new(shares[2].clone());

        let hash = B256::repeat_byte(0x33);

        let partial1 = signer.sign_partial(hash).unwrap();
        let partial2 = signer.sign_partial(hash).unwrap();

        assert_eq!(partial1.signature, partial2.signature);
    }

    #[test]
    fn test_validator_index() {
        let shares = test_shares();
        let signer = BLSSigner::new(shares[0].clone());

        assert_eq!(signer.validator_index(), shares[0].index.get());
    }
}
