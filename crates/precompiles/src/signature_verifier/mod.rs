pub mod dispatch;

use crate::{SIGNATURE_VERIFIER_ADDRESS, error::Result};
use alloy::primitives::{Address, B256, Bytes, aliases::U384, keccak256, uint};
use aws_lc_rs::{
    digest::{Digest as AwsLcDigest, SHA256 as AwsLcSha256, SHA384 as AwsLcSha384},
    signature::{
        ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ParsedPublicKey as AwsLcParsedPublicKey,
    },
};
use sha2::{Digest, Sha256, Sha384};
use tempo_contracts::precompiles::SignatureVerifierError;
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::tt_signature::PrimitiveSignature;

/// Gas cost for secp256k1 signature verification.
const SECP256K1_VERIFY_GAS: u64 = 3_000;

/// Gas cost for P256 signature verification.
const P256_VERIFY_GAS: u64 = 8_000;

/// Gas cost for P384 signature verification.
const P384_VERIFY_GAS: u64 = 12_000;

/// Gas cost for WebAuthn signature verification.
const WEBAUTHN_VERIFY_GAS: u64 = 8_000;

/// P384 signatures use a precompile-specific type byte. `0x03` and `0x04` stay reserved for
/// keychain signatures, so the next free value is `0x05`.
const SIGNATURE_TYPE_P384: u8 = 0x05;

/// Encoded P384 payload length excluding the leading type byte.
const P384_SIGNATURE_LENGTH: usize = 48 * 4 + 1;

/// Encoded P384 signature length including the leading type byte.
const P384_ENCODED_SIGNATURE_LENGTH: usize = 1 + P384_SIGNATURE_LENGTH;

/// ES384 signatures are raw `r || s` values over a SHA-384 digest.
const ES384_SIGNATURE_LENGTH: usize = 48 * 2;
const ES384_DIGEST_LENGTH: usize = 48;
const P384_PUBLIC_KEY_LENGTH: usize = 48 * 2;
const P384_UNCOMPRESSED_PUBLIC_KEY_LENGTH: usize = 1 + P384_PUBLIC_KEY_LENGTH;

/// Gas cost for SHA-384 hashing, modeled after the native SHA-256 precompile pricing.
const SHA384_BASE_GAS: u64 = 60;
const SHA384_PER_WORD_GAS: u64 = 12;

/// The secp384r1 curve order n.
#[cfg(test)]
const P384_ORDER: U384 =
    uint!(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973_U384);

/// Half of the secp384r1 curve order (n/2).
const P384N_HALF: U384 =
    uint!(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE3B1A6C0FA1B96EFAC0D06D9245853BD76760CB5666294B9_U384);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P384SignatureWithPreHash {
    r: [u8; 48],
    s: [u8; 48],
    pub_key_x: [u8; 48],
    pub_key_y: [u8; 48],
    pre_hash: bool,
}

impl P384SignatureWithPreHash {
    fn recover_signer(
        &self,
        sig_hash: &B256,
    ) -> core::result::Result<Address, alloy::consensus::crypto::RecoveryError> {
        let message_hash = if self.pre_hash {
            B256::from_slice(Sha256::digest(sig_hash.as_slice()).as_ref())
        } else {
            *sig_hash
        };

        verify_p384_signature_with_aws_lc(
            &self.r,
            &self.s,
            &self.pub_key_x,
            &self.pub_key_y,
            &message_hash,
        )
        .map_err(|_| alloy::consensus::crypto::RecoveryError::new())?;

        Ok(derive_curve_address(&self.pub_key_x, &self.pub_key_y))
    }
}

enum ParsedSignature {
    Tempo(PrimitiveSignature),
    P384(P384SignatureWithPreHash),
}

impl ParsedSignature {
    fn from_bytes(data: &[u8]) -> core::result::Result<Self, &'static str> {
        if data.first() == Some(&SIGNATURE_TYPE_P384) {
            if data.len() != P384_ENCODED_SIGNATURE_LENGTH {
                return Err("Invalid P384 signature length");
            }

            let sig_data = &data[1..];
            let mut r = [0u8; 48];
            let mut s = [0u8; 48];
            let mut pub_key_x = [0u8; 48];
            let mut pub_key_y = [0u8; 48];
            r.copy_from_slice(&sig_data[0..48]);
            s.copy_from_slice(&sig_data[48..96]);
            pub_key_x.copy_from_slice(&sig_data[96..144]);
            pub_key_y.copy_from_slice(&sig_data[144..192]);

            return Ok(Self::P384(P384SignatureWithPreHash {
                r,
                s,
                pub_key_x,
                pub_key_y,
                pre_hash: sig_data[192] != 0,
            }));
        }

        PrimitiveSignature::from_bytes(data).map(Self::Tempo)
    }

    const fn verification_gas(&self) -> u64 {
        match self {
            Self::Tempo(PrimitiveSignature::Secp256k1(_)) => SECP256K1_VERIFY_GAS,
            Self::Tempo(PrimitiveSignature::P256(_)) => P256_VERIFY_GAS,
            Self::Tempo(PrimitiveSignature::WebAuthn(_)) => WEBAUTHN_VERIFY_GAS,
            Self::P384(_) => P384_VERIFY_GAS,
        }
    }

    fn recover_signer(
        &self,
        hash: &B256,
    ) -> core::result::Result<Address, alloy::consensus::crypto::RecoveryError> {
        match self {
            Self::Tempo(sig) => sig.recover_signer(hash),
            Self::P384(sig) => sig.recover_signer(hash),
        }
    }
}

fn derive_curve_address(pub_key_x: &[u8], pub_key_y: &[u8]) -> Address {
    let hash = keccak256([pub_key_x, pub_key_y].concat());
    Address::from_slice(&hash[12..])
}

fn concat<const N: usize>(slices: &[&[u8]]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut offset = 0;
    for slice in slices {
        out[offset..offset + slice.len()].copy_from_slice(slice);
        offset += slice.len();
    }
    debug_assert_eq!(offset, N, "slices length doesn't match array size");
    out
}

fn p384_signature_as_der(r: &[u8], s: &[u8]) -> core::result::Result<Vec<u8>, &'static str> {
    let signature = p384::ecdsa::Signature::from_slice(&concat::<96>(&[r, s]))
        .map_err(|_| "Invalid P384 signature encoding")?;
    Ok(signature.to_der().as_bytes().to_vec())
}

fn verify_p384_signature_with_aws_lc(
    r: &[u8; 48],
    s: &[u8; 48],
    pub_key_x: &[u8; 48],
    pub_key_y: &[u8; 48],
    message_hash: &B256,
) -> core::result::Result<(), &'static str> {
    if U384::from_be_slice(s) > P384N_HALF {
        return Err("P384 signature has high s value");
    }

    let encoded_point = concat::<97>(&[&[0x04], pub_key_x, pub_key_y]);
    let verifying_key = AwsLcParsedPublicKey::new(&ECDSA_P384_SHA256_ASN1, encoded_point)
        .map_err(|_| "Invalid P384 public key")?;
    let digest = AwsLcDigest::import_less_safe(message_hash.as_slice(), &AwsLcSha256)
        .map_err(|_| "Invalid P384 message digest")?;
    let der_signature = p384_signature_as_der(r, s)?;

    verifying_key
        .verify_digest_sig(&digest, &der_signature)
        .map_err(|_| "P384 signature verification failed")
}

fn encode_p384_public_key(public_key: &[u8]) -> core::result::Result<[u8; 97], &'static str> {
    match public_key.len() {
        P384_PUBLIC_KEY_LENGTH => {
            let mut encoded = [0u8; P384_UNCOMPRESSED_PUBLIC_KEY_LENGTH];
            encoded[0] = 0x04;
            encoded[1..].copy_from_slice(public_key);
            Ok(encoded)
        }
        P384_UNCOMPRESSED_PUBLIC_KEY_LENGTH if public_key[0] == 0x04 => {
            let mut encoded = [0u8; P384_UNCOMPRESSED_PUBLIC_KEY_LENGTH];
            encoded.copy_from_slice(public_key);
            Ok(encoded)
        }
        _ => Err("Invalid P384 public key encoding"),
    }
}

fn verify_es384_signature_with_aws_lc(
    digest: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> core::result::Result<bool, &'static str> {
    if digest.len() != ES384_DIGEST_LENGTH || signature.len() != ES384_SIGNATURE_LENGTH {
        return Err("Invalid ES384 digest or signature length");
    }

    let mut r = [0u8; 48];
    let mut s = [0u8; 48];
    r.copy_from_slice(&signature[..48]);
    s.copy_from_slice(&signature[48..]);

    let encoded_point = encode_p384_public_key(public_key)?;
    let verifying_key = AwsLcParsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, encoded_point)
        .map_err(|_| "Invalid P384 public key")?;
    let digest =
        AwsLcDigest::import_less_safe(digest, &AwsLcSha384).map_err(|_| "Invalid ES384 digest")?;
    let der_signature = p384_signature_as_der(&r, &s)?;

    Ok(verifying_key
        .verify_digest_sig(&digest, &der_signature)
        .is_ok())
}

fn sha384_gas_cost(input_len: usize) -> u64 {
    SHA384_BASE_GAS + input_len.div_ceil(32) as u64 * SHA384_PER_WORD_GAS
}

#[contract(addr = SIGNATURE_VERIFIER_ADDRESS)]
pub struct SignatureVerifier {}

impl SignatureVerifier {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn recover(&mut self, hash: B256, signature: Bytes) -> Result<Address> {
        // Parse and validate signature (handles size checks + type disambiguation).
        let sig = ParsedSignature::from_bytes(&signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;

        // Charge verification gas before performing verification.
        self.storage.deduct_gas(sig.verification_gas())?;

        // Verify and recover signer.
        sig.recover_signer(&hash)
            .map_err(|_| SignatureVerifierError::invalid_signature().into())
    }

    pub fn verify_es384(
        &mut self,
        digest: Bytes,
        signature: Bytes,
        public_key: Bytes,
    ) -> Result<bool> {
        self.storage.deduct_gas(P384_VERIFY_GAS)?;

        verify_es384_signature_with_aws_lc(&digest, &signature, &public_key)
            .map_err(|_| SignatureVerifierError::invalid_format().into())
    }

    pub fn sha384(&mut self, data: Bytes) -> Result<Bytes> {
        self.storage.deduct_gas(sha384_gas_cost(data.len()))?;
        let digest = Sha384::digest(data.as_ref());
        Ok(Bytes::copy_from_slice(digest.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use p384::{
        ecdsa::{SigningKey, signature::hazmat::PrehashSigner},
        elliptic_curve::rand_core::OsRng,
    };
    use sha2::Sha384;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::transaction::tt_signature::{
        SIGNATURE_TYPE_P256, SIGNATURE_TYPE_WEBAUTHN,
    };

    fn sign_recover(hash: B256, signature: Vec<u8>) -> Result<Address> {
        SignatureVerifier::new().recover(hash, Bytes::from(signature))
    }

    fn sign_p384(hash: B256, pre_hash: bool) -> eyre::Result<(Vec<u8>, Address)> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let encoded = verifying_key.to_encoded_point(false);
        let pub_key_x = encoded.x().ok_or_else(|| eyre::eyre!("missing x coord"))?;
        let pub_key_y = encoded.y().ok_or_else(|| eyre::eyre!("missing y coord"))?;
        let expected_address = derive_curve_address(pub_key_x, pub_key_y);

        let digest = if pre_hash {
            B256::from_slice(Sha256::digest(hash.as_slice()).as_ref())
        } else {
            hash
        };
        let signature: p384::ecdsa::Signature = signing_key.sign_prehash(digest.as_slice())?;
        let sig_bytes = signature.to_bytes();
        let normalized_s = {
            let s = U384::from_be_slice(&sig_bytes[48..96]);
            if s > P384N_HALF { P384_ORDER - s } else { s }
        };

        let mut encoded_sig = Vec::with_capacity(P384_ENCODED_SIGNATURE_LENGTH);
        encoded_sig.push(SIGNATURE_TYPE_P384);
        encoded_sig.extend_from_slice(&sig_bytes[..48]);
        encoded_sig.extend_from_slice(&normalized_s.to_be_bytes::<48>());
        encoded_sig.extend_from_slice(pub_key_x);
        encoded_sig.extend_from_slice(pub_key_y);
        encoded_sig.push(if pre_hash { 1 } else { 0 });
        assert_eq!(encoded_sig.len(), P384_ENCODED_SIGNATURE_LENGTH);

        Ok((encoded_sig, expected_address))
    }

    fn sign_es384_digest(message: &[u8]) -> eyre::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let encoded = verifying_key.to_encoded_point(false);
        let digest = Sha384::digest(message);
        let signature: p384::ecdsa::Signature = signing_key.sign_prehash(digest.as_slice())?;

        Ok((
            digest.to_vec(),
            signature.to_bytes().to_vec(),
            encoded.as_bytes().to_vec(),
        ))
    }

    #[test]
    fn test_verify_secp256k1_valid() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let signer = PrivateKeySigner::random();
            let hash = B256::from([0xAA; 32]);
            let sig = signer.sign_hash_sync(&hash)?;
            let sig_bytes = sig.as_bytes().to_vec();
            assert_eq!(sig_bytes.len(), 65);

            let result = sign_recover(hash, sig_bytes)?;
            assert_eq!(result, signer.address());
            Ok(())
        })
    }

    #[test]
    fn test_verify_p256_valid() -> eyre::Result<()> {
        use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
        use tempo_primitives::transaction::tt_signature::{derive_p256_address, normalize_p256_s};

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let encoded = verifying_key.to_encoded_point(false);
            let pub_key_x =
                B256::from_slice(encoded.x().ok_or_else(|| eyre::eyre!("missing x coord"))?);
            let pub_key_y =
                B256::from_slice(encoded.y().ok_or_else(|| eyre::eyre!("missing y coord"))?);
            let expected_address = derive_p256_address(&pub_key_x, &pub_key_y);

            let hash = B256::from([0xBB; 32]);
            let (signature, _) = signing_key.sign_prehash_recoverable(hash.as_slice())?;
            let r = B256::from_slice(&signature.r().to_bytes());
            let s =
                normalize_p256_s(&signature.s().to_bytes()).expect("p256 crate produces valid s");

            // Build encoded P256 signature: 0x01 || r || s || x || y || prehash(0)
            let mut sig_bytes = Vec::new();
            sig_bytes.push(SIGNATURE_TYPE_P256);
            sig_bytes.extend_from_slice(r.as_slice());
            sig_bytes.extend_from_slice(s.as_slice());
            sig_bytes.extend_from_slice(pub_key_x.as_slice());
            sig_bytes.extend_from_slice(pub_key_y.as_slice());
            sig_bytes.push(0); // pre_hash = false
            assert_eq!(sig_bytes.len(), 130);

            let result = sign_recover(hash, sig_bytes)?;
            assert_eq!(result, expected_address);
            Ok(())
        })
    }

    #[test]
    fn test_verify_p384_valid() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let hash = B256::from([0xCC; 32]);
            let (sig_bytes, expected_address) = sign_p384(hash, false)?;

            let result = sign_recover(hash, sig_bytes)?;
            assert_eq!(result, expected_address);
            Ok(())
        })
    }

    #[test]
    fn test_verify_p384_valid_with_prehash() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let hash = B256::from([0xCD; 32]);
            let (sig_bytes, expected_address) = sign_p384(hash, true)?;

            let result = sign_recover(hash, sig_bytes)?;
            assert_eq!(result, expected_address);
            Ok(())
        })
    }

    #[test]
    fn test_verify_es384_valid() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let (digest, signature, public_key) = sign_es384_digest(b"tempo es384")?;

            let result = SignatureVerifier::new().verify_es384(
                digest.into(),
                signature.into(),
                public_key.into(),
            )?;
            assert!(result);
            Ok(())
        })
    }

    #[test]
    fn test_sha384_hashes_input() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let input = b"tempo sha384";
            let digest = SignatureVerifier::new().sha384(Bytes::copy_from_slice(input))?;
            assert_eq!(digest.as_ref(), Sha384::digest(input).as_slice());
            Ok(())
        })
    }

    #[test]
    fn test_verify_empty_signature_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let result = sign_recover(B256::ZERO, vec![]);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_secp256k1_wrong_length_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            // 64 bytes — not 65
            let result = sign_recover(B256::ZERO, vec![0u8; 64]);
            assert!(result.is_err());
            // 66 bytes — not 65
            let result = sign_recover(B256::ZERO, vec![0u8; 66]);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_p256_wrong_length_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            // 0x01 prefix + 128 bytes (should be 129)
            let mut sig = vec![SIGNATURE_TYPE_P256];
            sig.extend_from_slice(&[0u8; 128]);
            let result = sign_recover(B256::ZERO, sig);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_p384_wrong_length_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut sig = vec![SIGNATURE_TYPE_P384];
            sig.extend_from_slice(&[0u8; P384_SIGNATURE_LENGTH - 1]);
            let result = sign_recover(B256::ZERO, sig);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_p384_high_s_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let hash = B256::from([0xCE; 32]);
            let (mut sig_bytes, _) = sign_p384(hash, false)?;

            let s = U384::from_be_slice(&sig_bytes[49..97]);
            let high_s = P384_ORDER - s;
            assert!(
                high_s > P384N_HALF,
                "mutated signature should use a high-s value"
            );
            sig_bytes[49..97].copy_from_slice(&high_s.to_be_bytes::<48>());

            let result = sign_recover(hash, sig_bytes);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_webauthn_too_short_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            // 0x02 prefix + 127 bytes (min is 128)
            let mut sig = vec![SIGNATURE_TYPE_WEBAUTHN];
            sig.extend_from_slice(&[0u8; 127]);
            let result = sign_recover(B256::ZERO, sig);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_webauthn_too_long_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            // 0x02 prefix + 2049 bytes (max is 2048)
            let mut sig = vec![SIGNATURE_TYPE_WEBAUTHN];
            sig.extend_from_slice(&[0u8; 2049]);
            let result = sign_recover(B256::ZERO, sig);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_unknown_type_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut sig = vec![0x06];
            sig.extend_from_slice(&[0u8; 129]);
            let result = sign_recover(B256::ZERO, sig);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_invalid_secp256k1_signature_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let result = sign_recover(B256::ZERO, vec![0u8; 65]);
            assert!(result.is_err());
            Ok(())
        })
    }
}
