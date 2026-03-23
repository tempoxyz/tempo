pub mod dispatch;

pub use tempo_contracts::precompiles::ISignatureVerifier;
use tempo_contracts::precompiles::SignatureVerifierError;

use crate::{SIGNATURE_VERIFIER_ADDRESS, error::Result};
use alloy::primitives::Address;
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::{
    SignatureType,
    tt_signature::PrimitiveSignature,
};

/// Gas cost for secp256k1 signature verification.
const SECP256K1_VERIFY_GAS: u64 = 3_000;

/// Gas cost for P256 signature verification.
const P256_VERIFY_GAS: u64 = 8_000;

/// Gas cost for WebAuthn signature verification.
const WEBAUTHN_VERIFY_GAS: u64 = 8_000;

#[contract(addr = SIGNATURE_VERIFIER_ADDRESS)]
pub struct SignatureVerifier {}

impl SignatureVerifier {
    pub fn verify(
        &mut self,
        call: ISignatureVerifier::verifyCall,
    ) -> Result<Address> {
        // Parse and validate signature (handles size checks + type disambiguation).
        let sig = PrimitiveSignature::from_bytes(&call.signature)
            .map_err(|_| SignatureVerifierError::invalid_signature_format())?;

        // Charge verification gas before crypto (SV5).
        let verify_gas = match sig.signature_type() {
            SignatureType::Secp256k1 => SECP256K1_VERIFY_GAS,
            SignatureType::P256 => P256_VERIFY_GAS,
            SignatureType::WebAuthn => WEBAUTHN_VERIFY_GAS,
        };
        self.storage.deduct_gas(verify_gas)?;

        // Verify and recover signer (SV1, SV2, SV4).
        let signer = sig
            .recover_signer(&call.hash)
            .map_err(|_| SignatureVerifierError::signature_verification_failed())?;

        Ok(signer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::primitives::{B256, Bytes};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_primitives::transaction::tt_signature::{
        SIGNATURE_TYPE_P256, SIGNATURE_TYPE_WEBAUTHN,
    };

    fn run<R>(f: impl FnOnce() -> R) -> R {
        let mut storage =
            HashMapStorageProvider::new_with_spec(1, tempo_chainspec::hardfork::TempoHardfork::T3);
        StorageCtx::enter(&mut storage, f)
    }

    fn make_verify_call(hash: B256, signature: Vec<u8>) -> ISignatureVerifier::verifyCall {
        ISignatureVerifier::verifyCall {
            hash,
            signature: Bytes::from(signature),
        }
    }

    #[test]
    fn test_verify_secp256k1_valid() {
        run(|| {
            let signer = PrivateKeySigner::random();
            let hash = B256::from([0xAA; 32]);
            let sig = signer.sign_hash_sync(&hash).unwrap();
            let sig_bytes = sig.as_bytes().to_vec();
            assert_eq!(sig_bytes.len(), 65);

            let mut verifier = SignatureVerifier::new();
            let result = verifier.verify(make_verify_call(hash, sig_bytes)).unwrap();
            assert_eq!(result, signer.address());
        })
    }

    #[test]
    fn test_verify_p256_valid() {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;
        use tempo_primitives::transaction::tt_signature::{
            derive_p256_address, normalize_p256_s,
        };

        run(|| {
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let encoded = verifying_key.to_encoded_point(false);
            let pub_key_x = B256::from_slice(encoded.x().unwrap());
            let pub_key_y = B256::from_slice(encoded.y().unwrap());
            let expected_address = derive_p256_address(&pub_key_x, &pub_key_y);

            let hash = B256::from([0xBB; 32]);
            let (signature, _) =
                signing_key.sign_prehash_recoverable(hash.as_slice()).unwrap();
            let r = B256::from_slice(&signature.r().to_bytes());
            let s = normalize_p256_s(&signature.s().to_bytes());

            // Build encoded P256 signature: 0x01 || r || s || x || y || prehash(0)
            let mut sig_bytes = Vec::with_capacity(130);
            sig_bytes.push(SIGNATURE_TYPE_P256);
            sig_bytes.extend_from_slice(r.as_slice());
            sig_bytes.extend_from_slice(s.as_slice());
            sig_bytes.extend_from_slice(pub_key_x.as_slice());
            sig_bytes.extend_from_slice(pub_key_y.as_slice());
            sig_bytes.push(0); // pre_hash = false
            assert_eq!(sig_bytes.len(), 130);

            let mut verifier = SignatureVerifier::new();
            let result = verifier.verify(make_verify_call(hash, sig_bytes)).unwrap();
            assert_eq!(result, expected_address);
        })
    }

    #[test]
    fn test_verify_empty_signature_reverts() {
        run(|| {
            let mut verifier = SignatureVerifier::new();
            let result = verifier.verify(make_verify_call(B256::ZERO, vec![]));
            assert!(result.is_err());
        })
    }

    #[test]
    fn test_verify_secp256k1_wrong_length_reverts() {
        run(|| {
            let mut verifier = SignatureVerifier::new();
            // 64 bytes — not 65
            let result = verifier.verify(make_verify_call(B256::ZERO, vec![0u8; 64]));
            assert!(result.is_err());
            // 66 bytes — not 65
            let result = verifier.verify(make_verify_call(B256::ZERO, vec![0u8; 66]));
            assert!(result.is_err());
        })
    }

    #[test]
    fn test_verify_p256_wrong_length_reverts() {
        run(|| {
            let mut verifier = SignatureVerifier::new();
            // 0x01 prefix + 128 bytes (should be 129)
            let mut sig = vec![SIGNATURE_TYPE_P256];
            sig.extend_from_slice(&[0u8; 128]);
            let result = verifier.verify(make_verify_call(B256::ZERO, sig));
            assert!(result.is_err());
        })
    }

    #[test]
    fn test_verify_webauthn_too_short_reverts() {
        run(|| {
            let mut verifier = SignatureVerifier::new();
            // 0x02 prefix + 127 bytes (min is 128)
            let mut sig = vec![SIGNATURE_TYPE_WEBAUTHN];
            sig.extend_from_slice(&[0u8; 127]);
            let result = verifier.verify(make_verify_call(B256::ZERO, sig));
            assert!(result.is_err());
        })
    }

    #[test]
    fn test_verify_webauthn_too_long_reverts() {
        run(|| {
            let mut verifier = SignatureVerifier::new();
            // 0x02 prefix + 2049 bytes (max is 2048)
            let mut sig = vec![SIGNATURE_TYPE_WEBAUTHN];
            sig.extend_from_slice(&[0u8; 2049]);
            let result = verifier.verify(make_verify_call(B256::ZERO, sig));
            assert!(result.is_err());
        })
    }

    #[test]
    fn test_verify_unknown_type_reverts() {
        run(|| {
            let mut verifier = SignatureVerifier::new();
            let mut sig = vec![0x05];
            sig.extend_from_slice(&[0u8; 129]);
            let result = verifier.verify(make_verify_call(B256::ZERO, sig));
            assert!(result.is_err());
        })
    }

    #[test]
    fn test_verify_invalid_secp256k1_signature_reverts() {
        run(|| {
            let mut verifier = SignatureVerifier::new();
            let result = verifier.verify(make_verify_call(B256::ZERO, vec![0u8; 65]));
            assert!(result.is_err());
        })
    }
}
