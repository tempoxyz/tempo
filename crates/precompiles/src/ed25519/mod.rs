pub mod dispatch;

pub use tempo_contracts::precompiles::IEd25519;
use tempo_contracts::precompiles::Ed25519Error;

use crate::{error::Result, input_cost};
use alloy::primitives::{Bytes, B256};
use ed25519_dalek::{Signature, VerifyingKey};

const BASE_GAS: u64 = 3_000;
const INPUT_OVERHEAD_GAS: u64 = 100;
const GAS_PER_WORD: u64 = 3;
const BATCH_PER_SIG_GAS: u64 = 2_500;

pub struct Ed25519Verifier;

impl Ed25519Verifier {
    pub const fn new() -> Self {
        Self
    }

    fn calculate_gas(message_len: usize) -> u64 {
        let words = (message_len as u64 + 31) / 32;
        BASE_GAS + INPUT_OVERHEAD_GAS + words * GAS_PER_WORD
    }

    fn calculate_batch_gas(messages: &[Bytes]) -> u64 {
        let n = messages.len() as u64;
        let message_gas: u64 = messages
            .iter()
            .map(|m| ((m.len() as u64 + 31) / 32) * GAS_PER_WORD)
            .sum();
        BASE_GAS + n * BATCH_PER_SIG_GAS + message_gas
    }

    fn verify_internal(
        message: &[u8],
        signature_r: B256,
        signature_s: B256,
        public_key: B256,
    ) -> bool {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(signature_r.as_slice());
        sig_bytes[32..].copy_from_slice(signature_s.as_slice());

        let signature = Signature::from_bytes(&sig_bytes);

        let pk_bytes: &[u8; 32] = match public_key.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(pk_bytes) {
            Ok(key) => key,
            Err(_) => return false,
        };

        verifying_key.verify_strict(message, &signature).is_ok()
    }

    pub fn verify(&self, call: IEd25519::verifyCall) -> Result<(bool, u64)> {
        let gas = Self::calculate_gas(call.message.len()) + input_cost(call.message.len());
        let valid = Self::verify_internal(
            &call.message,
            call.signatureR,
            call.signatureS,
            call.publicKey,
        );
        Ok((valid, gas))
    }

    pub fn verify_packed(&self, call: IEd25519::verifyPackedCall) -> Result<(bool, u64)> {
        let gas = Self::calculate_gas(call.message.len()) + input_cost(call.message.len());
        if call.signature.len() != 64 {
            return Err(Ed25519Error::invalid_signature_length().into());
        }
        let signature_r = B256::from_slice(&call.signature[..32]);
        let signature_s = B256::from_slice(&call.signature[32..]);
        let valid =
            Self::verify_internal(&call.message, signature_r, signature_s, call.publicKey);
        Ok((valid, gas))
    }

    pub fn verify_batch(&self, call: IEd25519::verifyBatchCall) -> Result<(bool, u64)> {
        let len = call.messages.len();
        if len == 0 {
            return Err(Ed25519Error::empty_batch().into());
        }
        if call.signaturesR.len() != len
            || call.signaturesS.len() != len
            || call.publicKeys.len() != len
        {
            return Err(Ed25519Error::array_length_mismatch().into());
        }

        let gas = Self::calculate_batch_gas(&call.messages)
            + call
                .messages
                .iter()
                .map(|m| input_cost(m.len()))
                .sum::<u64>();

        for i in 0..len {
            if !Self::verify_internal(
                &call.messages[i],
                call.signaturesR[i],
                call.signaturesS[i],
                call.publicKeys[i],
            ) {
                return Ok((false, gas));
            }
        }
        Ok((true, gas))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Bytes;
    use ed25519_dalek::{Signer, SigningKey};

    fn generate_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let mut secret_bytes = [0u8; 32];
        rand_08::RngCore::fill_bytes(&mut rand_08::rngs::OsRng, &mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn sign_message(signing_key: &SigningKey, message: &[u8]) -> (B256, B256) {
        let sig = signing_key.sign(message);
        let sig_bytes = sig.to_bytes();
        (
            B256::from_slice(&sig_bytes[..32]),
            B256::from_slice(&sig_bytes[32..]),
        )
    }

    #[test]
    fn test_valid_signature() {
        let (sk, vk) = generate_keypair();
        let msg = b"Hello, Ed25519!";
        let (r, s) = sign_message(&sk, msg);
        let pk = B256::from_slice(vk.as_bytes());

        let verifier = Ed25519Verifier::new();
        let (valid, gas) = verifier
            .verify(IEd25519::verifyCall {
                message: Bytes::copy_from_slice(msg),
                signatureR: r,
                signatureS: s,
                publicKey: pk,
            })
            .unwrap();

        assert!(valid);
        assert!(gas > 0);
    }

    #[test]
    fn test_invalid_signature() {
        let (sk, vk) = generate_keypair();
        let msg = b"Hello, Ed25519!";
        let (r, _s) = sign_message(&sk, msg);
        let pk = B256::from_slice(vk.as_bytes());

        let verifier = Ed25519Verifier::new();
        let (valid, _) = verifier
            .verify(IEd25519::verifyCall {
                message: Bytes::copy_from_slice(msg),
                signatureR: r,
                signatureS: B256::ZERO,
                publicKey: pk,
            })
            .unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_wrong_message() {
        let (sk, vk) = generate_keypair();
        let msg = b"Hello, Ed25519!";
        let (r, s) = sign_message(&sk, msg);
        let pk = B256::from_slice(vk.as_bytes());

        let verifier = Ed25519Verifier::new();
        let (valid, _) = verifier
            .verify(IEd25519::verifyCall {
                message: Bytes::copy_from_slice(b"Wrong message"),
                signatureR: r,
                signatureS: s,
                publicKey: pk,
            })
            .unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_verify_packed() {
        let (sk, vk) = generate_keypair();
        let msg = b"Packed test";
        let sig = sk.sign(msg);
        let sig_bytes = sig.to_bytes();
        let pk = B256::from_slice(vk.as_bytes());

        let verifier = Ed25519Verifier::new();
        let (valid, _) = verifier
            .verify_packed(IEd25519::verifyPackedCall {
                message: Bytes::copy_from_slice(msg),
                signature: Bytes::copy_from_slice(&sig_bytes),
                publicKey: pk,
            })
            .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_verify_packed_invalid_length() {
        let verifier = Ed25519Verifier::new();
        let result = verifier.verify_packed(IEd25519::verifyPackedCall {
            message: Bytes::copy_from_slice(b"test"),
            signature: Bytes::copy_from_slice(&[0u8; 32]),
            publicKey: B256::ZERO,
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_batch() {
        let (sk1, vk1) = generate_keypair();
        let (sk2, vk2) = generate_keypair();

        let msg1 = b"Message 1";
        let msg2 = b"Message 2";
        let (r1, s1) = sign_message(&sk1, msg1);
        let (r2, s2) = sign_message(&sk2, msg2);

        let verifier = Ed25519Verifier::new();
        let (valid, _) = verifier
            .verify_batch(IEd25519::verifyBatchCall {
                messages: vec![
                    Bytes::copy_from_slice(msg1),
                    Bytes::copy_from_slice(msg2),
                ],
                signaturesR: vec![r1, r2],
                signaturesS: vec![s1, s2],
                publicKeys: vec![
                    B256::from_slice(vk1.as_bytes()),
                    B256::from_slice(vk2.as_bytes()),
                ],
            })
            .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_verify_batch_empty() {
        let verifier = Ed25519Verifier::new();
        let result = verifier.verify_batch(IEd25519::verifyBatchCall {
            messages: vec![],
            signaturesR: vec![],
            signaturesS: vec![],
            publicKeys: vec![],
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_batch_length_mismatch() {
        let verifier = Ed25519Verifier::new();
        let result = verifier.verify_batch(IEd25519::verifyBatchCall {
            messages: vec![Bytes::copy_from_slice(b"test")],
            signaturesR: vec![B256::ZERO, B256::ZERO],
            signaturesS: vec![B256::ZERO],
            publicKeys: vec![B256::ZERO],
        });

        assert!(result.is_err());
    }
}
