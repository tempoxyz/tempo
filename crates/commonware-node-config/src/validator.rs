use std::net::{IpAddr, SocketAddr};

use alloy_primitives::{Address, B256, Keccak256};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::{Verifier as _, ed25519};
use tempo_contracts::precompiles::VALIDATOR_CONFIG_V2_ADDRESS;

/// Namespace used for ed25519 signatures when adding a validator.
pub const ADD_VALIDATOR_NAMESPACE: &[u8] = b"TEMPO_VALIDATOR_CONFIG_V2_ADD_VALIDATOR";

/// Namespace used for ed25519 signatures when rotating a validator.
pub const ROTATE_VALIDATOR_NAMESPACE: &[u8] = b"TEMPO_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR";

#[derive(Debug, thiserror::Error)]
pub enum ValidatorConfigError {
    #[error("invalid ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid ed25519 signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
}
pub struct ValidatorConfig {
    pub chain_id: u64,
    pub validator_address: Address,
    pub public_key: B256,
    pub ingress: SocketAddr,
    pub egress: IpAddr,
}

impl ValidatorConfig {
    /// Returns the keccak256 hash of the message preimage:
    /// `keccak256(chainId || contractAddr || validatorAddr || ingress || egress)`.
    pub fn message_hash(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.chain_id.to_be_bytes());
        hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
        hasher.update(self.validator_address.as_slice());
        hasher.update(self.ingress.to_string().as_bytes());
        hasher.update(self.egress.to_string().as_bytes());
        hasher.finalize()
    }

    /// Verifies that `signature` is a valid `addValidator` ed25519 signature.
    pub fn check_add_validator_signature(
        &self,
        signature: &[u8],
    ) -> Result<(), ValidatorConfigError> {
        self.check_signature(ADD_VALIDATOR_NAMESPACE, signature)
    }

    /// Verifies that `signature` is a valid `rotateValidator` ed25519 signature.
    pub fn check_rotate_validator_signature(
        &self,
        signature: &[u8],
    ) -> Result<(), ValidatorConfigError> {
        self.check_signature(ROTATE_VALIDATOR_NAMESPACE, signature)
    }

    fn check_signature(
        &self,
        namespace: &[u8],
        signature: &[u8],
    ) -> Result<(), ValidatorConfigError> {
        let public_key = ed25519::PublicKey::decode(self.public_key.as_slice())
            .map_err(|_| ValidatorConfigError::InvalidPublicKey)?;
        let sig = ed25519::Signature::decode(signature)
            .map_err(|_| ValidatorConfigError::InvalidSignature)?;
        let message = self.message_hash();
        if !public_key.verify(namespace, message.as_slice(), &sig) {
            return Err(ValidatorConfigError::SignatureVerificationFailed);
        }
        Ok(())
    }
}
