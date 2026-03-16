use std::net::{IpAddr, SocketAddr};

use alloy_primitives::{Address, B256, Keccak256};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::{Verifier as _, ed25519};
use tempo_contracts::precompiles::VALIDATOR_CONFIG_V2_ADDRESS;
use tempo_precompiles::validator_config_v2::{VALIDATOR_NS_ADD, VALIDATOR_NS_ROTATE};

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
    pub fee_recipient: Address,
}

impl ValidatorConfig {
    /// Returns the keccak256 hash of the message preimage:
    /// `keccak256(chainId || contractAddr || validatorAddr || ingress || egress)`.
    pub fn message_hash(&self) -> B256 {
        let ingress = self.ingress.to_string();
        let ingress_length = u8::try_from(ingress.len()).expect("ingress length must fit u8");

        let egress = self.egress.to_string();
        let egress_length = u8::try_from(egress.len()).expect("egress length must fit u8");

        let mut hasher = Keccak256::new();
        hasher.update(self.chain_id.to_be_bytes());
        hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
        hasher.update(self.validator_address.as_slice());
        hasher.update([ingress_length]);
        hasher.update(ingress.as_bytes());
        hasher.update([egress_length]);
        hasher.update(egress.as_bytes());
        hasher.update(self.fee_recipient.as_slice());
        hasher.finalize()
    }

    /// Verifies that `signature` is a valid `addValidator` ed25519 signature.
    pub fn check_add_validator_signature(
        &self,
        signature: &[u8],
    ) -> Result<(), ValidatorConfigError> {
        self.check_signature(VALIDATOR_NS_ADD, signature)
    }

    /// Verifies that `signature` is a valid `rotateValidator` ed25519 signature.
    pub fn check_rotate_validator_signature(
        &self,
        signature: &[u8],
    ) -> Result<(), ValidatorConfigError> {
        self.check_signature(VALIDATOR_NS_ROTATE, signature)
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
