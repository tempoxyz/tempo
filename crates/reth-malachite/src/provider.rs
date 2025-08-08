//! Cryptographic providers for signing and verification in Malachite consensus.
//!
//! This module provides the Ed25519 signing implementation required by Malachite
//! for signing and verifying consensus messages. It implements the necessary traits
//! to enable validators to participate in the consensus protocol by signing votes,
//! proposals, and other consensus messages.
//!
//! # Key Components
//!
//! - [`Ed25519Provider`]: Main signing provider implementing Malachite's `SigningProvider` trait
//! - [`ToSignBytes`]: Trait for converting consensus messages to canonical byte representations
//! - Re-exports of Ed25519 cryptographic types from the malachite-signing crate

use malachitebft_core_types::{
    SignedExtension, SignedProposal, SignedProposalPart, SignedVote, SigningProvider, SigningScheme,
};
pub use malachitebft_signing_ed25519::{PrivateKey, PublicKey, Signature};

use crate::{
    context::{BaseProposal, BaseVote, MalachiteContext},
    types::ProposalPart,
};
use malachitebft_core_types::{Height as MalachiteHeight, NilOrVal, VoteType};

/// Ed25519 signing provider for Malachite consensus
#[derive(Debug, Clone)]
pub struct Ed25519Provider {
    private_key: PrivateKey,
}

impl PartialEq for Ed25519Provider {
    fn eq(&self, other: &Self) -> bool {
        // Compare public keys instead of private keys
        self.public_key() == other.public_key()
    }
}

impl Eq for Ed25519Provider {}

impl Ed25519Provider {
    /// Create a new provider with a private key
    pub fn new(private_key: PrivateKey) -> Self {
        Self { private_key }
    }

    /// Create a new provider with a default/test key
    pub fn new_test() -> Self {
        let private_key = PrivateKey::generate(rand::thread_rng());
        Self::new(private_key)
    }

    /// Create a new provider from raw private key bytes
    pub fn from_bytes(private_key_bytes: &[u8]) -> Result<Self, String> {
        if private_key_bytes.len() != 32 {
            return Err("Private key must be exactly 32 bytes".to_string());
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(private_key_bytes);
        let private_key = PrivateKey::from(key_array);
        Ok(Self::new(private_key))
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        self.private_key.public_key()
    }

    /// Get the private key reference
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Sign raw bytes
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.private_key.sign(data)
    }

    /// Verify a signature
    pub fn verify(&self, data: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
        public_key.verify(data, signature).is_ok()
    }
}

impl Default for Ed25519Provider {
    fn default() -> Self {
        Self::new_test()
    }
}

impl SigningScheme for Ed25519Provider {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Signature = Signature;
    type DecodingError = std::io::Error;

    fn decode_signature(bytes: &[u8]) -> Result<Self::Signature, Self::DecodingError> {
        if bytes.len() != 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid signature length",
            ));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(bytes);
        Ok(Signature::from_bytes(sig_bytes))
    }

    fn encode_signature(signature: &Self::Signature) -> Vec<u8> {
        signature.to_bytes().to_vec()
    }
}

// Implement the to_sign_bytes trait for our types
pub trait ToSignBytes {
    fn to_sign_bytes(&self) -> Vec<u8>;
}

impl ToSignBytes for BaseVote {
    fn to_sign_bytes(&self) -> Vec<u8> {
        // Create a canonical byte representation for signing
        // In production, this should match the consensus protocol's canonical format
        let mut bytes = Vec::new();

        // Add vote type (1 byte)
        bytes.push(match self.vote_type.0 {
            VoteType::Prevote => 0,
            VoteType::Precommit => 1,
        });

        // Add height (8 bytes)
        bytes.extend_from_slice(&self.height.as_u64().to_le_bytes());

        // Add round (4 bytes)
        bytes.extend_from_slice(&self.round.0.as_u32().unwrap_or(0).to_le_bytes());

        // Add value_id (32 bytes or 0 for nil)
        match &self.value_id {
            NilOrVal::Val(id) => bytes.extend_from_slice(&id.as_u64().to_be_bytes()),
            NilOrVal::Nil => bytes.extend_from_slice(&[0u8; 8]),
        }

        // Add voter address (20 bytes)
        bytes.extend_from_slice(self.voter.0.as_bytes());

        bytes
    }
}

impl ToSignBytes for BaseProposal {
    fn to_sign_bytes(&self) -> Vec<u8> {
        // Create a canonical byte representation for signing
        let mut bytes = Vec::new();

        // Add height (8 bytes)
        bytes.extend_from_slice(&self.height.as_u64().to_le_bytes());

        // Add round (4 bytes)
        bytes.extend_from_slice(&self.round.0.as_u32().unwrap_or(0).to_le_bytes());

        // Add value data (encode the block)
        let value_bytes = crate::app::encode_value(&self.value);
        // Add length prefix for value data
        bytes.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&value_bytes);

        // Add proposer address (20 bytes)
        bytes.extend_from_slice(self.proposer.0.as_bytes());

        // Add pol_round (4 bytes)
        bytes.extend_from_slice(&self.pol_round.0.as_u32().unwrap_or(0).to_le_bytes());

        bytes
    }
}

impl ToSignBytes for ProposalPart {
    fn to_sign_bytes(&self) -> Vec<u8> {
        // Create a canonical byte representation for signing
        match self {
            ProposalPart::Init(init) => {
                let mut bytes = Vec::new();
                bytes.push(0); // Type marker for Init
                bytes.extend_from_slice(&init.height.as_u64().to_le_bytes());
                bytes.extend_from_slice(&init.round.as_u32().unwrap_or(0).to_le_bytes());
                bytes.extend_from_slice(init.proposer.as_bytes());
                bytes
            }
            ProposalPart::Data(data) => {
                let mut bytes = Vec::new();
                bytes.push(1); // Type marker for Data
                bytes.extend_from_slice(&data.bytes);
                bytes
            }
            ProposalPart::Fin(fin) => {
                let mut bytes = Vec::new();
                bytes.push(2); // Type marker for Fin
                bytes.extend_from_slice(fin.signature.to_bytes().as_ref());
                bytes
            }
        }
    }
}

impl SigningProvider<MalachiteContext> for Ed25519Provider {
    fn sign_vote(&self, vote: BaseVote) -> SignedVote<MalachiteContext> {
        let signature = self.sign(&vote.to_sign_bytes());
        SignedVote::new(vote, signature)
    }

    fn verify_signed_vote(
        &self,
        vote: &BaseVote,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        public_key.verify(&vote.to_sign_bytes(), signature).is_ok()
    }

    fn sign_proposal(&self, proposal: BaseProposal) -> SignedProposal<MalachiteContext> {
        let signature = self.sign(&proposal.to_sign_bytes());
        SignedProposal::new(proposal, signature)
    }

    fn verify_signed_proposal(
        &self,
        proposal: &BaseProposal,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        public_key
            .verify(&proposal.to_sign_bytes(), signature)
            .is_ok()
    }

    fn sign_proposal_part(
        &self,
        proposal_part: ProposalPart,
    ) -> SignedProposalPart<MalachiteContext> {
        let signature = self.sign(&proposal_part.to_sign_bytes());
        SignedProposalPart::new(proposal_part, signature)
    }

    fn verify_signed_proposal_part(
        &self,
        proposal_part: &ProposalPart,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        public_key
            .verify(&proposal_part.to_sign_bytes(), signature)
            .is_ok()
    }

    fn sign_vote_extension(
        &self,
        extension: crate::context::BaseExtension,
    ) -> SignedExtension<MalachiteContext> {
        let signature = self.sign(&extension.data);
        malachitebft_core_types::SignedMessage::new(extension, signature)
    }

    fn verify_signed_vote_extension(
        &self,
        extension: &crate::context::BaseExtension,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        public_key.verify(&extension.data, signature).is_ok()
    }
}
