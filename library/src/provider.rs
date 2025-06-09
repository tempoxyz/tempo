use crate::context::MalachiteContext;
use malachite_core_types::{PrivateKey, PublicKey, Signature, SigningProvider};

// TODO: Implement Ed25519Provider
#[derive(Debug)]
pub struct Ed25519Provider {
    private_key: [u8; 32],
}

// impl Ed25519Provider {
//     pub fn new(private_key: PrivateKey) -> Self {
//         Self { private_key }
//     }

//     pub fn private_key(&self) -> &PrivateKey {
//         &self.private_key
//     }

//     pub fn sign(&self, data: &[u8]) -> Signature {
//         self.private_key.sign(data)
//     }

//     pub fn verify(&self, data: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
//         public_key.verify(data, signature).is_ok()
//     }
// }

// impl SigningProvider<MalachiteContext> for Ed25519Provider {
//     fn sign_vote(&self, vote: Vote) -> SignedVote<TestContext> {
//         let signature = self.sign(&vote.to_sign_bytes());
//         SignedVote::new(vote, signature)
//     }

//     fn verify_signed_vote(
//         &self,
//         vote: &Vote,
//         signature: &Signature,
//         public_key: &PublicKey,
//     ) -> bool {
//         public_key.verify(&vote.to_sign_bytes(), signature).is_ok()
//     }

//     fn sign_proposal(&self, proposal: Proposal) -> SignedProposal<TestContext> {
//         let signature = self.private_key.sign(&proposal.to_sign_bytes());
//         SignedProposal::new(proposal, signature)
//     }

//     fn verify_signed_proposal(
//         &self,
//         proposal: &Proposal,
//         signature: &Signature,
//         public_key: &PublicKey,
//     ) -> bool {
//         public_key
//             .verify(&proposal.to_sign_bytes(), signature)
//             .is_ok()
//     }

//     fn sign_proposal_part(&self, proposal_part: ProposalPart) -> SignedProposalPart<TestContext> {
//         let signature = self.private_key.sign(&proposal_part.to_sign_bytes());
//         SignedProposalPart::new(proposal_part, signature)
//     }

//     fn verify_signed_proposal_part(
//         &self,
//         proposal_part: &ProposalPart,
//         signature: &Signature,
//         public_key: &PublicKey,
//     ) -> bool {
//         public_key
//             .verify(&proposal_part.to_sign_bytes(), signature)
//             .is_ok()
//     }

//     fn sign_vote_extension(&self, extension: Bytes) -> SignedExtension<TestContext> {
//         let signature = self.private_key.sign(extension.as_ref());
//         malachitebft_core_types::SignedMessage::new(extension, signature)
//     }

//     fn verify_signed_vote_extension(
//         &self,
//         extension: &Bytes,
//         signature: &Signature,
//         public_key: &PublicKey,
//     ) -> bool {
//         public_key.verify(extension.as_ref(), signature).is_ok()
//     }
// }
