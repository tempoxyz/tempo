pub mod dispatch;

use std::borrow::Cow;

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    sol_types::{Eip712Domain, SolStruct},
};
use ed25519_consensus::{Signature, VerificationKey};
use tempo_contracts::precompiles::{
    IZkTlsVerifier::{TempoZkTlsClaim, VerificationPolicy},
    ZK_TLS_VERIFIER_ADDRESS, ZkTlsVerifierError, ZkTlsVerifierEvent,
};
use tempo_precompiles_macros::contract;

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};

const ED25519_VERIFY_GAS: u64 = 8_000;
const EIP712_HASH_GAS: u64 = 180;

#[contract(addr = ZK_TLS_VERIFIER_ADDRESS)]
pub struct ZkTlsVerifier {
    owner: Address,
    approved_attestors: Mapping<B256, bool>,
    approved_provider_hashes: Mapping<B256, bool>,
    approved_measurements: Mapping<B256, bool>,
    used_nonces: Mapping<Address, Mapping<B256, bool>>,
}

impl ZkTlsVerifier {
    pub fn initialize(&mut self, owner: Address) -> Result<()> {
        if owner == Address::ZERO {
            return Err(ZkTlsVerifierError::invalid_owner().into());
        }

        self.__initialize()?;
        self.owner.write(owner)
    }

    pub fn owner(&self) -> Result<Address> {
        self.owner.read()
    }

    pub fn is_attestor_approved(&self, attestor_public_key: B256) -> Result<bool> {
        self.approved_attestors[attestor_public_key].read()
    }

    pub fn is_provider_hash_approved(&self, provider_hash: B256) -> Result<bool> {
        self.approved_provider_hashes[provider_hash].read()
    }

    pub fn is_measurement_approved(&self, measurement: B256) -> Result<bool> {
        self.approved_measurements[measurement].read()
    }

    pub fn set_attestor_approved(
        &mut self,
        msg_sender: Address,
        attestor_public_key: B256,
        approved: bool,
    ) -> Result<()> {
        self.require_owner(msg_sender)?;
        if attestor_public_key == B256::ZERO {
            return Err(ZkTlsVerifierError::attestor_public_key_zero().into());
        }

        self.approved_attestors[attestor_public_key].write(approved)?;
        self.emit_event(ZkTlsVerifierEvent::attestor_approval_updated(
            attestor_public_key,
            approved,
        ))
    }

    pub fn set_provider_hash_approved(
        &mut self,
        msg_sender: Address,
        provider_hash: B256,
        approved: bool,
    ) -> Result<()> {
        self.require_owner(msg_sender)?;
        self.approved_provider_hashes[provider_hash].write(approved)?;
        self.emit_event(ZkTlsVerifierEvent::provider_hash_approval_updated(
            provider_hash,
            approved,
        ))
    }

    pub fn set_measurement_approved(
        &mut self,
        msg_sender: Address,
        measurement: B256,
        approved: bool,
    ) -> Result<()> {
        self.require_owner(msg_sender)?;
        self.approved_measurements[measurement].write(approved)?;
        self.emit_event(ZkTlsVerifierEvent::measurement_approval_updated(
            measurement,
            approved,
        ))
    }

    pub fn transfer_ownership(&mut self, msg_sender: Address, new_owner: Address) -> Result<()> {
        self.require_owner(msg_sender)?;
        if new_owner == Address::ZERO {
            return Err(ZkTlsVerifierError::invalid_owner().into());
        }

        let old_owner = self.owner()?;
        self.owner.write(new_owner)?;
        self.emit_event(ZkTlsVerifierEvent::ownership_transferred(
            old_owner, new_owner,
        ))
    }

    pub fn hash_tempo_claim(&mut self, claim: TempoZkTlsClaim) -> Result<B256> {
        self.storage.deduct_gas(EIP712_HASH_GAS)?;
        Ok(claim.eip712_signing_hash(&self.eip712_domain()))
    }

    pub fn is_nonce_used(&self, subject: Address, nonce: B256) -> Result<bool> {
        self.used_nonces[subject][nonce].read()
    }

    pub fn verify_tempo_claim(
        &mut self,
        claim: TempoZkTlsClaim,
        policy: VerificationPolicy,
        signature: Bytes,
    ) -> Result<B256> {
        self.validate_policy(&claim, &policy)?;
        let claim_hash = self.hash_tempo_claim(claim)?;
        self.verify_attestor_signature(policy.attestorPublicKey, claim_hash, signature)?;
        Ok(claim_hash)
    }

    pub fn verify_and_mark_tempo_claim(
        &mut self,
        claim: TempoZkTlsClaim,
        policy: VerificationPolicy,
        signature: Bytes,
    ) -> Result<B256> {
        if self.is_nonce_used(claim.subject, claim.nonce)? {
            return Err(ZkTlsVerifierError::nonce_already_used().into());
        }

        let claim_hash = self.verify_tempo_claim(claim.clone(), policy.clone(), signature)?;
        self.used_nonces[claim.subject][claim.nonce].write(true)?;
        self.emit_event(ZkTlsVerifierEvent::tempo_zk_tls_claim_verified(
            claim.subject,
            claim.providerHash,
            claim.nonce,
            claim.claimType,
            claim.extractedHash,
            claim.sessionId,
            claim.sourceHash,
            claim.measurement,
            claim.imageDigest,
            claim.evidenceHash,
            policy.attestorPublicKey,
            claim_hash,
        ))?;

        Ok(claim_hash)
    }

    fn validate_policy(&self, claim: &TempoZkTlsClaim, policy: &VerificationPolicy) -> Result<()> {
        if policy.attestorPublicKey == B256::ZERO {
            return Err(ZkTlsVerifierError::attestor_public_key_zero().into());
        }
        if !self.is_attestor_approved(policy.attestorPublicKey)? {
            return Err(ZkTlsVerifierError::attestor_not_approved().into());
        }
        if claim.subject != policy.expectedSubject {
            return Err(ZkTlsVerifierError::subject_mismatch().into());
        }
        if claim.nonce != policy.expectedNonce {
            return Err(ZkTlsVerifierError::nonce_mismatch().into());
        }
        if claim.providerHash != policy.expectedProviderHash {
            return Err(ZkTlsVerifierError::provider_hash_mismatch().into());
        }
        if !self.is_provider_hash_approved(claim.providerHash)? {
            return Err(ZkTlsVerifierError::provider_hash_not_approved().into());
        }
        if claim.claimType != policy.expectedClaimType {
            return Err(ZkTlsVerifierError::claim_type_mismatch().into());
        }
        if claim.sourceHash != policy.expectedSourceHash {
            return Err(ZkTlsVerifierError::source_hash_mismatch().into());
        }
        if claim.measurement != policy.expectedMeasurement {
            return Err(ZkTlsVerifierError::measurement_mismatch().into());
        }
        if !self.is_measurement_approved(claim.measurement)? {
            return Err(ZkTlsVerifierError::measurement_not_approved().into());
        }
        if policy.expectedImageDigest != B256::ZERO
            && claim.imageDigest != policy.expectedImageDigest
        {
            return Err(ZkTlsVerifierError::image_digest_mismatch().into());
        }
        if policy.expectedEvidenceHash != B256::ZERO
            && claim.evidenceHash != policy.expectedEvidenceHash
        {
            return Err(ZkTlsVerifierError::evidence_hash_mismatch().into());
        }

        let now: u64 = self.storage.timestamp().saturating_to();
        if now > claim.expiresAt {
            return Err(ZkTlsVerifierError::claim_expired().into());
        }
        if claim.issuedAt > now.saturating_add(policy.maxFutureSkewSeconds) {
            return Err(ZkTlsVerifierError::claim_issued_from_future().into());
        }
        if now >= claim.issuedAt && now.saturating_sub(claim.issuedAt) > policy.maxClaimAgeSeconds {
            return Err(ZkTlsVerifierError::claim_stale().into());
        }

        Ok(())
    }

    fn verify_attestor_signature(
        &mut self,
        public_key: B256,
        claim_hash: B256,
        signature: Bytes,
    ) -> Result<()> {
        let signature_bytes: [u8; 64] = signature
            .as_ref()
            .try_into()
            .map_err(|_| ZkTlsVerifierError::invalid_signature_length())?;
        let key_bytes: [u8; 32] = public_key.into();
        let verification_key = VerificationKey::try_from(key_bytes)
            .map_err(|_| ZkTlsVerifierError::invalid_public_key())?;
        let signature = Signature::from(signature_bytes);

        self.storage.deduct_gas(ED25519_VERIFY_GAS)?;
        verification_key
            .verify(&signature, claim_hash.as_slice())
            .map_err(|_| ZkTlsVerifierError::invalid_signature().into())
    }

    fn require_owner(&self, msg_sender: Address) -> Result<()> {
        if self.owner()? != msg_sender {
            return Err(ZkTlsVerifierError::unauthorized().into());
        }
        Ok(())
    }

    fn eip712_domain(&self) -> Eip712Domain {
        Eip712Domain::new(
            Some(Cow::Borrowed("Tempo zkTLS")),
            Some(Cow::Borrowed("1")),
            Some(U256::from(self.storage.chain_id())),
            Some(ZK_TLS_VERIFIER_ADDRESS),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::{U256, address};
    use ed25519_consensus::SigningKey;
    use tempo_chainspec::hardfork::TempoHardfork;

    const NOW: u64 = 1_000;

    fn claim() -> TempoZkTlsClaim {
        TempoZkTlsClaim {
            subject: address!("0x0000000000000000000000000000000000000001"),
            providerHash: B256::from([0x11; 32]),
            claimType: B256::from([0x22; 32]),
            extractedHash: B256::from([0x33; 32]),
            nonce: B256::from([0x44; 32]),
            sessionId: B256::from([0x55; 32]),
            issuedAt: NOW,
            expiresAt: NOW + 300,
            sourceHash: B256::from([0x66; 32]),
            measurement: B256::from([0x77; 32]),
            imageDigest: B256::from([0x88; 32]),
            evidenceHash: B256::from([0x99; 32]),
        }
    }

    fn policy(attestor_public_key: B256) -> VerificationPolicy {
        let claim = claim();
        VerificationPolicy {
            expectedSubject: claim.subject,
            expectedProviderHash: claim.providerHash,
            expectedClaimType: claim.claimType,
            expectedNonce: claim.nonce,
            expectedSourceHash: claim.sourceHash,
            expectedMeasurement: claim.measurement,
            expectedImageDigest: claim.imageDigest,
            expectedEvidenceHash: claim.evidenceHash,
            attestorPublicKey: attestor_public_key,
            maxClaimAgeSeconds: 60,
            maxFutureSkewSeconds: 5,
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from([0xAB; 32])
    }

    fn public_key(signing_key: &SigningKey) -> B256 {
        B256::from(signing_key.verification_key().to_bytes())
    }

    fn owner() -> Address {
        address!("0x000000000000000000000000000000000000000A")
    }

    fn initialize_verifier(verifier: &mut ZkTlsVerifier, attestor_public_key: B256) -> Result<()> {
        let owner = owner();
        let claim = claim();
        verifier.initialize(owner)?;
        verifier.set_attestor_approved(owner, attestor_public_key, true)?;
        verifier.set_provider_hash_approved(owner, claim.providerHash, true)?;
        verifier.set_measurement_approved(owner, claim.measurement, true)?;
        Ok(())
    }

    fn sign_claim(verifier: &mut ZkTlsVerifier, claim: TempoZkTlsClaim) -> Result<Bytes> {
        let signing_key = signing_key();
        let claim_hash = verifier.hash_tempo_claim(claim)?;
        Ok(Bytes::copy_from_slice(
            &signing_key.sign(claim_hash.as_slice()).to_bytes(),
        ))
    }

    fn storage() -> HashMapStorageProvider {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(NOW));
        storage
    }

    #[test]
    fn verifies_signed_claim() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let claim = claim();
            let policy = policy(public_key(&signing_key()));
            initialize_verifier(&mut verifier, policy.attestorPublicKey)?;
            let signature = sign_claim(&mut verifier, claim.clone())?;

            let expected_hash = verifier.hash_tempo_claim(claim.clone())?;
            let verified_hash = verifier.verify_tempo_claim(claim, policy, signature)?;

            assert_eq!(verified_hash, expected_hash);
            Ok(())
        })
    }

    #[test]
    fn rejects_policy_mismatch() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let claim = claim();
            let mut policy = policy(public_key(&signing_key()));
            initialize_verifier(&mut verifier, policy.attestorPublicKey)?;
            policy.expectedProviderHash = B256::from([0xAA; 32]);
            let signature = sign_claim(&mut verifier, claim.clone())?;

            let err = verifier
                .verify_tempo_claim(claim, policy, signature)
                .unwrap_err();

            assert_eq!(
                err,
                TempoPrecompileError::ZkTlsVerifierError(
                    ZkTlsVerifierError::provider_hash_mismatch()
                )
            );
            Ok(())
        })
    }

    #[test]
    fn rejects_bad_signature() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let claim = claim();
            let policy = policy(public_key(&signing_key()));
            initialize_verifier(&mut verifier, policy.attestorPublicKey)?;
            let mut signature = sign_claim(&mut verifier, claim.clone())?.to_vec();
            signature[0] ^= 0x01;

            let err = verifier
                .verify_tempo_claim(claim, policy, Bytes::from(signature))
                .unwrap_err();

            assert_eq!(
                err,
                TempoPrecompileError::ZkTlsVerifierError(ZkTlsVerifierError::invalid_signature())
            );
            Ok(())
        })
    }

    #[test]
    fn verify_and_mark_rejects_replay() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let claim = claim();
            let policy = policy(public_key(&signing_key()));
            initialize_verifier(&mut verifier, policy.attestorPublicKey)?;
            let signature = sign_claim(&mut verifier, claim.clone())?;

            verifier.verify_and_mark_tempo_claim(
                claim.clone(),
                policy.clone(),
                signature.clone(),
            )?;
            assert!(verifier.is_nonce_used(claim.subject, claim.nonce)?);

            let err = verifier
                .verify_and_mark_tempo_claim(claim, policy, signature)
                .unwrap_err();

            assert_eq!(
                err,
                TempoPrecompileError::ZkTlsVerifierError(ZkTlsVerifierError::nonce_already_used())
            );
            Ok(())
        })
    }

    #[test]
    fn rejects_unapproved_attestor() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let claim = claim();
            let policy = policy(public_key(&signing_key()));
            let owner = owner();
            verifier.initialize(owner)?;
            verifier.set_provider_hash_approved(owner, claim.providerHash, true)?;
            verifier.set_measurement_approved(owner, claim.measurement, true)?;
            let signature = sign_claim(&mut verifier, claim.clone())?;

            let err = verifier
                .verify_tempo_claim(claim, policy, signature)
                .unwrap_err();

            assert_eq!(
                err,
                TempoPrecompileError::ZkTlsVerifierError(
                    ZkTlsVerifierError::attestor_not_approved()
                )
            );
            Ok(())
        })
    }

    #[test]
    fn rejects_unapproved_provider_hash() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let claim = claim();
            let policy = policy(public_key(&signing_key()));
            let owner = owner();
            verifier.initialize(owner)?;
            verifier.set_attestor_approved(owner, policy.attestorPublicKey, true)?;
            verifier.set_measurement_approved(owner, claim.measurement, true)?;
            let signature = sign_claim(&mut verifier, claim.clone())?;

            let err = verifier
                .verify_tempo_claim(claim, policy, signature)
                .unwrap_err();

            assert_eq!(
                err,
                TempoPrecompileError::ZkTlsVerifierError(
                    ZkTlsVerifierError::provider_hash_not_approved()
                )
            );
            Ok(())
        })
    }

    #[test]
    fn rejects_unapproved_measurement() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let claim = claim();
            let policy = policy(public_key(&signing_key()));
            let owner = owner();
            verifier.initialize(owner)?;
            verifier.set_attestor_approved(owner, policy.attestorPublicKey, true)?;
            verifier.set_provider_hash_approved(owner, claim.providerHash, true)?;
            let signature = sign_claim(&mut verifier, claim.clone())?;

            let err = verifier
                .verify_tempo_claim(claim, policy, signature)
                .unwrap_err();

            assert_eq!(
                err,
                TempoPrecompileError::ZkTlsVerifierError(
                    ZkTlsVerifierError::measurement_not_approved()
                )
            );
            Ok(())
        })
    }

    #[test]
    fn admin_updates_require_owner() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            verifier.initialize(owner())?;

            let err = verifier
                .set_attestor_approved(
                    address!("0x000000000000000000000000000000000000000B"),
                    public_key(&signing_key()),
                    true,
                )
                .unwrap_err();

            assert_eq!(
                err,
                TempoPrecompileError::ZkTlsVerifierError(ZkTlsVerifierError::unauthorized())
            );
            Ok(())
        })
    }
}
