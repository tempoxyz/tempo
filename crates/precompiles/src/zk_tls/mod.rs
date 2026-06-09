pub mod dispatch;

use alloy::{
    primitives::{Address, B256, Bytes, Signature, U256},
    sol_types::SolValue,
};
use tempo_contracts::precompiles::{
    IZkTlsVerifier::{TempoZkTlsClaim, VerificationPolicy},
    ZK_TLS_VERIFIER_ADDRESS, ZkTlsVerifierError, ZkTlsVerifierEvent,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::tt_signature::PrimitiveSignature;

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};

const SECP256K1_VERIFY_GAS: u64 = 3_000;

const TDX_QUOTE_HEADER_LENGTH: usize = 48;
const TDX_TD10_REPORT_LENGTH: usize = 584;
const TDX_TD15_REPORT_LENGTH: usize = 648;
const TDX_MRCONFIG_OFFSET: usize = 184;
const TDX_MRCONFIG_LENGTH: usize = 48;
const TDX_REPORTDATA_OFFSET: usize = 520;
const TDX_REPORTDATA_LENGTH: usize = 64;

const QUOTE_VERSION_V4: u16 = 4;
const QUOTE_VERSION_V5: u16 = 5;
const TDX_TD10_QUOTE_BODY_TYPE: u16 = 2;
const TDX_TD15_QUOTE_BODY_TYPE: u16 = 3;

const ETH_SIGNED_MESSAGE_PREFIX_32: &[u8] = b"\x19Ethereum Signed Message:\n32";
const CLAIM_TYPEHASH_PREIMAGE: &[u8] = b"TempoZkTlsClaim:v2";
const SECP256K1N_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

#[contract(addr = ZK_TLS_VERIFIER_ADDRESS)]
pub struct ZkTlsVerifier {
    owner: Address,
    approved_provider_hashes: Mapping<B256, bool>,
    claim_type_for_provider_hash: Mapping<B256, B256>,
    approved_dstack_apps: Mapping<Address, bool>,
    approved_dstack_compose_hashes: Mapping<Address, Mapping<B256, bool>>,
    approved_dstack_devices: Mapping<Address, Mapping<B256, bool>>,
    dstack_allow_any_device: Mapping<Address, bool>,
    approved_dstack_signers: Mapping<Address, Mapping<Address, bool>>,
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

    pub fn is_provider_hash_approved(&self, provider_hash: B256) -> Result<bool> {
        self.approved_provider_hashes[provider_hash].read()
    }

    pub fn claim_type_for_provider_hash(&self, provider_hash: B256) -> Result<B256> {
        self.claim_type_for_provider_hash[provider_hash].read()
    }

    pub fn is_dstack_app_approved(&self, dstack_app: Address) -> Result<bool> {
        self.approved_dstack_apps[dstack_app].read()
    }

    pub fn is_dstack_compose_hash_approved(
        &self,
        dstack_app: Address,
        compose_hash: B256,
    ) -> Result<bool> {
        self.approved_dstack_compose_hashes[dstack_app][compose_hash].read()
    }

    pub fn is_dstack_device_approved(&self, dstack_app: Address, device_id: B256) -> Result<bool> {
        self.approved_dstack_devices[dstack_app][device_id].read()
    }

    pub fn is_dstack_any_device_allowed(&self, dstack_app: Address) -> Result<bool> {
        self.dstack_allow_any_device[dstack_app].read()
    }

    pub fn is_dstack_signer_approved(
        &self,
        dstack_app: Address,
        tee_signer: Address,
    ) -> Result<bool> {
        self.approved_dstack_signers[dstack_app][tee_signer].read()
    }

    pub fn set_provider_hash_approved(
        &mut self,
        msg_sender: Address,
        provider_hash: B256,
        claim_type: B256,
        approved: bool,
    ) -> Result<()> {
        self.require_owner(msg_sender)?;
        if provider_hash == B256::ZERO {
            return Err(ZkTlsVerifierError::provider_hash_zero().into());
        }
        if claim_type == B256::ZERO {
            return Err(ZkTlsVerifierError::claim_type_zero().into());
        }

        self.approved_provider_hashes[provider_hash].write(approved)?;
        self.claim_type_for_provider_hash[provider_hash].write(if approved {
            claim_type
        } else {
            B256::ZERO
        })?;
        self.emit_event(ZkTlsVerifierEvent::provider_hash_approval_updated(
            provider_hash,
            claim_type,
            approved,
        ))
    }

    pub fn set_dstack_app_approved(
        &mut self,
        msg_sender: Address,
        dstack_app: Address,
        approved: bool,
    ) -> Result<()> {
        self.require_owner(msg_sender)?;
        if dstack_app == Address::ZERO {
            return Err(ZkTlsVerifierError::dstack_app_zero().into());
        }

        self.approved_dstack_apps[dstack_app].write(approved)?;
        self.emit_event(ZkTlsVerifierEvent::dstack_app_approval_updated(
            dstack_app, approved,
        ))
    }

    pub fn set_dstack_compose_hash_approved(
        &mut self,
        msg_sender: Address,
        dstack_app: Address,
        compose_hash: B256,
        approved: bool,
    ) -> Result<()> {
        self.require_owner(msg_sender)?;
        if dstack_app == Address::ZERO {
            return Err(ZkTlsVerifierError::dstack_app_zero().into());
        }

        self.approved_dstack_compose_hashes[dstack_app][compose_hash].write(approved)?;
        self.emit_event(ZkTlsVerifierEvent::dstack_compose_hash_approval_updated(
            dstack_app,
            compose_hash,
            approved,
        ))
    }

    pub fn set_dstack_device_approved(
        &mut self,
        msg_sender: Address,
        dstack_app: Address,
        device_id: B256,
        approved: bool,
    ) -> Result<()> {
        self.require_owner(msg_sender)?;
        if dstack_app == Address::ZERO {
            return Err(ZkTlsVerifierError::dstack_app_zero().into());
        }

        self.approved_dstack_devices[dstack_app][device_id].write(approved)?;
        self.emit_event(ZkTlsVerifierEvent::dstack_device_approval_updated(
            dstack_app, device_id, approved,
        ))
    }

    pub fn set_dstack_allow_any_device(
        &mut self,
        msg_sender: Address,
        dstack_app: Address,
        approved: bool,
    ) -> Result<()> {
        self.require_owner(msg_sender)?;
        if dstack_app == Address::ZERO {
            return Err(ZkTlsVerifierError::dstack_app_zero().into());
        }

        self.dstack_allow_any_device[dstack_app].write(approved)?;
        self.emit_event(ZkTlsVerifierEvent::dstack_allow_any_device_updated(
            dstack_app, approved,
        ))
    }

    pub fn set_dstack_signer_approved(
        &mut self,
        msg_sender: Address,
        dstack_app: Address,
        tee_signer: Address,
        approved: bool,
    ) -> Result<()> {
        self.require_owner(msg_sender)?;
        if dstack_app == Address::ZERO {
            return Err(ZkTlsVerifierError::dstack_app_zero().into());
        }
        if tee_signer == Address::ZERO {
            return Err(ZkTlsVerifierError::dstack_signer_zero().into());
        }

        self.approved_dstack_signers[dstack_app][tee_signer].write(approved)?;
        self.emit_event(ZkTlsVerifierEvent::dstack_signer_approval_updated(
            dstack_app, tee_signer, approved,
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
        let claim_typehash = self.storage.keccak256(CLAIM_TYPEHASH_PREIMAGE)?;
        self.storage.keccak256(
            &(
                claim_typehash,
                claim.subject,
                claim.providerHash,
                claim.claimType,
                claim.extractedHash,
                claim.nonce,
                claim.sessionId,
                claim.issuedAt,
                claim.expiresAt,
                claim.sourceHash,
                claim.dstackApp,
                claim.composeHash,
                claim.deviceId,
                claim.quoteHash,
            )
                .abi_encode(),
        )
    }

    pub fn to_eth_signed_message_hash(&mut self, claim_hash: B256) -> Result<B256> {
        let mut encoded = Vec::with_capacity(ETH_SIGNED_MESSAGE_PREFIX_32.len() + 32);
        encoded.extend_from_slice(ETH_SIGNED_MESSAGE_PREFIX_32);
        encoded.extend_from_slice(claim_hash.as_slice());
        self.storage.keccak256(&encoded)
    }

    pub fn is_nonce_used(&self, subject: Address, nonce: B256) -> Result<bool> {
        self.used_nonces[subject][nonce].read()
    }

    pub fn verify_tempo_claim(
        &mut self,
        claim: TempoZkTlsClaim,
        policy: VerificationPolicy,
        raw_quote: Bytes,
        signature: Bytes,
    ) -> Result<(B256, Address)> {
        self.validate_policy(&claim, &policy)?;
        if self.storage.keccak256(raw_quote.as_ref())? != claim.quoteHash {
            return Err(ZkTlsVerifierError::quote_hash_mismatch().into());
        }

        let tee_signer = self.verify_quote_bindings(&claim, raw_quote.as_ref())?;
        self.validate_tee_signer(&claim, &policy, tee_signer)?;

        let claim_hash = self.hash_tempo_claim(claim)?;
        let digest = self.to_eth_signed_message_hash(claim_hash)?;
        self.verify_dstack_signature(tee_signer, digest, signature)?;
        Ok((claim_hash, tee_signer))
    }

    pub fn verify_and_mark_tempo_claim(
        &mut self,
        claim: TempoZkTlsClaim,
        policy: VerificationPolicy,
        raw_quote: Bytes,
        signature: Bytes,
    ) -> Result<(B256, Address)> {
        if self.is_nonce_used(claim.subject, claim.nonce)? {
            return Err(ZkTlsVerifierError::nonce_already_used().into());
        }

        let (claim_hash, tee_signer) =
            self.verify_tempo_claim(claim.clone(), policy, raw_quote, signature)?;
        let digest = self.to_eth_signed_message_hash(claim_hash)?;
        self.used_nonces[claim.subject][claim.nonce].write(true)?;
        self.emit_event(ZkTlsVerifierEvent::tempo_zk_tls_claim_verified(
            claim.subject,
            claim.providerHash,
            claim.nonce,
            claim.claimType,
            claim.extractedHash,
            claim.sessionId,
            claim.sourceHash,
            claim.dstackApp,
            claim.composeHash,
            claim.deviceId,
            claim.quoteHash,
            tee_signer,
            claim_hash,
            digest,
        ))?;

        Ok((claim_hash, tee_signer))
    }

    fn validate_policy(&self, claim: &TempoZkTlsClaim, policy: &VerificationPolicy) -> Result<()> {
        if claim.subject != policy.expectedSubject {
            return Err(ZkTlsVerifierError::subject_mismatch().into());
        }
        if claim.nonce != policy.expectedNonce {
            return Err(ZkTlsVerifierError::nonce_mismatch().into());
        }
        if claim.providerHash != policy.expectedProviderHash {
            return Err(ZkTlsVerifierError::provider_hash_mismatch().into());
        }
        if claim.claimType != policy.expectedClaimType {
            return Err(ZkTlsVerifierError::claim_type_mismatch().into());
        }
        if claim.sourceHash != policy.expectedSourceHash {
            return Err(ZkTlsVerifierError::source_hash_mismatch().into());
        }
        if policy.expectedDstackApp != Address::ZERO && claim.dstackApp != policy.expectedDstackApp
        {
            return Err(ZkTlsVerifierError::dstack_app_mismatch().into());
        }
        if policy.expectedComposeHash != B256::ZERO
            && claim.composeHash != policy.expectedComposeHash
        {
            return Err(ZkTlsVerifierError::dstack_compose_hash_mismatch().into());
        }
        if policy.expectedDeviceId != B256::ZERO && claim.deviceId != policy.expectedDeviceId {
            return Err(ZkTlsVerifierError::dstack_device_mismatch().into());
        }
        if !self.is_provider_hash_approved(claim.providerHash)?
            || self.claim_type_for_provider_hash(claim.providerHash)? != claim.claimType
        {
            return Err(ZkTlsVerifierError::provider_hash_not_approved().into());
        }
        if !self.is_dstack_app_approved(claim.dstackApp)? {
            return Err(ZkTlsVerifierError::dstack_app_not_approved().into());
        }
        if !self.is_dstack_compose_hash_approved(claim.dstackApp, claim.composeHash)? {
            return Err(ZkTlsVerifierError::dstack_compose_hash_not_approved().into());
        }
        if !self.is_dstack_any_device_allowed(claim.dstackApp)?
            && !self.is_dstack_device_approved(claim.dstackApp, claim.deviceId)?
        {
            return Err(ZkTlsVerifierError::dstack_device_not_approved().into());
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

    fn validate_tee_signer(
        &self,
        claim: &TempoZkTlsClaim,
        policy: &VerificationPolicy,
        tee_signer: Address,
    ) -> Result<()> {
        if policy.expectedTeeSigner != Address::ZERO && tee_signer != policy.expectedTeeSigner {
            return Err(ZkTlsVerifierError::dstack_signer_mismatch().into());
        }
        if !self.is_dstack_signer_approved(claim.dstackApp, tee_signer)? {
            return Err(ZkTlsVerifierError::dstack_signer_not_approved().into());
        }
        Ok(())
    }

    fn verify_quote_bindings(&self, claim: &TempoZkTlsClaim, raw_quote: &[u8]) -> Result<Address> {
        let quote_body_offset = self.verified_tdx_quote_body_offset(raw_quote)?;
        let compose_hash = self.extract_compose_hash(raw_quote, quote_body_offset)?;
        if compose_hash != claim.composeHash {
            return Err(ZkTlsVerifierError::quote_compose_hash_mismatch().into());
        }

        let (tee_signer, nonce) = self.extract_report_data(raw_quote, quote_body_offset)?;
        if nonce != claim.nonce {
            return Err(ZkTlsVerifierError::quote_report_data_nonce_mismatch().into());
        }
        Ok(tee_signer)
    }

    fn verified_tdx_quote_body_offset(&self, raw_quote: &[u8]) -> Result<usize> {
        self.require_quote_length(raw_quote, TDX_QUOTE_HEADER_LENGTH)?;

        let quote_version = self.read_u16_le(raw_quote, 0)?;
        if quote_version != QUOTE_VERSION_V4 && quote_version != QUOTE_VERSION_V5 {
            return Err(ZkTlsVerifierError::quote_version_unsupported(quote_version).into());
        }

        let quote_body_type = self.read_u16_le(raw_quote, 2)?;
        let quote_body_length = match quote_body_type {
            TDX_TD10_QUOTE_BODY_TYPE => TDX_TD10_REPORT_LENGTH,
            TDX_TD15_QUOTE_BODY_TYPE => TDX_TD15_REPORT_LENGTH,
            _ => {
                return Err(
                    ZkTlsVerifierError::quote_body_type_unsupported(quote_body_type).into(),
                );
            }
        };

        self.require_quote_length(raw_quote, TDX_QUOTE_HEADER_LENGTH + quote_body_length)?;
        Ok(TDX_QUOTE_HEADER_LENGTH)
    }

    fn extract_compose_hash(&self, raw_quote: &[u8], quote_body_offset: usize) -> Result<B256> {
        let mrconfig_offset = quote_body_offset + TDX_MRCONFIG_OFFSET;
        self.require_quote_length(raw_quote, mrconfig_offset + TDX_MRCONFIG_LENGTH)?;

        if raw_quote[mrconfig_offset] != 0x01 {
            return Err(ZkTlsVerifierError::quote_compose_hash_mismatch().into());
        }
        if raw_quote[mrconfig_offset + 33..mrconfig_offset + TDX_MRCONFIG_LENGTH]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ZkTlsVerifierError::quote_compose_hash_mismatch().into());
        }
        Ok(B256::from_slice(
            &raw_quote[mrconfig_offset + 1..mrconfig_offset + 33],
        ))
    }

    fn extract_report_data(
        &self,
        raw_quote: &[u8],
        quote_body_offset: usize,
    ) -> Result<(Address, B256)> {
        let report_data_offset = quote_body_offset + TDX_REPORTDATA_OFFSET;
        self.require_quote_length(raw_quote, report_data_offset + TDX_REPORTDATA_LENGTH)?;

        let signer_word = &raw_quote[report_data_offset..report_data_offset + 32];
        if signer_word[20..].iter().any(|byte| *byte != 0) {
            return Err(ZkTlsVerifierError::quote_report_data_signer_mismatch().into());
        }
        let tee_signer = Address::from_slice(&signer_word[..20]);
        if tee_signer == Address::ZERO {
            return Err(ZkTlsVerifierError::quote_report_data_signer_mismatch().into());
        }
        let nonce = B256::from_slice(&raw_quote[report_data_offset + 32..report_data_offset + 64]);
        Ok((tee_signer, nonce))
    }

    fn verify_dstack_signature(
        &mut self,
        expected_signer: Address,
        digest: B256,
        signature: Bytes,
    ) -> Result<()> {
        self.storage.deduct_gas(SECP256K1_VERIFY_GAS)?;
        match signature.len() {
            64 => {
                if self.is_high_s(&signature[32..64]) {
                    return Err(ZkTlsVerifierError::invalid_signature().into());
                }
                for parity in [false, true] {
                    let sig = Signature::from_bytes_and_parity(signature.as_ref(), parity);
                    let signer = PrimitiveSignature::Secp256k1(sig)
                        .recover_signer(&digest)
                        .map_err(|_| ZkTlsVerifierError::invalid_signature())?;
                    if signer == expected_signer {
                        return Ok(());
                    }
                }
                Err(ZkTlsVerifierError::invalid_signature().into())
            }
            65 => {
                if self.is_high_s(&signature[32..64]) {
                    return Err(ZkTlsVerifierError::invalid_signature().into());
                }
                let signer = PrimitiveSignature::from_bytes(signature.as_ref())
                    .map_err(|_| ZkTlsVerifierError::invalid_signature_length())?
                    .recover_signer(&digest)
                    .map_err(|_| ZkTlsVerifierError::invalid_signature())?;
                if signer != expected_signer {
                    return Err(ZkTlsVerifierError::invalid_signature().into());
                }
                Ok(())
            }
            _ => Err(ZkTlsVerifierError::invalid_signature_length().into()),
        }
    }

    fn is_high_s(&self, s_bytes: &[u8]) -> bool {
        U256::from_be_slice(s_bytes) > U256::from_be_slice(&SECP256K1N_HALF)
    }

    fn read_u16_le(&self, raw_quote: &[u8], offset: usize) -> Result<u16> {
        self.require_quote_length(raw_quote, offset + 2)?;
        Ok(u16::from_le_bytes([
            raw_quote[offset],
            raw_quote[offset + 1],
        ]))
    }

    fn require_quote_length(&self, raw_quote: &[u8], min_length: usize) -> Result<()> {
        if raw_quote.len() < min_length {
            return Err(ZkTlsVerifierError::quote_too_short().into());
        }
        Ok(())
    }

    fn require_owner(&self, msg_sender: Address) -> Result<()> {
        if self.owner()? != msg_sender {
            return Err(ZkTlsVerifierError::unauthorized().into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::address;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_chainspec::hardfork::TempoHardfork;

    const NOW: u64 = 1_000;

    fn subject() -> Address {
        address!("0x0000000000000000000000000000000000000001")
    }

    fn owner() -> Address {
        address!("0x000000000000000000000000000000000000000A")
    }

    fn dstack_app() -> Address {
        address!("0x0000000000000000000000000000000000000d5a")
    }

    fn tee_signer() -> PrivateKeySigner {
        "0x59c6995e998f97a5a004497e5da108fd4eae01d05b09b7b6b4832c5c2d8c6c6d"
            .parse()
            .expect("valid test key")
    }

    fn claim(raw_quote: &[u8]) -> TempoZkTlsClaim {
        TempoZkTlsClaim {
            subject: subject(),
            providerHash: B256::from([0x11; 32]),
            claimType: B256::from([0x22; 32]),
            extractedHash: B256::from([0x33; 32]),
            nonce: B256::from([0x44; 32]),
            sessionId: B256::from([0x55; 32]),
            issuedAt: NOW,
            expiresAt: NOW + 300,
            sourceHash: B256::from([0x66; 32]),
            dstackApp: dstack_app(),
            composeHash: B256::from([0x77; 32]),
            deviceId: B256::from([0x88; 32]),
            quoteHash: alloy::primitives::keccak256(raw_quote),
        }
    }

    fn policy(claim: &TempoZkTlsClaim, expected_tee_signer: Address) -> VerificationPolicy {
        VerificationPolicy {
            expectedSubject: claim.subject,
            expectedProviderHash: claim.providerHash,
            expectedClaimType: claim.claimType,
            expectedNonce: claim.nonce,
            expectedSourceHash: claim.sourceHash,
            expectedDstackApp: claim.dstackApp,
            expectedComposeHash: claim.composeHash,
            expectedDeviceId: claim.deviceId,
            expectedTeeSigner: expected_tee_signer,
            maxClaimAgeSeconds: 60,
            maxFutureSkewSeconds: 5,
        }
    }

    fn raw_quote(signer: Address, nonce: B256, compose_hash: B256) -> Vec<u8> {
        let mut quote = vec![0u8; TDX_QUOTE_HEADER_LENGTH + TDX_TD10_REPORT_LENGTH];
        quote[0..2].copy_from_slice(&QUOTE_VERSION_V4.to_le_bytes());
        quote[2..4].copy_from_slice(&TDX_TD10_QUOTE_BODY_TYPE.to_le_bytes());

        let mrconfig_offset = TDX_QUOTE_HEADER_LENGTH + TDX_MRCONFIG_OFFSET;
        quote[mrconfig_offset] = 0x01;
        quote[mrconfig_offset + 1..mrconfig_offset + 33].copy_from_slice(compose_hash.as_slice());

        let report_data_offset = TDX_QUOTE_HEADER_LENGTH + TDX_REPORTDATA_OFFSET;
        quote[report_data_offset..report_data_offset + 20].copy_from_slice(signer.as_slice());
        quote[report_data_offset + 32..report_data_offset + 64].copy_from_slice(nonce.as_slice());
        quote
    }

    fn initialize_verifier(
        verifier: &mut ZkTlsVerifier,
        claim: &TempoZkTlsClaim,
        tee_signer: Address,
    ) -> Result<()> {
        let owner = owner();
        verifier.initialize(owner)?;
        verifier.set_provider_hash_approved(owner, claim.providerHash, claim.claimType, true)?;
        verifier.set_dstack_app_approved(owner, claim.dstackApp, true)?;
        verifier.set_dstack_compose_hash_approved(
            owner,
            claim.dstackApp,
            claim.composeHash,
            true,
        )?;
        verifier.set_dstack_device_approved(owner, claim.dstackApp, claim.deviceId, true)?;
        verifier.set_dstack_signer_approved(owner, claim.dstackApp, tee_signer, true)?;
        Ok(())
    }

    fn sign_claim(verifier: &mut ZkTlsVerifier, claim: TempoZkTlsClaim) -> Result<Bytes> {
        let signer = tee_signer();
        let claim_hash = verifier.hash_tempo_claim(claim)?;
        let digest = verifier.to_eth_signed_message_hash(claim_hash)?;
        Ok(Bytes::copy_from_slice(
            &signer
                .sign_hash_sync(&digest)
                .expect("signature")
                .as_bytes(),
        ))
    }

    fn compact_signature(signature: Bytes) -> Bytes {
        Bytes::copy_from_slice(&signature[..64])
    }

    fn storage() -> HashMapStorageProvider {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(NOW));
        storage
    }

    #[test]
    fn verifies_signed_phala_claim() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let signer_address = tee_signer().address();
            let raw_quote = raw_quote(
                signer_address,
                B256::from([0x44; 32]),
                B256::from([0x77; 32]),
            );
            let claim = claim(&raw_quote);
            let policy = policy(&claim, signer_address);
            initialize_verifier(&mut verifier, &claim, signer_address)?;
            let signature = sign_claim(&mut verifier, claim.clone())?;

            let expected_hash = verifier.hash_tempo_claim(claim.clone())?;
            let (verified_hash, verified_signer) =
                verifier.verify_tempo_claim(claim, policy, Bytes::from(raw_quote), signature)?;

            assert_eq!(verified_hash, expected_hash);
            assert_eq!(verified_signer, signer_address);
            Ok(())
        })
    }

    #[test]
    fn verifies_compact_dstack_signature() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let signer_address = tee_signer().address();
            let raw_quote = raw_quote(
                signer_address,
                B256::from([0x44; 32]),
                B256::from([0x77; 32]),
            );
            let claim = claim(&raw_quote);
            let policy = policy(&claim, signer_address);
            initialize_verifier(&mut verifier, &claim, signer_address)?;
            let signature = compact_signature(sign_claim(&mut verifier, claim.clone())?);

            let (_, verified_signer) =
                verifier.verify_tempo_claim(claim, policy, Bytes::from(raw_quote), signature)?;

            assert_eq!(verified_signer, signer_address);
            Ok(())
        })
    }

    #[test]
    fn verify_and_mark_rejects_replay() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let signer_address = tee_signer().address();
            let raw_quote = raw_quote(
                signer_address,
                B256::from([0x44; 32]),
                B256::from([0x77; 32]),
            );
            let claim = claim(&raw_quote);
            let policy = policy(&claim, signer_address);
            initialize_verifier(&mut verifier, &claim, signer_address)?;
            let signature = sign_claim(&mut verifier, claim.clone())?;

            verifier.verify_and_mark_tempo_claim(
                claim.clone(),
                policy.clone(),
                Bytes::from(raw_quote.clone()),
                signature.clone(),
            )?;
            assert!(verifier.is_nonce_used(claim.subject, claim.nonce)?);

            let err = verifier
                .verify_and_mark_tempo_claim(claim, policy, Bytes::from(raw_quote), signature)
                .unwrap_err();

            assert_eq!(
                err,
                TempoPrecompileError::ZkTlsVerifierError(ZkTlsVerifierError::nonce_already_used())
            );
            Ok(())
        })
    }

    #[test]
    fn rejects_unapproved_provider_hash() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let signer_address = tee_signer().address();
            let raw_quote = raw_quote(
                signer_address,
                B256::from([0x44; 32]),
                B256::from([0x77; 32]),
            );
            let claim = claim(&raw_quote);
            let policy = policy(&claim, signer_address);
            verifier.initialize(owner())?;
            verifier.set_dstack_app_approved(owner(), claim.dstackApp, true)?;
            verifier.set_dstack_compose_hash_approved(
                owner(),
                claim.dstackApp,
                claim.composeHash,
                true,
            )?;
            verifier.set_dstack_device_approved(owner(), claim.dstackApp, claim.deviceId, true)?;
            verifier.set_dstack_signer_approved(owner(), claim.dstackApp, signer_address, true)?;
            let signature = sign_claim(&mut verifier, claim.clone())?;

            let err = verifier
                .verify_tempo_claim(claim, policy, Bytes::from(raw_quote), signature)
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
    fn rejects_unapproved_dstack_signer() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let signer_address = tee_signer().address();
            let raw_quote = raw_quote(
                signer_address,
                B256::from([0x44; 32]),
                B256::from([0x77; 32]),
            );
            let claim = claim(&raw_quote);
            let policy = policy(&claim, signer_address);
            let owner = owner();
            verifier.initialize(owner)?;
            verifier.set_provider_hash_approved(
                owner,
                claim.providerHash,
                claim.claimType,
                true,
            )?;
            verifier.set_dstack_app_approved(owner, claim.dstackApp, true)?;
            verifier.set_dstack_compose_hash_approved(
                owner,
                claim.dstackApp,
                claim.composeHash,
                true,
            )?;
            verifier.set_dstack_device_approved(owner, claim.dstackApp, claim.deviceId, true)?;
            let signature = sign_claim(&mut verifier, claim.clone())?;

            let err = verifier
                .verify_tempo_claim(claim, policy, Bytes::from(raw_quote), signature)
                .unwrap_err();

            assert_eq!(
                err,
                TempoPrecompileError::ZkTlsVerifierError(
                    ZkTlsVerifierError::dstack_signer_not_approved()
                )
            );
            Ok(())
        })
    }

    #[test]
    fn rejects_quote_nonce_mismatch() -> eyre::Result<()> {
        let mut storage = storage();
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            let signer_address = tee_signer().address();
            let raw_quote = raw_quote(
                signer_address,
                B256::from([0x44; 32]),
                B256::from([0x77; 32]),
            );
            let mut bad_raw_quote = raw_quote.clone();
            let claim = claim(&raw_quote);
            let policy = policy(&claim, signer_address);
            initialize_verifier(&mut verifier, &claim, signer_address)?;
            let signature = sign_claim(&mut verifier, claim.clone())?;
            let report_data_offset = TDX_QUOTE_HEADER_LENGTH + TDX_REPORTDATA_OFFSET;
            bad_raw_quote[report_data_offset + 32] ^= 0x01;

            let err = verifier
                .verify_tempo_claim(claim, policy, Bytes::from(bad_raw_quote), signature)
                .unwrap_err();

            assert_eq!(
                err,
                TempoPrecompileError::ZkTlsVerifierError(ZkTlsVerifierError::quote_hash_mismatch())
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
                .set_dstack_app_approved(
                    address!("0x000000000000000000000000000000000000000B"),
                    dstack_app(),
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
