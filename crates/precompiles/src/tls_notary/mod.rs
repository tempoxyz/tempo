pub mod dispatch;

use tempo_contracts::precompiles::TLS_NOTARY_ADDRESS;
pub use tempo_contracts::precompiles::{ITLSNotary, TLSNotaryError, TLSNotaryEvent};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    error::Result,
    storage::{Handler, Mapping, StorageCtx},
};
use alloy::primitives::{Address, B256, U256, keccak256};

/// Domain separator prefix for attestation messages.
const ATTESTATION_DOMAIN: &[u8] = b"TEMPO_TLSNOTARY_V1";

/// Required quorum: 2/3 of total voting power (expressed as numerator/denominator).
const QUORUM_NUMERATOR: u64 = 2;
const QUORUM_DENOMINATOR: u64 = 3;

/// Maximum number of validator signatures accepted (DoS protection).
const MAX_SIGNATURES: usize = 200;

/// ECDSA signature length (r[32] + s[32] + v[1]).
const SIGNATURE_LENGTH: usize = 65;

/// Session record stored on-chain for registered attestations.
#[derive(Debug, Clone, Default, Storable)]
pub struct SessionRecord {
    pub epoch: u64,
    pub proof_hash: B256,
    pub statement_hash: B256,
    pub server_name_hash: B256,
    pub submitter: Address,
    pub timestamp: u64,
}

/// TLSNotary precompile: verifies and registers TLSNotary attestations
/// where Tempo validators act as MPC participants in the TLSNotary protocol.
///
/// Validators run MPC-TLS off-chain and produce attestations (signed proof hashes).
/// This precompile verifies validator quorum signatures and optionally stores
/// session metadata on-chain for indexing and replay prevention.
#[contract(addr = TLS_NOTARY_ADDRESS)]
pub struct TLSNotary {
    sessions: Mapping<B256, SessionRecord>,
    registered_proofs: Mapping<B256, bool>,
}

impl TLSNotary {
    /// Initialize the TLSNotary precompile.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Derive a deterministic session ID from epoch and proof hash.
    pub fn derive_session_id(epoch: u64, proof_hash: B256) -> B256 {
        let mut data = Vec::with_capacity(8 + 32);
        data.extend_from_slice(&epoch.to_be_bytes());
        data.extend_from_slice(proof_hash.as_slice());
        keccak256(&data)
    }

    /// Compute the canonical attestation message that validators sign.
    pub fn compute_attestation_message(
        chain_id: u64,
        epoch: u64,
        proof_hash: B256,
        statement_hash: B256,
        server_name_hash: B256,
    ) -> B256 {
        let mut data = Vec::with_capacity(ATTESTATION_DOMAIN.len() + 8 + 8 + 32 + 32 + 32);
        data.extend_from_slice(ATTESTATION_DOMAIN);
        data.extend_from_slice(&chain_id.to_be_bytes());
        data.extend_from_slice(&epoch.to_be_bytes());
        data.extend_from_slice(proof_hash.as_slice());
        data.extend_from_slice(statement_hash.as_slice());
        data.extend_from_slice(server_name_hash.as_slice());
        keccak256(&data)
    }

    /// Parse a bitmap to determine which validator indices have signed.
    fn parse_bitmap(bitmap: &[u8], validator_count: usize) -> Vec<usize> {
        let mut indices = Vec::new();
        for (byte_idx, &byte) in bitmap.iter().enumerate() {
            for bit_idx in 0..8 {
                let global_idx = byte_idx * 8 + bit_idx;
                if global_idx >= validator_count {
                    break;
                }
                if byte & (1 << bit_idx) != 0 {
                    indices.push(global_idx);
                }
            }
        }
        indices
    }

    /// Verify an attestation: check validator quorum signatures over the attestation message.
    ///
    /// This is a view function that does not modify state. It verifies:
    /// 1. The attestation message format
    /// 2. Each validator signature in the bitmap
    /// 3. That the total signed voting power meets quorum (2/3)
    pub fn verify_attestation(
        &self,
        call: ITLSNotary::verifyAttestationCall,
    ) -> Result<ITLSNotary::verifyAttestationReturn> {
        let attestation_data = &call.attestation;

        if attestation_data.len() < 8 + 32 + 32 + 32 {
            return Err(TLSNotaryError::invalid_attestation().into());
        }

        let mut offset = 0;

        // Parse epoch (8 bytes)
        let epoch = u64::from_be_bytes(
            attestation_data[offset..offset + 8]
                .try_into()
                .map_err(|_| TLSNotaryError::invalid_attestation())?,
        );
        offset += 8;

        // Parse proofHash (32 bytes)
        let proof_hash = B256::from_slice(&attestation_data[offset..offset + 32]);
        offset += 32;

        // Parse statementHash (32 bytes)
        let statement_hash = B256::from_slice(&attestation_data[offset..offset + 32]);
        offset += 32;

        // Parse serverNameHash (32 bytes)
        let server_name_hash = B256::from_slice(&attestation_data[offset..offset + 32]);
        offset += 32;

        if attestation_data.len() < offset + 4 {
            return Err(TLSNotaryError::invalid_attestation().into());
        }

        // Parse bitmap length (4 bytes) then bitmap
        let bitmap_len = u32::from_be_bytes(
            attestation_data[offset..offset + 4]
                .try_into()
                .map_err(|_| TLSNotaryError::invalid_attestation())?,
        ) as usize;
        offset += 4;

        if attestation_data.len() < offset + bitmap_len {
            return Err(TLSNotaryError::invalid_bitmap_length().into());
        }

        let bitmap = &attestation_data[offset..offset + bitmap_len];
        offset += bitmap_len;

        // Remaining bytes are signatures
        let signatures_data = &attestation_data[offset..];

        // Get validator count from ValidatorConfig precompile
        let validator_count = self.get_validator_count()?;

        // Parse bitmap to get signing validator indices
        let signing_indices = Self::parse_bitmap(bitmap, validator_count as usize);

        if signing_indices.len() > MAX_SIGNATURES {
            return Err(TLSNotaryError::invalid_attestation().into());
        }

        // Verify signature count matches bitmap
        if signatures_data.len() != signing_indices.len() * SIGNATURE_LENGTH {
            return Err(TLSNotaryError::invalid_signature_length().into());
        }

        // Compute the message that should have been signed
        let chain_id = StorageCtx.chain_id();
        let attestation_message = Self::compute_attestation_message(
            chain_id,
            epoch,
            proof_hash,
            statement_hash,
            server_name_hash,
        );

        // Verify each signature and sum voting power
        // For simplicity, each active validator has equal voting power of 1
        let mut signed_power = U256::ZERO;
        let total_power = U256::from(validator_count);

        for (i, &validator_idx) in signing_indices.iter().enumerate() {
            let sig_start = i * SIGNATURE_LENGTH;
            let sig_bytes = &signatures_data[sig_start..sig_start + SIGNATURE_LENGTH];

            // Extract r, s, v from signature
            let r = B256::from_slice(&sig_bytes[..32]);
            let s = B256::from_slice(&sig_bytes[32..64]);
            let v = sig_bytes[64];

            // Recover signer address from signature
            let recovered = Self::ecrecover(attestation_message, v, r, s);

            match recovered {
                Some(recovered_addr) => {
                    // Get the validator address at this index
                    let expected_addr = self.get_validator_address(validator_idx as u64)?;

                    if recovered_addr != expected_addr {
                        return Err(TLSNotaryError::signature_verification_failed(
                            validator_idx as u64,
                        )
                        .into());
                    }

                    // Add voting power (1 per active validator)
                    signed_power += U256::from(1);
                }
                None => {
                    return Err(TLSNotaryError::signature_verification_failed(
                        validator_idx as u64,
                    )
                    .into());
                }
            }
        }

        // Check quorum: signed_power * QUORUM_DENOMINATOR >= total_power * QUORUM_NUMERATOR
        let quorum_met = signed_power * U256::from(QUORUM_DENOMINATOR)
            >= total_power * U256::from(QUORUM_NUMERATOR);

        Ok(ITLSNotary::verifyAttestationReturn {
            ok: quorum_met,
            epoch,
            signedPower: signed_power,
            totalPower: total_power,
        })
    }

    /// Register an attestation on-chain after verifying the quorum.
    pub fn register_attestation(
        &mut self,
        msg_sender: Address,
        call: ITLSNotary::registerAttestationCall,
    ) -> Result<B256> {
        let epoch = call.epoch;
        let proof_hash = call.proofHash;
        let statement_hash = call.statementHash;
        let server_name_hash = call.serverNameHash;
        let signatures = &call.signatures;
        let bitmap = &call.bitmap;

        // Derive session ID
        let session_id = Self::derive_session_id(epoch, proof_hash);

        // Check if already registered
        let already_registered = self.registered_proofs[proof_hash].read()?;
        if already_registered {
            return Err(TLSNotaryError::session_already_registered(session_id).into());
        }

        // Verify quorum by building attestation bytes and calling verify
        let mut attestation_data = Vec::new();
        attestation_data.extend_from_slice(&epoch.to_be_bytes());
        attestation_data.extend_from_slice(proof_hash.as_slice());
        attestation_data.extend_from_slice(statement_hash.as_slice());
        attestation_data.extend_from_slice(server_name_hash.as_slice());
        attestation_data.extend_from_slice(&(bitmap.len() as u32).to_be_bytes());
        attestation_data.extend_from_slice(bitmap);
        attestation_data.extend_from_slice(signatures);

        let verify_result = self.verify_attestation(ITLSNotary::verifyAttestationCall {
            attestation: attestation_data.into(),
        })?;

        if !verify_result.ok {
            let required_power =
                verify_result.totalPower * U256::from(QUORUM_NUMERATOR) / U256::from(QUORUM_DENOMINATOR);
            return Err(
                TLSNotaryError::insufficient_quorum(verify_result.signedPower, required_power)
                    .into(),
            );
        }

        // Get block timestamp
        let timestamp = StorageCtx.timestamp();
        let timestamp_u64 = timestamp.as_limbs()[0];

        // Store session record
        let session = SessionRecord {
            epoch,
            proof_hash,
            statement_hash,
            server_name_hash,
            submitter: msg_sender,
            timestamp: timestamp_u64,
        };

        self.sessions[session_id].write(session)?;
        self.registered_proofs[proof_hash].write(true)?;

        // Emit event
        self.emit_event(TLSNotaryEvent::AttestationRegistered(
            ITLSNotary::AttestationRegistered {
                sessionId: session_id,
                proofHash: proof_hash,
                epoch,
                statementHash: statement_hash,
                serverNameHash: server_name_hash,
                submitter: msg_sender,
            },
        ))?;

        Ok(session_id)
    }

    /// Get a registered session by ID.
    pub fn get_session(
        &self,
        call: ITLSNotary::getSessionCall,
    ) -> Result<ITLSNotary::getSessionReturn> {
        let session = self.sessions[call.sessionId].read()?;

        // Check if session exists (proof_hash will be zero for non-existent sessions)
        if session.proof_hash.is_zero() {
            return Err(TLSNotaryError::session_not_found(call.sessionId).into());
        }

        Ok(ITLSNotary::getSessionReturn {
            epoch: session.epoch,
            proofHash: session.proof_hash,
            statementHash: session.statement_hash,
            serverNameHash: session.server_name_hash,
            submitter: session.submitter,
            timestamp: session.timestamp,
        })
    }

    /// Check if a proof hash has been registered.
    pub fn is_proof_registered(&self, call: ITLSNotary::isProofRegisteredCall) -> Result<bool> {
        self.registered_proofs[call.proofHash].read()
    }

    /// Get the session ID for a given epoch and proof hash (pure computation).
    pub fn get_session_id(
        epoch: u64,
        proof_hash: B256,
    ) -> B256 {
        Self::derive_session_id(epoch, proof_hash)
    }

    // --- Internal helpers ---

    /// Get validator count by reading from the ValidatorConfig precompile's storage.
    fn get_validator_count(&self) -> Result<u64> {
        use tempo_contracts::precompiles::VALIDATOR_CONFIG_ADDRESS;

        // ValidatorConfig layout: slot 0 = owner, slot 1 = validators_array length
        // The array length is stored at the base slot for Vec fields
        let count_slot = U256::from(1);
        let count = StorageCtx.sload(VALIDATOR_CONFIG_ADDRESS, count_slot)?;
        Ok(count.as_limbs()[0])
    }

    /// Get validator address at a specific index from ValidatorConfig storage.
    fn get_validator_address(&self, index: u64) -> Result<Address> {
        use tempo_contracts::precompiles::VALIDATOR_CONFIG_ADDRESS;

        // ValidatorConfig: slot 1 = validators_array
        // Array elements at keccak256(1) + index
        let base_slot = U256::from(1);
        let array_base = keccak256(B256::from(base_slot));
        let element_slot = U256::from_be_bytes(*array_base) + U256::from(index);

        let value = StorageCtx.sload(VALIDATOR_CONFIG_ADDRESS, element_slot)?;

        // Address is stored in the lower 20 bytes
        let bytes: [u8; 32] = value.to_be_bytes();
        Ok(Address::from_slice(&bytes[12..32]))
    }

    /// Perform ECDSA recovery to get the signer address.
    fn ecrecover(message: B256, v: u8, r: B256, s: B256) -> Option<Address> {
        use alloy::primitives::Signature;

        let v_normalized = if v >= 27 { v - 27 } else { v };
        let sig = Signature::new(
            U256::from_be_bytes(*r),
            U256::from_be_bytes(*s),
            v_normalized != 0,
        );

        sig.recover_address_from_prehash(&message).ok()
    }
}
