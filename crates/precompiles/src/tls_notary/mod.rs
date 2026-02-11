pub mod dispatch;

use tempo_contracts::precompiles::TLS_NOTARY_ADDRESS;
pub use tempo_contracts::precompiles::{ITLSNotary, TLSNotaryError, TLSNotaryEvent};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    error::Result,
    storage::{Handler, Mapping, StorageCtx},
};
use alloy::primitives::{Address, B256, Signature, U256, keccak256};

const ATTESTATION_DOMAIN: &[u8] = b"TEMPO_TLSNOTARY_V1";
const SIGNATURE_LENGTH: usize = 65;
const MAX_SIGNATURES: usize = 200;

#[derive(Debug, Clone, Default, Storable)]
pub struct SessionRecord {
    pub proof_hash: B256,
    pub statement_hash: B256,
    pub server_name_hash: B256,
    pub submitter: Address,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Default, Storable)]
pub struct EmailClaim {
    pub claimant: Address,
    pub timestamp: u64,
}

#[contract(addr = TLS_NOTARY_ADDRESS)]
pub struct TLSNotary {
    owner: Address,
    notaries: Mapping<Address, bool>,
    sessions: Mapping<B256, SessionRecord>,
    registered_proofs: Mapping<B256, bool>,
    email_claims: Mapping<B256, EmailClaim>,
}

impl TLSNotary {
    pub fn initialize(&mut self, owner: Address) -> Result<()> {
        self.__initialize()?;
        self.owner.write(owner)
    }

    fn check_owner(&self, caller: Address) -> Result<()> {
        let owner = self.owner.read()?;
        if owner != caller {
            return Err(TLSNotaryError::unauthorized().into());
        }
        Ok(())
    }

    pub fn owner(&self) -> Result<Address> {
        self.owner.read()
    }

    pub fn transfer_ownership(
        &mut self,
        sender: Address,
        call: ITLSNotary::transferOwnershipCall,
    ) -> Result<()> {
        self.check_owner(sender)?;
        self.owner.write(call.newOwner)
    }

    // ──── Notary Management ────

    pub fn add_notary(
        &mut self,
        sender: Address,
        call: ITLSNotary::addNotaryCall,
    ) -> Result<()> {
        self.check_owner(sender)?;

        let already = self.notaries[call.notary].read()?;
        if already {
            return Err(TLSNotaryError::notary_already_registered(call.notary).into());
        }

        self.notaries[call.notary].write(true)?;

        self.emit_event(TLSNotaryEvent::NotaryAdded(ITLSNotary::NotaryAdded {
            notary: call.notary,
            addedBy: sender,
        }))
    }

    pub fn remove_notary(
        &mut self,
        sender: Address,
        call: ITLSNotary::removeNotaryCall,
    ) -> Result<()> {
        self.check_owner(sender)?;

        let exists = self.notaries[call.notary].read()?;
        if !exists {
            return Err(TLSNotaryError::notary_not_found(call.notary).into());
        }

        self.notaries[call.notary].write(false)?;

        self.emit_event(TLSNotaryEvent::NotaryRemoved(ITLSNotary::NotaryRemoved {
            notary: call.notary,
            removedBy: sender,
        }))
    }

    pub fn is_notary(&self, call: ITLSNotary::isNotaryCall) -> Result<bool> {
        self.notaries[call.notary].read()
    }

    // ──── Attestation message ────

    pub fn compute_attestation_message(
        chain_id: u64,
        proof_hash: B256,
        statement_hash: B256,
        server_name_hash: B256,
    ) -> B256 {
        let mut data = Vec::with_capacity(ATTESTATION_DOMAIN.len() + 8 + 32 * 3);
        data.extend_from_slice(ATTESTATION_DOMAIN);
        data.extend_from_slice(&chain_id.to_be_bytes());
        data.extend_from_slice(proof_hash.as_slice());
        data.extend_from_slice(statement_hash.as_slice());
        data.extend_from_slice(server_name_hash.as_slice());
        keccak256(&data)
    }

    fn verify_notary_signatures(
        &self,
        message: B256,
        signatures: &[u8],
    ) -> Result<u64> {
        if signatures.len() % SIGNATURE_LENGTH != 0 {
            return Err(TLSNotaryError::invalid_signature_length().into());
        }

        let sig_count = signatures.len() / SIGNATURE_LENGTH;
        if sig_count > MAX_SIGNATURES {
            return Err(TLSNotaryError::invalid_signature_length().into());
        }

        let mut valid_count = 0u64;

        for i in 0..sig_count {
            let offset = i * SIGNATURE_LENGTH;
            let sig_bytes = &signatures[offset..offset + SIGNATURE_LENGTH];

            let r = B256::from_slice(&sig_bytes[..32]);
            let s = B256::from_slice(&sig_bytes[32..64]);
            let v = sig_bytes[64];

            let recovered = Self::ecrecover(message, v, r, s);
            match recovered {
                Some(addr) => {
                    let is_notary = self.notaries[addr].read()?;
                    if !is_notary {
                        return Err(TLSNotaryError::signature_verification_failed(
                            U256::from(i),
                        )
                        .into());
                    }
                    valid_count += 1;
                }
                None => {
                    return Err(TLSNotaryError::signature_verification_failed(
                        U256::from(i),
                    )
                    .into());
                }
            }
        }

        Ok(valid_count)
    }

    // ──── Register Attestation ────

    pub fn register_attestation(
        &mut self,
        msg_sender: Address,
        call: ITLSNotary::registerAttestationCall,
    ) -> Result<B256> {
        let proof_hash = call.proofHash;
        let statement_hash = call.statementHash;
        let server_name_hash = call.serverNameHash;

        let already = self.registered_proofs[proof_hash].read()?;
        if already {
            return Err(TLSNotaryError::proof_already_registered(proof_hash).into());
        }

        let chain_id = StorageCtx.chain_id();
        let message = Self::compute_attestation_message(
            chain_id,
            proof_hash,
            statement_hash,
            server_name_hash,
        );

        let valid_count = self.verify_notary_signatures(message, &call.signatures)?;
        if valid_count == 0 {
            return Err(
                TLSNotaryError::insufficient_signatures(U256::ZERO, U256::from(1)).into(),
            );
        }

        let session_id =
            keccak256(&[proof_hash.as_slice(), msg_sender.as_slice()].concat());

        let timestamp = StorageCtx.timestamp();
        let ts_u64 = timestamp.as_limbs()[0];

        self.sessions[session_id].write(SessionRecord {
            proof_hash,
            statement_hash,
            server_name_hash,
            submitter: msg_sender,
            timestamp: ts_u64,
        })?;
        self.registered_proofs[proof_hash].write(true)?;

        self.emit_event(TLSNotaryEvent::AttestationRegistered(
            ITLSNotary::AttestationRegistered {
                sessionId: session_id,
                proofHash: proof_hash,
                statementHash: statement_hash,
                serverNameHash: server_name_hash,
                submitter: msg_sender,
            },
        ))?;

        Ok(session_id)
    }

    // ──── Email Claims ────

    pub fn claim_email(
        &mut self,
        msg_sender: Address,
        call: ITLSNotary::claimEmailCall,
    ) -> Result<B256> {
        let email_hash = keccak256(call.email.as_bytes());
        let server_name_hash = call.serverNameHash;
        let proof_hash = call.proofHash;

        let existing = self.email_claims[email_hash].read()?;
        if existing.claimant != Address::ZERO {
            return Err(
                TLSNotaryError::email_already_claimed(email_hash, existing.claimant).into(),
            );
        }

        let statement = format!("email:{} owner:{}", call.email, msg_sender);
        let statement_hash = keccak256(statement.as_bytes());

        let chain_id = StorageCtx.chain_id();
        let message = Self::compute_attestation_message(
            chain_id,
            proof_hash,
            statement_hash,
            server_name_hash,
        );

        let valid_count = self.verify_notary_signatures(message, &call.signatures)?;
        if valid_count == 0 {
            return Err(
                TLSNotaryError::insufficient_signatures(U256::ZERO, U256::from(1)).into(),
            );
        }

        let timestamp = StorageCtx.timestamp();
        let ts_u64 = timestamp.as_limbs()[0];

        self.email_claims[email_hash].write(EmailClaim {
            claimant: msg_sender,
            timestamp: ts_u64,
        })?;

        let claim_id = email_hash;
        self.registered_proofs[proof_hash].write(true)?;

        self.emit_event(TLSNotaryEvent::EmailClaimed(ITLSNotary::EmailClaimed {
            emailHash: email_hash,
            claimant: msg_sender,
            proofHash: proof_hash,
            serverNameHash: server_name_hash,
        }))?;

        Ok(claim_id)
    }

    pub fn email_owner(
        &self,
        call: ITLSNotary::emailOwnerCall,
    ) -> Result<ITLSNotary::emailOwnerReturn> {
        let claim = self.email_claims[call.emailHash].read()?;
        Ok(ITLSNotary::emailOwnerReturn {
            claimant: claim.claimant,
            timestamp: claim.timestamp,
        })
    }

    // ──── Queries ────

    pub fn get_session(
        &self,
        call: ITLSNotary::getSessionCall,
    ) -> Result<ITLSNotary::getSessionReturn> {
        let session = self.sessions[call.sessionId].read()?;
        if session.proof_hash.is_zero() {
            return Err(TLSNotaryError::session_not_found(call.sessionId).into());
        }
        Ok(ITLSNotary::getSessionReturn {
            proofHash: session.proof_hash,
            statementHash: session.statement_hash,
            serverNameHash: session.server_name_hash,
            submitter: session.submitter,
            timestamp: session.timestamp,
        })
    }

    pub fn is_proof_registered(
        &self,
        call: ITLSNotary::isProofRegisteredCall,
    ) -> Result<bool> {
        self.registered_proofs[call.proofHash].read()
    }

    // ──── Internal ────

    fn ecrecover(message: B256, v: u8, r: B256, s: B256) -> Option<Address> {
        let v_normalized = if v >= 27 { v - 27 } else { v };
        let sig = Signature::new(
            U256::from_be_bytes(*r),
            U256::from_be_bytes(*s),
            v_normalized != 0,
        );
        sig.recover_address_from_prehash(&message).ok()
    }
}
