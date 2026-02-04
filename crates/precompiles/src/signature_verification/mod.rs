//! Signature Verification Precompile (TIP-1020)
//!
//! Enables contracts to verify Tempo signature types (secp256k1, P256, WebAuthn, Keychain)
//! using the same verification logic as Tempo transaction processing.

pub mod dispatch;

use crate::{
    SIGNATURE_VERIFICATION_ADDRESS, account_keychain::AccountKeychain, error::Result,
};
use alloy::primitives::{Address, B256};
use tempo_contracts::precompiles::{
    ISignatureVerification::verifyCall, SignatureVerificationError,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::tt_signature::{
    KeychainSignature, PrimitiveSignature, TempoSignature,
};

pub use tempo_contracts::precompiles::ISignatureVerification;

/// Gas cost for ecrecover signature verification (baseline)
const ECRECOVER_GAS: u64 = 3_000;

/// Additional gas for P256 signature verification
/// P256 precompile cost (6900 from EIP-7951) + 1100 for extra signature bytes
const P256_VERIFY_GAS: u64 = 8_000;

/// Additional gas for Keychain validation (cold SLOAD + processing)
const KEYCHAIN_VALIDATION_GAS: u64 = 2_100 + 900;

/// Gas per calldata token (16 gas per non-zero byte, 4 per zero byte, averaged to 16)
const CALLDATA_TOKEN_GAS: u64 = 16;

/// Signature Verification precompile
#[contract(addr = SIGNATURE_VERIFICATION_ADDRESS)]
pub struct SignatureVerification {}

impl SignatureVerification {
    /// Calculate gas cost for signature verification based on signature type.
    ///
    /// This mirrors the gas schedule from tempo_revm/handler.rs but includes
    /// the ecrecover baseline since precompile calls don't have the 21k tx base.
    pub fn calculate_verification_gas(signature: &TempoSignature) -> u64 {
        match signature {
            TempoSignature::Primitive(prim) => Self::primitive_signature_gas(prim),
            TempoSignature::Keychain(keychain) => {
                Self::primitive_signature_gas(&keychain.signature) + KEYCHAIN_VALIDATION_GAS
            }
        }
    }

    fn primitive_signature_gas(prim: &PrimitiveSignature) -> u64 {
        match prim {
            PrimitiveSignature::Secp256k1(_) => ECRECOVER_GAS,
            PrimitiveSignature::P256(_) => P256_VERIFY_GAS,
            PrimitiveSignature::WebAuthn(webauthn) => {
                let data_tokens = webauthn.webauthn_data.len() as u64;
                P256_VERIFY_GAS + data_tokens * CALLDATA_TOKEN_GAS
            }
        }
    }

    /// Verify a Tempo signature
    ///
    /// Returns true if the signature is valid and the recovered signer matches.
    /// Reverts with appropriate error otherwise.
    pub fn verify(&mut self, call: verifyCall) -> Result<bool> {
        let signer = call.signer;
        let hash = call.hash;
        let signature_bytes = call.signature;

        let signature = TempoSignature::from_bytes(&signature_bytes)
            .map_err(|_| SignatureVerificationError::invalid_signature())?;

        let verification_gas = Self::calculate_verification_gas(&signature);
        self.storage.deduct_gas(verification_gas)?;

        let recovered = signature
            .recover_signer(&hash)
            .map_err(|_| SignatureVerificationError::invalid_signature())?;

        if let Some(keychain_sig) = signature.as_keychain() {
            self.validate_keychain_authorization(&hash, signer, keychain_sig)?;
        }

        if recovered != signer {
            return Err(SignatureVerificationError::signer_mismatch(signer, recovered).into());
        }

        Ok(true)
    }

    /// Validate that a keychain access key is authorized
    fn validate_keychain_authorization(
        &mut self,
        hash: &B256,
        expected_signer: Address,
        keychain_sig: &KeychainSignature,
    ) -> Result<()> {
        let access_key = keychain_sig
            .key_id(hash)
            .map_err(|_| SignatureVerificationError::invalid_signature())?;

        let user_address = keychain_sig.user_address;

        if user_address != expected_signer {
            return Err(
                SignatureVerificationError::signer_mismatch(expected_signer, user_address).into(),
            );
        }

        let key_slot = AccountKeychain::new().keys[user_address][access_key].base_slot();
        let key_value = self.storage.sload(
            tempo_contracts::precompiles::ACCOUNT_KEYCHAIN_ADDRESS,
            key_slot,
        )?;

        let key_info = crate::account_keychain::AuthorizedKey::decode_from_slot(key_value);

        if key_info.expiry == 0 {
            return Err(SignatureVerificationError::unauthorized_keychain_key().into());
        }

        if key_info.is_revoked {
            return Err(SignatureVerificationError::unauthorized_keychain_key().into());
        }

        let now = self.storage.timestamp().saturating_to::<u64>();
        if key_info.expiry != u64::MAX && key_info.expiry <= now {
            return Err(SignatureVerificationError::unauthorized_keychain_key().into());
        }

        let expected_sig_type = keychain_sig.signature.signature_type() as u8;
        if key_info.signature_type != expected_sig_type {
            return Err(SignatureVerificationError::unauthorized_keychain_key().into());
        }

        Ok(())
    }
}
