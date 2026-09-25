pub mod dispatch;

use crate::{
    SIGNATURE_VERIFIER_ADDRESS,
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    native_multisig::{keccak_cost, valid_account},
};
use alloy::primitives::{Address, B256, Bytes};
use alloy_rlp::Encodable;
use revm::interpreter::gas::{STANDARD_TOKEN_COST, get_tokens_in_calldata_istanbul};
use tempo_contracts::precompiles::SignatureVerifierError;
use tempo_precompiles_macros::contract;
use tempo_primitives::{
    account::decode_config_commitment,
    transaction::{
        MultisigSignature, MultisigWeightAccumulator,
        multisig::{MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN, MULTISIG_SIGNATURE_DOMAIN},
        tt_signature::{AccountSignature, KeychainSignature, PrimitiveSignature, TempoSignature},
    },
};

/// Gas cost for secp256k1 signature verification.
const SECP256K1_VERIFY_GAS: u64 = 3_000;

/// Gas cost for P256 signature verification.
const P256_VERIFY_GAS: u64 = 8_000;

/// Gas cost for WebAuthn signature verification.
const WEBAUTHN_VERIFY_GAS: u64 = 8_000;

#[contract(addr = SIGNATURE_VERIFIER_ADDRESS)]
pub struct SignatureVerifier {}

impl SignatureVerifier {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn recover(&mut self, hash: B256, signature: Bytes) -> Result<Address> {
        // Parse and validate signature (handles size checks + type disambiguation).
        let sig = PrimitiveSignature::from_bytes(&signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;

        // Charge verification gas before performing verification.
        let verify_gas = match &sig {
            PrimitiveSignature::Secp256k1(_) => SECP256K1_VERIFY_GAS,
            PrimitiveSignature::P256(_) => P256_VERIFY_GAS,
            PrimitiveSignature::WebAuthn(_) => WEBAUTHN_VERIFY_GAS,
        };
        self.storage.deduct_gas(verify_gas)?;

        // Verify and recover signer.
        sig.recover_signer(&hash)
            .map_err(|_| SignatureVerifierError::invalid_signature().into())
    }

    pub fn verify_keychain(
        &mut self,
        account: Address,
        hash: B256,
        signature: Bytes,
    ) -> Result<bool> {
        let (embedded_account, key_id, signature_type) =
            self.recover_keychain_key(hash, signature)?;
        if embedded_account != account {
            return Ok(false);
        }

        self.verify_registered_key(account, key_id, signature_type, false)
    }

    pub fn verify_keychain_admin(
        &mut self,
        account: Address,
        hash: B256,
        signature: Bytes,
    ) -> Result<bool> {
        let (embedded_account, key_id, signature_type) =
            self.recover_keychain_key(hash, signature)?;
        if embedded_account != account {
            return Ok(false);
        }

        self.verify_registered_key(account, key_id, signature_type, true)
    }

    pub fn verify_multisig(&mut self, account: Address, hash: B256, bytes: Bytes) -> Result<bool> {
        let signature = TempoSignature::from_bytes(&bytes)
            .map_err(|_| SignatureVerifierError::invalid_format())?;
        let Some(signature) = signature.as_multisig() else {
            return Err(SignatureVerifierError::invalid_format().into());
        };
        let config = signature.config();
        let (commitment, has_code) = self.storage.with_account_info(account, |info| {
            let commitment = decode_config_commitment(&info.extension, true)
                .map_err(|error| TempoPrecompileError::Fatal(error.to_string()))?;
            Ok((commitment, !info.is_empty_code_hash()))
        })?;

        self.charge_multisig_gas(signature, commitment.is_zero())?;
        if signature.account() != account
            || !valid_account(account, self.storage.spec())
            || has_code
        {
            return Ok(false);
        }
        let actual = signature.config_commitment();
        if commitment.is_zero() {
            let factory = self
                .storage
                .with_block_env(|block| block.multisig_recovery_factory)
                .filter(|factory| !factory.is_zero());
            if config.version != 0
                || factory
                    .is_none_or(|factory| config.derive_account(factory).ok() != Some(account))
            {
                return Ok(false);
            }
        } else if commitment != actual {
            return Ok(false);
        }

        let digest = signature.digest(hash);
        let mut weight = MultisigWeightAccumulator::new(config.threshold)
            .map_err(|_| SignatureVerifierError::invalid_signature())?;
        for (index, approval) in signature.signatures().iter().enumerate() {
            let owner = approval
                .recover_signer(&digest)
                .map_err(|_| SignatureVerifierError::invalid_signature())?;
            let owner_weight = config
                .owner_weight(owner)
                .ok_or_else(SignatureVerifierError::invalid_signature)?;
            weight
                .record_owner(owner, owner_weight)
                .map_err(|_| SignatureVerifierError::invalid_signature())?;
            if weight.has_quorum() && index + 1 != signature.signatures().len() {
                return Err(SignatureVerifierError::invalid_signature().into());
            }
        }
        weight
            .finish()
            .map_err(|_| SignatureVerifierError::invalid_signature())?;
        Ok(true)
    }

    fn charge_multisig_gas(&mut self, signature: &MultisigSignature, initial: bool) -> Result<()> {
        let config = signature.config();
        let mut witness = Vec::new();
        signature.account().encode(&mut witness);
        config.encode(&mut witness);
        let witness_gas = get_tokens_in_calldata_istanbul(&witness) * STANDARD_TOKEN_COST;
        let proof_gas = keccak_cost(config.commitment_preimage_len())
            + if initial {
                keccak_cost(config.account_salt_preimage_len())
                    + keccak_cost(MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN)
            } else {
                0
            };
        let owner_gas = signature
            .signatures()
            .iter()
            .map(|signature| match signature {
                PrimitiveSignature::Secp256k1(_) => SECP256K1_VERIFY_GAS,
                PrimitiveSignature::P256(_) => P256_VERIFY_GAS,
                PrimitiveSignature::WebAuthn(sig) => {
                    WEBAUTHN_VERIFY_GAS
                        + get_tokens_in_calldata_istanbul(&sig.webauthn_data) * STANDARD_TOKEN_COST
                }
            })
            .sum::<u64>();
        self.storage.deduct_gas(
            witness_gas
                + proof_gas
                + keccak_cost(MULTISIG_SIGNATURE_DOMAIN.len() + 32 + 20 + 8)
                + owner_gas,
        )
    }

    fn verify_registered_key(
        &self,
        account: Address,
        key_id: Address,
        signature_type: u8,
        require_admin: bool,
    ) -> Result<bool> {
        // The root is implicitly admin without a stored access-key grant.
        if require_admin && key_id == account {
            return Ok(true);
        }

        let timestamp = self.storage.timestamp().saturating_to::<u64>();
        // Pre-T14 verification ignored the stored type; preserve that behavior on replay.
        let expected_type = self.storage.spec().is_t14().then_some(signature_type);
        match AccountKeychain::new().validate_keychain_authorization(
            account,
            key_id,
            timestamp,
            expected_type,
        ) {
            Ok(key) => Ok(!require_admin || key.is_admin),
            Err(err) if err.is_system_error() => Err(err),
            Err(_) => Ok(false),
        }
    }

    fn recover_keychain_key(
        &mut self,
        hash: B256,
        signature: Bytes,
    ) -> Result<(Address, Address, u8)> {
        let sig = TempoSignature::from_bytes(&signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;
        let keychain_sig = sig
            .as_keychain()
            .ok_or_else(SignatureVerifierError::invalid_format)?;

        if keychain_sig.is_legacy() {
            return Err(SignatureVerifierError::invalid_format().into());
        }
        let AccountSignature::Primitive(signature) = &keychain_sig.signature else {
            return Err(SignatureVerifierError::invalid_format().into());
        };

        let signing_hash = KeychainSignature::signing_hash(hash, keychain_sig.user_address);
        let key_id = self.recover(signing_hash, signature.to_bytes())?;
        Ok((
            keychain_sig.user_address,
            key_id,
            signature.signature_type().into(),
        ))
    }
}

#[cfg(test)]
mod tests;
