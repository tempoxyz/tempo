pub mod dispatch;

use crate::{
    SIGNATURE_VERIFIER_ADDRESS,
    account_keychain::{AccountKeychain, AuthorizedKey},
    configurable_account::{initial_account_proof_gas, valid_account},
    error::{Result, TempoPrecompileError},
    storage::{account_config_commitment, keccak_cost},
};
use alloy::{
    primitives::{Address, B256, Bytes, KECCAK256_EMPTY},
    rlp::{self, Encodable},
};
use evm2::interpreter::gas::STANDARD_TOKEN_COST;
use tempo_contracts::precompiles::SignatureVerifierError;
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::{
    ConfigurableAccountSignature, SignatureType,
    configurable_account::CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN,
    tt_signature::{AccountSignature, KeychainSignature, PrimitiveSignature, TempoSignature},
};
use tracing::trace;

#[contract(addr = SIGNATURE_VERIFIER_ADDRESS)]
pub struct SignatureVerifier {}

impl SignatureVerifier {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn recover(&self, hash: B256, signature: Bytes) -> Result<Address> {
        // Parse and validate signature (handles size checks + type disambiguation).
        let sig = PrimitiveSignature::from_bytes(&signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;

        // Charge verification gas before performing verification.
        self.storage.deduct_gas(sig.base_verification_gas())?;

        // Verify and recover signer.
        sig.recover_signer(&hash)
            .map_err(|_| SignatureVerifierError::invalid_signature().into())
    }

    /// Returns whether `signature` is an active access-key signature for `account`.
    ///
    /// From T14, `false` when the recovered key ID has a nonzero configuration commitment
    /// (TIP-1112), even under a stored grant, or when the inner signature type differs from the
    /// stored key type.
    pub fn verify_keychain(&self, account: Address, hash: B256, signature: Bytes) -> Result<bool> {
        let recovered = self.recover_keychain_key(hash, signature)?;
        if recovered.account != account || self.storage.is_retired_root(recovered.key_id)? {
            return Ok(false);
        }

        Ok(self
            .active_key(account, recovered.key_id, recovered.signature_type)?
            .is_some())
    }

    /// Returns whether `signature` is an active admin access-key signature for `account`, or its
    /// root key's.
    ///
    /// From T14, `false` when the recovered key ID has a nonzero configuration commitment
    /// (TIP-1112), including the implicit root of `account` itself, or when the inner signature
    /// type of an access-key signature differs from the stored key type.
    pub fn verify_keychain_admin(
        &self,
        account: Address,
        hash: B256,
        signature: Bytes,
    ) -> Result<bool> {
        let recovered = self.recover_keychain_key(hash, signature)?;
        if recovered.account != account || self.storage.is_retired_root(recovered.key_id)? {
            return Ok(false);
        }

        // The root is implicitly admin without a stored access-key grant.
        if recovered.key_id == account {
            return Ok(true);
        }
        Ok(self
            .active_key(account, recovered.key_id, recovered.signature_type)?
            .is_some_and(|key| key.is_admin))
    }

    fn verify_configurable_account(
        &self,
        account: Address,
        hash: B256,
        bytes: &[u8],
    ) -> Result<bool> {
        let signature = TempoSignature::from_bytes(bytes).map_err(|error| {
            trace!(%error, "malformed configurable account signature");
            SignatureVerifierError::invalid_format()
        })?;
        let Some(signature) = signature.as_configurable_account() else {
            return Err(SignatureVerifierError::invalid_format().into());
        };
        let config = signature.config();
        let spec = self.storage.spec();
        let (commitment, has_code) = self.storage.with_account_info(account, |info| {
            Ok((
                account_config_commitment(info, spec)?,
                info.code_hash != KECCAK256_EMPTY,
            ))
        })?;

        let initial_proof_gas = if commitment.is_zero() {
            initial_account_proof_gas(config)?
        } else {
            0
        };
        let verification_gas = configurable_account_verification_gas(signature)?
            .checked_add(initial_proof_gas)
            .ok_or(TempoPrecompileError::OutOfGas)?;
        self.storage.deduct_gas(verification_gas)?;
        if signature.account() != account
            || !valid_account(account, self.storage.spec())
            || has_code
        {
            return Ok(false);
        }
        let factory = self
            .storage
            .with_block_env(|block_env| block_env.ext.configurable_account_recovery_factory());
        if signature
            .validate_account_commitment(commitment, factory)
            .is_err()
        {
            return Ok(false);
        }

        signature.verify_approvals(hash).map_err(|error| {
            trace!(%error, "invalid configurable account approvals");
            SignatureVerifierError::invalid_signature()
        })?;
        Ok(true)
    }

    /// Returns the active access key, or `None` when the keychain rejects it.
    fn active_key(
        &self,
        account: Address,
        key_id: Address,
        signature_type: SignatureType,
    ) -> Result<Option<AuthorizedKey>> {
        let timestamp = self.storage.timestamp().saturating_to::<u64>();
        // Pre-T14 verification ignored the stored type; preserve that behavior on replay.
        let expected_type = self
            .storage
            .spec()
            .is_t14()
            .then_some(signature_type.into());
        match AccountKeychain::new().validate_keychain_authorization(
            account,
            key_id,
            timestamp,
            expected_type,
        ) {
            Ok(key) => Ok(Some(key)),
            Err(err) if err.is_system_error() => Err(err),
            Err(err) => {
                trace!(?err, %account, %key_id, "keychain rejected the key");
                Ok(None)
            }
        }
    }

    fn recover_keychain_key(&self, hash: B256, signature: Bytes) -> Result<RecoveredKeychainKey> {
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
        Ok(RecoveredKeychainKey {
            account: keychain_sig.user_address,
            key_id,
            signature_type: signature.signature_type(),
        })
    }
}

/// The access key a keychain signature was made with, and the account it claims to act for.
struct RecoveredKeychainKey {
    /// Account embedded in the keychain signature.
    account: Address,
    /// Key ID recovered from the inner primitive signature.
    key_id: Address,
    /// Type of the inner primitive signature.
    signature_type: SignatureType,
}

/// Full configurable account verification cost for a registered account, before account access.
/// Initial address derivation is charged separately when the stored commitment is zero.
///
/// Fails with `OutOfGas` if the cost overflows `u64`.
pub fn configurable_account_verification_gas(
    signature: &ConfigurableAccountSignature,
) -> Result<u64> {
    let mut witness = rlp::encode(signature.account());
    signature.config().encode(&mut witness);
    signature
        .signatures()
        .iter()
        .map(primitive_verification_gas)
        .chain([
            calldata_gas(&witness),
            keccak_cost(signature.config().commitment_preimage_len())?,
            keccak_cost(CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN.len() + 32 + 20 + 8)?,
        ])
        .try_fold(0u64, u64::checked_add)
        .ok_or(TempoPrecompileError::OutOfGas)
}

/// Full primitive verification cost, including `WebAuthn` data calldata.
///
/// Unlike `tempo_evm`'s `primitive_signature_verification_gas`, this does not subtract the
/// ecrecover baseline already covered by ordinary intrinsic gas.
fn primitive_verification_gas(signature: &PrimitiveSignature) -> u64 {
    let webauthn_data_gas = match signature {
        PrimitiveSignature::WebAuthn(sig) => calldata_gas(&sig.webauthn_data),
        PrimitiveSignature::Secp256k1(_) | PrimitiveSignature::P256(_) => 0,
    };
    signature.base_verification_gas() + webauthn_data_gas
}

/// Istanbul calldata cost of `input`: one token per zero byte, four per nonzero byte.
fn calldata_gas(input: &[u8]) -> u64 {
    input
        .iter()
        .map(|byte| if *byte == 0 { 1 } else { 4 })
        .sum::<u64>()
        * u64::from(STANDARD_TOKEN_COST)
}

#[cfg(test)]
mod tests;
