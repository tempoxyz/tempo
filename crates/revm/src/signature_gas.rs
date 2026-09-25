use revm::interpreter::gas::{
    COLD_SLOAD_COST, STANDARD_TOKEN_COST, get_tokens_in_calldata_istanbul,
};
use tempo_precompiles::{ECRECOVER_GAS, signature_verifier::multisig_verification_gas};
use tempo_primitives::transaction::{AccountSignature, PrimitiveSignature, TempoSignature};

/// Additional gas for keychain signatures (key validation overhead: cold SLOAD + processing).
const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST + 900;

/// Calculates the gas cost for verifying a primitive signature.
///
/// Returns the additional gas required beyond the base transaction cost:
/// - Secp256k1: 0 (already included in base 21k)
/// - P256: 5000 gas
/// - WebAuthn: 5000 gas + calldata cost for `webauthn_data`
#[inline]
pub(crate) fn primitive_signature_verification_gas(signature: &PrimitiveSignature) -> u64 {
    let webauthn_data_gas = match signature {
        PrimitiveSignature::WebAuthn(sig) => {
            get_tokens_in_calldata_istanbul(&sig.webauthn_data) * STANDARD_TOKEN_COST
        }
        _ => 0,
    };
    signature.base_verification_gas() - ECRECOVER_GAS + webauthn_data_gas
}

/// Verification cost beyond the baseline signature charge, without keychain processing.
#[inline]
pub(crate) fn account_signature_verification_gas(signature: &AccountSignature) -> u64 {
    match signature {
        AccountSignature::Primitive(signature) => primitive_signature_verification_gas(signature),
        AccountSignature::Multisig(signature) => {
            multisig_verification_gas(signature).saturating_sub(ECRECOVER_GAS)
        }
    }
}

/// Calculates the gas cost for verifying an AA signature.
///
/// For keychain signatures, adds key validation overhead to the inner signature cost. Returns the
/// additional gas required beyond the base transaction cost.
#[inline]
pub(crate) fn tempo_signature_verification_gas(signature: &TempoSignature) -> u64 {
    match signature {
        TempoSignature::Primitive(prim_sig) => primitive_signature_verification_gas(prim_sig),
        TempoSignature::Keychain(keychain_sig) => {
            account_signature_verification_gas(&keychain_sig.signature) + KEYCHAIN_VALIDATION_GAS
        }
        TempoSignature::Multisig(signature) => {
            multisig_verification_gas(signature).saturating_sub(ECRECOVER_GAS)
        }
    }
}
