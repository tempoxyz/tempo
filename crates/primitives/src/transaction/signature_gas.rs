//! Gas calculation for Tempo signature verification.
//!
//! This module provides gas cost calculations for different signature types.
//! Used by both transaction validation (tempo-revm handler) and the signature
//! verification precompile (tempo-precompiles).

use super::tt_signature::{PrimitiveSignature, TempoSignature};
use revm::interpreter::gas::{COLD_SLOAD_COST, STANDARD_TOKEN_COST, get_tokens_in_calldata_istanbul};

/// Additional gas for P256 signature verification.
/// P256 precompile cost (6900 from EIP-7951) + 1100 for 129 bytes extra signature size - ecrecover savings (3000)
pub const P256_VERIFY_GAS: u64 = 5_000;

/// Gas cost for ecrecover signature verification.
pub const ECRECOVER_GAS: u64 = 3_000;

/// Additional gas for Keychain signatures (key validation overhead: COLD_SLOAD_COST + 900 processing)
pub const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST + 900;

/// Calculate gas for a primitive signature type.
///
/// Returns the *additional* gas beyond the base transaction cost:
/// - Secp256k1: 0 (already included in base 21k)
/// - P256: 5000 gas
/// - WebAuthn: 5000 gas + calldata cost for webauthn_data
#[inline]
pub fn primitive_signature_verification_gas(signature: &PrimitiveSignature) -> u64 {
    match signature {
        PrimitiveSignature::Secp256k1(_) => 0,
        PrimitiveSignature::P256(_) => P256_VERIFY_GAS,
        PrimitiveSignature::WebAuthn(webauthn_sig) => {
            let tokens = get_tokens_in_calldata_istanbul(&webauthn_sig.webauthn_data);
            P256_VERIFY_GAS + tokens * STANDARD_TOKEN_COST
        }
    }
}

/// Calculate gas for a Tempo signature.
///
/// Returns the *additional* gas beyond the base transaction cost.
/// For Keychain signatures, adds key validation overhead to the inner signature cost.
#[inline]
pub fn tempo_signature_verification_gas(signature: &TempoSignature) -> u64 {
    match signature {
        TempoSignature::Primitive(prim_sig) => primitive_signature_verification_gas(prim_sig),
        TempoSignature::Keychain(keychain_sig) => {
            primitive_signature_verification_gas(&keychain_sig.signature) + KEYCHAIN_VALIDATION_GAS
        }
    }
}

/// Calculate gas for signature verification in a precompile context.
///
/// Unlike transaction validation, precompile calls don't have the 21k base gas
/// that includes ecrecover. This function adds the ECRECOVER_GAS baseline.
#[inline]
pub fn precompile_signature_verification_gas(signature: &TempoSignature) -> u64 {
    ECRECOVER_GAS + tempo_signature_verification_gas(signature)
}
