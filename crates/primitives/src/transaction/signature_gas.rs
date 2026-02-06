//! Gas calculation for Tempo signature verification.
//!
//! This module provides gas cost calculations for different signature types.
//! Used by both transaction validation (tempo-revm handler) and the signature
//! verification precompile (tempo-precompiles).
//!
//! # Gas Calculation Contexts
//!
//! There are two contexts where signature verification gas is calculated:
//!
//! 1. **Transaction validation** (`tempo_signature_verification_gas`): The signature is part of
//!    the transaction envelope, NOT calldata. WebAuthn's variable-length data must be charged.
//!
//! 2. **Precompile calls** (`precompile_signature_verification_gas`): The signature is passed
//!    as calldata, so the EVM already charges calldata gas. We only add the verification cost,
//!    NOT the WebAuthn calldata cost (that would be double-charging).

use super::tt_signature::{PrimitiveSignature, TempoSignature};
use revm::interpreter::gas::{COLD_SLOAD_COST, STANDARD_TOKEN_COST, get_tokens_in_calldata_istanbul};

/// Additional gas for P256 signature verification.
/// P256 precompile cost (6900 from EIP-7951) + 1100 for 129 bytes extra signature size - ecrecover savings (3000)
pub const P256_VERIFY_GAS: u64 = 5_000;

/// Gas cost for ecrecover signature verification.
pub const ECRECOVER_GAS: u64 = 3_000;

/// Additional gas for Keychain signatures (key validation overhead: COLD_SLOAD_COST + 900 processing)
pub const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST + 900;

/// Calculate gas for a primitive signature type in transaction context.
///
/// Returns the *additional* gas beyond the base transaction cost:
/// - Secp256k1: 0 (already included in base 21k)
/// - P256: 5000 gas
/// - WebAuthn: 5000 gas + calldata cost for webauthn_data
///
/// Note: This includes WebAuthn calldata gas because transaction signatures are NOT
/// part of EVM calldata - they're in the transaction envelope.
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

/// Calculate gas for a primitive signature type in precompile context.
///
/// Unlike transaction validation, precompile calls receive the signature as calldata,
/// so the EVM already charges for WebAuthn's variable-length data. We only charge
/// for the verification cost.
///
/// - Secp256k1: 0 (baseline covered by ECRECOVER_GAS in the precompile function)
/// - P256: 5000 gas
/// - WebAuthn: 5000 gas (NO calldata cost - already paid by EVM)
#[inline]
pub fn primitive_signature_verification_gas_precompile(signature: &PrimitiveSignature) -> u64 {
    match signature {
        PrimitiveSignature::Secp256k1(_) => 0,
        PrimitiveSignature::P256(_) => P256_VERIFY_GAS,
        PrimitiveSignature::WebAuthn(_) => P256_VERIFY_GAS,
    }
}

/// Calculate gas for a Tempo signature in transaction context.
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
/// Unlike transaction validation:
/// 1. Precompile calls don't have the 21k base gas that includes ecrecover,
///    so we add ECRECOVER_GAS as the baseline.
/// 2. The signature is passed as calldata, so the EVM already charges for
///    WebAuthn's variable-length data - we don't add it again.
#[inline]
pub fn precompile_signature_verification_gas(signature: &TempoSignature) -> u64 {
    let verification_gas = match signature {
        TempoSignature::Primitive(prim_sig) => {
            primitive_signature_verification_gas_precompile(prim_sig)
        }
        TempoSignature::Keychain(keychain_sig) => {
            primitive_signature_verification_gas_precompile(&keychain_sig.signature)
                + KEYCHAIN_VALIDATION_GAS
        }
    };
    ECRECOVER_GAS + verification_gas
}
