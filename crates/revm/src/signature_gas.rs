use alloy_rlp::Encodable;
use revm::interpreter::gas::{
    COLD_SLOAD_COST, STANDARD_TOKEN_COST, get_tokens_in_calldata_istanbul,
};
use tempo_precompiles::native_multisig::keccak_cost;
use tempo_primitives::transaction::{
    AccountSignature, MultisigSignature, PrimitiveSignature, TempoSignature,
    multisig::MULTISIG_SIGNATURE_DOMAIN,
};

/// Additional gas for P256 signature verification.
///
/// This includes the P256 precompile cost, the extra signature calldata, and the ecrecover savings
/// already included in the base transaction cost.
pub(crate) const P256_VERIFY_GAS: u64 = 5_000;

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
    match signature {
        PrimitiveSignature::Secp256k1(_) => 0,
        PrimitiveSignature::P256(_) => P256_VERIFY_GAS,
        PrimitiveSignature::WebAuthn(webauthn_sig) => {
            let tokens = get_tokens_in_calldata_istanbul(&webauthn_sig.webauthn_data);
            P256_VERIFY_GAS + tokens * STANDARD_TOKEN_COST
        }
    }
}

/// Verification cost beyond the baseline signature charge, without keychain processing.
#[inline]
pub(crate) fn account_signature_verification_gas(signature: &AccountSignature) -> u64 {
    match signature {
        AccountSignature::Primitive(signature) => primitive_signature_verification_gas(signature),
        AccountSignature::Multisig(signature) => {
            multisig_verification_gas(signature).saturating_sub(3_000)
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
            multisig_verification_gas(signature).saturating_sub(3_000)
        }
    }
}

/// Registered-state V cost. Initial derivation and per-account registration are added after
/// reading the account leaf. Each role pays this cost independently.
pub(crate) fn multisig_verification_gas(signature: &MultisigSignature) -> u64 {
    let mut witness =
        Vec::with_capacity(signature.account().length() + signature.config().length());
    signature.account().encode(&mut witness);
    signature.config().encode(&mut witness);
    get_tokens_in_calldata_istanbul(&witness) * STANDARD_TOKEN_COST
        + keccak_cost(signature.config().commitment_preimage_len())
        + keccak_cost(MULTISIG_SIGNATURE_DOMAIN.len() + 32 + 20 + 8)
        + signature
            .signatures()
            .iter()
            .map(|signature| 3_000 + primitive_signature_verification_gas(signature))
            .sum::<u64>()
}
