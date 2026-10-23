use evm2::interpreter::gas::COLD_SLOAD_COST;
use tempo_precompiles::ECRECOVER_GAS;
use tempo_primitives::transaction::{
    AccountSignature, ConfigurableAccountSignature, PrimitiveSignature, TempoSignature,
};

/// Additional gas for keychain signatures (key validation overhead: cold SLOAD + processing).
const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST as u64 + 900;

/// Calculates the gas cost for verifying a primitive signature.
///
/// Returns the additional gas required beyond the base transaction cost:
/// - Secp256k1: 0 (already included in base 21k)
/// - P256: 5000 gas
/// - WebAuthn: 5000 gas + calldata cost for `webauthn_data`
#[inline]
pub(crate) fn primitive_signature_verification_gas(signature: &PrimitiveSignature) -> u64 {
    // Every signature type costs at least `ECRECOVER_GAS`, so this cannot underflow.
    signature.verification_gas() - ECRECOVER_GAS
}

/// Verification cost beyond the baseline signature charge, without keychain processing.
#[inline]
pub(crate) fn account_signature_verification_gas(signature: &AccountSignature) -> u64 {
    match signature {
        AccountSignature::Primitive(signature) => primitive_signature_verification_gas(signature),
        AccountSignature::ConfigurableAccount(signature) => {
            configurable_account_signature_verification_gas(signature)
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
            account_signature_verification_gas(&keychain_sig.signature)
                .saturating_add(KEYCHAIN_VALIDATION_GAS)
        }
        TempoSignature::ConfigurableAccount(signature) => {
            configurable_account_signature_verification_gas(signature)
        }
    }
}

pub(crate) fn calldata_tokens(input: &[u8]) -> u64 {
    input
        .iter()
        .map(|byte| if *byte == 0 { 1 } else { 4 })
        .sum()
}

/// Owner quorum verification cost beyond the baseline signature charge.
fn configurable_account_signature_verification_gas(
    signature: &ConfigurableAccountSignature,
) -> u64 {
    // Only a `u64` overflow fails; saturating keeps such a transaction unaffordable.
    signature
        .verification_gas()
        .map_or(u64::MAX, |gas| gas.saturating_sub(ECRECOVER_GAS))
}
