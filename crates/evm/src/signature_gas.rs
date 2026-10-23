use evm2::interpreter::gas::COLD_SLOAD_COST;
use tempo_primitives::transaction::{AccountSignature, TempoSignature};

/// Additional gas for keychain signatures (key validation overhead: cold SLOAD + processing).
const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST as u64 + 900;

/// Verification cost beyond the baseline signature charge, without keychain processing.
#[inline]
pub(crate) fn account_signature_verification_gas(signature: &AccountSignature) -> u64 {
    match signature {
        AccountSignature::Primitive(signature) => signature.intrinsic_verification_gas(),
        // TODO: Configurable account verification gas is implemented in #7578.
        AccountSignature::ConfigurableAccount(_) => 0,
    }
}

/// Calculates the gas cost for verifying an AA signature.
///
/// For keychain signatures, adds key validation overhead to the inner signature cost. Returns the
/// additional gas required beyond the base transaction cost.
#[inline]
pub(crate) fn tempo_signature_verification_gas(signature: &TempoSignature) -> u64 {
    match signature {
        TempoSignature::Primitive(primitive_sig) => primitive_sig.intrinsic_verification_gas(),
        TempoSignature::Keychain(keychain_sig) => {
            account_signature_verification_gas(&keychain_sig.signature) + KEYCHAIN_VALIDATION_GAS
        }
        // TODO: Configurable account verification gas is implemented in #7578.
        TempoSignature::ConfigurableAccount(_) => 0,
    }
}

pub(crate) fn calldata_tokens(input: &[u8]) -> u64 {
    input
        .iter()
        .map(|byte| if *byte == 0 { 1 } else { 4 })
        .sum()
}
