use evm2::interpreter::gas::COLD_SLOAD_COST;
use tempo_primitives::transaction::{AccountSignature, TempoSignature};

/// Additional gas for keychain signatures (key validation overhead: cold SLOAD + processing).
const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST as u64 + 900;

/// Calculates the gas cost for verifying an AA signature.
///
/// For keychain signatures, adds key validation overhead to the inner signature cost. Returns the
/// additional gas required beyond the base transaction cost.
#[inline]
pub(crate) fn tempo_signature_verification_gas(signature: &TempoSignature) -> u64 {
    match signature {
        TempoSignature::Primitive(primitive_sig) => primitive_sig.intrinsic_verification_gas(),
        TempoSignature::Keychain(keychain_sig) => {
            match &keychain_sig.signature {
                AccountSignature::Primitive(signature) => signature.intrinsic_verification_gas(),
                // Only a `u64` overflow fails; saturating keeps such a transaction unaffordable.
                AccountSignature::ConfigurableAccount(signature) => {
                    signature.intrinsic_verification_gas().unwrap_or(u64::MAX)
                }
            }
            .saturating_add(KEYCHAIN_VALIDATION_GAS)
        }
        TempoSignature::ConfigurableAccount(signature) => {
            signature.intrinsic_verification_gas().unwrap_or(u64::MAX)
        }
    }
}

pub(crate) fn calldata_tokens(input: &[u8]) -> u64 {
    input
        .iter()
        .map(|byte| if *byte == 0 { 1 } else { 4 })
        .sum()
}
