use revm::interpreter::gas::COLD_SLOAD_COST;
use tempo_primitives::transaction::TempoSignature;

/// Additional gas for keychain signatures (key validation overhead: cold SLOAD + processing).
const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST + 900;

/// Calculates the gas cost for verifying an AA signature.
///
/// For keychain signatures, adds key validation overhead to the inner signature cost. Returns the
/// additional gas required beyond the base transaction cost.
#[inline]
pub(crate) fn tempo_signature_verification_gas(signature: &TempoSignature) -> u64 {
    match signature {
        TempoSignature::Primitive(primitive_sig) => primitive_sig.intrinsic_verification_gas(),
        TempoSignature::Keychain(keychain_sig) => {
            keychain_sig.signature.intrinsic_verification_gas() + KEYCHAIN_VALIDATION_GAS
        }
    }
}
