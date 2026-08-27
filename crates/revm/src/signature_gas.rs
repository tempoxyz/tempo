use alloy_rlp::Encodable;
use revm::interpreter::gas::{
    COLD_ACCOUNT_ACCESS_COST, COLD_SLOAD_COST, KECCAK256, KECCAK256WORD, STANDARD_TOKEN_COST,
    get_tokens_in_calldata_istanbul,
};
use tempo_precompiles::ECRECOVER_GAS;
use tempo_primitives::transaction::{
    MAX_MULTISIG_NESTING_DEPTH, MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN, MULTISIG_SIGNATURE_DOMAIN,
    MultisigSignature, PrimitiveSignature, TempoSignature,
};

/// Additional gas for P256 signature verification.
///
/// This includes the P256 precompile cost, the extra signature calldata, and the ecrecover savings
/// already included in the base transaction cost.
pub const P256_VERIFY_GAS: u64 = 5_000;

/// Additional gas for keychain signatures (key validation overhead: cold SLOAD + processing).
const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST + 900;

/// Gas for reading a multisig account's configuration commitment.
pub const NATIVE_MULTISIG_COMMITMENT_READ_GAS: u64 = COLD_SLOAD_COST;

/// Gas for checking that each nested multisig owner account has no code or delegation.
pub const NATIVE_MULTISIG_NESTED_ACCOUNT_GAS: u64 = COLD_ACCOUNT_ACCESS_COST;

const MULTISIG_DIGEST_PREIMAGE_LEN: usize = MULTISIG_SIGNATURE_DOMAIN.len() + 32 + 20 + 8;

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

#[inline]
fn full_primitive_signature_gas(signature: &PrimitiveSignature) -> u64 {
    ECRECOVER_GAS + primitive_signature_verification_gas(signature)
}

fn native_multisig_owner_approval_gas(signature: &TempoSignature, depth: usize) -> u64 {
    match signature {
        TempoSignature::Primitive(primitive) => full_primitive_signature_gas(primitive),
        TempoSignature::Multisig(multisig) if depth < MAX_MULTISIG_NESTING_DEPTH => {
            NATIVE_MULTISIG_NESTED_ACCOUNT_GAS
                .saturating_add(native_multisig_node_gas(multisig, depth + 1))
        }
        // Shape validation rejects these cases before intrinsic gas is computed.
        TempoSignature::Keychain(_) | TempoSignature::Multisig(_) => 0,
    }
}

fn keccak_gas(byte_len: usize) -> u64 {
    KECCAK256.saturating_add(
        KECCAK256WORD.saturating_mul(u64::try_from(byte_len.div_ceil(32)).unwrap_or(u64::MAX)),
    )
}

fn native_multisig_witness_calldata_gas(signature: &MultisigSignature) -> u64 {
    let mut encoded =
        Vec::with_capacity(signature.account().length() + signature.config().length());
    signature.account().encode(&mut encoded);
    signature.config().encode(&mut encoded);
    get_tokens_in_calldata_istanbul(&encoded).saturating_mul(STANDARD_TOKEN_COST)
}

fn native_multisig_node_gas(signature: &MultisigSignature, depth: usize) -> u64 {
    let config = signature.config();
    let config_proof_gas = if config.version == 0 {
        keccak_gas(config.account_derivation_preimage_len())
            .saturating_add(keccak_gas(MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN))
    } else {
        keccak_gas(config.commitment_preimage_len())
    };
    let approval_gas = signature
        .signatures()
        .iter()
        .map(|approval| native_multisig_owner_approval_gas(approval, depth))
        .fold(0u64, u64::saturating_add);

    NATIVE_MULTISIG_COMMITMENT_READ_GAS
        .saturating_add(native_multisig_witness_calldata_gas(signature))
        .saturating_add(config_proof_gas)
        .saturating_add(keccak_gas(MULTISIG_DIGEST_PREIMAGE_LEN))
        .saturating_add(approval_gas)
}

/// Calculates the gas cost for verifying an AA signature.
///
/// For keychain signatures, adds key validation overhead to the inner signature cost. Returns the
/// additional gas required beyond the base transaction cost.
#[inline]
pub(crate) fn tempo_signature_verification_gas(signature: &TempoSignature) -> u64 {
    match signature {
        TempoSignature::Primitive(primitive) => primitive_signature_verification_gas(primitive),
        TempoSignature::Keychain(keychain) => {
            primitive_signature_verification_gas(&keychain.signature) + KEYCHAIN_VALIDATION_GAS
        }
        TempoSignature::Multisig(multisig) => {
            native_multisig_node_gas(multisig, 1).saturating_sub(ECRECOVER_GAS)
        }
    }
}
