use revm::{
    context_interface::cfg::{GasId, GasParams},
    interpreter::gas::{COLD_SLOAD_COST, STANDARD_TOKEN_COST, get_tokens_in_calldata_istanbul},
};
use tempo_chainspec::{constants::gas::STORAGE_CREDIT_VALUE, hardfork::TempoHardfork};
use tempo_precompiles::ECRECOVER_GAS;
use tempo_primitives::transaction::{
    InitMultisig, KeychainInnerSignature, MAX_MULTISIG_NESTING_DEPTH, MultisigSignature,
    PrimitiveSignature, TempoSignature,
};

/// Additional gas for P256 signature verification
/// P256 precompile cost (6900 from EIP-7951) + 1100 for 129 bytes extra signature size - ecrecover savings (3000)
pub(crate) const P256_VERIFY_GAS: u64 = 5_000;

/// Additional gas for Keychain signatures (key validation overhead: COLD_SLOAD_COST + 900 processing)
const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST + 900;

/// Additional gas for each native multisig config/header validation.
///
/// Owner signature verification and owner-weight lookups are charged separately, relative to the
/// secp256k1 verification already covered by the base transaction stipend.
pub(crate) const NATIVE_MULTISIG_VALIDATION_GAS: u64 = COLD_SLOAD_COST;

/// Additional gas for each native multisig owner-weight lookup.
pub(crate) const NATIVE_MULTISIG_OWNER_WEIGHT_GAS: u64 = COLD_SLOAD_COST;

/// Persistent storage rows created by native multisig bootstrap before owner rows:
/// the packed `{ threshold, owner_count }` account header.
const NATIVE_MULTISIG_BOOTSTRAP_FIXED_STORAGE_SLOTS: u64 = 1;

/// Approximate buffer for the LOG3/no-data `MultisigInitialized` event emitted during bootstrap.
pub(crate) const NATIVE_MULTISIG_BOOTSTRAP_EVENT_BUFFER: u64 = 1_500;

/// Calculates the gas cost for verifying a primitive signature.
///
/// Returns the additional gas required beyond the base transaction cost:
/// - Secp256k1: 0 (already included in base 21k)
/// - P256: 5000 gas
/// - WebAuthn: 5000 gas + calldata cost for webauthn_data
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

/// Calculates full primitive owner-signature verification gas.
///
/// Unlike transaction signatures, owner approvals are nested inside the multisig signature, so this
/// returns the full verification cost before the top-level native multisig schedule subtracts the
/// one traditional secp256k1 verification already included in base transaction gas.
#[inline]
fn native_multisig_primitive_owner_signature_verification_gas(
    signature: &PrimitiveSignature,
) -> u64 {
    ECRECOVER_GAS + primitive_signature_verification_gas(signature)
}

fn native_multisig_owner_approval_verification_gas(
    signature: &TempoSignature,
    depth: usize,
) -> u64 {
    match signature {
        TempoSignature::Primitive(primitive) => {
            native_multisig_primitive_owner_signature_verification_gas(primitive)
        }
        TempoSignature::Multisig(multisig_signature) if depth < MAX_MULTISIG_NESTING_DEPTH => {
            native_multisig_signature_verification_gas(multisig_signature, false, depth + 1)
        }
        TempoSignature::Keychain(_) | TempoSignature::Multisig(_) => {
            ECRECOVER_GAS + P256_VERIFY_GAS
        }
    }
}

fn native_multisig_signature_verification_gas(
    signature: &MultisigSignature,
    subtract_base_secp256k1: bool,
    depth: usize,
) -> u64 {
    let owner_signature_gas = signature
        .signatures()
        .iter()
        .map(|sig| native_multisig_owner_approval_verification_gas(sig, depth))
        .fold(0u64, u64::saturating_add);
    let owner_weight_gas =
        NATIVE_MULTISIG_OWNER_WEIGHT_GAS.saturating_mul(signature.signatures().len() as u64);

    let gas = NATIVE_MULTISIG_VALIDATION_GAS
        .saturating_add(owner_weight_gas)
        .saturating_add(owner_signature_gas);
    if subtract_base_secp256k1 {
        gas.saturating_sub(ECRECOVER_GAS)
    } else {
        gas
    }
}

/// Gas for verifying a keychain access key's inner signature (primitive or native multisig).
///
/// TIP-1061 requires a native multisig access key's authorization cost to be metered in addition to
/// normal AccountKeychain key validation, so multisig inners are charged the full owner-approval
/// schedule (as a top-level node).
#[inline]
fn keychain_inner_signature_verification_gas(signature: &KeychainInnerSignature) -> u64 {
    match signature {
        KeychainInnerSignature::Primitive(primitive) => {
            primitive_signature_verification_gas(primitive)
        }
        KeychainInnerSignature::Multisig(multisig) => {
            native_multisig_signature_verification_gas(multisig, true, 1)
        }
    }
}

/// Calculates the gas cost for verifying an AA signature.
///
/// For Keychain signatures, adds key validation overhead to the inner signature cost
/// Returns the additional gas required beyond the base transaction cost.
#[inline]
pub(crate) fn tempo_signature_verification_gas(signature: &TempoSignature) -> u64 {
    match signature {
        TempoSignature::Primitive(prim_sig) => primitive_signature_verification_gas(prim_sig),
        TempoSignature::Keychain(keychain_sig) => {
            keychain_inner_signature_verification_gas(&keychain_sig.signature)
                + KEYCHAIN_VALIDATION_GAS
        }
        TempoSignature::Multisig(multisig_sig) => {
            native_multisig_signature_verification_gas(multisig_sig, true, 1)
        }
    }
}

#[inline]
pub(crate) fn native_multisig_bootstrap_storage_slots(init: &InitMultisig) -> u64 {
    let owner_slots = u64::try_from(init.owners.len()).unwrap_or(u64::MAX);
    NATIVE_MULTISIG_BOOTSTRAP_FIXED_STORAGE_SLOTS.saturating_add(owner_slots.saturating_mul(2))
}

/// Calculates persistent storage gas for native multisig bootstrap.
///
/// The committed bootstrap write is a protocol pre-execution write. It runs without TIP-1060
/// storage-credit accounting because this intrinsic charge includes the creditable portion.
/// The packed native multisig layout creates exactly:
/// - one packed account header slot containing threshold and owner count
/// - one packed owner slot per owner
/// - one direct owner-weight lookup slot per owner
#[inline]
pub(crate) fn calculate_native_multisig_bootstrap_storage_gas(
    init: &InitMultisig,
    gas_params: &GasParams,
    spec: TempoHardfork,
) -> (u64, u64) {
    let num_sstores = native_multisig_bootstrap_storage_slots(init);

    let mut sstore_cost = gas_params.get(GasId::sstore_set_without_load_cost());
    if spec.is_t7() {
        // T7 exposes only the SSTORE residual in the gas table. Since bootstrap storage is
        // intrinsic-only, also charge the TIP-1060 creditable portion here.
        sstore_cost = sstore_cost.saturating_add(STORAGE_CREDIT_VALUE);
    }

    let regular_gas = sstore_cost
        .saturating_mul(num_sstores)
        .saturating_add(NATIVE_MULTISIG_BOOTSTRAP_EVENT_BUFFER);
    let state_gas = gas_params
        .get(GasId::sstore_set_state_gas())
        .saturating_mul(num_sstores);

    (regular_gas, state_gas)
}
