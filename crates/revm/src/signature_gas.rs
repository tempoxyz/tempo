use revm::interpreter::gas::{
    COLD_SLOAD_COST, STANDARD_TOKEN_COST, get_tokens_in_calldata_istanbul,
};
use tempo_primitives::transaction::{
    KeyAuthorizationSignature, PrimitiveSignature, TempoSignature, ZkSignature,
};

/// Additional gas for P256 signature verification.
///
/// This includes the P256 precompile cost, the extra signature calldata, and the ecrecover savings
/// already included in the base transaction cost.
pub(crate) const P256_VERIFY_GAS: u64 = 5_000;

/// Additional gas for keychain signatures (key validation overhead: cold SLOAD + processing).
const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST + 900;

/// Gas for decoding, curve and subgroup checks, the public-input hash, and a proof's share of a
/// batched pairing check (TIP-1131). Placeholder pending the reference benchmark.
pub const ZK_VERIFY_GAS: u64 = 350_000;

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

/// Calculates the gas cost for verifying an AA signature.
///
/// For keychain signatures, adds key validation overhead to the inner signature cost. Returns the
/// additional gas required beyond the base transaction cost.
#[inline]
pub(crate) fn tempo_signature_verification_gas(signature: &TempoSignature) -> u64 {
    match signature {
        TempoSignature::Primitive(prim_sig) => primitive_signature_verification_gas(prim_sig),
        TempoSignature::Keychain(keychain_sig) => {
            primitive_signature_verification_gas(&keychain_sig.signature) + KEYCHAIN_VALIDATION_GAS
        }
        TempoSignature::Zk(zk_sig) => zk_signature_verification_gas(zk_sig),
    }
}

/// Calculates the gas for verifying a key authorization's signature, beyond the `ECRECOVER_GAS`
/// baseline that every key authorization pays.
#[inline]
pub(crate) fn key_authorization_signature_gas(signature: &KeyAuthorizationSignature) -> u64 {
    match signature {
        KeyAuthorizationSignature::Primitive(prim_sig) => {
            primitive_signature_verification_gas(prim_sig)
        }
        KeyAuthorizationSignature::Zk(zk_sig) => zk_signature_verification_gas(zk_sig),
    }
}

/// Calculates `zk_cost - 3,000` for a ZK signature (TIP-1131), where
/// `zk_cost = ZK_VERIFY_GAS + primitive_signature_cost(access_key_signature) + COLD_SLOAD_COST +
/// calldata_gas(zk_signature without access_key_signature)`.
///
/// The 3,000 is the ecrecover cost already in the base transaction cost, which is also the
/// secp256k1 baseline of `primitive_signature_cost`, so it cancels.
#[inline]
pub(crate) fn zk_signature_verification_gas(signature: &ZkSignature) -> u64 {
    // The access key signature is the last RLP field, so the bytes before it are everything
    // except that signature.
    let bytes = signature.to_bytes();
    let rest = &bytes[..bytes.len() - signature.access_key_signature_length()];
    ZK_VERIFY_GAS
        + primitive_signature_verification_gas(&signature.access_key_signature)
        + COLD_SLOAD_COST
        + get_tokens_in_calldata_istanbul(rest) * STANDARD_TOKEN_COST
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Signature};
    use tempo_primitives::transaction::{ZkProof, tt_signature::P256SignatureWithPreHash};

    fn zk(access_key_signature: PrimitiveSignature) -> ZkSignature {
        ZkSignature::new(
            1,
            B256::repeat_byte(0x11),
            B256::repeat_byte(0x02),
            B256::repeat_byte(0x03),
            B256::repeat_byte(0x04),
            1_700_000_000,
            1_700_000_540,
            ZkProof::repeat_byte(0x55),
            access_key_signature,
        )
    }

    #[test]
    fn zk_signature_gas() {
        // A P256 access key: 350,000 + 5,000 (P256 beyond the base ecrecover) + 2,100 + calldata.
        let p256 = PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::repeat_byte(1),
            s: B256::repeat_byte(1),
            pub_key_x: B256::repeat_byte(1),
            pub_key_y: B256::repeat_byte(1),
            pre_hash: false,
        });
        let signature = zk(p256);
        let bytes = signature.to_bytes();
        assert_eq!(
            bytes.len(),
            538,
            "TIP-1131 size of a ZK signature with a P256 access key"
        );
        let rest = bytes.len() - signature.access_key_signature_length();
        let tokens = get_tokens_in_calldata_istanbul(&bytes[..rest]);
        let gas = zk_signature_verification_gas(&signature);
        assert_eq!(
            gas,
            ZK_VERIFY_GAS + P256_VERIFY_GAS + COLD_SLOAD_COST + tokens * 4
        );
        // As a transaction signature the total is the base 21,000 plus `zk_cost - 3,000`, so
        // `zk_cost` is within TIP-1131's range of about 367,000 to 386,000.
        let zk_cost = gas + 3_000;
        assert!((360_000..=386_000).contains(&zk_cost), "zk_cost {zk_cost}");

        assert_eq!(
            tempo_signature_verification_gas(&TempoSignature::from(signature.clone())),
            gas
        );
        assert_eq!(
            key_authorization_signature_gas(&KeyAuthorizationSignature::from(signature)),
            gas
        );

        // A secp256k1 access key pays no extra primitive cost.
        let secp = zk(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let bytes = secp.to_bytes();
        let rest = bytes.len() - secp.access_key_signature_length();
        assert_eq!(
            zk_signature_verification_gas(&secp),
            ZK_VERIFY_GAS + COLD_SLOAD_COST + get_tokens_in_calldata_istanbul(&bytes[..rest]) * 4
        );
    }
}
