//! Signature verification gas of published `tempo-primitives`, pinned to literal values.

use alloy_primitives::{B256, Bytes, Signature, U256};
use tempo_primitives::{
    gas::{calldata_gas, keccak_gas},
    transaction::{
        PrimitiveSignature,
        tt_signature::{P256SignatureWithPreHash, WebAuthnSignature},
    },
};

/// `WebAuthn` data of 10 zero and 27 nonzero bytes: 118 tokens, 472 gas.
const WEBAUTHN_DATA_GAS: u64 = 472;

fn secp256k1() -> PrimitiveSignature {
    PrimitiveSignature::Secp256k1(Signature::new(U256::ONE, U256::from(2), false))
}

fn p256() -> PrimitiveSignature {
    PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: B256::repeat_byte(1),
        s: B256::repeat_byte(2),
        pub_key_x: B256::repeat_byte(3),
        pub_key_y: B256::repeat_byte(4),
        pre_hash: false,
    })
}

fn webauthn() -> PrimitiveSignature {
    PrimitiveSignature::WebAuthn(WebAuthnSignature {
        r: B256::repeat_byte(1),
        s: B256::repeat_byte(2),
        pub_key_x: B256::repeat_byte(3),
        pub_key_y: B256::repeat_byte(4),
        webauthn_data: Bytes::from([vec![0; 10], vec![0xab; 27]].concat()),
    })
}

#[test]
fn primitive_signatures_charge_the_flat_schedule_and_webauthn_data() {
    assert_eq!(secp256k1().base_verification_gas(), 3_000);
    assert_eq!(p256().base_verification_gas(), 8_000);
    assert_eq!(webauthn().base_verification_gas(), 8_000);

    assert_eq!(secp256k1().verification_gas(), 3_000);
    assert_eq!(p256().verification_gas(), 8_000);
    assert_eq!(webauthn().verification_gas(), 8_000 + WEBAUTHN_DATA_GAS);
}

#[test]
fn calldata_and_keccak_gas_follow_their_formulas() {
    assert_eq!(calldata_gas(&[]), 0);
    assert_eq!(calldata_gas(&[0]), 4);
    assert_eq!(calldata_gas(&[1]), 16);
    assert_eq!(calldata_gas(&[0, 0, 1, 2]), 40);

    for (len, gas) in [(0, 30), (1, 36), (32, 36), (33, 42), (96, 48), (138, 60)] {
        assert_eq!(keccak_gas(len), Some(gas), "len {len}");
    }
}

#[cfg(feature = "evm")]
#[test]
fn gas_constants_match_the_evm_schedule() {
    use revm::interpreter::gas::{KECCAK256, KECCAK256WORD, STANDARD_TOKEN_COST};
    use tempo_primitives::gas::{CALLDATA_TOKEN_GAS, KECCAK256_BASE_GAS, KECCAK256_WORD_GAS};

    assert_eq!(CALLDATA_TOKEN_GAS, STANDARD_TOKEN_COST);
    assert_eq!(KECCAK256_BASE_GAS, KECCAK256);
    assert_eq!(KECCAK256_WORD_GAS, KECCAK256WORD);
}
