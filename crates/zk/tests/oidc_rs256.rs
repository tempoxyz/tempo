//! Verifies proofs from the reference OIDC RS256 v1 circuit (`circuits/oidc-rs256`), made with a
//! development verifying key, against the statements nodes build.

use alloy_primitives::{Address, B256, hex};
use serde_json::Value;
use tempo_zk::{
    MessageStatement, PreparedVerifyingKey, Proof, SCHEME_OIDC_RS256_V1, SignatureStatement,
    VerifyingKey, field::fr_to_be, verify_many,
};

/// Written by `circuits/oidc-rs256/scripts/vectors.ts`.
const VECTORS: &str = include_str!("../testdata/oidc_rs256_v1_dev.json");

#[test]
fn verifies_circuit_proofs() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let key = verifying_key(&vectors["verifyingKey"]);

    let signature = &vectors["signature"];
    let signature_statement = SignatureStatement {
        scheme: SCHEME_OIDC_RS256_V1,
        issuer: word(&signature["issuer"]),
        key_hash: word(&signature["keyHash"]),
        address_seed: word(&signature["addressSeed"]),
        access_key_id: Address::from_slice(&bytes(&signature["accessKeyId"])),
        valid_until: signature["validUntil"].as_u64().unwrap(),
        issued_at: signature["issuedAt"].as_u64().unwrap(),
    };
    let signature_input = signature_statement.public_input().unwrap();
    assert_eq!(fr_to_be(&signature_input), word(&signature["publicInput"]));
    let signature_proof = proof(&signature["proof"]);
    assert!(key.verify(&signature_proof, &signature_input));

    let message = &vectors["message"];
    let message_statement = MessageStatement {
        scheme: SCHEME_OIDC_RS256_V1,
        issuer: word(&message["issuer"]),
        key_hash: word(&message["keyHash"]),
        address_seed: word(&message["addressSeed"]),
        digest: word(&message["digest"]),
        issued_at: message["issuedAt"].as_u64().unwrap(),
    };
    let message_input = message_statement.public_input().unwrap();
    assert_eq!(fr_to_be(&message_input), word(&message["publicInput"]));
    let message_proof = proof(&message["proof"]);
    assert!(key.verify(&message_proof, &message_input));

    assert_eq!(
        verify_many(
            &key,
            &[
                (&signature_proof, signature_input),
                (&message_proof, message_input)
            ]
        ),
        vec![true, true]
    );

    // A proof only verifies its own statement.
    assert!(!key.verify(&message_proof, &signature_input));
    assert!(!key.verify(&signature_proof, &message_input));
    for statement in [
        SignatureStatement {
            valid_until: signature_statement.valid_until + 1,
            ..signature_statement
        },
        SignatureStatement {
            issued_at: signature_statement.issued_at + 1,
            ..signature_statement
        },
        SignatureStatement {
            access_key_id: Address::ZERO,
            ..signature_statement
        },
        SignatureStatement {
            address_seed: B256::ZERO,
            ..signature_statement
        },
    ] {
        assert!(!key.verify(&signature_proof, &statement.public_input().unwrap()));
    }
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn word(value: &Value) -> B256 {
    B256::from_slice(&bytes(value))
}

fn verifying_key(value: &Value) -> PreparedVerifyingKey {
    VerifyingKey::decode(bytes(value).as_slice().try_into().unwrap())
        .unwrap()
        .prepare()
}

fn proof(value: &Value) -> Proof {
    Proof::decode(bytes(value).as_slice().try_into().unwrap()).unwrap()
}
