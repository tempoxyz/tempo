//! Tests for the redacted zone RPC module.

use crate::utils::{
    build_signed_token_blob, now_secs, sign_keychain_signature, sign_p256_signature,
    sign_webauthn_signature,
};
use alloy::signers::{Signer, local::PrivateKeySigner};
use alloy_primitives::Address;
use p256::{ecdsa::SigningKey as P256SigningKey, elliptic_curve::rand_core::OsRng};
use tempo_primitives::transaction::tt_signature::TempoSignature;
use test_case::test_case;
use zone_node::rpc::auth::{AuthError, AuthorizationToken, build_token_fields};

/// Build a raw token blob from the given fields with a fake 65-byte secp256k1 signature.
///
/// Uses [`build_token_fields`] for the canonical encoding and patches the
/// version byte when a non-zero version is requested (for negative tests).
fn build_token_blob(
    version: u8,
    zone_id: u32,
    chain_id: u64,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let (mut fields, _digest) = build_token_fields(zone_id, chain_id, issued_at, expires_at);
    fields[0] = version;
    let mut blob = vec![0u8; 65]; // fake secp256k1 sig
    blob.extend_from_slice(&fields);
    blob
}

fn make_test_token(
    version: u8,
    zone_id: u32,
    chain_id: u64,
    issued_at: u64,
    expires_at: u64,
) -> AuthorizationToken {
    let blob = build_token_blob(version, zone_id, chain_id, issued_at, expires_at);
    AuthorizationToken::parse(&blob).unwrap()
}

// ============ Auth Token Parsing ============

#[test]
fn parse_token_fields() {
    let now = now_secs();

    let token = make_test_token(0, 42, 1337, now, now + 600);

    assert_eq!(token.version, 0);
    assert_eq!(token.zone_id, 42);
    assert_eq!(token.chain_id, 1337);
    assert_eq!(token.issued_at, now);
    assert_eq!(token.expires_at, now + 600);
    assert_eq!(token.signature.len(), 65);
}

#[test]
fn parse_token_too_short() {
    // 29 bytes = exactly the message length, no room for a signature
    let blob = vec![0u8; 29];
    assert!(AuthorizationToken::parse(&blob).is_err());

    // Even shorter
    assert!(AuthorizationToken::parse(&[0u8; 10]).is_err());
}

#[test]
fn parse_unknown_signature_length() {
    // 50-byte signature (not 65 or 130, and first byte is not 0x02/0x03) → should error
    let mut blob = vec![0u8; 50];
    // 29 bytes of fields
    blob.push(0);
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob.extend_from_slice(&1u64.to_be_bytes());
    let now = now_secs();
    blob.extend_from_slice(&now.to_be_bytes());
    blob.extend_from_slice(&(now + 600).to_be_bytes());

    let token = AuthorizationToken::parse(&blob).unwrap();
    assert!(TempoSignature::from_bytes(&token.signature).is_err());
}

#[test]
fn digest_is_deterministic_and_covers_params() {
    let t1 = make_test_token(0, 1, 2, 1000, 1600);
    let t2 = make_test_token(0, 1, 2, 1000, 1600);
    let t3 = make_test_token(0, 1, 3, 1000, 1600);
    assert_eq!(t1.digest, t2.digest);
    assert_ne!(t1.digest, t3.digest);
}

// ============ Auth Token Validation ============

#[test_case(0, 42, 42, 1337 => matches Ok(_); "valid token")]
#[test_case(1, 42, 42, 1337 => matches Err(_); "wrong version")]
#[test_case(0, 42, 99, 1337 => matches Err(_); "zone id mismatch")]
#[test_case(0, 0, 42, 1337 => matches Ok(_); "unscoped zone id")]
#[test_case(0, 0, 99, 1337 => matches Ok(_); "unscoped zone id on another zone")]
#[test_case(0, 42, 42, 9999 => matches Err(_); "chain id mismatch")]
fn validate_checks_version_zone_id_and_chain_id(
    version: u8,
    token_zone_id: u32,
    zone_id: u32,
    chain_id: u64,
) -> Result<(), AuthError> {
    let now = now_secs();
    make_test_token(version, token_zone_id, 1337, now, now + 600).validate(zone_id, chain_id)
}

#[tokio::test]
async fn tempo_signature_roundtrip_secp256k1_from_token_bytes() {
    let signer = PrivateKeySigner::random();
    let now = now_secs();
    let (fields, digest) = build_token_fields(1, 2, now, now + 600);
    let sig = signer.sign_hash(&digest).await.unwrap();

    let blob = [sig.as_rsy().as_slice(), &fields].concat();
    let token = AuthorizationToken::parse(&blob).unwrap();
    let parsed = TempoSignature::from_bytes(&token.signature).unwrap();

    assert_eq!(
        parsed.recover_signer(&token.digest).unwrap(),
        signer.address()
    );
}

#[test]
fn tempo_signature_rejects_wrong_secp256k1_lengths() {
    assert!(TempoSignature::from_bytes(&[0u8; 64]).is_err());
    assert!(TempoSignature::from_bytes(&[0u8; 66]).is_err());
    assert!(TempoSignature::from_bytes(&[]).is_err());
}

#[test]
fn tempo_signature_roundtrip_p256_from_token_bytes() {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let now = now_secs();
    let (fields, digest) = build_token_fields(1, 2, now, now + 600);
    let expected = sign_p256_signature(digest, &signing_key)
        .expect("p256 signing should succeed")
        .recover_signer(&digest)
        .expect("p256 recovery should succeed");
    let blob = build_signed_token_blob(
        sign_p256_signature(digest, &signing_key).expect("p256 signing should succeed"),
        &fields,
    );
    let token = AuthorizationToken::parse(&blob).unwrap();
    let parsed = TempoSignature::from_bytes(&token.signature).unwrap();

    assert_eq!(parsed.recover_signer(&token.digest).unwrap(), expected);
}

#[test]
fn tempo_signature_roundtrip_webauthn_from_token_bytes() {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let now = now_secs();
    let (fields, digest) = build_token_fields(1, 2, now, now + 600);
    let signature =
        sign_webauthn_signature(&signing_key, digest).expect("webauthn signing should succeed");
    let expected = signature
        .recover_signer(&digest)
        .expect("webauthn recovery should succeed");
    let blob = build_signed_token_blob(signature, &fields);
    let token = AuthorizationToken::parse(&blob).unwrap();
    let parsed = TempoSignature::from_bytes(&token.signature).unwrap();

    assert_eq!(parsed.recover_signer(&token.digest).unwrap(), expected);
}

#[test_case(Address::repeat_byte(0x44), 0x03; "keychain v1")]
#[test_case(Address::repeat_byte(0x55), 0x04; "keychain v2")]
fn tempo_signature_roundtrip_keychain_from_token_bytes(root_account: Address, version: u8) {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let now = now_secs();
    let (fields, digest) = build_token_fields(1, 2, now, now + 600);
    let (signature, expected_key_id) =
        sign_keychain_signature(digest, &signing_key, root_account, version)
            .expect("keychain signing should succeed");
    let blob = build_signed_token_blob(signature, &fields);
    let token = AuthorizationToken::parse(&blob).unwrap();
    let parsed = TempoSignature::from_bytes(&token.signature).unwrap();

    assert_eq!(parsed.recover_signer(&token.digest).unwrap(), root_account);
    match parsed {
        TempoSignature::Keychain(keychain) => {
            assert_eq!(keychain.key_id(&token.digest).unwrap(), expected_key_id);
        }
        TempoSignature::Primitive(_) | TempoSignature::ConfigurableAccount(_) => {
            panic!("expected keychain signature")
        }
    }
}

#[test]
fn tempo_signature_rejects_malformed_signature_bytes() {
    let malformed = [0x04, 0x11, 0x22];
    assert!(TempoSignature::from_bytes(&malformed).is_err());
}
