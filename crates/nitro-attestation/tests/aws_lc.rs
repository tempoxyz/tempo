#![cfg(feature = "aws-lc")]

use aws_lc_rs::digest::{SHA256, digest};
use base64::Engine;
use tempo_nitro_attestation::{
    AWS_NITRO_ROOT_DER, AwsLcP384, Error, SignatureError, parse_attestation, verify_parsed,
};

#[test]
fn pinned_root_has_expected_sha256() {
    assert_eq!(
        digest(&SHA256, AWS_NITRO_ROOT_DER).as_ref(),
        hex_literal::hex!("641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b")
    );
}

#[test]
fn verifies_production_attestation_and_rejects_corrupt_signature() {
    let encoded: String = include_str!("../testdata/aws_attestation_2026_01_03.b64")
        .split_whitespace()
        .collect();
    let document = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    let parsed = parse_attestation(&document).unwrap();
    let verified = verify_parsed(
        parsed.clone(),
        1_767_472_867,
        AWS_NITRO_ROOT_DER,
        &AwsLcP384,
    )
    .unwrap();
    assert_eq!(verified.timestamp, 1_767_472_867_402);
    assert_eq!(verified.pcrs.len(), 16);

    let mut corrupted = parsed;
    corrupted.signature[0] ^= 1;
    assert_eq!(
        verify_parsed(corrupted, 1_767_472_867, AWS_NITRO_ROOT_DER, &AwsLcP384),
        Err(Error::InvalidSignature(SignatureError::Document))
    );
}
