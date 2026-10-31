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

#[cfg(feature = "test-utils")]
#[test]
fn verifies_dev_attestation_under_dev_root_only() {
    use tempo_nitro_attestation::{
        CertificateError, NITRO_DEV_ROOT_DER,
        testing::{DEV_PCRS, DevAttestation},
    };

    assert_eq!(
        digest(&SHA256, NITRO_DEV_ROOT_DER).as_ref(),
        hex_literal::hex!("eef02ddde90ed0c4cbcdfa551b60b00ddbaae3824d929ecb9102ddff3f34e666")
    );
    let now = 1_800_000_000;
    let document = DevAttestation::new([0xAB; 32], now * 1_000).build();
    let parsed = parse_attestation(&document).unwrap();
    assert_eq!(parsed.signature_count(), 3);

    let verified = verify_parsed(parsed.clone(), now, NITRO_DEV_ROOT_DER, &AwsLcP384).unwrap();
    assert_eq!(verified.user_data, [0xAB; 32]);
    assert_eq!(verified.timestamp, now * 1_000);
    let pcrs: Vec<_> = verified
        .pcrs
        .iter()
        .map(|pcr| pcr.value.as_slice())
        .collect();
    assert_eq!(
        pcrs,
        DEV_PCRS
            .iter()
            .map(|pcr| pcr.as_slice())
            .collect::<Vec<_>>()
    );

    assert_eq!(
        verify_parsed(parsed, now, AWS_NITRO_ROOT_DER, &AwsLcP384),
        Err(Error::InvalidCertificate(CertificateError::RootMismatch))
    );
}
