use base64::Engine;
use p384::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use sha2::{Digest, Sha256, Sha384};
use tempo_nitro_attestation::{
    P384_FIXED_SIGNATURE_SIZE, P384_PUBLIC_KEY_SIZE, P384Verifier, SHA384_SIZE, Sha384Hasher,
    parse_attestation, verify_parsed,
};

/// An independent crypto backend keeps the production fixture test local to this crate.
struct RustCrypto;

impl P384Verifier for RustCrypto {
    fn validate_public_key(&self, public_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> bool {
        VerifyingKey::from_sec1_bytes(public_key).is_ok()
    }

    fn verify_der(
        &self,
        public_key: &[u8; P384_PUBLIC_KEY_SIZE],
        digest: &[u8; SHA384_SIZE],
        signature_der: &[u8],
    ) -> bool {
        let (Ok(key), Ok(signature)) = (
            VerifyingKey::from_sec1_bytes(public_key),
            Signature::from_der(signature_der),
        ) else {
            return false;
        };
        key.verify_prehash(digest, &signature).is_ok()
    }

    fn verify_fixed(
        &self,
        public_key: &[u8; P384_PUBLIC_KEY_SIZE],
        digest: &[u8; SHA384_SIZE],
        signature: &[u8; P384_FIXED_SIGNATURE_SIZE],
    ) -> bool {
        let (Ok(key), Ok(signature)) = (
            VerifyingKey::from_sec1_bytes(public_key),
            Signature::from_slice(signature),
        ) else {
            return false;
        };
        key.verify_prehash(digest, &signature).is_ok()
    }
}

impl Sha384Hasher for RustCrypto {
    fn sha384(&self, input: &[u8]) -> [u8; SHA384_SIZE] {
        Sha384::digest(input).into()
    }
}

#[test]
fn verifies_production_attestation_with_independent_crypto() {
    let encoded: String = include_str!("../testdata/aws_attestation_2026_01_03.b64")
        .split_whitespace()
        .collect();
    let document = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    let parsed = parse_attestation(&document).unwrap();
    let root = parsed.cabundle[0].clone();
    // Pin the fixture's root to the same AWS root as the production Zone verifier.
    assert_eq!(
        format!("{:x}", Sha256::digest(&root)),
        "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
    );
    let verified = verify_parsed(parsed, 1_767_472_867, &root, &RustCrypto).unwrap();
    assert_eq!(verified.timestamp, 1_767_472_867_402);
    assert_eq!(verified.pcrs.len(), 16);
    assert!(verified.public_key.is_empty());
    assert!(verified.nonce.is_empty());
}
