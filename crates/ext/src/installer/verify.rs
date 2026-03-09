//! Minisign signature verification and SHA-256 checksums for release artifacts.

use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};

use crate::installer::error::InstallerError;

pub(super) fn decode_public_key(encoded_key: &str) -> Result<PublicKey, InstallerError> {
    PublicKey::from_base64(encoded_key).map_err(|err| InstallerError::SignatureFormat {
        field: "release public key",
        details: err.to_string(),
    })
}

pub(super) fn verify_signature(
    artifact: &str,
    data: &[u8],
    encoded_signature: &str,
    public_key: &PublicKey,
    expected_trusted_comment: Option<&str>,
) -> Result<(), InstallerError> {
    let signature =
        Signature::decode(encoded_signature).map_err(|err| InstallerError::SignatureFormat {
            field: "release signature",
            details: err.to_string(),
        })?;

    public_key
        .verify(data, &signature, false)
        .map_err(|_| InstallerError::SignatureVerificationFailed(artifact.to_string()))?;

    // After cryptographic verification succeeds, the trusted comment is
    // authenticated. Check it matches the expected artifact identity to
    // prevent cross-extension substitution attacks.
    if let Some(expected) = expected_trusted_comment {
        let tc = signature.trusted_comment();
        if !tc.split('\t').any(|token| token == expected) {
            return Err(InstallerError::TrustedCommentMismatch {
                artifact: artifact.to_string(),
                expected: expected.to_string(),
                actual: tc.to_string(),
            });
        }
    }

    Ok(())
}

pub(super) fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minisign::KeyPair;
    use std::io::Cursor;

    fn test_keypair() -> (minisign::PublicKey, minisign::SecretKey) {
        let KeyPair { pk, sk } = KeyPair::generate_unencrypted_keypair().unwrap();
        (pk, sk)
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn decode_public_key_valid() {
        let (pk, _) = test_keypair();
        let encoded = pk.to_base64();
        assert!(decode_public_key(&encoded).is_ok());
    }

    #[test]
    fn decode_public_key_invalid() {
        assert!(matches!(
            decode_public_key("not-valid!!!"),
            Err(InstallerError::SignatureFormat { .. })
        ));
    }

    #[test]
    fn verify_signature_valid() {
        let (pk, sk) = test_keypair();
        let data = b"test data";
        let sig_box = minisign::sign(Some(&pk), &sk, Cursor::new(data), None, None).unwrap();
        let sig_str = sig_box.into_string();

        let verify_pk = decode_public_key(&pk.to_base64()).unwrap();
        assert!(verify_signature("test", data, &sig_str, &verify_pk, None).is_ok());
    }

    #[test]
    fn verify_signature_wrong_key() {
        let (pk, sk) = test_keypair();
        let (other_pk, _) = test_keypair();
        let data = b"test data";
        let sig_box = minisign::sign(Some(&pk), &sk, Cursor::new(data), None, None).unwrap();
        let sig_str = sig_box.into_string();

        let wrong_pk = decode_public_key(&other_pk.to_base64()).unwrap();
        assert!(matches!(
            verify_signature("test", data, &sig_str, &wrong_pk, None),
            Err(InstallerError::SignatureVerificationFailed(_))
        ));
    }

    #[test]
    fn verify_signature_tampered_data() {
        let (pk, sk) = test_keypair();
        let data = b"original data";
        let sig_box = minisign::sign(Some(&pk), &sk, Cursor::new(data), None, None).unwrap();
        let sig_str = sig_box.into_string();

        let verify_pk = decode_public_key(&pk.to_base64()).unwrap();
        assert!(matches!(
            verify_signature("test", b"tampered data", &sig_str, &verify_pk, None),
            Err(InstallerError::SignatureVerificationFailed(_))
        ));
    }

    #[test]
    fn verify_signature_invalid_format() {
        let (pk, _) = test_keypair();
        let verify_pk = decode_public_key(&pk.to_base64()).unwrap();
        assert!(matches!(
            verify_signature("test", b"data", "not a valid signature", &verify_pk, None),
            Err(InstallerError::SignatureFormat { .. })
        ));
    }

    #[test]
    fn verify_trusted_comment_match() {
        let (pk, sk) = test_keypair();
        let data = b"test data";
        let sig_box = minisign::sign(
            Some(&pk),
            &sk,
            Cursor::new(data),
            Some("file:tempo-wallet-darwin-arm64"),
            None,
        )
        .unwrap();
        let sig_str = sig_box.into_string();

        let verify_pk = decode_public_key(&pk.to_base64()).unwrap();
        assert!(
            verify_signature(
                "tempo-wallet",
                data,
                &sig_str,
                &verify_pk,
                Some("file:tempo-wallet-darwin-arm64"),
            )
            .is_ok()
        );
    }

    #[test]
    fn verify_trusted_comment_mismatch() {
        let (pk, sk) = test_keypair();
        let data = b"test data";
        let sig_box = minisign::sign(
            Some(&pk),
            &sk,
            Cursor::new(data),
            Some("file:tempo-mpp-darwin-arm64"),
            None,
        )
        .unwrap();
        let sig_str = sig_box.into_string();

        let verify_pk = decode_public_key(&pk.to_base64()).unwrap();
        assert!(matches!(
            verify_signature(
                "tempo-wallet",
                data,
                &sig_str,
                &verify_pk,
                Some("file:tempo-wallet-darwin-arm64"),
            ),
            Err(InstallerError::TrustedCommentMismatch { .. })
        ));
    }

    #[test]
    fn verify_trusted_comment_none_skips_check() {
        let (pk, sk) = test_keypair();
        let data = b"test data";
        let sig_box = minisign::sign(
            Some(&pk),
            &sk,
            Cursor::new(data),
            Some("file:anything"),
            None,
        )
        .unwrap();
        let sig_str = sig_box.into_string();

        let verify_pk = decode_public_key(&pk.to_base64()).unwrap();
        assert!(verify_signature("test", data, &sig_str, &verify_pk, None).is_ok());
    }
}
