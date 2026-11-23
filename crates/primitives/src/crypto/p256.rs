//! P256 (secp256r1) signatures.

use alloy_primitives::{Address, B256, U256, uint};

/// The P256 (secp256r1/prime256v1) curve order n.
pub const P256_ORDER: U256 =
    uint!(0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551_U256);

/// Half of the P256 curve order (n/2).
///
/// For signatures to be valid, the s value must be less than or equal to n/2
/// (low-s requirement). This prevents signature malleability where (r, s) and
/// (r, n-s) are both valid signatures for the same message.
pub const P256N_HALF: U256 =
    uint!(0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8_U256);

/// Normalize P256 signature s value to low-s form.
///
/// For any ECDSA signature (r, s), both (r, s) and (r, n-s) are valid.
/// To prevent signature malleability, we require s <= n/2.
/// If s > n/2, we replace it with n - s.
///
/// Returns an error if `s` is zero or `s >= P256_ORDER` (out of range for a
/// valid scalar). This function should be called by all P256 signing code
/// before creating a signature, as the p256 crate does not guarantee low-s
/// signatures.
pub fn normalize_p256_s(s_bytes: &[u8]) -> Result<B256, &'static str> {
    let s = U256::from_be_slice(s_bytes);
    if s.is_zero() || s >= P256_ORDER {
        return Err("P256 s value out of range");
    }
    let normalized_s = if s > P256N_HALF { P256_ORDER - s } else { s };
    Ok(B256::from(normalized_s))
}

/// Derives a P256 address from public key coordinates
pub fn derive_p256_address(pub_key_x: &B256, pub_key_y: &B256) -> Address {
    let mut encoded_key = [0u8; 64];
    encoded_key[..32].copy_from_slice(pub_key_x.as_slice());
    encoded_key[32..].copy_from_slice(pub_key_y.as_slice());
    Address::from_raw_public_key(&encoded_key)
}

/// Whether `(r, s)` is a valid P256 signature by `(x, y)` over `digest`.
pub fn verify_p256(r: &B256, s: &B256, x: &B256, y: &B256, digest: &B256) -> bool {
    #[cfg(feature = "mock-crypto")]
    if super::mock::verify_p256(r, s, x, y, digest) {
        return true;
    }
    verify_p256_signature_internal(
        r.as_slice(),
        s.as_slice(),
        x.as_slice(),
        y.as_slice(),
        digest,
    )
    .is_ok()
}

/// Concatenates byte slices into a fixed-size array without heap allocations.
fn concat<const N: usize>(slices: &[&[u8]]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut offset = 0;
    for s in slices {
        out[offset..offset + s.len()].copy_from_slice(s);
        offset += s.len();
    }
    debug_assert_eq!(offset, N, "slices length doesn't match array size");
    out
}

#[cfg(feature = "std")]
fn verify_p256_signature_with_aws_lc(
    r: &[u8],
    s: &[u8],
    pub_key_x: &[u8],
    pub_key_y: &[u8],
    message_hash: &B256,
) -> Result<(), &'static str> {
    use aws_lc_rs::{
        digest::{Digest as AwsLcDigest, SHA256 as AwsLcSha256},
        signature::{ECDSA_P256_SHA256_FIXED, ParsedPublicKey as AwsLcParsedPublicKey},
    };

    let encoded_point = concat::<65>(&[&[0x04], pub_key_x, pub_key_y]);
    let verifying_key = AwsLcParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, encoded_point)
        .map_err(|_| "Invalid P256 public key")?;

    let signature = concat::<64>(&[r, s]);

    // Tempo verifies already-computed 32-byte message digests.
    // Switching to message-based aws-lc verifier would hash again and change consensus behavior.
    let digest = AwsLcDigest::import_less_safe(message_hash.as_slice(), &AwsLcSha256)
        .map_err(|_| "Invalid P256 message digest")?;

    verifying_key
        .verify_digest_sig(&digest, &signature)
        .map_err(|_| "P256 signature verification failed")
}

#[cfg(any(test, not(feature = "std")))]
fn verify_p256_signature_with_p256(
    r: &[u8],
    s: &[u8],
    pub_key_x: &[u8],
    pub_key_y: &[u8],
    message_hash: &B256,
) -> Result<(), &'static str> {
    use p256::{
        EncodedPoint,
        ecdsa::{Signature as P256Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
    };

    let encoded_point =
        EncodedPoint::from_affine_coordinates(pub_key_x.into(), pub_key_y.into(), false);
    let verifying_key =
        VerifyingKey::from_encoded_point(&encoded_point).map_err(|_| "Invalid P256 public key")?;

    let signature = P256Signature::from_slice(&concat::<64>(&[r, s]))
        .map_err(|_| "Invalid P256 signature encoding")?;

    // Tempo verifies already-computed 32-byte message digests.
    verifying_key
        .verify_prehash(message_hash.as_slice(), &signature)
        .map_err(|_| "P256 signature verification failed")
}

/// Verifies a P256 signature using the provided components
///
/// This performs actual cryptographic verification of the P256 signature
/// according to the spec. Called during `recover_signer()` to ensure only
/// valid signatures enter the mempool.
///
/// Includes a high-s value check to prevent signature malleability. For any
/// ECDSA signature (r, s), a second valid signature (r, n-s) exists. By
/// requiring s <= n/2 (the "low-s" requirement), we ensure only one canonical
/// form is accepted, preventing transaction hash malleability attacks.
///
/// NOTE: this function conditionally compiles based on the cfg
/// - !std → p256
/// - std && !test → aws-lc-rs (best performance)
/// - std && test → both (ensures verification backend alignment)
pub(crate) fn verify_p256_signature_internal(
    r: &[u8],
    s: &[u8],
    pub_key_x: &[u8],
    pub_key_y: &[u8],
    message_hash: &B256,
) -> Result<(), &'static str> {
    // High-s value check: reject signatures where s > n/2 to prevent malleability
    if U256::from_be_slice(s) > P256N_HALF {
        return Err("P256 signature has high s value");
    }

    #[cfg(all(feature = "std", not(test)))]
    {
        // production `std` builds use the `aws-lc-rs` crate
        verify_p256_signature_with_aws_lc(r, s, pub_key_x, pub_key_y, message_hash)
    }

    #[cfg(not(feature = "std"))]
    {
        // production `no-std` builds use the `p256` crate
        verify_p256_signature_with_p256(r, s, pub_key_x, pub_key_y, message_hash)
    }

    #[cfg(all(feature = "std", test))]
    {
        // test builds use both crates to verify alignment
        let aws_lc = verify_p256_signature_with_aws_lc(r, s, pub_key_x, pub_key_y, message_hash);
        let p256 = verify_p256_signature_with_p256(r, s, pub_key_x, pub_key_y, message_hash);

        assert_eq!(
            aws_lc.is_ok(),
            p256.is_ok(),
            "aws-lc and p256 verification backends disagreed"
        );

        aws_lc
    }
}
