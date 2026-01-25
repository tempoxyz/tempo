//! EIP-2537 BLS12-381 format conversion utilities.
//!
//! The EIP-2537 precompiles expect points in uncompressed format with
//! specific padding for each field element:
//!
//! - G1 points: 128 bytes (2 × 64-byte Fp elements)
//! - G2 points: 256 bytes (4 × 64-byte Fp elements)
//!
//! Each Fp element is 64 bytes: 16 zero-padding bytes + 48-byte value (big-endian).
//!
//! For MinSig variant (matching consensus):
//! - Signatures are G1 (48 bytes compressed → 128 bytes EIP-2537)
//! - Public keys are G2 (96 bytes compressed → 256 bytes EIP-2537)

use crate::{
    error::{BridgeError, Result},
    message::{G1_COMPRESSED_LEN, G1_UNCOMPRESSED_LEN, G2_COMPRESSED_LEN, G2_UNCOMPRESSED_LEN},
};

use blst::{
    BLST_ERROR, blst_p1_affine, blst_p1_affine_serialize, blst_p1_uncompress, blst_p2_affine,
    blst_p2_affine_serialize, blst_p2_uncompress,
};

/// Uncompressed G1 size from blst (96 bytes: 2 × 48-byte Fp elements).
const BLST_G1_SERIALIZE_LEN: usize = 96;

/// Uncompressed G2 size from blst (192 bytes: 4 × 48-byte Fp elements).
const BLST_G2_SERIALIZE_LEN: usize = 192;

/// Convert a compressed G2 public key (96 bytes) to EIP-2537 format (256 bytes).
///
/// The EIP-2537 format for G2 points is:
/// - x.c1: 16 zero bytes + 48-byte field element (big-endian)
/// - x.c0: 16 zero bytes + 48-byte field element (big-endian)
/// - y.c1: 16 zero bytes + 48-byte field element (big-endian)
/// - y.c0: 16 zero bytes + 48-byte field element (big-endian)
///
/// Total: 4 × 64 = 256 bytes
pub fn g2_to_eip2537(compressed: &[u8; G2_COMPRESSED_LEN]) -> Result<[u8; G2_UNCOMPRESSED_LEN]> {
    let mut affine = blst_p2_affine::default();

    // SAFETY: blst_p2_uncompress validates the compressed point encoding
    let result = unsafe { blst_p2_uncompress(&mut affine, compressed.as_ptr()) };

    if result != BLST_ERROR::BLST_SUCCESS {
        return Err(BridgeError::Signing(format!(
            "failed to decompress G2 point: {result:?}"
        )));
    }

    // Use blst's native serialization (192 bytes: x.c1, x.c0, y.c1, y.c0 each 48 bytes)
    let mut serialized = [0u8; BLST_G2_SERIALIZE_LEN];
    // SAFETY: output buffer is correctly sized, affine point is valid
    unsafe { blst_p2_affine_serialize(serialized.as_mut_ptr(), &affine) };

    // Pad each 48-byte Fp element to 64 bytes for EIP-2537 format
    let mut output = [0u8; G2_UNCOMPRESSED_LEN];
    for i in 0..4 {
        // 16 zero-padding bytes are already zero from array initialization
        output[i * 64 + 16..(i + 1) * 64].copy_from_slice(&serialized[i * 48..(i + 1) * 48]);
    }

    Ok(output)
}

/// Convert a compressed G1 signature (48 bytes) to EIP-2537 format (128 bytes).
///
/// The EIP-2537 format for G1 points is:
/// - x: 16 zero bytes + 48-byte field element (big-endian)
/// - y: 16 zero bytes + 48-byte field element (big-endian)
///
/// Total: 2 × 64 = 128 bytes
pub fn g1_to_eip2537(compressed: &[u8; G1_COMPRESSED_LEN]) -> Result<[u8; G1_UNCOMPRESSED_LEN]> {
    let mut affine = blst_p1_affine::default();

    // SAFETY: blst_p1_uncompress validates the compressed point encoding
    let result = unsafe { blst_p1_uncompress(&mut affine, compressed.as_ptr()) };

    if result != BLST_ERROR::BLST_SUCCESS {
        return Err(BridgeError::Signing(format!(
            "failed to decompress G1 point: {result:?}"
        )));
    }

    // Use blst's native serialization (96 bytes: x, y each 48 bytes big-endian)
    let mut serialized = [0u8; BLST_G1_SERIALIZE_LEN];
    // SAFETY: output buffer is correctly sized, affine point is valid
    unsafe { blst_p1_affine_serialize(serialized.as_mut_ptr(), &affine) };

    // Pad each 48-byte Fp element to 64 bytes for EIP-2537 format
    let mut output = [0u8; G1_UNCOMPRESSED_LEN];
    for i in 0..2 {
        // 16 zero-padding bytes are already zero from array initialization
        output[i * 64 + 16..(i + 1) * 64].copy_from_slice(&serialized[i * 48..(i + 1) * 48]);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_cryptography::bls12381::{
        dkg,
        primitives::{group::G1, ops::sign, sharing::Mode, variant::MinSig},
    };
    use commonware_utils::{N3f1, NZU32};
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_g1_to_eip2537_produces_128_bytes() {
        // Create test share (MinSig variant, same as consensus)
        let mut rng = StdRng::seed_from_u64(42);
        let n = NZU32!(5);
        let (_sharing, shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::default(), n);
        let share = &shares[0];

        let message = b"test message";
        let dst = b"TEMPO_BRIDGE_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";

        // MinSig: signature is G1
        let signature: G1 = sign::<MinSig>(&share.private, dst, message);

        // Get compressed signature (48 bytes)
        let compressed = signature.encode();
        assert_eq!(compressed.len(), G1_COMPRESSED_LEN);

        let compressed_array: [u8; G1_COMPRESSED_LEN] = compressed.as_ref().try_into().unwrap();

        // Convert to EIP-2537 format
        let eip2537 = g1_to_eip2537(&compressed_array).unwrap();
        assert_eq!(eip2537.len(), G1_UNCOMPRESSED_LEN);

        // Verify padding structure: each 64-byte element starts with 16 zero bytes
        for i in 0..2 {
            let offset = i * 64;
            assert_eq!(
                &eip2537[offset..offset + 16],
                &[0u8; 16],
                "element {i} should have 16-byte zero padding"
            );
        }
    }

    #[test]
    fn test_g1_to_eip2537_deterministic() {
        let mut rng = StdRng::seed_from_u64(123);
        let n = NZU32!(5);
        let (_sharing, shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::default(), n);
        let share = &shares[0];

        let signature: G1 = sign::<MinSig>(
            &share.private,
            b"TEMPO_BRIDGE_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_",
            b"hello",
        );

        let compressed = signature.encode();
        let compressed_array: [u8; G1_COMPRESSED_LEN] = compressed.as_ref().try_into().unwrap();

        let result1 = g1_to_eip2537(&compressed_array).unwrap();
        let result2 = g1_to_eip2537(&compressed_array).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_g1_to_eip2537_different_signatures_produce_different_output() {
        let mut rng = StdRng::seed_from_u64(456);
        let n = NZU32!(5);
        let (_sharing, shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::default(), n);
        let share = &shares[0];

        let dst = b"TEMPO_BRIDGE_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";

        let sig1: G1 = sign::<MinSig>(&share.private, dst, b"message1");
        let sig2: G1 = sign::<MinSig>(&share.private, dst, b"message2");

        let c1: [u8; G1_COMPRESSED_LEN] = sig1.encode().as_ref().try_into().unwrap();
        let c2: [u8; G1_COMPRESSED_LEN] = sig2.encode().as_ref().try_into().unwrap();

        let eip1 = g1_to_eip2537(&c1).unwrap();
        let eip2 = g1_to_eip2537(&c2).unwrap();

        assert_ne!(eip1, eip2);
    }

    #[test]
    fn test_g2_public_key_to_eip2537() {
        // Test that G2 public keys can be converted for on-chain use
        let mut rng = StdRng::seed_from_u64(789);
        let n = NZU32!(5);
        let (sharing, _shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::default(), n);

        // Get the group public key (G2)
        let public_key = sharing.public();
        let compressed = public_key.encode();
        assert_eq!(compressed.len(), G2_COMPRESSED_LEN);

        let compressed_array: [u8; G2_COMPRESSED_LEN] = compressed.as_ref().try_into().unwrap();

        // Convert to EIP-2537 format (256 bytes)
        let eip2537 = g2_to_eip2537(&compressed_array).unwrap();
        assert_eq!(eip2537.len(), G2_UNCOMPRESSED_LEN);

        // Verify padding structure
        for i in 0..4 {
            let offset = i * 64;
            assert_eq!(
                &eip2537[offset..offset + 16],
                &[0u8; 16],
                "element {i} should have 16-byte zero padding"
            );
        }
    }
}
