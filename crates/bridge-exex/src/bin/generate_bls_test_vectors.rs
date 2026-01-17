//! Generates BLS12-381 test vectors for Solidity contract testing.
//!
//! Run with: cargo run -p tempo-bridge-exex --bin generate-bls-test-vectors
//!
//! ## Signature Scheme
//!
//! This generates test vectors for a simplified BLS scheme compatible with EIP-2537:
//!
//! 1. Message hash (32 bytes) is padded to 64 bytes (EIP-2537 Fp format)
//! 2. `map_fp_to_g1` precompile maps to G1 point
//! 3. Signature = sk * H(m) where H(m) is the G1 point from step 2
//! 4. Verification: e(sig, G2_gen) == e(H(m), pk)
//!
//! ## Important Note on Production Use
//!
//! This scheme differs from standard BLS (hash-to-curve with DST) because EIP-2537
//! only provides `map_fp_to_g1`, not full `hash_to_g1` with domain separation.
//!
//! For production bridge verification:
//! - The bridge operator must convert consensus signatures to this format
//! - Or implement full hash-to-curve in Solidity (expensive, ~200k+ gas)
//!
//! The consensus layer uses: `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_`
//! which requires multiple expand_message_xmd + map_to_curve calls.

use blst::{
    blst_bendian_from_fp, blst_fp, blst_fp_from_bendian, blst_hash_to_g1, blst_map_to_g1, blst_p1,
    blst_p1_affine, blst_p1_compress, blst_p1_from_affine, blst_p1_mult, blst_p1_to_affine,
    blst_p2, blst_p2_affine, blst_p2_generator, blst_p2_mult, blst_p2_to_affine, blst_scalar,
    blst_scalar_from_bendian,
};

/// Domain separation tag used by commonware-cryptography for MinSig messages
const COMMONWARE_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Check for --commonware flag to generate vectors matching consensus
    let use_commonware_scheme = args.iter().any(|a| a == "--commonware");

    // Use provided message hash or default
    let message_hash: [u8; 32] = if let Some(pos) = args.iter().position(|a| !a.starts_with('-') && a != &args[0]) {
        let hex_str = args[pos].trim_start_matches("0x");
        let bytes = hex::decode(hex_str).expect("Invalid hex message");
        bytes.try_into().expect("Message must be 32 bytes")
    } else {
        // Default test message
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]
    };

    // Generate deterministic private key from fixed seed
    let sk_bytes: [u8; 32] = [
        0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a,
        0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a,
        0x2a, 0x2a,
    ];
    let sk = scalar_from_bytes(&sk_bytes);

    // Public key = sk * G2_generator (MinSig: pk in G2)
    let pk_affine = compute_public_key(&sk);

    // Hash message to G1 point
    let h_m = if use_commonware_scheme {
        // Standard hash-to-curve matching commonware-cryptography
        hash_to_g1_standard(&message_hash)
    } else {
        // Simplified scheme for EIP-2537 map_fp_to_g1
        hash_to_g1_eip2537(&message_hash)
    };

    // Signature = sk * H(m) (MinSig: sig in G1)
    let sig_affine = scalar_mul_g1(&h_m, &sk);

    // Encode to EIP-2537 format (uncompressed, padded)
    let pk_bytes = encode_g2_affine(&pk_affine);
    let sig_bytes = encode_g1_affine(&sig_affine);

    // Also compute compressed formats for reference
    let pk_compressed = compress_g2(&pk_affine);
    let sig_compressed = compress_g1(&sig_affine);

    let scheme = if use_commonware_scheme {
        "standard hash-to-curve (BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_)"
    } else {
        "EIP-2537 map_fp_to_g1(pad(msg_hash))"
    };

    println!("// BLS12-381 Test Vectors (EIP-2537 format)");
    println!("// Scheme: {}", scheme);
    println!("// Verify: e(sig, G2_gen) == e(H(m), pk)");
    println!("// Message: 0x{}", hex::encode(message_hash));
    println!();
    println!(
        "bytes constant TEST_BLS_PUBLIC_KEY = hex\"{}\";",
        hex::encode(&pk_bytes)
    );
    println!();
    println!(
        "bytes constant TEST_BLS_SIGNATURE = hex\"{}\";",
        hex::encode(&sig_bytes)
    );
    println!();
    println!(
        "bytes32 constant TEST_MESSAGE_HASH = hex\"{}\";",
        hex::encode(message_hash)
    );

    // Print G2 generator for verification
    let g2_gen = unsafe { &*blst_p2_generator() };
    let mut g2_gen_affine = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut g2_gen_affine, g2_gen) };
    let g2_gen_bytes = encode_g2_affine(&g2_gen_affine);
    println!();
    println!("// G2 Generator (256 bytes, EIP-2537 format):");
    println!(
        "bytes constant G2_GENERATOR = hex\"{}\";",
        hex::encode(&g2_gen_bytes)
    );

    // Print compressed formats for bridge operator reference
    println!();
    println!("// Compressed formats (for consensus/bridge operator reference):");
    println!("// Public key (G2, 96 bytes compressed): 0x{}", hex::encode(&pk_compressed));
    println!("// Signature (G1, 48 bytes compressed): 0x{}", hex::encode(&sig_compressed));
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> blst_scalar {
    let mut scalar = blst_scalar::default();
    unsafe { blst_scalar_from_bendian(&mut scalar, bytes.as_ptr()) };
    scalar
}

fn compute_public_key(sk: &blst_scalar) -> blst_p2_affine {
    let g2_gen = unsafe { &*blst_p2_generator() };

    let mut pk = blst_p2::default();
    unsafe { blst_p2_mult(&mut pk, g2_gen, sk.b.as_ptr(), 256) };

    let mut pk_affine = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut pk_affine, &pk) };
    pk_affine
}

/// Hash to G1 using EIP-2537's map_fp_to_g1 approach.
///
/// This matches Solidity's hashToG1 function:
/// - Pad 32-byte hash to 64 bytes (16 zeros + 48-byte field element where hash is in last 32 bytes)
/// - Call map_fp_to_g1
fn hash_to_g1_eip2537(msg_hash: &[u8; 32]) -> blst_p1_affine {
    // Create 48-byte field element: 16 zero bytes + 32-byte hash
    let mut fp_bytes = [0u8; 48];
    fp_bytes[16..48].copy_from_slice(msg_hash);

    // Convert to blst_fp
    let mut fp = blst_fp::default();
    unsafe { blst_fp_from_bendian(&mut fp, fp_bytes.as_ptr()) };

    // Map to G1
    let mut p1 = blst_p1::default();
    unsafe { blst_map_to_g1(&mut p1, &fp, core::ptr::null()) };

    let mut affine = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut affine, &p1) };
    affine
}

/// Hash to G1 using standard hash-to-curve (matching commonware-cryptography).
///
/// Uses blst_hash_to_g1 with the standard DST for MinSig.
fn hash_to_g1_standard(msg_hash: &[u8; 32]) -> blst_p1_affine {
    let mut p1 = blst_p1::default();
    unsafe {
        blst_hash_to_g1(
            &mut p1,
            msg_hash.as_ptr(),
            msg_hash.len(),
            COMMONWARE_DST.as_ptr(),
            COMMONWARE_DST.len(),
            core::ptr::null(),
            0,
        );
    }

    let mut affine = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut affine, &p1) };
    affine
}

fn scalar_mul_g1(point: &blst_p1_affine, scalar: &blst_scalar) -> blst_p1_affine {
    let mut p = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut p, point) };

    let mut result = blst_p1::default();
    unsafe { blst_p1_mult(&mut result, &p, scalar.b.as_ptr(), 256) };

    let mut affine = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut affine, &result) };
    affine
}

fn encode_g1_affine(point: &blst_p1_affine) -> [u8; 128] {
    let mut result = [0u8; 128];

    let mut x_bytes = [0u8; 48];
    let mut y_bytes = [0u8; 48];

    unsafe {
        blst_bendian_from_fp(x_bytes.as_mut_ptr(), &point.x);
        blst_bendian_from_fp(y_bytes.as_mut_ptr(), &point.y);
    }

    // EIP-2537: 16 bytes padding + 48 bytes for each coordinate
    result[16..64].copy_from_slice(&x_bytes);
    result[80..128].copy_from_slice(&y_bytes);

    result
}

fn encode_g2_affine(point: &blst_p2_affine) -> [u8; 256] {
    let mut result = [0u8; 256];

    let mut x_c0 = [0u8; 48];
    let mut x_c1 = [0u8; 48];
    let mut y_c0 = [0u8; 48];
    let mut y_c1 = [0u8; 48];

    unsafe {
        blst_bendian_from_fp(x_c0.as_mut_ptr(), &point.x.fp[0]);
        blst_bendian_from_fp(x_c1.as_mut_ptr(), &point.x.fp[1]);
        blst_bendian_from_fp(y_c0.as_mut_ptr(), &point.y.fp[0]);
        blst_bendian_from_fp(y_c1.as_mut_ptr(), &point.y.fp[1]);
    }

    // EIP-2537 format: encode(c0) || encode(c1) for each Fp2 element
    // Each encode is 16 bytes padding + 48 bytes
    result[16..64].copy_from_slice(&x_c0);
    result[80..128].copy_from_slice(&x_c1);
    result[144..192].copy_from_slice(&y_c0);
    result[208..256].copy_from_slice(&y_c1);

    result
}

fn compress_g1(point: &blst_p1_affine) -> [u8; 48] {
    let mut p1 = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut p1, point) };

    let mut compressed = [0u8; 48];
    unsafe { blst_p1_compress(compressed.as_mut_ptr(), &p1) };
    compressed
}

fn compress_g2(point: &blst_p2_affine) -> [u8; 96] {
    use blst::{blst_p2_compress, blst_p2_from_affine};

    let mut p2 = blst_p2::default();
    unsafe { blst_p2_from_affine(&mut p2, point) };

    let mut compressed = [0u8; 96];
    unsafe { blst_p2_compress(compressed.as_mut_ptr(), &p2) };
    compressed
}
