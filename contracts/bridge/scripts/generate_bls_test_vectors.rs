#!/usr/bin/env cargo +nightly -Zscript
//! Generates BLS12-381 test vectors for Solidity contract testing.
//! 
//! Run with: cargo +nightly -Zscript contracts/bridge/scripts/generate_bls_test_vectors.rs
//!
//! Or compile and run:
//!   rustc --edition 2021 contracts/bridge/scripts/generate_bls_test_vectors.rs -o gen_bls
//!   ./gen_bls

// For cargo script:
// ```cargo
// [dependencies]
// blst = "0.3"
// hex = "0.4"
// sha2 = "0.10"
// ```

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    use blst::min_sig::*;
    use blst::BLST_ERROR;

    // Domain separation tag for hashing to curve (must match Solidity)
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    // Generate a deterministic private key for testing
    let ikm = [42u8; 32]; // Seed for key generation
    let sk = SecretKey::key_gen(&ikm, &[]).expect("key gen failed");

    // Get the public key (G2 point for MinSig variant)
    let pk = sk.sk_to_pk();

    // Create a test message hash (matches what Solidity will compute)
    // HEADER_DOMAIN = keccak256("TEMPO_HEADER_V1")
    // headerDigest = keccak256(abi.encodePacked(HEADER_DOMAIN, tempoChainId, height, parentHash, stateRoot, receiptsRoot, epoch))
    // For simplicity, we'll use a direct hash
    let message = b"test message for bls verification";
    
    // Sign the message (produces G1 signature for MinSig)
    let sig = sk.sign(message, dst, &[]);

    // Verify it works
    let result = sig.verify(true, message, dst, &[], &pk, true);
    assert_eq!(result, BLST_ERROR::BLST_SUCCESS, "Signature verification failed");

    // Serialize to uncompressed format
    let pk_bytes = pk.serialize(); // Compressed G2 (96 bytes for MinSig)
    let sig_bytes = sig.serialize(); // Compressed G1 (48 bytes for MinSig)

    // For EIP-2537 precompiles, we need UNCOMPRESSED points:
    // - G1: 128 bytes (2 x 64-byte coordinates)
    // - G2: 256 bytes (2 x 128-byte coordinates)
    
    // Unfortunately blst doesn't directly expose uncompressed serialization in the standard way.
    // We need to use the raw affine point accessors.
    
    // For G1 (signature) - uncompressed
    let sig_affine = sig.to_affine();
    let mut sig_uncompressed = [0u8; 128];
    // blst uses little-endian internally but EIP-2537 expects big-endian
    // We need to access the x and y coordinates properly
    unsafe {
        let p = &sig_affine as *const _ as *const blst::blst_p1_affine;
        // x coordinate (Fp element - 48 bytes, needs 64-byte padding for EIP-2537)
        let x_bytes = std::slice::from_raw_parts((*p).x.l.as_ptr() as *const u8, 48);
        let y_bytes = std::slice::from_raw_parts((*p).y.l.as_ptr() as *const u8, 48);
        
        // EIP-2537 format: 64 bytes per coordinate, big-endian, zero-padded on the left
        // x: 16 zero bytes + 48 bytes (reversed for big-endian)
        // y: 16 zero bytes + 48 bytes (reversed for big-endian)
        for i in 0..48 {
            sig_uncompressed[16 + 47 - i] = x_bytes[i];
            sig_uncompressed[64 + 16 + 47 - i] = y_bytes[i];
        }
    }

    // For G2 (public key) - uncompressed
    let pk_affine = pk.to_affine();
    let mut pk_uncompressed = [0u8; 256];
    unsafe {
        let p = &pk_affine as *const _ as *const blst::blst_p2_affine;
        // G2 has Fp2 coordinates: x = x0 + x1*i, y = y0 + y1*i
        // Each component is 48 bytes
        let x_c0 = std::slice::from_raw_parts((*p).x.fp[0].l.as_ptr() as *const u8, 48);
        let x_c1 = std::slice::from_raw_parts((*p).x.fp[1].l.as_ptr() as *const u8, 48);
        let y_c0 = std::slice::from_raw_parts((*p).y.fp[0].l.as_ptr() as *const u8, 48);
        let y_c1 = std::slice::from_raw_parts((*p).y.fp[1].l.as_ptr() as *const u8, 48);
        
        // EIP-2537 G2 format: x1 (64) | x0 (64) | y1 (64) | y0 (64)
        // Each is 16 zero bytes + 48 bytes big-endian
        for i in 0..48 {
            pk_uncompressed[16 + 47 - i] = x_c1[i];         // x1
            pk_uncompressed[64 + 16 + 47 - i] = x_c0[i];     // x0
            pk_uncompressed[128 + 16 + 47 - i] = y_c1[i];    // y1
            pk_uncompressed[192 + 16 + 47 - i] = y_c0[i];    // y0
        }
    }

    println!("// BLS12-381 Test Vectors for Solidity");
    println!("// Generated from message: {:?}", std::str::from_utf8(message).unwrap());
    println!();
    println!("// Public Key (G2 uncompressed, 256 bytes):");
    println!("bytes constant TEST_BLS_PUBLIC_KEY = hex\"{}\";", hex::encode(&pk_uncompressed));
    println!();
    println!("// Signature (G1 uncompressed, 128 bytes):");
    println!("bytes constant TEST_BLS_SIGNATURE = hex\"{}\";", hex::encode(&sig_uncompressed));
    println!();
    println!("// Compressed formats (for reference):");
    println!("// Public Key (G2 compressed, 96 bytes): {}", hex::encode(&pk_bytes));
    println!("// Signature (G1 compressed, 48 bytes): {}", hex::encode(&sig_bytes));

    Ok(())
}
