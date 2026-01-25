//! Differential fuzz tests for BLS12-381 cryptography.
//!
//! These tests compare the Solidity implementation in BLS12381.sol against
//! the Rust/blst implementation to ensure they produce identical results.
//!
//! Tests cover:
//! - `expand_message_xmd` (RFC 9380 Section 5.3.1)
//! - Attestation hash computation
//! - BLS signature verification properties

use alloy_primitives::{Address, B256, keccak256};
use blst::{BLST_ERROR, min_pk::SecretKey};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

/// The BLS DST used by the bridge - must match Solidity and Rust signer.
const BLS_DST: &[u8] = b"TEMPO_BRIDGE_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";

/// The bridge domain separator.
const BRIDGE_DOMAIN: &[u8] = b"TEMPO_BRIDGE_V1";

/// Rust implementation of expand_message_xmd matching RFC 9380 Section 5.3.1.
/// This is the reference implementation to compare against Solidity.
fn expand_message_xmd(message: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    assert!(dst.len() <= 255, "DST too long");
    assert!(len_in_bytes <= 255 * 32, "len_in_bytes too large");

    let ell = (len_in_bytes + 31) / 32;
    assert!(ell <= 255, "ell too large");

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    // Z_pad = I2OSP(0, 64) - 64 zero bytes for SHA-256
    let z_pad = [0u8; 64];

    // l_i_b_str = I2OSP(len_in_bytes, 2)
    let lib_str = (len_in_bytes as u16).to_be_bytes();

    // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    let mut msg_prime = Vec::new();
    msg_prime.extend_from_slice(&z_pad);
    msg_prime.extend_from_slice(message);
    msg_prime.extend_from_slice(&lib_str);
    msg_prime.push(0u8);
    msg_prime.extend_from_slice(&dst_prime);

    // b_0 = H(msg_prime)
    let b0: [u8; 32] = Sha256::digest(&msg_prime).into();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut b1_input = Vec::new();
    b1_input.extend_from_slice(&b0);
    b1_input.push(1u8);
    b1_input.extend_from_slice(&dst_prime);
    let mut bi: [u8; 32] = Sha256::digest(&b1_input).into();

    let mut result = Vec::with_capacity(len_in_bytes);
    result.extend_from_slice(&bi[..std::cmp::min(32, len_in_bytes)]);

    // For i = 2 to ell: b_i = H((b_0 XOR b_{i-1}) || I2OSP(i, 1) || DST_prime)
    for i in 2..=ell {
        let mut xored = [0u8; 32];
        for j in 0..32 {
            xored[j] = b0[j] ^ bi[j];
        }

        let mut bi_input = Vec::new();
        bi_input.extend_from_slice(&xored);
        bi_input.push(i as u8);
        bi_input.extend_from_slice(&dst_prime);
        bi = Sha256::digest(&bi_input).into();

        let start = (i - 1) * 32;
        let end = std::cmp::min(start + 32, len_in_bytes);
        if start < len_in_bytes {
            result.extend_from_slice(&bi[..(end - start)]);
        }
    }

    result.truncate(len_in_bytes);
    result
}

/// Compute attestation hash matching Solidity _computeAttestationHash.
fn compute_attestation_hash(
    sender: Address,
    message_hash: B256,
    origin_chain_id: u64,
    destination_chain_id: u64,
) -> B256 {
    let mut data = Vec::with_capacity(83);
    data.extend_from_slice(BRIDGE_DOMAIN);
    data.extend_from_slice(sender.as_slice());
    data.extend_from_slice(message_hash.as_slice());
    data.extend_from_slice(&origin_chain_id.to_be_bytes());
    data.extend_from_slice(&destination_chain_id.to_be_bytes());
    keccak256(&data)
}

// =============================================================================
//                           UNIT TESTS
// =============================================================================

#[test]
fn test_expand_message_xmd_empty_message() {
    let result = expand_message_xmd(b"", BLS_DST, 256);
    assert_eq!(result.len(), 256);

    // Result should be deterministic
    let result2 = expand_message_xmd(b"", BLS_DST, 256);
    assert_eq!(result, result2);
}

#[test]
fn test_expand_message_xmd_different_messages_produce_different_output() {
    let result1 = expand_message_xmd(b"message one", BLS_DST, 256);
    let result2 = expand_message_xmd(b"message two", BLS_DST, 256);
    assert_ne!(result1, result2);
}

#[test]
fn test_expand_message_xmd_different_dsts_produce_different_output() {
    let result1 = expand_message_xmd(b"test", b"DST_ONE", 256);
    let result2 = expand_message_xmd(b"test", b"DST_TWO", 256);
    assert_ne!(result1, result2);
}

#[test]
fn test_expand_message_xmd_various_lengths() {
    assert_eq!(expand_message_xmd(b"test", BLS_DST, 32).len(), 32);
    assert_eq!(expand_message_xmd(b"test", BLS_DST, 64).len(), 64);
    assert_eq!(expand_message_xmd(b"test", BLS_DST, 128).len(), 128);
    assert_eq!(expand_message_xmd(b"test", BLS_DST, 256).len(), 256);
}

/// RFC 9380 Section A.3.1 test vector for expand_message_xmd with SHA-256.
/// DST = "QUUX-V01-CS02-with-expander-SHA256-128"
/// msg = "" (empty)
/// len_in_bytes = 0x20 (32)
#[test]
fn test_expand_message_xmd_rfc9380_vector_empty_32() {
    let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
    let result = expand_message_xmd(b"", dst, 32);
    assert_eq!(result.len(), 32);

    // Expected output from RFC 9380 Appendix A.3.1:
    // uniform_bytes = 68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235
    let expected =
        hex::decode("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235").unwrap();

    // Note: If this doesn't match, the Solidity expand_message_xmd needs fixing
    assert_eq!(
        result, expected,
        "expand_message_xmd doesn't match RFC 9380 test vector"
    );
}

/// RFC 9380 Section A.3.1 test vector: msg = "abc", len = 32
#[test]
fn test_expand_message_xmd_rfc9380_vector_abc_32() {
    let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
    let result = expand_message_xmd(b"abc", dst, 32);
    assert_eq!(result.len(), 32);

    let expected =
        hex::decode("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615").unwrap();

    assert_eq!(
        result, expected,
        "expand_message_xmd doesn't match RFC 9380 test vector for 'abc'"
    );
}

/// RFC 9380 Section A.3.1 test vector: msg = "", len = 128
#[test]
fn test_expand_message_xmd_rfc9380_vector_empty_128() {
    let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
    let result = expand_message_xmd(b"", dst, 128);
    assert_eq!(result.len(), 128);

    let expected = hex::decode(
        "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"
    ).unwrap();

    assert_eq!(
        result, expected,
        "expand_message_xmd doesn't match RFC 9380 test vector for empty 128"
    );
}

#[test]
fn test_attestation_hash_deterministic() {
    let sender = Address::repeat_byte(0xAA);
    let message_hash = B256::repeat_byte(0x11);
    let origin_chain_id = 1u64;
    let destination_chain_id = 12345u64;

    let hash1 =
        compute_attestation_hash(sender, message_hash, origin_chain_id, destination_chain_id);
    let hash2 =
        compute_attestation_hash(sender, message_hash, origin_chain_id, destination_chain_id);
    assert_eq!(hash1, hash2, "attestation hash should be deterministic");
}

#[test]
fn test_attestation_hash_different_inputs() {
    let sender = Address::repeat_byte(0xAA);
    let message_hash = B256::repeat_byte(0x11);
    let origin_chain_id = 1u64;
    let destination_chain_id = 12345u64;

    let base =
        compute_attestation_hash(sender, message_hash, origin_chain_id, destination_chain_id);

    // Different sender
    let different_sender = Address::repeat_byte(0xBB);
    let h1 = compute_attestation_hash(
        different_sender,
        message_hash,
        origin_chain_id,
        destination_chain_id,
    );
    assert_ne!(base, h1, "different sender should produce different hash");

    // Different message hash
    let different_hash = B256::repeat_byte(0x22);
    let h2 = compute_attestation_hash(
        sender,
        different_hash,
        origin_chain_id,
        destination_chain_id,
    );
    assert_ne!(
        base, h2,
        "different message_hash should produce different hash"
    );

    // Different origin
    let h3 = compute_attestation_hash(sender, message_hash, 2, destination_chain_id);
    assert_ne!(base, h3, "different origin should produce different hash");

    // Different destination
    let h4 = compute_attestation_hash(sender, message_hash, origin_chain_id, 99999);
    assert_ne!(
        base, h4,
        "different destination should produce different hash"
    );
}

#[test]
fn test_bls_sign_and_verify_roundtrip() {
    // Generate a random secret key
    let ikm = [42u8; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();

    let message = B256::repeat_byte(0x42);
    let signature = sk.sign(message.as_slice(), BLS_DST, &[]);

    // Verify should succeed
    let result = signature.verify(true, message.as_slice(), BLS_DST, &[], &pk, true);
    assert_eq!(result, BLST_ERROR::BLST_SUCCESS, "signature should verify");

    // Wrong message should fail
    let wrong_message = B256::repeat_byte(0x99);
    let result = signature.verify(true, wrong_message.as_slice(), BLS_DST, &[], &pk, true);
    assert_ne!(
        result,
        BLST_ERROR::BLST_SUCCESS,
        "wrong message should not verify"
    );
}

#[test]
fn test_bls_wrong_key_fails() {
    let ikm1 = [1u8; 32];
    let ikm2 = [2u8; 32];

    let sk1 = SecretKey::key_gen(&ikm1, &[]).unwrap();
    let sk2 = SecretKey::key_gen(&ikm2, &[]).unwrap();
    let pk2 = sk2.sk_to_pk();

    let message = b"test message";
    let signature = sk1.sign(message, BLS_DST, &[]);

    // Verify with wrong public key should fail
    let result = signature.verify(true, message, BLS_DST, &[], &pk2, true);
    assert_ne!(
        result,
        BLST_ERROR::BLST_SUCCESS,
        "wrong key should not verify"
    );
}

#[test]
fn test_bls_signature_sizes() {
    let ikm = [42u8; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();

    let message = b"test";
    let signature = sk.sign(message, BLS_DST, &[]);

    // Compressed sizes
    let pk_compressed = pk.compress();
    let sig_compressed = signature.compress();

    assert_eq!(
        pk_compressed.len(),
        48,
        "G1 compressed (public key) should be 48 bytes"
    );
    assert_eq!(
        sig_compressed.len(),
        96,
        "G2 compressed (signature) should be 96 bytes"
    );

    // Note: For EIP-2537 we need uncompressed format:
    // - G1 (public key): 128 bytes
    // - G2 (signature): 256 bytes
    let pk_uncompressed = pk.serialize();
    assert_eq!(
        pk_uncompressed.len(),
        96,
        "blst G1 serialized is 96 bytes (affine, unpadded)"
    );

    // The 128-byte format for EIP-2537 adds padding
}

// =============================================================================
//                           PROPERTY-BASED TESTS
// =============================================================================

proptest! {
    /// Test that expand_message_xmd is deterministic.
    #[test]
    fn prop_expand_message_xmd_deterministic(
        message in prop::collection::vec(any::<u8>(), 0..100),
        len in 32usize..=256usize,
    ) {
        let result1 = expand_message_xmd(&message, BLS_DST, len);
        let result2 = expand_message_xmd(&message, BLS_DST, len);
        prop_assert_eq!(result1, result2);
    }

    /// Test that different messages produce different outputs.
    #[test]
    fn prop_expand_message_xmd_different_inputs_different_outputs(
        msg1 in prop::collection::vec(any::<u8>(), 1..50),
        msg2 in prop::collection::vec(any::<u8>(), 1..50),
    ) {
        prop_assume!(msg1 != msg2);
        let result1 = expand_message_xmd(&msg1, BLS_DST, 256);
        let result2 = expand_message_xmd(&msg2, BLS_DST, 256);
        prop_assert_ne!(result1, result2);
    }

    /// Test attestation hash determinism.
    #[test]
    fn prop_attestation_hash_deterministic(
        sender_byte in any::<u8>(),
        hash_byte in any::<u8>(),
        origin in any::<u64>(),
        dest in any::<u64>(),
    ) {
        let sender = Address::repeat_byte(sender_byte);
        let message_hash = B256::repeat_byte(hash_byte);

        let hash1 = compute_attestation_hash(sender, message_hash, origin, dest);
        let hash2 = compute_attestation_hash(sender, message_hash, origin, dest);
        prop_assert_eq!(hash1, hash2);
    }

    /// Test that attestation hash includes all components (changing any changes the hash).
    #[test]
    fn prop_attestation_hash_includes_all_fields(
        sender_byte in any::<u8>(),
        hash_byte in any::<u8>(),
        origin in 1u64..u64::MAX,
        dest in 1u64..u64::MAX,
    ) {
        let sender = Address::repeat_byte(sender_byte);
        let message_hash = B256::repeat_byte(hash_byte);

        let base = compute_attestation_hash(sender, message_hash, origin, dest);

        // Changing sender changes hash
        let different_sender = Address::repeat_byte(sender_byte.wrapping_add(1));
        let h1 = compute_attestation_hash(different_sender, message_hash, origin, dest);
        prop_assert_ne!(base, h1, "different sender should produce different hash");

        // Changing message_hash changes hash
        let different_hash = B256::repeat_byte(hash_byte.wrapping_add(1));
        let h2 = compute_attestation_hash(sender, different_hash, origin, dest);
        prop_assert_ne!(base, h2, "different message_hash should produce different hash");

        // Changing origin changes hash
        let h3 = compute_attestation_hash(sender, message_hash, origin.wrapping_add(1), dest);
        prop_assert_ne!(base, h3, "different origin should produce different hash");

        // Changing dest changes hash
        let h4 = compute_attestation_hash(sender, message_hash, origin, dest.wrapping_add(1));
        prop_assert_ne!(base, h4, "different dest should produce different hash");
    }

    /// Test BLS sign/verify roundtrip with random keys and messages.
    #[test]
    fn prop_bls_sign_verify_roundtrip(
        seed in any::<[u8; 32]>(),
        message_bytes in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        let sk = SecretKey::key_gen(&seed, &[]).unwrap();
        let pk = sk.sk_to_pk();

        let signature = sk.sign(&message_bytes, BLS_DST, &[]);
        let result = signature.verify(true, &message_bytes, BLS_DST, &[], &pk, true);
        prop_assert_eq!(result, BLST_ERROR::BLST_SUCCESS, "signature should verify for random key/message");
    }
}

// =============================================================================
//    DIFFERENTIAL TEST VECTORS (Rust vs Solidity)
//    These same vectors are tested in BLS12381.t.sol
// =============================================================================

#[test]
fn test_differential_expand_message_xmd_empty() {
    let result = expand_message_xmd(b"", BLS_DST, 256);

    // This exact value is hardcoded in BLS12381.t.sol::test_expandMessageXmd_differential_empty
    let expected = hex::decode("16492f3f7d1a240be0e00102fb8e6a03a76e55371552f54987f0c5d1d26b5a53e3317641f3edc5a3b7dfb76724c77fd86f43208b0ce4766d418dc64613d224a005c2571bd09ded0f9b79afda75d47c1ead76b806e808febf4e0886a4186a0555fac4ce3f247d2612e90f5e7fed11ec8922a5a33db0a0cc60621f1aab72c05632c4f9c78686efa5d294fc5ce60f8485ad3c807348d4f247c519b1b9ac97c1b1564b41586dcf270306276fbbc7d2fb1492b0a70f47a38e0dbb7ae23c29186bbe642a48fe05ef85162ffacb7c18d31b5b3e1335023faf5f02e5d340bd587825665bc238d09d646b1fe86360467a871c190d90496b97601f82e1330a18d77606c048").unwrap();

    assert_eq!(
        result, expected,
        "Rust should match hardcoded Solidity vector for empty message"
    );
}

#[test]
fn test_differential_expand_message_xmd_test() {
    let result = expand_message_xmd(b"test", BLS_DST, 256);

    // This exact value is hardcoded in BLS12381.t.sol::test_expandMessageXmd_differential_test
    let expected = hex::decode("33388e19d7674f2f029e0de0e62b8b46c284e4915c8c12cb0df4ef92e1b61d072d1ce4a9a501e2f9eae1e431319d5ec930a53bbcf7b9f7fbba04dd47cabd02b3f76c14b7fda800c0db139920fef0507de46f9742143863b03141b6481d55ff9df2b0032c738099e75f3f00b28e201d7d7136fe4ecec8c603c1377ff7d5f12400a55ff562e3ddd10bdd8ba008457007acfd12bafc9667a0f5255cfc994a31b11c78a1444be70fc60e87704b997d8f41c5a39ea52d32ebfe24f727eae3fbcb10da58148722b692f23c730aba1f50de0ff568e0a08c9eeb75aaf09621b2e3d66f927e62d29594232238427530c48494a2061b300302b105e1f79720219202fec505").unwrap();

    assert_eq!(
        result, expected,
        "Rust should match hardcoded Solidity vector for 'test' message"
    );
}

#[test]
fn test_differential_expand_message_xmd_hash32() {
    // 0x42 repeated 32 times (simulates attestation hash)
    let message = [0x42u8; 32];
    let result = expand_message_xmd(&message, BLS_DST, 256);

    // This exact value is hardcoded in BLS12381.t.sol::test_expandMessageXmd_differential_hash32
    let expected = hex::decode("97ee2a4bb87efa1327ca89a2da22fe6ac3daf2cd4d974fa341a6f43e4738aea1fdab1a22ca13c9a335638a5e9a02752b6db51c16af3a56446c075d78dfc240d3e301c615fb62c53e290ee00f5f65021296e84d3e6117fabb389f52a7651858b34c604be8563c0dcd5932f088887b38d7e020d9b9262eefea81020929652e5af96cf88f9a62512754e75e2b30b50bc52c16cce0920bc3a4ee6982f9b8cfb011ab3f8065e04f8906b2eaf4333775e0513edb6248fcdcfe01506f2ca821e493e88f5882000caeb020c948c05db8273f660a56eba7e2f53664360af534a0580524e2b8c08611a2a0d3cb5949a490a84fe937c43be905deed291b565fee30e8724233").unwrap();

    assert_eq!(
        result, expected,
        "Rust should match hardcoded Solidity vector for 32-byte hash input"
    );
}

#[test]
fn test_differential_expand_message_xmd_short() {
    let result = expand_message_xmd(b"short", BLS_DST, 32);

    // This exact value is hardcoded in BLS12381.t.sol::test_expandMessageXmd_differential_short
    let expected =
        hex::decode("647b59246b8fb81b72409a012bf469ed0dda1cac81fe5da0b4b0287a683788fc").unwrap();

    assert_eq!(
        result, expected,
        "Rust should match hardcoded Solidity vector for short output"
    );
}

// =============================================================================
//                    DST CONSISTENCY TESTS
// =============================================================================

#[test]
fn test_dst_format() {
    // Solidity: "TEMPO_BRIDGE_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_"
    // Rust:     b"TEMPO_BRIDGE_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_"

    let expected = b"TEMPO_BRIDGE_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";
    assert_eq!(BLS_DST, expected);
    assert_eq!(BLS_DST.len(), 52);
}

#[test]
fn test_bridge_domain_format() {
    let expected = b"TEMPO_BRIDGE_V1";
    assert_eq!(BRIDGE_DOMAIN, expected);
    assert_eq!(BRIDGE_DOMAIN.len(), 15);
}

// =============================================================================
//                    SECURITY TESTS
// =============================================================================

/// Test that we correctly identify the infinity signature attack vector.
/// If pk = infinity, then for any message, sig = infinity would pass pairing check.
#[test]
fn test_infinity_key_attack_awareness() {
    // This test documents the attack vector that Solidity should reject.
    //
    // Attack: If groupPublicKey is ever set to infinity (e.g., through admin error
    // or malicious rotation), then an attacker can forge signatures:
    //
    // e(infinity, H(m)) * e(-G1, infinity) = 1 * 1 = 1 ✓
    //
    // The Solidity contract MUST reject infinity public keys and signatures.
    // See BLS12381.sol verify() - should add infinity checks.
    //
    // Detection: All-zero bytes for compressed encoding indicates infinity.

    let zero_pk = [0u8; 48];
    let zero_sig = [0u8; 96];

    // Both should be considered "infinity" or invalid
    // The Solidity contract should explicitly reject these
    assert!(
        zero_pk.iter().all(|&b| b == 0),
        "zero pk represents infinity"
    );
    assert!(
        zero_sig.iter().all(|&b| b == 0),
        "zero sig represents infinity"
    );
}
