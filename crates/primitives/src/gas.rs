//! Gas schedule of signature verification and keccak hashing.

/// Gas cost for secp256k1 signature verification.
pub const SECP256K1_VERIFY_GAS: u64 = 3_000;

/// Gas cost for P256 signature verification.
pub const P256_VERIFY_GAS: u64 = 8_000;

/// Gas cost for WebAuthn signature verification.
pub const WEBAUTHN_VERIFY_GAS: u64 = 8_000;

/// Gas cost for SLH-DSA-SHA2-128s signature verification, excluding its calldata.
///
/// [`P256_VERIFY_GAS`] scaled by the measured verification time of the SLH-DSA verifier relative
/// to the node's P256 verifier (433 µs against 39.8 µs, ratio 10.9), rounded up to a thousand.
pub const SLH_DSA_VERIFY_GAS: u64 = 87_000;

/// Base gas of one `KECCAK256`.
const KECCAK256_BASE_GAS: u64 = 30;

/// Gas per 32-byte word hashed by `KECCAK256`.
const KECCAK256_WORD_GAS: u64 = 6;

/// Gas for one `KECCAK256` over `len` bytes of input.
///
/// Returns `None` if the cost overflows `u64`.
pub fn keccak_gas(len: usize) -> Option<u64> {
    let num_words = u64::try_from(len.div_ceil(32)).ok()?;
    KECCAK256_WORD_GAS
        .checked_mul(num_words)?
        .checked_add(KECCAK256_BASE_GAS)
}
