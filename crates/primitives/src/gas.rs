//! Gas schedule of signature verification and keccak hashing.

/// Gas cost for secp256k1 signature verification.
pub const SECP256K1_VERIFY_GAS: u64 = 3_000;

/// Gas cost for P256 signature verification.
pub const P256_VERIFY_GAS: u64 = 8_000;

/// Gas cost for WebAuthn signature verification.
pub const WEBAUTHN_VERIFY_GAS: u64 = 8_000;

/// Gas per calldata token.
pub const CALLDATA_TOKEN_GAS: u64 = 4;

/// Base gas of one `KECCAK256`.
pub const KECCAK256_BASE_GAS: u64 = 30;

/// Gas per 32-byte word hashed by `KECCAK256`.
pub const KECCAK256_WORD_GAS: u64 = 6;

/// Istanbul calldata cost of `input`: one token per zero byte, four per nonzero byte.
pub fn calldata_gas(input: &[u8]) -> u64 {
    input
        .iter()
        .map(|byte| if *byte == 0 { 1 } else { 4 })
        .sum::<u64>()
        * CALLDATA_TOKEN_GAS
}

/// Gas for one `KECCAK256` over `len` bytes of input.
///
/// Returns `None` if the cost overflows `u64`.
pub fn keccak_gas(len: usize) -> Option<u64> {
    let num_words = u64::try_from(len.div_ceil(32)).ok()?;
    KECCAK256_WORD_GAS
        .checked_mul(num_words)?
        .checked_add(KECCAK256_BASE_GAS)
}
