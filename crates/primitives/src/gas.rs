//! Gas schedule of signature verification and keccak hashing.

/// Gas cost for secp256k1 signature verification.
pub const SECP256K1_VERIFY_GAS: u64 = 3_000;

/// Gas cost for P256 signature verification.
pub const P256_VERIFY_GAS: u64 = 8_000;

/// Gas cost for WebAuthn signature verification.
pub const WEBAUTHN_VERIFY_GAS: u64 = 8_000;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_gas_empty_input() {
        // Empty input: 0 words, only base cost.
        assert_eq!(keccak_gas(0), Some(KECCAK256_BASE_GAS));
    }

    #[test]
    fn keccak_gas_single_byte() {
        // 1 byte rounds up to 1 word: 6 * 1 + 30 = 36.
        assert_eq!(keccak_gas(1), Some(36));
    }

    #[test]
    fn keccak_gas_exactly_one_word() {
        // 32 bytes = exactly 1 word: 6 * 1 + 30 = 36.
        assert_eq!(keccak_gas(32), Some(36));
    }

    #[test]
    fn keccak_gas_one_byte_over_word_boundary() {
        // 33 bytes rounds up to 2 words: 6 * 2 + 30 = 42.
        assert_eq!(keccak_gas(33), Some(42));
    }

    #[test]
    fn keccak_gas_word_boundary_scaling() {
        // Each additional 32-byte word adds KECCAK256_WORD_GAS.
        let one_word = keccak_gas(32).unwrap();
        let two_words = keccak_gas(64).unwrap();
        assert_eq!(two_words - one_word, KECCAK256_WORD_GAS);
    }

    #[test]
    fn keccak_gas_max_input_does_not_overflow() {
        // On 64-bit: ceil(usize::MAX / 32) = 576_460_752_303_423_488 words.
        // 6 * 576_460_752_303_423_488 + 30 = 3_458_764_513_820_540_958, which is
        // well within u64::MAX (18_446_744_073_709_551_615).
        assert!(keccak_gas(usize::MAX).is_some());
    }
}
