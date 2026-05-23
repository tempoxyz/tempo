use crate::ChainId;

/// Applies [EIP-155](https://eips.ethereum.org/EIPS/eip-155).
#[inline]
pub const fn to_eip155_v(v: u8, chain_id: ChainId) -> ChainId {
    (v as u64) + 35 + chain_id * 2
}

/// Attempts to normalize the v value to a boolean parity value.
///
/// Returns `None` if the value is invalid for any of the known Ethereum parity encodings.
#[inline]
pub const fn normalize_v(v: u64) -> Option<bool> {
    if !is_valid_v(v) {
        return None;
    }

    // Simplifying:
    //  0| 1 => v % 2 == 0
    // 27|28 => (v - 27) % 2 == 0
    //  35.. => (v - 35) % 2 == 0
    // ---
    //  0| 1 => v % 2 == 0
    // 27|28 => v % 2 == 1
    //  35.. => v % 2 == 1
    // ---
    //   ..2 => v % 2 == 0
    //     _ => v % 2 == 1
    let cmp = (v <= 1) as u64;
    Some(v % 2 == cmp)
}

/// Returns `true` if the given `v` value is valid for any of the known Ethereum parity encodings.
#[inline]
const fn is_valid_v(v: u64) -> bool {
    matches!(
        v,
        // Case 1: raw/bare
        0 | 1
        // Case 2: non-EIP-155 v value
        | 27 | 28
        // Case 3: EIP-155 V value
        | 35..
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn normalizes_v() {
        assert_eq!(normalize_v(0), Some(false));
        assert_eq!(normalize_v(1), Some(true));

        for invalid_v in 2..27 {
            assert_eq!(normalize_v(invalid_v), None);
        }

        assert_eq!(normalize_v(27), Some(false));
        assert_eq!(normalize_v(28), Some(true));

        for invalid_v in 29..35 {
            assert_eq!(normalize_v(invalid_v), None);
        }

        assert_eq!(normalize_v(35), Some(false));
        assert_eq!(normalize_v(36), Some(true));
        for v in 35..100 {
            assert_eq!(normalize_v(v), Some((v - 35) % 2 != 0));
        }
    }
}
