//! Epoch logic used by tempo.
//!
//! All logic is written with the assumption that there are at least 3 heights
//! per epoch. Having less heights per epoch will not immediately break the
//! logic, but it might lead to strange behavior and is not supported.
//!
//! Note that either way, 3 blocks per epoch is a highly unreasonable number.

pub(crate) mod manager;
mod scheme_provider;

use commonware_consensus::types::Epoch;
pub(crate) use manager::ingress::{Enter, Exit};
pub(crate) use scheme_provider::SchemeProvider;

/// The relative position of in an epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelativePosition {
    FirstHalf,
    Middle,
    SecondHalf,
}

/// Returns the relative position of `height` in an epoch given `epoch_length`.
///
/// This function is written under the assumption that a height `h` belongs to
/// epoch `E` if `(E*epoch_length) <= h <= (E+1)*epoch_length-1`. For example,
/// for `epoch_length == 1000`, epoch `E=0` includes blocks 0 to 999, epoch
/// `E=1` includes 1000 to 1999, and so on.
///
/// For epoch length 1000, we have the following cases:
///
/// 1. heights 0 to 499, 1000 to 1499, etc: first half.
/// 2. heights 500, 1500, etc: middle.
/// 3. heights 501 to 999, 1501 to 1999, etc: second half.
///
/// # Panics
///
/// Panics if `epoch_length = 0`.
pub(crate) fn relative_position(height: u64, epoch_length: u64) -> RelativePosition {
    let mid_point = epoch_length / 2;

    let height_finite_field = height.rem_euclid(epoch_length);

    match height_finite_field.cmp(&mid_point) {
        std::cmp::Ordering::Less => RelativePosition::FirstHalf,
        std::cmp::Ordering::Equal => RelativePosition::Middle,
        std::cmp::Ordering::Greater => RelativePosition::SecondHalf,
    }
}

/// Returns `Some(epoch)` if `height` is the last block in an epoch of `epoch_length`.
///
/// # Panics
///
/// Panics if `epoch_length = 0` and `height = 0`.
pub(crate) fn is_first_block_in_epoch(epoch_length: u64, height: u64) -> Option<Epoch> {
    // NOTE: `commonware_consensus::utils::epoch` pancis on epoch_length = 0,
    // but `u64::is_multiple_of = true` only if both values are 0.
    height
        .is_multiple_of(epoch_length)
        .then(|| commonware_consensus::utils::epoch(epoch_length, height))
}

/// Returns the first block height for the given epoch.
///
/// Epoch length is defined in number of blocks. Panics if `epoch_length` is
/// zero or if overflow occurs.
#[inline]
pub(crate) fn first_block_in_epoch(epoch_length: u64, epoch: Epoch) -> u64 {
    assert!(epoch_length > 0);

    // epoch * epoch_length
    epoch.get().checked_mul(epoch_length).unwrap()
}

#[cfg(test)]
mod tests {
    use commonware_consensus::types::Epoch;

    use crate::epoch::{first_block_in_epoch, is_first_block_in_epoch};

    use super::{RelativePosition, relative_position};

    #[track_caller]
    fn assert_relative_position(expected: RelativePosition, height: u64, epoch_length: u64) {
        assert_eq!(expected, relative_position(height, epoch_length),);
    }

    #[test]
    fn height_falls_into_correct_part_of_epoch() {
        use RelativePosition::*;

        assert_relative_position(FirstHalf, 0, 100);
        assert_relative_position(FirstHalf, 1, 100);
        assert_relative_position(Middle, 50, 100);
        assert_relative_position(SecondHalf, 51, 100);
        assert_relative_position(SecondHalf, 99, 100);

        assert_relative_position(FirstHalf, 100, 100);
        assert_relative_position(FirstHalf, 101, 100);
        assert_relative_position(Middle, 150, 100);
        assert_relative_position(SecondHalf, 151, 100);
        assert_relative_position(SecondHalf, 199, 100);

        assert_relative_position(FirstHalf, 200, 100);

        assert_relative_position(FirstHalf, 0, 99);
        assert_relative_position(FirstHalf, 1, 99);
        assert_relative_position(Middle, 49, 99);
        assert_relative_position(SecondHalf, 50, 99);
        assert_relative_position(SecondHalf, 51, 99);
        assert_relative_position(SecondHalf, 98, 99);

        assert_relative_position(FirstHalf, 99, 99);
        assert_relative_position(FirstHalf, 100, 99);
        assert_relative_position(Middle, 148, 99);
        assert_relative_position(SecondHalf, 149, 99);
        assert_relative_position(SecondHalf, 197, 99);

        assert_relative_position(FirstHalf, 198, 99);

        assert_relative_position(FirstHalf, 9, 199);
        assert_relative_position(FirstHalf, 1, 199);
        assert_relative_position(Middle, 99, 199);
        assert_relative_position(SecondHalf, 100, 199);
        assert_relative_position(SecondHalf, 101, 199);
        assert_relative_position(SecondHalf, 198, 199);

        assert_relative_position(FirstHalf, 199, 199);
    }

    #[should_panic]
    #[test]
    fn is_first_block_in_epoch_panics_on_epoch_length_0_height_0() {
        is_first_block_in_epoch(0, 0);
    }

    #[test]
    fn is_first_block_in_epoch_identifies_first_block() {
        assert_eq!(is_first_block_in_epoch(10, 0), Some(Epoch::new(0)));
        assert_eq!(is_first_block_in_epoch(10, 10), Some(Epoch::new(1)));
        assert_eq!(is_first_block_in_epoch(10, 20), Some(Epoch::new(2)));
        assert_eq!(is_first_block_in_epoch(5, 215), Some(Epoch::new(43)));
    }

    #[test]
    fn is_first_block_in_epoch_returns_none_when_not_first_block() {
        assert_eq!(is_first_block_in_epoch(10, 1), None);
        assert_eq!(is_first_block_in_epoch(10, 9), None);
        assert_eq!(is_first_block_in_epoch(10, 18), None);
    }

    #[should_panic]
    #[test]
    fn first_block_in_epoch_panics_on_epoch_length_0() {
        first_block_in_epoch(0, Epoch::new(42));
    }

    #[test]
    fn first_block_in_epoch_identifies_first_block() {
        assert_eq!(first_block_in_epoch(10, Epoch::new(0)), 0);
        assert_eq!(first_block_in_epoch(10, Epoch::new(10)), 100);
        assert_eq!(first_block_in_epoch(10, Epoch::new(20)), 200);
        assert_eq!(first_block_in_epoch(5, Epoch::new(215)), 1075);
    }
}
