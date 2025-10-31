//! Epoch logic used by tempo.
//!
//! All logic is written with the assumption that there are at least 3 heights
//! per epoch. Having less heights per epoch will not immediately break the
//! logic, but it might lead to strange behavior and is not supported.
//!
//! Note that either way, 3 blocks per epoch is a highly unreasonable number.

use commonware_consensus::types::Epoch;

pub(crate) mod manager;
mod scheme_provider;

pub(crate) use manager::ingress::{Enter, Exit};
pub(crate) use scheme_provider::SchemeProvider;

/// Returns the first height of `epoch` given `epoch_length`.
pub(crate) fn first_height(epoch: Epoch, epoch_length: u64) -> u64 {
    epoch.saturating_mul(epoch_length).saturating_add(1)
}

/// Returns the last height of `epoch` given `epoch_length`.
pub(crate) fn last_height(epoch: Epoch, epoch_length: u64) -> u64 {
    epoch.saturating_add(1).saturating_mul(epoch_length)
}

/// Returns the parent height of `epoch` given `epoch_length`.
pub(crate) fn parent_height(epoch: Epoch, epoch_length: u64) -> u64 {
    let first_height_of_epoch = first_height(epoch, epoch_length);
    first_height_of_epoch.saturating_sub(1)
}

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
/// epoch `E` if `(E*epoch_length)+1 <= h <= (E+1)*epoch_length`. For example,
/// for `epoch_length == 1000`, epoch `E=0` includes blocks 1 to 1000, epoch
/// `E=1` includes 1001 to 2000, and so on.
///
/// For epoch length 1000, we have the following cases:
///
/// 1. heights 1 to 500, 1001 to 1500, etc: first half.
/// 2. heights 501, 1501, etc: middle.
/// 3. heights 502 to 1000, 1502 to 2000, etc: second half.
///
/// # The special case `height == 0`
///
/// `height = 0` technically does not belong to any epoch, but in this
/// calculation we consider it to be in the second half of the epoch (because
/// depending on how one looks at it, it's always parent of the epoch = 0 and
/// hence the last height of epoch = -1).
///
/// # Panics
///
/// Panics if `epoch_length = 0`.
pub(crate) fn relative_position(height: u64, epoch_length: u64) -> RelativePosition {
    let mid_point = epoch_length / 2;

    // XXX: This is basically `(a+p-b)%p` like addition defined over a finite
    // field (just that we usually don't have a finite field):
    //
    // + b = 1 because height == (E+1)*epoch_length belongs is the last height
    //   in an epoch.
    // + % epoch_length because we need to map 0 to the last height.
    // + u64::rem_euclid because it's the same as `rem` or `%` for u64 but works
    // in postfix notation without importing a trait.
    let height_finite_field = height
        .saturating_add(epoch_length)
        .saturating_sub(1)
        .rem_euclid(epoch_length);

    match height_finite_field.cmp(&mid_point) {
        std::cmp::Ordering::Less => RelativePosition::FirstHalf,
        std::cmp::Ordering::Equal => RelativePosition::Middle,
        std::cmp::Ordering::Greater => RelativePosition::SecondHalf,
    }
}

/// Returns the epoch of `height` given `epoch_length`.
///
/// Returns `None` if `height == 0` because it does not fall into any epoch.
pub(crate) fn of_height(height: u64, epoch_length: u64) -> Option<Epoch> {
    (height != 0).then(|| height.saturating_sub(1).saturating_div(epoch_length))
}

/// Returns if `height % epoch_length == 1`.
pub(crate) fn is_first_height(height: u64, epoch_length: u64) -> bool {
    (height % epoch_length) == 1
}

/// Returns if the `height` falls inside `epoch`, given `epoch_length`.
pub(crate) fn contains_height(height: u64, epoch: Epoch, epoch_length: u64) -> bool {
    of_height(height, epoch_length).is_some_and(|calc_epoch| calc_epoch == epoch)
}

pub(crate) fn is_last_height(height: u64, epoch_length: u64) -> bool {
    height.is_multiple_of(epoch_length)
}

pub(crate) fn is_last_height_of_epoch(height: u64, epoch: Epoch, epoch_length: u64) -> bool {
    height == last_height(epoch, epoch_length)
}

#[cfg(test)]
mod tests {
    use commonware_consensus::types::Epoch;

    use crate::epoch::is_first_height;

    use super::{
        RelativePosition, contains_height, first_height, last_height, of_height, parent_height,
        relative_position,
    };

    #[test]
    fn are_first_heights() {
        assert!(is_first_height(1, 1000));
        assert!(is_first_height(1001, 1000));
        assert!(is_first_height(2001, 1000));

        assert!(!is_first_height(0, 1000));
        assert!(!is_first_height(1000, 1000));
        assert!(!is_first_height(2000, 1000));

        assert!(!is_first_height(999, 1000));
        assert!(!is_first_height(1999, 1000));
        assert!(!is_first_height(2999, 1000));
    }

    #[track_caller]
    fn assert_first_height(expected: u64, epoch: Epoch, epoch_length: u64) {
        assert_eq!(expected, first_height(epoch, epoch_length));
    }

    #[test]
    fn first_heights_are_correctly_calculated() {
        assert_first_height(1, 0, 10);
        assert_first_height(1, 0, 100);
        assert_first_height(1, 0, 1000);

        assert_first_height(11, 1, 10);
        assert_first_height(21, 2, 10);
        assert_first_height(31, 3, 10);

        assert_first_height(101, 1, 100);
        assert_first_height(201, 2, 100);
        assert_first_height(301, 3, 100);

        assert_first_height(1001, 1, 1000);
        assert_first_height(2001, 2, 1000);
        assert_first_height(3001, 3, 1000);
    }

    #[track_caller]
    fn assert_last_height(expected: u64, epoch: Epoch, epoch_length: u64) {
        assert_eq!(expected, last_height(epoch, epoch_length));
    }

    #[test]
    fn last_heights_are_correctly_calculated() {
        assert_last_height(10, 0, 10);
        assert_last_height(100, 0, 100);
        assert_last_height(1000, 0, 1000);

        assert_last_height(20, 1, 10);
        assert_last_height(30, 2, 10);
        assert_last_height(40, 3, 10);

        assert_last_height(200, 1, 100);
        assert_last_height(300, 2, 100);
        assert_last_height(400, 3, 100);

        assert_last_height(2000, 1, 1000);
        assert_last_height(3000, 2, 1000);
        assert_last_height(4000, 3, 1000);
    }

    #[track_caller]
    fn assert_source_height(expected: u64, epoch: Epoch, epoch_length: u64) {
        assert_eq!(expected, parent_height(epoch, epoch_length));
    }

    #[test]
    fn source_heights_are_correctly_calculated() {
        assert_source_height(0, 0, 10);
        assert_source_height(0, 0, 100);
        assert_source_height(0, 0, 1000);

        assert_source_height(10, 1, 10);
        assert_source_height(20, 2, 10);
        assert_source_height(30, 3, 10);

        assert_source_height(100, 1, 100);
        assert_source_height(200, 2, 100);
        assert_source_height(300, 3, 100);

        assert_source_height(1000, 1, 1000);
        assert_source_height(2000, 2, 1000);
        assert_source_height(3000, 3, 1000);
    }

    #[track_caller]
    fn assert_source_of_epoch_is_last_of_previous(epoch: Epoch, epoch_length: u64) {
        assert_eq!(
            last_height(epoch, epoch_length),
            parent_height(epoch + 1, epoch_length),
        );
    }

    #[test]
    fn source_heights_are_last_heights() {
        assert_source_of_epoch_is_last_of_previous(1, 10);
        assert_source_of_epoch_is_last_of_previous(2, 10);
        assert_source_of_epoch_is_last_of_previous(3, 10);

        assert_source_of_epoch_is_last_of_previous(1, 100);
        assert_source_of_epoch_is_last_of_previous(2, 100);
        assert_source_of_epoch_is_last_of_previous(3, 100);

        assert_source_of_epoch_is_last_of_previous(1, 1000);
        assert_source_of_epoch_is_last_of_previous(2, 1000);
        assert_source_of_epoch_is_last_of_previous(3, 1000);
    }

    #[track_caller]
    fn assert_height_of_epoch(expected: Epoch, height: u64, epoch_length: u64) {
        assert_eq!(Some(expected), of_height(height, epoch_length),)
    }

    #[test]
    fn height_epochs_are_correctly_calculated() {
        assert_eq!(None, of_height(0, 10), "height 0 has no epoch");
        assert_eq!(None, of_height(0, 100), "height 0 has no epoch");

        assert_height_of_epoch(0, 1, 10);
        assert_height_of_epoch(0, 1, 100);
        assert_height_of_epoch(0, 1, 1000);

        assert_height_of_epoch(0, 9, 10);
        assert_height_of_epoch(1, 19, 10);
        assert_height_of_epoch(2, 29, 10);

        assert_height_of_epoch(0, 99, 100);
        assert_height_of_epoch(1, 199, 100);
        assert_height_of_epoch(2, 299, 100);

        assert_height_of_epoch(0, 999, 1000);
        assert_height_of_epoch(1, 1999, 1000);
        assert_height_of_epoch(2, 2999, 1000);
    }

    #[track_caller]
    fn assert_height_in_epoch(height: u64, epoch: Epoch, epoch_length: u64) {
        assert!(contains_height(height, epoch, epoch_length));
    }

    #[test]
    fn height_falls_into_correct_epoch() {
        assert!(!contains_height(0, 0, 10), "height 0 is in no epoch");
        assert!(!contains_height(0, 0, 100), "height 0 is in no epoch");

        assert_height_in_epoch(1, 0, 10);
        assert_height_in_epoch(1, 0, 100);
        assert_height_in_epoch(1, 0, 1000);

        assert_height_in_epoch(9, 0, 10);
        assert_height_in_epoch(19, 1, 10);
        assert_height_in_epoch(29, 2, 10);

        assert_height_in_epoch(99, 0, 100);
        assert_height_in_epoch(199, 1, 100);
        assert_height_in_epoch(299, 2, 100);

        assert_height_in_epoch(999, 0, 1000);
        assert_height_in_epoch(1999, 1, 1000);
        assert_height_in_epoch(2999, 2, 1000);
    }

    #[track_caller]
    fn assert_relative_position(expected: RelativePosition, height: u64, epoch_length: u64) {
        assert_eq!(expected, relative_position(height, epoch_length),);
    }

    #[test]
    fn height_falls_into_correct_part_of_epoch() {
        use RelativePosition::*;

        assert_relative_position(SecondHalf, 0, 100);

        assert_relative_position(FirstHalf, 1, 100);
        assert_relative_position(FirstHalf, 50, 100);
        assert_relative_position(Middle, 51, 100);
        assert_relative_position(SecondHalf, 52, 100);
        assert_relative_position(SecondHalf, 100, 100);

        assert_relative_position(FirstHalf, 101, 100);
        assert_relative_position(FirstHalf, 150, 100);
        assert_relative_position(Middle, 151, 100);
        assert_relative_position(SecondHalf, 152, 100);
        assert_relative_position(SecondHalf, 200, 100);

        assert_relative_position(FirstHalf, 1, 99);
        assert_relative_position(FirstHalf, 49, 99);
        assert_relative_position(Middle, 50, 99);
        assert_relative_position(SecondHalf, 51, 99);
        assert_relative_position(SecondHalf, 99, 99);

        assert_relative_position(FirstHalf, 100, 99);
        assert_relative_position(FirstHalf, 148, 99);
        assert_relative_position(Middle, 149, 99);
        assert_relative_position(SecondHalf, 150, 99);
        assert_relative_position(SecondHalf, 198, 99);

        assert_relative_position(FirstHalf, 1, 199);
        assert_relative_position(FirstHalf, 99, 199);
        assert_relative_position(Middle, 100, 199);
        assert_relative_position(SecondHalf, 101, 199);
        assert_relative_position(SecondHalf, 199, 199);
    }
}
