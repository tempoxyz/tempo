use commonware_consensus::types::Epoch;

/// Returns the first height of `epoch` given `heights_per_epoch`.
pub(crate) fn first_height(epoch: Epoch, heights_per_epoch: u64) -> u64 {
    epoch.saturating_mul(heights_per_epoch).saturating_add(1)
}

/// Returns the last height of `epoch` given `heights_per_epoch`.
pub(crate) fn last_height(epoch: Epoch, heights_per_epoch: u64) -> u64 {
    epoch.saturating_add(1).saturating_mul(heights_per_epoch)
}

/// Returns the parent height of `epoch` given `heights_per_epoch`.
pub(crate) fn parent_height(epoch: Epoch, heights_per_epoch: u64) -> u64 {
    let first_height_of_epoch = first_height(epoch, heights_per_epoch);
    first_height_of_epoch.saturating_sub(1)
}

/// Returns the epoch of `height` given `heights_per_epoch`.
///
/// Returns `None` if `height == 0` because it does not fall into any epoch.
pub(crate) fn of_height(height: u64, heights_per_epoch: u64) -> Option<Epoch> {
    (height != 0).then(|| height.saturating_sub(1).saturating_div(heights_per_epoch))
}

pub(crate) fn is_first_height(height: u64, epoch: Epoch, heights_per_epoch: u64) -> bool {
    height == first_height(epoch, heights_per_epoch)
}

/// Returns if the `height` falls inside `epoch`, given `heights_per_epoch`.
pub(crate) fn contains_height(height: u64, epoch: Epoch, heights_per_epoch: u64) -> bool {
    of_height(height, heights_per_epoch).is_some_and(|calc_epoch| calc_epoch == epoch)
}

pub(crate) fn is_last_height(height: u64, epoch: Epoch, heights_per_epoch: u64) -> bool {
    height == last_height(epoch, heights_per_epoch)
}

#[cfg(test)]
mod tests {
    use commonware_consensus::types::Epoch;

    use super::{contains_height, first_height, last_height, of_height, parent_height};

    #[track_caller]
    fn assert_first_height(expected: u64, epoch: Epoch, heights_per_epoch: u64) {
        assert_eq!(expected, first_height(epoch, heights_per_epoch));
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
    fn assert_last_height(expected: u64, epoch: Epoch, heights_per_epoch: u64) {
        assert_eq!(expected, last_height(epoch, heights_per_epoch));
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
    fn assert_source_height(expected: u64, epoch: Epoch, heights_per_epoch: u64) {
        assert_eq!(expected, parent_height(epoch, heights_per_epoch));
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
    fn assert_source_of_epoch_is_last_of_previous(epoch: Epoch, heights_per_epoch: u64) {
        assert_eq!(
            last_height(epoch, heights_per_epoch),
            parent_height(epoch + 1, heights_per_epoch),
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
    fn assert_height_of_epoch(expected: Epoch, height: u64, heights_per_epoch: u64) {
        assert_eq!(Some(expected), of_height(height, heights_per_epoch),)
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
    fn assert_height_in_epoch(height: u64, epoch: Epoch, heights_per_epoch: u64) {
        assert!(contains_height(height, epoch, heights_per_epoch));
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
}
