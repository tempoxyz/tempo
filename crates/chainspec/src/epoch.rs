/// Number of blocks in a production Tempo consensus epoch.
pub const EPOCH_LENGTH_BLOCKS: u64 = 21_600;

/// Returns the consensus epoch containing `block_number`.
pub const fn block_to_epoch(block_number: u64) -> u64 {
    block_number / EPOCH_LENGTH_BLOCKS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_to_epoch_uses_fixed_epoch_boundaries() {
        assert_eq!(block_to_epoch(0), 0);
        assert_eq!(block_to_epoch(EPOCH_LENGTH_BLOCKS - 1), 0);
        assert_eq!(block_to_epoch(EPOCH_LENGTH_BLOCKS), 1);
        assert_eq!(block_to_epoch((EPOCH_LENGTH_BLOCKS * 2) - 1), 1);
        assert_eq!(block_to_epoch(EPOCH_LENGTH_BLOCKS * 2), 2);
    }

    #[test]
    #[cfg(feature = "reth")]
    fn production_chainspecs_match_shared_epoch_length() {
        assert_eq!(
            crate::spec::PRESTO.info.epoch_length(),
            Some(EPOCH_LENGTH_BLOCKS)
        );
        assert_eq!(
            crate::spec::MODERATO.info.epoch_length(),
            Some(EPOCH_LENGTH_BLOCKS)
        );
    }
}
