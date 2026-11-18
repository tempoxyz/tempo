//! Tempo-specific EVM2 block environment fields.

use alloy_primitives::{U256, uint};
use core::num::NonZeroU64;

use crate::ed25519::PublicKey;

/// Tempo's complete EVM2 block environment.
pub type TempoBlockEnv = evm2::env::BlockEnvExt<TempoBlockExt>;

/// Tempo fields carried in EVM2's block environment extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TempoBlockExt {
    /// Milliseconds portion of the block timestamp.
    pub timestamp_millis_part: u64,
    /// Number of blocks in a consensus epoch.
    pub epoch_length: NonZeroU64,
    /// Proposer's Ed25519 public key, taken from the block's consensus context
    /// (`header.consensus_context` on import, the payload attributes' context
    /// when building).
    ///
    /// `Some` for post-T4 blocks that go through consensus, which rejects a
    /// block without a consensus context. `None` for pre-T4 blocks and for
    /// blocks executed outside consensus, such as simulated blocks
    /// (`eth_simulateV1`) and pending-block environments, which never carry a
    /// consensus context.
    ///
    /// Downstream, block execution relies on this: when it is `None`, the
    /// boundary block's DKG outcome check (`check_boundary_outcome` in
    /// `tempo-evm`) is skipped. That check only applies from T15 onwards, so
    /// in practice it is skipped only for blocks executed outside consensus.
    pub proposer_public_key: Option<PublicKey>,
}

impl Default for TempoBlockExt {
    fn default() -> Self {
        Self {
            timestamp_millis_part: 0,
            epoch_length: NonZeroU64::MIN,
            proposer_public_key: None,
        }
    }
}

impl TempoBlockExt {
    /// Returns the timestamp with the millisecond component applied.
    pub fn timestamp_millis(&self, timestamp: U256) -> U256 {
        timestamp
            .saturating_mul(uint!(1000_U256))
            .saturating_add(U256::from(self.timestamp_millis_part))
    }

    /// Returns the epoch containing `height`.
    pub fn epoch(&self, height: u64) -> u64 {
        height / self.epoch_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Helper to create a TempoBlockExt with the given millis_part.
    fn make_block_env(millis_part: u64) -> TempoBlockExt {
        TempoBlockExt {
            timestamp_millis_part: millis_part,
            ..Default::default()
        }
    }

    /// Strategy for random U256 values.
    fn arb_u256() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(U256::from_limbs)
    }

    #[test]
    fn epoch_uses_epoch_length() {
        let block = TempoBlockExt {
            epoch_length: NonZeroU64::new(10).unwrap(),
            ..Default::default()
        };

        assert_eq!(block.epoch(0), 0);
        assert_eq!(block.epoch(9), 0);
        assert_eq!(block.epoch(10), 1);
        assert_eq!(block.epoch(29), 2);
    }

    #[test]
    fn epoch_defaults_to_height_when_epoch_length_is_one() {
        let block = TempoBlockExt::default();

        assert_eq!(block.epoch(0), 0);
        assert_eq!(block.epoch(100), 100);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Property: timestamp_millis >= timestamp * 1000 (saturation means >= not >)
        #[test]
        fn proptest_timestamp_millis_ge_scaled_timestamp(
            timestamp in arb_u256(),
            millis_part in any::<u64>(),
        ) {
            let block = make_block_env(millis_part);
            let result = block.timestamp_millis(timestamp);
            let scaled = timestamp.saturating_mul(uint!(1000_U256));

            prop_assert!(result >= scaled,
                "timestamp_millis ({}) should be >= timestamp * 1000 ({})",
                result, scaled);
        }

        /// Property: for small timestamps, timestamp_millis == timestamp * 1000 + millis_part
        #[test]
        fn proptest_timestamp_millis_exact_for_small_values(
            timestamp in 0u64..u64::MAX / 1000,
            millis_part in 0u64..1000,
        ) {
            let expected = U256::from(timestamp) * uint!(1000_U256) + U256::from(millis_part);
            let block = make_block_env(millis_part);
            prop_assert_eq!(block.timestamp_millis(U256::from(timestamp)), expected);
        }

        /// Property: timestamp_millis is monotonic in both inputs
        #[test]
        fn proptest_timestamp_millis_monotonicity(
            ts1 in 0u64..u64::MAX / 1000,
            ts2 in 0u64..u64::MAX / 1000,
            mp1 in 0u64..1000,
            mp2 in 0u64..1000,
        ) {
            let block1 = make_block_env(mp1);
            let block2 = make_block_env(mp2);

            let result1 = block1.timestamp_millis(U256::from(ts1));
            let result2 = block2.timestamp_millis(U256::from(ts2));

            if ts1 < ts2 || (ts1 == ts2 && mp1 <= mp2) {
                prop_assert!(result1 <= result2,
                    "Monotonicity violated: ts1={}, mp1={}, result1={}, ts2={}, mp2={}, result2={}",
                    ts1, mp1, result1, ts2, mp2, result2);
            }
        }

        /// Property: millis_part < 1000 means it doesn't overflow into the next second
        #[test]
        fn proptest_timestamp_millis_sub_second(
            timestamp in 0u64..u64::MAX / 1000,
            millis_part in 0u64..1000,
        ) {
            let block = make_block_env(millis_part);
            let result = block.timestamp_millis(U256::from(timestamp));
            let next_second = U256::from(timestamp + 1) * uint!(1000_U256);

            prop_assert!(result < next_second,
                "result ({}) should be < next_second ({})",
                result, next_second);
        }
    }
}
