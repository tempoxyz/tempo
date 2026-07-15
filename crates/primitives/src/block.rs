//! Tempo-specific EVM2 block environment fields.

use alloy_primitives::{U256, uint};
use core::num::NonZeroU64;

use crate::ed25519::PublicKey;

/// Tempo's complete EVM2 block environment.
pub type TempoBlockEnv = evm2::env::BlockEnvWithExt<TempoBlockExt>;

/// Tempo fields carried in EVM2's block environment extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TempoBlockExt {
    /// Milliseconds portion of the block timestamp.
    pub timestamp_millis_part: u64,
    /// Number of blocks in a consensus epoch.
    pub epoch_length: NonZeroU64,
    /// Proposer's Ed25519 public key. `Some` only for post-T4 blocks.
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
        height / self.epoch_length.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn block_ext(millis_part: u64) -> TempoBlockExt {
        TempoBlockExt {
            timestamp_millis_part: millis_part,
            ..Default::default()
        }
    }

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

        #[test]
        fn proptest_timestamp_millis_no_panic(
            timestamp in arb_u256(),
            millis_part in any::<u64>(),
        ) {
            let _ = block_ext(millis_part).timestamp_millis(timestamp);
        }

        #[test]
        fn proptest_timestamp_millis_ge_scaled_timestamp(
            timestamp in arb_u256(),
            millis_part in any::<u64>(),
        ) {
            let result = block_ext(millis_part).timestamp_millis(timestamp);
            let scaled = timestamp.saturating_mul(uint!(1000_U256));

            prop_assert!(result >= scaled,
                "timestamp_millis ({}) should be >= timestamp * 1000 ({})",
                result, scaled);
        }

        #[test]
        fn proptest_timestamp_millis_exact_for_small_values(
            timestamp in 0u64..u64::MAX / 1000,
            millis_part in 0u64..1000,
        ) {
            let expected = U256::from(timestamp) * uint!(1000_U256) + U256::from(millis_part);
            prop_assert_eq!(block_ext(millis_part).timestamp_millis(U256::from(timestamp)), expected);
        }

        #[test]
        fn proptest_timestamp_millis_monotonicity(
            ts1 in 0u64..u64::MAX / 1000,
            ts2 in 0u64..u64::MAX / 1000,
            mp1 in 0u64..1000,
            mp2 in 0u64..1000,
        ) {
            let result1 = block_ext(mp1).timestamp_millis(U256::from(ts1));
            let result2 = block_ext(mp2).timestamp_millis(U256::from(ts2));

            if ts1 < ts2 || (ts1 == ts2 && mp1 <= mp2) {
                prop_assert!(result1 <= result2,
                    "Monotonicity violated: ts1={}, mp1={}, result1={}, ts2={}, mp2={}, result2={}",
                    ts1, mp1, result1, ts2, mp2, result2);
            }
        }

        #[test]
        fn proptest_timestamp_millis_sub_second(
            timestamp in 0u64..u64::MAX / 1000,
            millis_part in 0u64..1000,
        ) {
            let result = block_ext(millis_part).timestamp_millis(U256::from(timestamp));
            let next_second = U256::from(timestamp + 1) * uint!(1000_U256);

            prop_assert!(result < next_second,
                "result ({}) should be < next_second ({})",
                result, next_second);
        }

        #[test]
        fn proptest_timestamp_millis_large_millis_part(
            timestamp in 0u64..u64::MAX / 1000,
            millis_part in 1000u64..u64::MAX,
        ) {
            let result = block_ext(millis_part).timestamp_millis(U256::from(timestamp));
            let scaled = U256::from(timestamp).saturating_mul(uint!(1000_U256));
            let expected = scaled.saturating_add(U256::from(millis_part));

            prop_assert_eq!(result, expected,
                "timestamp={}, millis_part={}, result={}, expected={}",
                timestamp, millis_part, result, expected);
        }

        #[test]
        fn proptest_timestamp_millis_large_millis_breaks_monotonicity(
            ts in 0u64..u64::MAX / 2000,
            large_mp in 1000u64..u64::MAX,
        ) {
            let result1 = block_ext(large_mp).timestamp_millis(U256::from(ts));
            let result2 = block_ext(0).timestamp_millis(U256::from(ts + 1));
            let expected1 = U256::from(ts).saturating_mul(uint!(1000_U256))
                .saturating_add(U256::from(large_mp));
            let expected2 = U256::from(ts + 1).saturating_mul(uint!(1000_U256));

            prop_assert_eq!(result1, expected1);
            prop_assert_eq!(result2, expected2);
        }
    }
}
