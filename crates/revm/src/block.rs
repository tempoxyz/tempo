use alloy_evm::env::BlockEnvironment;
use alloy_primitives::{Address, B256, U256, uint};
use revm::{
    context::{Block, BlockEnv},
    context_interface::block::BlobExcessGasAndPrice,
};

/// Tempo block environment.
#[derive(Debug, Clone, Default, derive_more::Deref, derive_more::DerefMut)]
pub struct TempoBlockEnv {
    /// Inner [`BlockEnv`].
    #[deref]
    #[deref_mut]
    pub inner: BlockEnv,

    /// Milliseconds portion of the timestamp.
    pub timestamp_millis_part: u64,
}

impl TempoBlockEnv {
    /// Returns the current timestamp in milliseconds.
    pub fn timestamp_millis(&self) -> U256 {
        self.inner
            .timestamp
            .saturating_mul(uint!(1000_U256))
            .saturating_add(U256::from(self.timestamp_millis_part))
    }
}

impl Block for TempoBlockEnv {
    #[inline]
    fn number(&self) -> U256 {
        self.inner.number()
    }

    #[inline]
    fn beneficiary(&self) -> Address {
        self.inner.beneficiary()
    }

    #[inline]
    fn timestamp(&self) -> U256 {
        self.inner.timestamp()
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    #[inline]
    fn basefee(&self) -> u64 {
        self.inner.basefee()
    }

    #[inline]
    fn difficulty(&self) -> U256 {
        self.inner.difficulty()
    }

    #[inline]
    fn prevrandao(&self) -> Option<B256> {
        self.inner.prevrandao()
    }

    #[inline]
    fn blob_excess_gas_and_price(&self) -> Option<BlobExcessGasAndPrice> {
        self.inner.blob_excess_gas_and_price()
    }
}

impl BlockEnvironment for TempoBlockEnv {
    fn inner_mut(&mut self) -> &mut BlockEnv {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Helper to create a TempoBlockEnv with the given timestamp and millis_part.
    fn make_block_env(timestamp: U256, millis_part: u64) -> TempoBlockEnv {
        TempoBlockEnv {
            inner: BlockEnv {
                timestamp,
                ..Default::default()
            },
            timestamp_millis_part: millis_part,
        }
    }

    /// Strategy for random U256 values.
    fn arb_u256() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(U256::from_limbs)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Property: timestamp_millis never panics (uses saturating arithmetic)
        #[test]
        fn proptest_timestamp_millis_no_panic(
            timestamp in arb_u256(),
            millis_part in any::<u64>(),
        ) {
            let block = make_block_env(timestamp, millis_part);
            let _ = block.timestamp_millis();
        }

        /// Property: timestamp_millis >= timestamp * 1000 (saturation means >= not >)
        #[test]
        fn proptest_timestamp_millis_ge_scaled_timestamp(
            timestamp in arb_u256(),
            millis_part in any::<u64>(),
        ) {
            let block = make_block_env(timestamp, millis_part);
            let result = block.timestamp_millis();
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
            let block = make_block_env(U256::from(timestamp), millis_part);
            let expected = U256::from(timestamp) * uint!(1000_U256) + U256::from(millis_part);
            prop_assert_eq!(block.timestamp_millis(), expected);
        }

        /// Property: timestamp_millis is monotonic in both inputs
        #[test]
        fn proptest_timestamp_millis_monotonicity(
            ts1 in 0u64..u64::MAX / 1000,
            ts2 in 0u64..u64::MAX / 1000,
            mp1 in 0u64..1000,
            mp2 in 0u64..1000,
        ) {
            let block1 = make_block_env(U256::from(ts1), mp1);
            let block2 = make_block_env(U256::from(ts2), mp2);

            let result1 = block1.timestamp_millis();
            let result2 = block2.timestamp_millis();

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
            let block = make_block_env(U256::from(timestamp), millis_part);
            let result = block.timestamp_millis();
            let next_second = U256::from(timestamp + 1) * uint!(1000_U256);

            prop_assert!(result < next_second,
                "result ({}) should be < next_second ({})",
                result, next_second);
        }

        /// Property: millis_part >= 1000 overflows into subsequent seconds but uses saturating math
        ///
        /// When millis_part >= 1000, the result "overflows" into subsequent seconds conceptually.
        /// E.g., timestamp=5, millis_part=2500 -> result = 5*1000 + 2500 = 7500 (equivalent to 7.5 seconds)
        /// This is technically invalid input but the function handles it safely via saturating arithmetic.
        #[test]
        fn proptest_timestamp_millis_large_millis_part(
            timestamp in 0u64..u64::MAX / 1000,
            millis_part in 1000u64..u64::MAX,
        ) {
            let block = make_block_env(U256::from(timestamp), millis_part);
            let result = block.timestamp_millis();

            // Result should equal timestamp * 1000 + millis_part (saturating)
            let scaled = U256::from(timestamp).saturating_mul(uint!(1000_U256));
            let expected = scaled.saturating_add(U256::from(millis_part));

            prop_assert_eq!(result, expected,
                "timestamp={}, millis_part={}, result={}, expected={}",
                timestamp, millis_part, result, expected);
        }

        /// Property: when millis_part >= 1000, monotonicity can be violated
        ///
        /// This demonstrates that millis_part should be constrained to 0..1000 for correct
        /// time ordering semantics. A large millis_part can cause a "smaller" timestamp to
        /// have a larger result than a "larger" timestamp with small millis_part.
        #[test]
        fn proptest_timestamp_millis_large_millis_breaks_monotonicity(
            ts in 0u64..u64::MAX / 2000,
            large_mp in 1000u64..u64::MAX,
        ) {
            // Block with timestamp=ts and large millis_part
            let block1 = make_block_env(U256::from(ts), large_mp);
            // Block with timestamp=ts+1 and millis_part=0
            let block2 = make_block_env(U256::from(ts + 1), 0);

            let result1 = block1.timestamp_millis();
            let result2 = block2.timestamp_millis();

            // When large_mp >= 1000, result1 may exceed result2 even though ts < ts+1
            // This is expected behavior - millis_part is expected to be < 1000
            // Just verify no panics and results are computed correctly
            let expected1 = U256::from(ts).saturating_mul(uint!(1000_U256))
                .saturating_add(U256::from(large_mp));
            let expected2 = U256::from(ts + 1).saturating_mul(uint!(1000_U256));

            prop_assert_eq!(result1, expected1);
            prop_assert_eq!(result2, expected2);
        }
    }
}
