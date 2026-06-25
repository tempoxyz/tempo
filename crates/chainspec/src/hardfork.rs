//! Tempo-specific hardfork definitions and reth chainspec integration.

pub use tempo_hardfork::TempoHardfork;

/// Generates the Reth-backed Tempo hardfork query trait for all post-Genesis hardforks.
#[cfg(feature = "reth")]
macro_rules! tempo_hardforks_trait {
    ($($variant:ident),* $(,)?) => {
        /// Trait for querying Tempo-specific hardfork activations.
        pub trait TempoHardforks: reth_chainspec::EthereumHardforks {
            /// Retrieves activation condition for a Tempo-specific hardfork.
            fn tempo_fork_activation(&self, fork: TempoHardfork) -> reth_chainspec::ForkCondition;

            /// Retrieves the Tempo hardfork active at a given timestamp.
            fn tempo_hardfork_at(&self, timestamp: u64) -> TempoHardfork {
                for &fork in TempoHardfork::VARIANTS.iter().rev() {
                    if self
                        .tempo_fork_activation(fork)
                        .active_at_timestamp(timestamp)
                    {
                        return fork;
                    }
                }
                TempoHardfork::Genesis
            }

            paste::paste! {
                $(
                    #[doc = concat!("Returns true if ", stringify!($variant), " is active at the given timestamp.")]
                    fn [<is_ $variant:lower _active_at_timestamp>](&self, timestamp: u64) -> bool {
                        self.tempo_fork_activation(TempoHardfork::$variant)
                            .active_at_timestamp(timestamp)
                    }
                )*
            }

            /// Returns the shared gas limit for the given timestamp and block.
            /// - T4+: 0 gas
            /// - Pre-T4: block_gas_limit / 10
            fn shared_gas_limit_at(&self, timestamp: u64, gas_limit: u64) -> u64 {
                self.tempo_hardfork_at(timestamp)
                    .shared_gas_limit(gas_limit)
            }
        }
    };
}

#[cfg(feature = "reth")]
tempo_hardfork::tempo_post_genesis_hardforks!(tempo_hardforks_trait);
