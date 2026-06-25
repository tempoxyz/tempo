//! Tempo-specific hardfork definitions and reth chainspec integration.

pub use tempo_hardfork::TempoHardfork;

/// Trait for querying Tempo-specific hardfork activations.
#[cfg(feature = "reth")]
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

    /// Returns true if T0 is active at the given timestamp.
    fn is_t0_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T0)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T1 is active at the given timestamp.
    fn is_t1_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T1)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T1A is active at the given timestamp.
    fn is_t1a_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T1A)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T1B is active at the given timestamp.
    fn is_t1b_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T1B)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T1C is active at the given timestamp.
    fn is_t1c_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T1C)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T2 is active at the given timestamp.
    fn is_t2_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T2)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T3 is active at the given timestamp.
    fn is_t3_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T3)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T4 is active at the given timestamp.
    fn is_t4_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T4)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T5 is active at the given timestamp.
    fn is_t5_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T5)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T6 is active at the given timestamp.
    fn is_t6_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T6)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T7 is active at the given timestamp.
    fn is_t7_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T7)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T8 is active at the given timestamp.
    fn is_t8_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T8)
            .active_at_timestamp(timestamp)
    }

    /// Returns the shared gas limit for the given timestamp and block.
    /// - T4+: 0 gas
    /// - Pre-T4: block_gas_limit / 10
    fn shared_gas_limit_at(&self, timestamp: u64, gas_limit: u64) -> u64 {
        self.tempo_hardfork_at(timestamp)
            .shared_gas_limit(gas_limit)
    }
}
