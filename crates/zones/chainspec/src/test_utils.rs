//! Explicit Tempo fork schedules for tests, independent of dev genesis defaults.

use alloy_genesis::Genesis;
use tempo_chainspec::hardfork::TempoHardfork;

/// Activates earlier Tempo forks at genesis, schedules `fork`, and disables all later forks.
///
/// Later forks use explicit nulls so Zone parent-schedule inheritance cannot re-enable them.
/// Allocations and non-Tempo fork settings are preserved.
pub fn set_tempo_fork(genesis: &mut Genesis, fork: TempoHardfork, activation: u64) {
    for &candidate in TempoHardfork::VARIANTS {
        if candidate == TempoHardfork::Genesis {
            continue;
        }
        let value = if candidate < fork {
            serde_json::json!(0)
        } else if candidate == fork {
            serde_json::json!(activation)
        } else {
            serde_json::Value::Null
        };
        genesis.config.extra_fields.insert(
            format!("{}Time", candidate.to_string().to_lowercase()),
            value,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZoneChainSpec;
    use tempo_chainspec::{TempoChainSpec, TempoHardforks, spec::DEV};
    use zone_primitives::constants::zone_chain_id;

    #[test]
    fn explicit_schedule_survives_parent_inheritance() {
        for (before, after) in [
            (TempoHardfork::T12, TempoHardfork::T13),
            (TempoHardfork::T13, TempoHardfork::T14),
        ] {
            let mut genesis = DEV.inner.genesis.clone();
            genesis.config.chain_id = zone_chain_id(1_337, 1).unwrap();
            // Start with no Tempo overrides, so later forks would otherwise be inherited.
            for &fork in TempoHardfork::VARIANTS {
                genesis
                    .config
                    .extra_fields
                    .remove(&format!("{}Time", fork.to_string().to_lowercase()));
            }
            let alloc = genesis.alloc.clone();
            set_tempo_fork(&mut genesis, after, 1_000);
            assert_eq!(genesis.alloc, alloc);

            let tempo = TempoChainSpec::from_genesis(genesis.clone());
            let zone = ZoneChainSpec::from_genesis_with_l1(genesis, &DEV).unwrap();
            for (timestamp, expected) in [
                (0, before),
                (999, before),
                (1_000, after),
                (u64::MAX, after),
            ] {
                assert_eq!(tempo.tempo_hardfork_at(timestamp), expected);
                assert_eq!(zone.tempo_hardfork_at(timestamp), expected);
            }
        }
    }
}
