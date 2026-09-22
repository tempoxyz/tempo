//! Reviewed expectations registered at the fork introducing a feature.
//!
//! Checks receive one difference, not a transaction. `None` means unexplained and `Some(())`
//! accepts it.

use super::{AccountDelta, Field};
use crate::shadow_replay::{Boundary, Evidence};
use alloy_primitives::keccak256;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::{
    precompiles::zone_factory::{
        ZONE_MESSENGER_ADDRESS, ZONE_PORTAL_IMPL_ADDRESS, ZONE_VERIFIER_ADDRESS,
    },
    zones::{
        T13_ZONE_MESSENGER_RUNTIME, T13_ZONE_PORTAL_RUNTIME, T13_ZONE_VERIFIER_RUNTIME,
        ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME, ZONE_VERIFIER_RUNTIME,
    },
};

#[derive(Debug)]
pub(crate) struct Expectation {
    pub id: &'static str,
    pub check: fn(&Context<'_>, &Field) -> Option<()>,
}

pub(crate) struct Context<'a> {
    pub boundary: Boundary,
    pub real: &'a Evidence,
    pub shadow: &'a Evidence,
}

const T13_ZONE_RUNTIME_UPGRADE: Expectation = Expectation {
    id: "t13.zone-runtime-upgrade",
    check: |ctx, field| {
        if ctx.boundary != Boundary::PreBlock || field.name != "code" || field.slot.is_some() {
            return None;
        }
        let address = field.address?;
        let (old_runtime, new_runtime) = match address {
            ZONE_PORTAL_IMPL_ADDRESS => (ZONE_PORTAL_RUNTIME, T13_ZONE_PORTAL_RUNTIME),
            ZONE_VERIFIER_ADDRESS => (ZONE_VERIFIER_RUNTIME, T13_ZONE_VERIFIER_RUNTIME),
            ZONE_MESSENGER_ADDRESS => (ZONE_MESSENGER_RUNTIME, T13_ZONE_MESSENGER_RUNTIME),
            _ => return None,
        };
        let real = ctx.real.pre_block.as_ref()?;
        let shadow = ctx.shadow.pre_block.as_ref()?;
        let empty_hash = keccak256([]);

        // The canonical arm must not change code. The shadow arm must perform exactly the reviewed
        // T10-to-T13 upgrade. An empty prior hash is also valid when replay activates the T10
        // installation and T13 upgrade together at the same boundary.
        if AccountDelta(real.transitions.get(&address))
            .info(|info| info.code_hash)
            .is_some()
        {
            return None;
        }
        let transition = shadow.transitions.get(&address)?;
        let before = transition
            .previous_info
            .as_ref()
            .map_or(empty_hash, |info| info.code_hash);
        let after = transition.info.as_ref()?.code_hash;
        ((before == empty_hash || before == keccak256(&old_runtime))
            && after == keccak256(&new_runtime))
        .then_some(())
    },
};

/// Forks are ordered oldest-first; canonical features are excluded.
const REGISTRY: &[(TempoHardfork, &[Expectation])] =
    &[(TempoHardfork::T13, &[T13_ZONE_RUNTIME_UPGRADE])];

pub(crate) fn between(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> Vec<&'static Expectation> {
    select(REGISTRY, canonical, candidate)
}

fn select(
    registry: &'static [(TempoHardfork, &[Expectation])],
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> Vec<&'static Expectation> {
    registry
        .iter()
        .filter(|(fork, _)| *fork > canonical && *fork <= candidate)
        .flat_map(|(_, rules)| *rules)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_revm::{db::states::TransitionAccount, state::AccountInfo};

    #[test]
    fn accepts_exact_bytecode_upgrades() {
        let upgrades = [(
            &T13_ZONE_RUNTIME_UPGRADE,
            ZONE_VERIFIER_ADDRESS,
            keccak256([]),
            keccak256(&T13_ZONE_VERIFIER_RUNTIME),
        )];

        for (rule, address, before, after) in upgrades {
            let mut real = Evidence {
                pre_block: Some(Default::default()),
                ..Default::default()
            };
            real.pre_block.as_mut().unwrap().transitions.insert(
                address,
                TransitionAccount {
                    previous_info: Some(AccountInfo::default()),
                    info: Some(AccountInfo::default()),
                    ..Default::default()
                },
            );
            let mut shadow = Evidence {
                pre_block: Some(Default::default()),
                ..Default::default()
            };
            shadow.pre_block.as_mut().unwrap().transitions.insert(
                address,
                TransitionAccount {
                    previous_info: (before != keccak256([])).then_some(AccountInfo {
                        code_hash: before,
                        ..Default::default()
                    }),
                    info: Some(AccountInfo {
                        code_hash: after,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let ctx = Context {
                boundary: Boundary::PreBlock,
                real: &real,
                shadow: &shadow,
            };
            let field = Field {
                name: "code",
                address: Some(address),
                slot: None,
                fee_associated: false,
            };
            assert!((rule.check)(&ctx, &field,).is_some());
        }
    }

    #[test]
    fn selects_only_newly_active_forks() {
        use TempoHardfork::*;
        const T11_RULE: Expectation = Expectation {
            id: "t11",
            check: |_, _| None,
        };
        const SPARSE: &[(TempoHardfork, &[Expectation])] =
            &[(T11, &[T11_RULE]), (T13, &[T13_ZONE_RUNTIME_UPGRADE])];

        let ids = |a, b| {
            select(SPARSE, a, b)
                .into_iter()
                .map(|rule| rule.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(T10, T13), ["t11", T13_ZONE_RUNTIME_UPGRADE.id]);
        assert_eq!(ids(T12, T13), [T13_ZONE_RUNTIME_UPGRADE.id]);
        assert!(ids(T11, T12).is_empty());
        assert!(ids(T13, T13).is_empty());
        assert!(ids(T13, T12).is_empty());
    }
}
