//! Common helpers for DKG tests.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use alloy::consensus::BlockHeader as _;
use alloy_primitives::Sealable as _;
use commonware_codec::DecodeExt as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{Clock as _, deterministic::Context};
use commonware_utils::{NZU64, ordered};
use reth_chainspec::ChainSpecProvider as _;
use reth_ethereum::{
    evm::revm::{State, database::StateProviderDatabase},
    provider::{BlockReader as _, StateProviderFactory as _},
};
use reth_node_builder::ConfigureEvm as _;
use tempo_chainspec::{TempoHardfork, TempoHardforks as _};
use tempo_dkg_onchain_artifacts::{LegacyDkgConfig, OnchainDkgOutcome};
use tempo_precompiles::{
    storage::{StorageActions, StorageCtx},
    validator_config_v2::ValidatorConfigV2,
};

use crate::{TestingNode, metrics::wait_for_metrics};

/// Returns the target epoch to wait for depending on `event_height`.
///
/// TIP-1123 includes changes in the boundary itself in the following ceremony.
/// Legacy ceremonies only see the boundary's parent state.
pub(crate) fn target_epoch(epoch_length: u64, event_height: u64, fork: TempoHardfork) -> Epoch {
    let strat = FixedEpocher::new(NZU64!(epoch_length));
    let event_height = Height::new(event_height);
    let info = strat.containing(event_height).unwrap();
    if info.last() == event_height && !fork.is_tip1123() {
        info.epoch().next().next()
    } else {
        info.epoch().next()
    }
}

/// Reads the DKG outcome from a block, returns None if block doesn't exist or has no outcome.
pub(crate) fn read_outcome_from_validator(
    validator: &TestingNode<Context>,
    block_num: Height,
) -> Option<OnchainDkgOutcome> {
    let provider = validator.execution_provider();
    let block = provider.block_by_number(block_num.get()).ok()??;
    let extra_data = &block.header.inner.extra_data;

    if extra_data.is_empty() {
        return None;
    }

    Some(
        OnchainDkgOutcome::decode_boundary(
            extra_data.as_ref(),
            &provider
                .chain_spec()
                .tempo_hardfork_at(block.header.timestamp()),
        )
        .expect("valid DKG outcome"),
    )
}

#[test]
fn configuration_changes_in_boundary_apply_to_following_ceremony() {
    for (height, legacy_epoch, compact_epoch) in [(8, 1, 1), (9, 2, 1), (10, 2, 2), (19, 3, 2)] {
        assert_eq!(
            target_epoch(10, height, TempoHardfork::T13).get(),
            legacy_epoch
        );
        assert_eq!(
            target_epoch(10, height, TempoHardfork::Tip1123).get(),
            compact_epoch
        );
    }
}

/// Waits for and reads the DKG outcome from the last block of the given epoch.
pub(crate) async fn wait_for_outcome(
    context: &Context,
    validators: &[TestingNode<Context>],
    epoch: u64,
    epoch_length: u64,
) -> OnchainDkgOutcome {
    let height = FixedEpocher::new(NZU64!(epoch_length))
        .last(Epoch::new(epoch))
        .expect("valid epoch");

    tracing::info!(epoch, %height, "Waiting for DKG outcome");

    loop {
        context.sleep(Duration::from_secs(1)).await;

        if let Some(outcome) = read_outcome_from_validator(&validators[0], height) {
            tracing::info!(
                epoch,
                %height,
                outcome_epoch = %outcome.epoch,
                "Read DKG outcome"
            );
            return outcome;
        }
    }
}

/// Waits until at least `min_validators` have reached the target epoch.
pub(crate) async fn wait_for_validators_to_reach_epoch(
    context: &Context,
    target_epoch: u64,
    min_validators: u32,
) {
    tracing::info!(target_epoch, min_validators, "Waiting for epoch");

    wait_for_metrics(context, |metrics| {
        metrics.consensus_at_epoch(target_epoch) >= min_validators as usize
    })
    .await;

    tracing::info!(target_epoch, "Validators reached epoch");
}

/// Inspect the same finalized boundary post-state used to initialize this ceremony.
pub(crate) fn read_ceremony_configuration(
    validator: &TestingNode<Context>,
    outcome: &OnchainDkgOutcome,
) -> LegacyDkgConfig {
    if let Some(config) = &outcome.legacy_config {
        return config.clone();
    }
    let node = validator.execution();
    let epocher = FixedEpocher::new(node.provider.chain_spec().info.epoch_length().unwrap());
    let height = outcome
        .epoch()
        .previous()
        .map_or(0, |epoch| epocher.last(epoch).unwrap().get());
    let block = node.provider.block_by_number(height).unwrap().unwrap();
    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.provider
                .state_by_block_hash(block.header.hash_slow())
                .unwrap(),
        ))
        .build();
    let mut evm = node.evm_config.evm_for_block(db, &block.header).unwrap();
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        StorageActions::disabled(),
        || {
            let config = ValidatorConfigV2::default();
            let next_players = ordered::Set::from_iter_dedup(
                config
                    .get_active_validators()
                    .unwrap()
                    .into_iter()
                    .filter_map(|v| {
                        v.ingress.parse::<SocketAddr>().ok()?;
                        v.egress.parse::<IpAddr>().ok()?;
                        PublicKey::decode(v.publicKey.as_ref()).ok()
                    }),
            );
            LegacyDkgConfig {
                next_players,
                is_next_full_dkg: config.get_next_network_identity_rotation_epoch().unwrap()
                    == outcome.epoch,
            }
        },
    )
}
