//! Common helpers for DKG tests.

use std::time::Duration;

use alloy_primitives::B256;
use commonware_codec::DecodeExt as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{Clock as _, deterministic::Context};
use commonware_utils::{NZU64, TryFromIterator as _, ordered};
use reth_ethereum::{
    evm::primitives::{ConfigureEvm as _, database::StateProviderDatabase},
    provider::{
        BlockReader as _, ChainSpecProvider as _, HeaderProvider as _, StateProvider,
        StateProviderFactory as _,
    },
};
use tempo_dkg_onchain_artifacts::{DkgCeremony, OnchainDkgOutcome};
use tempo_precompiles::{
    current_committee::{CurrentCommittee, ICurrentCommittee},
    error::TempoPrecompileError,
    storage::StorageCtx,
};

use crate::{TestingNode, metrics::wait_for_metrics};

/// Returns the target epoch to wait for depending on `event_height`.
///
/// If `event_height` is less than a boundary height, then the next epoch is
/// returned. Otherwise, the one *after* the next is returned.
pub(crate) fn target_epoch(epoch_length: u64, event_height: u64) -> Epoch {
    let strat = FixedEpocher::new(NZU64!(epoch_length));
    let event_height = Height::new(event_height);
    let info = strat.containing(event_height).unwrap();
    if info.last() == event_height {
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

    let encoding = provider
        .chain_spec()
        .dkg_outcome_encoding_at(block.header.inner.timestamp);
    Some(OnchainDkgOutcome::decode_extra_data(extra_data, encoding).expect("valid DKG outcome"))
}

/// Reads `getDkgCeremony()` of the `CurrentCommittee` precompile in the state after block
/// `block_num`.
pub(crate) fn read_stored_dkg_ceremony(
    validator: &TestingNode<Context>,
    block_num: Height,
) -> Result<ICurrentCommittee::getDkgCeremonyReturn, TempoPrecompileError> {
    let node = validator.execution();
    let header = node
        .provider
        .header_by_number(block_num.get())
        .unwrap()
        .expect("block exists");
    let state = node
        .provider
        .history_by_block_number(block_num.get())
        .unwrap();
    let mut evm = node
        .evm_config
        .evm_for_block(
            StateProviderDatabase::new(StateProvider::into_evm_state_provider(state)),
            &header,
        )
        .unwrap();
    StorageCtx::enter_evm(&mut evm, || CurrentCommittee::new().get_dkg_ceremony())
}

/// Reads the DKG ceremony running during the epoch of the outcome in boundary block `block_num`:
/// from the legacy outcome before TIP-1123, and from the `CurrentCommittee` precompile in the
/// boundary's state after.
pub(crate) fn read_ceremony_from_validator(
    validator: &TestingNode<Context>,
    block_num: Height,
) -> DkgCeremony {
    let outcome =
        read_outcome_from_validator(validator, block_num).expect("boundary has a DKG outcome");
    if let Some(ceremony) = outcome.next_ceremony {
        return ceremony;
    }
    let stored = read_stored_dkg_ceremony(validator, block_num).expect("ceremony is stored");
    assert_eq!(stored.epoch, outcome.epoch);
    assert_eq!(stored.dealers, public_keys(outcome.players()));
    DkgCeremony {
        players: ordered::Set::try_from_iter(
            stored
                .players
                .iter()
                .map(|key| PublicKey::decode(key.as_slice()).expect("valid player key")),
        )
        .expect("stored players are distinct"),
        is_full_dkg: stored.isRotatingNetworkIdentity,
    }
}

/// Returns `keys` as the `bytes32` keys the `CurrentCommittee` precompile stores.
pub(crate) fn public_keys(keys: &ordered::Set<PublicKey>) -> Vec<B256> {
    keys.iter()
        .map(|key| B256::from_slice(key.as_ref()))
        .collect()
}

/// Waits for the DKG outcome in the last block of `epoch` and returns the ceremony running during
/// the outcome's epoch, see [`read_ceremony_from_validator`].
pub(crate) async fn wait_for_ceremony(
    context: &Context,
    validators: &[TestingNode<Context>],
    epoch: u64,
    epoch_length: u64,
) -> DkgCeremony {
    wait_for_outcome(context, validators, epoch, epoch_length).await;
    let height = FixedEpocher::new(NZU64!(epoch_length))
        .last(Epoch::new(epoch))
        .expect("valid epoch");
    read_ceremony_from_validator(&validators[0], height)
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
                encoding = ?outcome.encoding(),
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
