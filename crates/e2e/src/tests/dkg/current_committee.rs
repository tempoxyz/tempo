//! Tests for the current committee precompile populated from DKG outcomes.

use alloy_primitives::{B256, U256, keccak256};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;
use reth_ethereum::provider::{StateProvider as _, StateProviderFactory as _};
use tempo_precompiles::current_committee::CURRENT_COMMITTEE_ADDRESS;

use super::common::{wait_for_outcome, wait_for_validators_to_reach_epoch};
use crate::{Setup, metrics::MetricsExt as _, setup_validators};

#[test_traced]
fn current_committee_matches_boundary_dkg_outcome() {
    let _ = tempo_eyre::install();

    let how_many_signers = 1;
    let epoch_length = 5;
    let setup = Setup::new()
        .how_many_signers(how_many_signers)
        .epoch_length(epoch_length);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let outcome = wait_for_outcome(&context, &validators, 0, epoch_length).await;
        wait_for_validators_to_reach_epoch(&context, outcome.epoch.get(), how_many_signers).await;
        context.to_metrics().assert_no_dkg_failures();

        let provider = validators[0].execution_provider();
        let state = provider.history_by_block_number(epoch_length - 1).unwrap();

        let epoch = state
            .storage(CURRENT_COMMITTEE_ADDRESS, U256::ZERO.into())
            .unwrap()
            .unwrap_or_default()
            .to::<u64>();
        let public_keys_len = state
            .storage(CURRENT_COMMITTEE_ADDRESS, U256::from(1).into())
            .unwrap()
            .unwrap_or_default()
            .to::<usize>();
        let public_keys_data_slot =
            U256::from_be_bytes(keccak256(U256::from(1).to_be_bytes::<32>()).0);
        let public_keys = (0..public_keys_len)
            .map(|index| {
                state
                    .storage(
                        CURRENT_COMMITTEE_ADDRESS,
                        (public_keys_data_slot + U256::from(index)).into(),
                    )
                    .unwrap()
                    .unwrap_or_default()
            })
            .map(|value| B256::from(value.to_be_bytes::<32>()))
            .collect::<Vec<_>>();
        let expected_public_keys = outcome
            .players()
            .iter()
            .map(|key| B256::from_slice(key.as_ref()))
            .collect::<Vec<_>>();

        assert_eq!(epoch, outcome.epoch.get());
        assert_eq!(public_keys, expected_public_keys);
    });
}
