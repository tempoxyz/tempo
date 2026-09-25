//! A live validator network switches DKG transcripts only between ceremonies.

use std::time::{Duration, UNIX_EPOCH};

use commonware_codec::Read as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{self as dkg, Info, Logs, Reveal, SignedDealerLog},
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519::{Batch, PrivateKey, PublicKey},
};
use commonware_macros::test_traced;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use commonware_utils::{N3f1, NZU32, NZU64};
use futures::future::join_all;
use reth_ethereum::provider::BlockReader as _;

use super::super::common::read_outcome_from_validator;
use crate::{Setup, connect_execution_peers, metrics::wait_for_metrics, setup_validators};

#[test_traced]
fn validators_switch_dkg_reveal_version_at_t12() {
    let _ = tempo_eyre::install();
    const EPOCH_LENGTH: u64 = 20;
    const ACTIVATION: u64 = 1;

    // Genesis starts a V0 ceremony. All proposed blocks are at or after T12,
    // but V1 must wait for the next ceremony.
    let setup = Setup::new()
        .how_many_signers(4)
        .epoch_length(EPOCH_LENGTH)
        .t12_time(ACTIVATION);

    let cfg = Config::default()
        .with_seed(setup.seed)
        .with_start_time(UNIX_EPOCH + Duration::from_secs(ACTIVATION));

    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&validators).await;

        // Upon reaching Epoch 2, all validators must have agreed on the first boundary post-transition (Epoch 1 boundary)
        let epoch_strategy = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
        let target_height = epoch_strategy.first(Epoch::new(2)).unwrap();
        wait_for_metrics(&context, |metrics| {
            metrics.assert_no_dkg_failures();
            metrics.consensus_at_height(target_height.get()) == validators.len()
        })
        .await;

        let validator = &validators[0];
        let provider = validator.execution_provider();
        for epoch in [Epoch::zero(), Epoch::new(1)] {
            let boundary = epoch.previous().map_or(Height::zero(), |previous| {
                epoch_strategy.last(previous).unwrap()
            });

            let last = epoch_strategy.last(epoch).unwrap();
            let starting_header = provider
                .block_by_number(boundary.get())
                .unwrap()
                .unwrap()
                .header;
            assert_eq!(
                starting_header.inner.timestamp >= ACTIVATION,
                !epoch.is_zero()
            );

            let input = read_outcome_from_validator(validator, boundary).unwrap();
            let outcome = read_outcome_from_validator(validator, last).unwrap();
            assert_eq!(outcome.epoch, epoch.next().get());
            assert!(!input.is_next_full_dkg);

            let info = |reveal| {
                Info::<MinSig, PublicKey>::new::<N3f1>(
                    tempo_consensus::NAMESPACE,
                    epoch.get(),
                    Some(input.output.clone()),
                    Mode::NonZeroCounter,
                    reveal,
                    input.output.players().clone(),
                    input.next_players.clone(),
                )
                .unwrap()
            };

            #[expect(deprecated, reason = "verify the pre-T12 ceremony transcript")]
            let v0 = info(Reveal::V0);
            let v1 = info(Reveal::V1);
            let (selected, other) = if epoch.is_zero() {
                (&v0, &v1)
            } else {
                (&v1, &v0)
            };

            let mut logs = Logs::<MinSig, PublicKey, N3f1>::new(selected.clone());
            let mut log_count = 0;
            for height in boundary.next().get()..last.get() {
                let block = provider.block_by_number(height).unwrap().unwrap();
                assert!(block.header.inner.timestamp >= ACTIVATION);

                let extra_data = &block.header.inner.extra_data;
                if extra_data.is_empty() {
                    continue;
                }

                let signed = SignedDealerLog::<MinSig, PrivateKey>::read_cfg(
                    &mut extra_data.as_ref(),
                    &NZU32!(input.next_players.len() as u32),
                )
                .unwrap();
                assert!(
                    signed.clone().check(other).is_none(),
                    "dealer logs must reject the other reveal version"
                );

                let (dealer, log) = signed
                    .check(selected)
                    .expect("dealer log uses the expected reveal version");

                logs.record(dealer, log);
                log_count += 1;
            }
            assert!(
                log_count >= 3,
                "a four-validator ceremony needs a dealer quorum"
            );
            let observed =
                dkg::observe::<_, _, N3f1, Batch>(&mut context, logs, &Sequential).unwrap();
            assert_eq!(
                observed, outcome.output,
                "on-chain outcome must match the ceremony logs"
            );
            assert_ne!(
                outcome.output, input.output,
                "the ceremony must succeed rather than carry forward its input"
            );
        }
    });
}
