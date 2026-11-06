//! Restarting a chain that halted because an epoch lost its threshold signing key.

use std::{sync::Arc, time::Duration};

use alloy::consensus::BlockHeader as _;
use alloy_primitives::Address;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Context, Runner},
};
use futures::future::join_all;
use rand::SeedableRng as _;
use reth_ethereum::{
    chainspec::EthChainSpec as _,
    storage::{BlockHashReader as _, BlockIdReader as _, HeaderProvider as _},
};
use tempo_chainspec::spec::TempoChainSpec;

use crate::{
    Setup, TestingNode, connect_execution_peers,
    consensus_snapshot::write_consensus_snapshot,
    metrics::{wait_for_height, wait_for_metrics},
    setup_validators,
};

/// Every node loses its share in the middle of an epoch and the chain halts. A chainspec recovery
/// hands the next epoch to one member, whose ceremony reshares to everyone for the epoch after.
#[test_traced]
fn chain_restarts_after_epoch_lost_its_signing_key() {
    restart_after_epoch_lost_its_signing_key(None);
}

/// From T14 executors check that a block pays its proposer's fee recipient, fill blocks included.
#[test_traced]
fn chain_restarts_after_epoch_lost_its_signing_key_post_t14() {
    restart_after_epoch_lost_its_signing_key(Some(FEE_RECIPIENT));
}

const FEE_RECIPIENT: Address = Address::repeat_byte(0xFE);

/// Runs the recovery with T14 active from genesis and validators paying `t14_fee_recipient`, or
/// before T14 without one.
fn restart_after_epoch_lost_its_signing_key(t14_fee_recipient: Option<Address>) {
    let _ = tempo_eyre::install();

    let seed = 0;
    let epoch_length = 20;

    let executor = Runner::from(Config::default().with_seed(seed));
    executor.start(|mut context| async move {
        let mut setup = Setup::new(crate::VERIFICATION_MODE)
            .seed(seed)
            .epoch_length(epoch_length);
        if let Some(fee_recipient) = t14_fee_recipient {
            setup = setup.t14_time(0).fee_recipient(fee_recipient);
        }
        let (mut validators, execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;
        connect_execution_peers(&validators).await;

        let halt_after = epoch_length + epoch_length / 4;
        for validator in &validators {
            wait_for_height(&context, validator, halt_after).await;
        }

        // Stop early in an epoch, so the halt lands inside it even if a few more blocks finalize.
        loop {
            let height = validators[0]
                .execution_provider()
                .finalized_block_number()
                .unwrap()
                .unwrap_or_default();
            if (2..=6).contains(&(height % epoch_length)) {
                break;
            }
            context.sleep(Duration::from_millis(50)).await;
        }

        // Losing a quorum halts the chain; then every node goes down with its share.
        // Aborting consensus is immediate; shutting down execution nodes is not, and the chain
        // would keep finalizing meanwhile.
        join_all(validators[..2].iter_mut().map(|v| v.stop_consensus())).await;
        join_all(validators[..2].iter_mut().map(|v| v.stop_execution())).await;
        context.sleep(Duration::from_secs(5)).await;
        join_all(validators[2..].iter_mut().map(|v| v.stop())).await;

        // The first two lose their consensus state, and with it their shares, and come back from
        // a consensus snapshot. Without a quorum of
        // shares nobody can sign, so the chain stays halted while every node applies the
        // finalizations it holds and catches up to the others.
        for validator in &mut validators[..2] {
            let restored = format!("{}_restored", validator.partition_prefix);
            write_consensus_snapshot(
                &context,
                validator,
                validator.execution_provider_offline(),
                &restored,
            )
            .await;
            validator.partition_prefix = restored;
            validator.share = None;
        }
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;
        connect_execution_peers(&validators).await;
        let finalized_height = wait_for_settled_finalized_height(&context, &validators).await;
        join_all(validators.iter_mut().map(|v| v.stop())).await;

        let halted_epoch = finalized_height / epoch_length;
        let boundary = (halted_epoch + 1) * epoch_length - 1;
        assert!(
            finalized_height < boundary,
            "the chain must halt inside an epoch, but finalized boundary {finalized_height}",
        );

        let chain_spec = Arc::new(execution_runtime.chain_spec());
        let member = validators[0].public_key();
        let (recovery, share) = tempo_consensus::recovery::prepare(
            validators[0].execution_provider_offline(),
            &chain_spec,
            member,
            rand::rngs::StdRng::seed_from_u64(seed),
        )
        .expect("must be able to prepare the recovery");
        assert_eq!(recovery.finalized_height, finalized_height);

        // All nodes share the same recovery entry.
        let mut genesis = chain_spec.genesis().clone();
        genesis.config.extra_fields.insert(
            "recovery".to_string(),
            serde_json::to_value(&recovery).unwrap(),
        );
        let recovered_spec = TempoChainSpec::from_genesis(genesis);
        assert_eq!(recovered_spec.info.recovery(), Some(&recovery));
        assert_eq!(recovered_spec.genesis_hash(), chain_spec.genesis_hash());
        execution_runtime.set_chain_spec(recovered_spec);

        for validator in &mut validators {
            validator.share = None;
        }
        validators[0].share = Some(share);

        // A node that fills to the boundary and restarts before the recovery epoch certifies a
        // block must still start.
        validators[1].start(&context).await;
        context.sleep(Duration::from_secs(5)).await;
        validators[1].stop().await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;
        connect_execution_peers(&validators).await;

        // The next epoch runs on the member alone; its ceremony reshares to the full committee.
        let full_committee_epoch = halted_epoch + 2;
        wait_for_metrics(&context, |metrics| {
            metrics.assert_no_blocked_peers();
            validators.iter().all(|validator| {
                metrics
                    .for_scope(validator)
                    .latest_consensus_epoch()
                    .is_some_and(|epoch| epoch > full_committee_epoch)
            })
        })
        .await;

        for validator in &validators {
            assert_eq!(
                validator.execution_provider().block_hash(boundary).unwrap(),
                Some(recovery.boundary_hash),
                "{} must have the recovery boundary",
                validator.uid(),
            );
        }

        let provider = validators[0].execution_provider();
        for height in finalized_height + 1..=boundary {
            let header = provider
                .sealed_header(height)
                .unwrap()
                .unwrap_or_else(|| panic!("fill block {height} not found"));
            assert_eq!(
                header.beneficiary(),
                t14_fee_recipient.unwrap_or_default(),
                "fill block {height} must pay the proposer's fee recipient",
            );
        }
    });
}

/// Waits until every node reports the same finalized height for several seconds, and returns it.
async fn wait_for_settled_finalized_height(
    context: &Context,
    validators: &[TestingNode<Context>],
) -> u64 {
    let mut settled = None;
    let mut stable_for = 0;
    loop {
        context.sleep(Duration::from_secs(1)).await;
        let heights: Vec<_> = validators
            .iter()
            .map(|validator| {
                validator
                    .execution_provider()
                    .finalized_block_number()
                    .unwrap()
            })
            .collect();
        let agreed = heights
            .iter()
            .all(|height| *height == heights[0])
            .then_some(heights[0])
            .flatten();
        if agreed.is_some() && agreed == settled {
            stable_for += 1;
        } else {
            settled = agreed;
            stable_for = 0;
        }
        if stable_for >= 5 {
            return settled.unwrap();
        }
    }
}
