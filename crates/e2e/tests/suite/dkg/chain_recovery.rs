//! Restarting a chain that halted because an epoch lost its threshold signing key.

use std::{sync::Arc, time::Duration};

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;
use rand::SeedableRng as _;
use reth_ethereum::{
    chainspec::EthChainSpec as _,
    storage::{BlockHashReader as _, BlockIdReader as _, BlockNumReader as _},
};
use tempo_chainspec::spec::TempoChainSpec;

use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers,
    metrics::{wait_for_height, wait_for_metrics},
    setup_validators,
};

/// Every node loses its share in the middle of an epoch and the chain halts. A chainspec recovery
/// hands the next epoch to one member, whose ceremony reshares to everyone for the epoch after.
#[test_traced]
fn chain_restarts_after_epoch_lost_its_signing_key() {
    let _ = tempo_eyre::install();

    let seed = 0;
    let epoch_length = 20;

    let executor = Runner::from(Config::default().with_seed(seed));
    executor.start(|mut context| async move {
        let setup = Setup::new(crate::VERIFICATION_MODE)
            .seed(seed)
            .epoch_length(epoch_length);
        let (mut validators, execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;
        connect_execution_peers(&validators).await;

        let halt_after = epoch_length + epoch_length / 4;
        for validator in &validators {
            wait_for_height(&context, validator, halt_after).await;
        }

        // The lagger goes down first and misses the halt's last finalized block.
        let lagger = validators.len() - 1;
        validators[lagger].stop().await;
        let lagger_tip = validators[lagger]
            .execution_provider_offline()
            .best_block_number()
            .unwrap();
        wait_for_height(&context, &validators[0], lagger_tip + 3).await;

        // Losing a quorum halts the chain; then every node goes down with its share.
        for validator in &mut validators[..2] {
            validator.stop().await;
        }
        context.sleep(Duration::from_secs(5)).await;
        validators[2].stop().await;

        // The network's last finalized block is the highest any node finalized.
        let finalized_height = validators
            .iter()
            .map(|validator| {
                validator
                    .execution_provider_offline()
                    .finalized_block_number()
                    .unwrap()
                    .expect("every node finalized a block before the halt")
            })
            .max()
            .unwrap();

        assert!(
            lagger_tip < finalized_height,
            "the lagger must miss the last finalized block {finalized_height}, but has {lagger_tip}",
        );

        // Nodes that lagged at the halt sync up to it first: with the shares gone nobody signs,
        // so the chain stays halted while they catch up. The lagger stays down.
        for validator in &mut validators {
            validator.share = None;
        }
        let online = &mut validators[..lagger];
        join_all(online.iter_mut().map(|v| v.start(&context))).await;
        connect_execution_peers(online).await;
        while !online.iter().all(|validator| {
            validator
                .execution_provider()
                .finalized_block_number()
                .unwrap()
                .is_some_and(|finalized| finalized >= finalized_height)
        }) {
            context.sleep(Duration::from_secs(1)).await;
        }
        for validator in online {
            validator.stop().await;
        }

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

        validators[0].share = Some(share);

        join_all(validators[..lagger].iter_mut().map(|v| v.start(&context))).await;
        connect_execution_peers(&validators[..lagger]).await;

        // Without the last finalized block the lagger cannot fill; it syncs the boundary from
        // its execution peers instead.
        validators[lagger].start_execution().await;
        connect_execution_to_peers(&validators[lagger], &validators).await;
        validators[lagger].start_consensus(&context).await;

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
    });
}
