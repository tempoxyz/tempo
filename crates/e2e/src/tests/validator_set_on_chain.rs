//! Tests for validator set persistence on chain

use crate::{
    CONSENSUS_NODE_PREFIX, ExecutionRuntime, Setup, execution_runtime::validator, setup_validators,
};
use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
use reth_ethereum::storage::BlockReader as _;
use std::{net::SocketAddr, time::Duration};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_dkg_onchain_artifacts::PublicOutcome;

/// Test that new nodes can bootstrap peer connections from chain data.
///
/// After an epoch transition, decoding `PublicOutcome` from a block's extra_data
/// should provide validator inbound addresses for peer connections.
#[test_traced]
fn can_bootstrap_peer_addresses_from_chain() {
    let _ = tempo_eyre::install();

    let seed = 0;
    let cfg = Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let execution_runtime = ExecutionRuntime::new();

        let epoch_length = 20;
        let setup = Setup::new()
            .how_many_signers(3)
            .seed(seed)
            .epoch_length(epoch_length)
            .hardfork(TempoHardfork::Allegretto);

        let nodes = setup_validators(context.clone(), &execution_runtime, setup).await;
        let running = futures::future::join_all(nodes.into_iter().map(|node| node.start())).await;

        // Register all validators on the ValidatorConfig contract.
        // Post-allegretto reads validators from the contract, so we need to
        // register them before the first epoch transition.
        let http_url: Url = running[0]
            .execution_node
            .node
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        for (i, node) in running.iter().enumerate() {
            let addr: SocketAddr = format!("127.0.0.1:{}", i + 1).parse().unwrap();
            execution_runtime
                .add_validator(
                    http_url.clone(),
                    validator(i as u32),
                    node.public_key.clone(),
                    addr,
                )
                .await
                .expect("should register validator on contract");
        }

        let pat = format!("{CONSENSUS_NODE_PREFIX}-");

        // Wait until we've passed epoch boundary
        let mut epoch_reached = false;
        while !epoch_reached {
            context.sleep(Duration::from_secs(1)).await;

            let metrics = context.encode();
            for line in metrics.lines() {
                if !line.starts_with(&pat) {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    epoch_reached |= value >= 1;
                }
            }
        }

        // Read the epoch boundary block (last block of epoch 0)
        let exec_node = &running[0].execution_node;
        let epoch_boundary_block = exec_node
            .node
            .provider
            .block_by_number(epoch_length - 1)
            .expect("should query block")
            .expect("epoch boundary block should exist");

        let mut extra_data = epoch_boundary_block.header.inner.extra_data.as_ref();
        assert!(
            !extra_data.is_empty(),
            "epoch boundary block should have extra_data"
        );

        // Decode PublicOutcome and extract peer addresses for bootstrap
        let outcome = <PublicOutcome as alloy_rlp::Decodable>::decode(&mut extra_data)
            .expect("should decode PublicOutcome from extra_data");

        // Verify the outcome is for the correct epoch.
        // The epoch boundary block at height (epoch_length - 1) marks the end of epoch 0
        // and should contain the PublicOutcome for epoch 1 (the next epoch).
        assert_eq!(
            outcome.epoch,
            1,
            "epoch boundary block at height {} should contain outcome for epoch 1, not epoch 0",
            epoch_length - 1
        );

        // Verify the validator state structure is coherent
        let dealers = outcome.validator_state.dealers();
        let players = outcome.validator_state.players();
        let syncing_players = outcome.validator_state.syncing_players();

        assert!(
            !dealers.is_empty(),
            "dealers should not be empty in epoch 1 outcome"
        );
        assert!(
            !players.is_empty(),
            "players should not be empty in epoch 1 outcome"
        );
        assert!(
            !syncing_players.is_empty(),
            "syncing_players should not be empty in epoch 1 outcome"
        );

        // Get peer addresses from the validators in PublicOutcome
        let peer_addresses = outcome.validator_state.resolve_addresses_and_merge_peers();

        assert_eq!(peer_addresses.len(), 3, "should have 3 peer addresses");

        // Verify each validator has a valid inbound address
        for (pubkey, addr) in peer_addresses.iter_pairs() {
            assert!(!pubkey.to_string().is_empty(), "pubkey should not be empty");
            assert!(addr.port() > 0, "should have valid port for {pubkey}");
        }
    });
}
