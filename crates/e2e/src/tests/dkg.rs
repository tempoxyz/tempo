//! Tests on chain DKG and epoch transition

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{
    ExecutionRuntime, Setup, execution_runtime::validator, link_validators, run, setup_validators,
};

fn assert_static_transitions(how_many: u32, epoch_length: u64, transitions: u64) {
    let _ = tempo_eyre::install();
    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    let setup = Setup {
        how_many_signers: how_many,
        how_many_verifiers: 0,
        seed: 0,
        linkage,
        epoch_length,
        connect_execution_layer_nodes: false,
        allegretto_timestamp: None,
    };

    let mut epoch_reached = false;
    let mut dkg_successful = false;
    let _first = run(setup, move |metric, value| {
        if metric.ends_with("_dkg_manager_ceremony_failures_total") {
            let value = value.parse::<u64>().unwrap();
            assert!(value < 1);
        }

        if metric.ends_with("_epoch_manager_latest_epoch") {
            let value = value.parse::<u64>().unwrap();
            epoch_reached |= value >= transitions;
        }
        if metric.ends_with("_dkg_manager_ceremony_successes_total") {
            let value = value.parse::<u64>().unwrap();
            dkg_successful |= value >= transitions;
        }
        epoch_reached && dkg_successful
    });
}

#[test_traced]
fn two_validators_can_transition_once() {
    assert_static_transitions(2, 20, 1);
}

#[test_traced]
fn two_validators_can_transition_twice() {
    assert_static_transitions(2, 20, 2);
}

#[test_traced]
fn four_validators_can_transition_once() {
    assert_static_transitions(4, 20, 1);
}

#[test_traced]
fn four_validators_can_transition_twice() {
    assert_static_transitions(4, 20, 2);
}

#[test_traced]
fn validator_lost_key_but_gets_key_in_next_epoch() {
    let _ = tempo_eyre::install();

    let seed = 0;

    let cfg = Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let execution_runtime = ExecutionRuntime::new();

        let linkage = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };

        let epoch_length = 30;
        let setup = Setup {
            how_many_signers: 4,
            how_many_verifiers: 0,
            seed,
            linkage: linkage.clone(),
            epoch_length,
            connect_execution_layer_nodes: false,
            allegretto_timestamp: None,
        };

        let (mut nodes, mut oracle) =
            setup_validators(context.clone(), &execution_runtime, setup).await;
        let last_node = {
            let last_node = nodes
                .last_mut()
                .expect("we just asked for a couple of validators");
            last_node
                .consensus_config
                .share
                .take()
                .expect("the node must have had a share");
            last_node.uid.clone()
        };

        let running = join_all(nodes.into_iter().map(|node| node.start())).await;
        link_validators(&mut oracle, &running, linkage, None).await;

        let mut epoch_reached = false;
        let mut height_reached = false;
        let mut dkg_successful = false;

        let mut node_forgot_share = false;
        let mut node_is_not_signer = true;
        let mut node_got_new_share = false;

        let pat = format!("{}-", crate::CONSENSUS_NODE_PREFIX);

        let mut success = false;
        while !success {
            context.sleep(Duration::from_secs(1)).await;

            let metrics = context.encode();

            'metrics: for line in metrics.lines() {
                if !line.starts_with(&pat) {
                    continue 'metrics;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metrics.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    if value > 1 {
                        assert!(
                            node_forgot_share && node_got_new_share,
                            "reached 2nd epoch without recovering new share",
                        );
                    }
                }

                // Ensures that node has no share.
                if !node_forgot_share
                    && metric.ends_with(&format!(
                        "{last_node}_epoch_manager_how_often_verifier_total"
                    ))
                {
                    let value = value.parse::<u64>().unwrap();
                    node_forgot_share = value > 0;
                }

                // Double check that the node is indeed not a signer.
                if !node_is_not_signer
                    && metric
                        .ends_with(&format!("{last_node}_epoch_manager_how_often_signer_total"))
                {
                    let value = value.parse::<u64>().unwrap();
                    node_is_not_signer = value == 0;
                }

                // Ensure that the node gets a share by becoming a signer.
                if node_forgot_share
                    && node_is_not_signer
                    && !node_got_new_share
                    && metric
                        .ends_with(&format!("{last_node}_epoch_manager_how_often_signer_total"))
                {
                    let value = value.parse::<u64>().unwrap();
                    node_got_new_share = value > 0;
                }

                if metric.ends_with("_dkg_manager_ceremony_failures_total") {
                    let value = value.parse::<u64>().unwrap();
                    assert!(value < 1);
                }

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    epoch_reached |= value >= 1;
                }
                if metric.ends_with("_marshal_processed_height") {
                    let value = value.parse::<u64>().unwrap();
                    height_reached |= value >= epoch_length;
                }
                if metric.ends_with("_dkg_manager_ceremony_successes_total") {
                    let value = value.parse::<u64>().unwrap();
                    dkg_successful |= value >= 1;
                }
            }

            success = epoch_reached
                && height_reached
                && dkg_successful
                && node_forgot_share
                && node_got_new_share;
        }
    });
}

#[test_traced]
fn validator_is_added() {
    let _ = tempo_eyre::install();

    let seed = 0;

    let cfg = Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let execution_runtime = ExecutionRuntime::new();

        let linkage = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };

        let epoch_length = 30;
        let setup = Setup {
            how_many_signers: 3,
            how_many_verifiers: 1,
            seed,
            linkage: linkage.clone(),
            epoch_length,
            connect_execution_layer_nodes: false,
            allegretto_timestamp: None,
        };

        let (mut nodes, mut oracle) =
            setup_validators(context.clone(), &execution_runtime, setup).await;

        let new_node = {
            let idx = nodes
                .iter()
                .position(|node| node.consensus_config.share.is_none())
                .expect("at least one node must be a verifier, i.e. not have a share");
            nodes.remove(idx)
        };

        assert!(
            nodes
                .iter()
                .all(|node| node.consensus_config.share.is_some()),
            "must have removed the one non-signer node; must be left with only signers",
        );

        let mut running = join_all(nodes.into_iter().map(|node| node.start())).await;

        link_validators(&mut oracle, &running, linkage.clone(), None).await;

        // We will send an arbitrary node of the initial validator set the smart
        // contract call.
        let http_url = running[0]
            .execution_node
            .node
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        let receipt = execution_runtime
            .add_validator(
                http_url,
                validator(4),
                new_node.public_key.clone(),
                "127.0.0.1:4".parse::<SocketAddr>().unwrap(),
            )
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "addValidator call returned receipt"
        );

        // Now start the node and link it to the other validators. There will
        // duplicate linking, but that's ok.
        let new_node = new_node.start().await;
        running.push(new_node);
        link_validators(&mut oracle, &running, linkage, None).await;

        let pat = format!("{}-", crate::CONSENSUS_NODE_PREFIX);

        let mut success = false;

        let mut observed_3_dealers_4_players = false;
        while !success {
            context.sleep(Duration::from_secs(1)).await;

            let metrics = context.encode();

            
            // This exists to ensure that a single validator starts a ceremony
            // with 3 dealers and 4 players. We can't just check for `_ceremony_dealers`
            // and `_ceremony_players` without accounting for the validator uid, because
            // at the moment we read all metrics, there could be one validator that
            // has not yet started a new ceremony (so we read its old metrics), while
            // another validator has already started a new ceremony.
            #[derive(Default)]
            struct CeremonyParticipants {
                dealers: u64,
                players: u64,
            }
            #[derive(Default)]
            struct Observations(HashMap::<String, CeremonyParticipants>);
            impl Observations {
                fn observe(&mut self, metric: &str, value: &str) {
                    if let Some(metric) = metric.strip_suffix("_dkg_manager_ceremony_dealers") {
                        let value = value.parse::<u64>().unwrap();
                        self.0.entry(metric.to_string()).or_default().dealers = value;
                    }
                    if let Some(metric) = metric.strip_suffix("_dkg_manager_ceremony_players") {
                        let value = value.parse::<u64>().unwrap();
                        self.0.entry(metric.to_string()).or_default().players = value;
                    }
                }
                fn had_expected(&self) -> bool {
                    self.0.values().any(|participants| participants.dealers == 3 && participants.players == 4)
                }
            }

            let mut observations = Observations::default();
            
            'metrics: for line in metrics.lines() {
                if !line.starts_with(&pat) {
                    continue 'metrics;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metrics.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                observations.observe(metric, value);

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    assert!(value < 4, "the validator should have joined before epoch 4");
                }

                if metric.ends_with("_epoch_manager_latest_participants") {
                    let value = value.parse::<u64>().unwrap();
                    if value > 3 && observed_3_dealers_4_players {
                        success = true
                    } else if value > 3 {
                        panic!("got more than 3 participants, but never observed a ceremony with 3 dealers and 4 players");
                    }
                }
            }
            observed_3_dealers_4_players |= observations.had_expected();
        }
    });
}

#[test_traced]
fn validator_is_removed() {
    let _ = tempo_eyre::install();

    let seed = 0;

    let cfg = Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let execution_runtime = ExecutionRuntime::new();

        let linkage = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };

        let epoch_length = 30;
        let setup = Setup {
            how_many_signers: 4,
            how_many_verifiers: 0,
            seed,
            linkage: linkage.clone(),
            epoch_length,
            connect_execution_layer_nodes: false,
            allegretto_timestamp: None,
        };

        let (nodes, mut oracle) =
            setup_validators(context.clone(), &execution_runtime, setup).await;

        assert!(
            nodes
                .iter()
                .all(|node| node.consensus_config.share.is_some()),
            "all nodes must be signers",
        );

        let running = join_all(nodes.into_iter().map(|node| node.start())).await;

        link_validators(&mut oracle, &running, linkage.clone(), None).await;

        // We will send an arbitrary node of the initial validator set the smart
        // contract call.
        let http_url = running[0]
            .execution_node
            .node
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        let receipt = execution_runtime
            .change_validator_status(
                http_url,
                validator(3),
                false,
            )
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "chanegValiidatorStatus call returned receipt"
        );

        let pat = format!("{}-", crate::CONSENSUS_NODE_PREFIX);

        let mut success = false;

        let mut observed_4_dealers_3_players = false;
        while !success {
            context.sleep(Duration::from_secs(1)).await;

            let metrics = context.encode();

            
            // This exists to ensure that a single validator starts a ceremony
            // with 3 dealers and 4 players. We can't just check for `_ceremony_dealers`
            // and `_ceremony_players` without accounting for the validator uid, because
            // at the moment we read all metrics, there could be one validator that
            // has not yet started a new ceremony (so we read its old metrics), while
            // another validator has already started a new ceremony.
            #[derive(Default)]
            struct CeremonyParticipants {
                dealers: u64,
                players: u64,
            }
            #[derive(Default)]
            struct Observations(HashMap::<String, CeremonyParticipants>);
            impl Observations {
                fn observe(&mut self, metric: &str, value: &str) {
                    if let Some(metric) = metric.strip_suffix("_dkg_manager_ceremony_dealers") {
                        let value = value.parse::<u64>().unwrap();
                        self.0.entry(metric.to_string()).or_default().dealers = value;
                    }
                    if let Some(metric) = metric.strip_suffix("_dkg_manager_ceremony_players") {
                        let value = value.parse::<u64>().unwrap();
                        self.0.entry(metric.to_string()).or_default().players = value;
                    }
                }
                fn had_expected(&self) -> bool {
                    self.0.values().any(|participants| participants.dealers == 4 && participants.players == 3)
                }
            }

            let mut observations = Observations::default();
            
            'metrics: for line in metrics.lines() {
                if !line.starts_with(&pat) {
                    continue 'metrics;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metrics.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                observations.observe(metric, value);

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    assert!(value < 4, "the validator should have joined before epoch 4");
                }

                if metric.ends_with("_epoch_manager_latest_participants") {
                    let value = value.parse::<u64>().unwrap();
                    if value < 4 && observed_4_dealers_3_players {
                        success = true
                    } else if value < 4 {
                        panic!("got less than 4 participants, but never observed a ceremony with 4 dealers and 3 players");
                    }
                }
            }
            observed_4_dealers_3_players |= observations.had_expected();
        }
    });
}

// #[test_traced]
// fn transitions_with_fallible_links() {
//     let _ = tempo_eyre::install();
//     let linkage = Link {
//         latency: Duration::from_millis(10),
//         jitter: Duration::from_millis(1),
//         success_rate: 0.9,
//     };

//     let setup = Setup {
//         how_many: 5,
//         seed: 0,
//         linkage,
//         epoch_length: 2,
//     };

//     let mut epoch_reached = false;
//     let mut height_reached = false;
//     let _first = run(setup, move |metric, value| {
//         if metric.ends_with("_epoch_manager_latest_epoch") {
//             let value = value.parse::<u64>().unwrap();
//             epoch_reached |= value >= 3;
//         }
//         if metric.ends_with("_sync_processed_height") {
//             let value = value.parse::<u64>().unwrap();
//             height_reached |= value >= 6;
//         }
//         epoch_reached && height_reached
//     });
// }
