//! Tests for the consensus RPC namespace.
//!
//! These tests verify that the consensus RPC endpoints work correctly,
//! including subscriptions and queries.

use std::{net::SocketAddr, time::Duration};

use super::dkg::common::{assert_no_dkg_failures, wait_for_epoch, wait_for_outcome};
use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};
use alloy::transports::http::reqwest::Url;
use alloy_primitives::hex;
use commonware_codec::ReadExt as _;
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    ed25519::PublicKey,
};
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use futures::{channel::oneshot, future::join_all};
use jsonrpsee::{http_client::HttpClientBuilder, ws_client::WsClientBuilder};
use tempo_commonware_node::consensus::Digest;
use tempo_node::rpc::consensus::{Event, Query, TempoConsensusApiClient};

/// Test that subscribing to consensus events works and that finalization
/// can be queried via HTTP after receiving a finalization event.
#[tokio::test]
#[test_traced]
async fn consensus_subscribe_and_query_finalization() {
    let _ = tempo_eyre::install();

    let initial_height = 3;
    let setup = Setup::new().how_many_signers(1).epoch_length(100);
    let cfg = deterministic::Config::default().with_seed(setup.seed);

    let (addr_tx, addr_rx) = oneshot::channel::<(SocketAddr, SocketAddr)>();
    let (done_tx, done_rx) = oneshot::channel::<()>();

    let executor_handle = std::thread::spawn(move || {
        let executor = Runner::from(cfg);
        executor.start(|mut context| async move {
            let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
            validators[0].start(&context).await;
            wait_for_height(&context, initial_height).await;

            let execution = validators[0].execution();

            addr_tx
                .send((
                    execution.rpc_server_handles.rpc.http_local_addr().unwrap(),
                    execution.rpc_server_handles.rpc.ws_local_addr().unwrap(),
                ))
                .unwrap();

            let _ = done_rx.await;
        });
    });

    let (http_addr, ws_addr) = addr_rx.await.unwrap();
    let ws_url = format!("ws://{ws_addr}");
    let http_url = format!("http://{http_addr}");
    let ws_client = WsClientBuilder::default().build(&ws_url).await.unwrap();
    let mut subscription = ws_client.subscribe_events().await.unwrap();

    let http_client = HttpClientBuilder::default().build(&http_url).unwrap();

    let mut saw_notarized = false;
    let mut saw_finalized = false;
    let mut current_height = initial_height;

    while !saw_notarized || !saw_finalized {
        let event = tokio::time::timeout(Duration::from_secs(10), subscription.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        match event {
            Event::Notarized { .. } => {
                saw_notarized = true;
            }
            Event::Finalized { block, .. } => {
                let height = block.height.unwrap();
                assert!(
                    height > current_height,
                    "finalized height should be > {current_height}"
                );

                let queried_block = http_client
                    .get_finalization(Query::Height(height))
                    .await
                    .unwrap()
                    .unwrap();

                assert_eq!(queried_block, block);

                current_height = height;
                saw_finalized = true;
            }
            Event::Nullified { .. } => {}
        }
    }

    let _ = http_client
        .get_finalization(Query::Latest)
        .await
        .unwrap()
        .unwrap();

    let state = http_client.get_latest().await.unwrap();

    assert!(state.finalized.is_some());

    drop(done_tx);
    executor_handle.join().unwrap();
}

/// Wait for a validator to reach a target height by checking metrics.
async fn wait_for_height(context: &Context, target_height: u64) {
    loop {
        let metrics = context.encode();
        for line in metrics.lines() {
            if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                continue;
            }
            let mut parts = line.split_whitespace();
            let metric = parts.next().unwrap();
            let value = parts.next().unwrap();
            if metric.ends_with("_marshal_processed_height") {
                let height = value.parse::<u64>().unwrap();
                if height >= target_height {
                    return;
                }
            }
        }
        context.sleep(Duration::from_millis(100)).await;
    }
}

/// Test that `get_identity_transition_proof` returns valid proofs after two full DKG ceremonies.
///
/// This verifies:
/// 1. After two full DKGs, `full=true` returns both transitions plus genesis marker
/// 2. `full=false` returns only the most recent transition
/// 3. Transition epochs, identities, and proofs are correct
/// 4. Repeated calls return consistent results (cache correctness)
/// 5. Querying from epoch 0 returns no transitions
#[test_traced]
fn get_identity_transition_proof_after_full_dkg() {
    let _ = tempo_eyre::install();

    let how_many_signers = 1;
    let epoch_length = 10;
    let first_full_dkg_epoch: u64 = 1;
    let second_full_dkg_epoch: u64 = 3;

    let setup = Setup::new()
        .how_many_signers(how_many_signers)
        .epoch_length(epoch_length);

    let seed = setup.seed;
    let cfg = deterministic::Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // Get HTTP URL for RPC
        let http_url: Url = validators[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        // --- First full DKG ---
        execution_runtime
            .set_next_full_dkg_ceremony(http_url.clone(), first_full_dkg_epoch)
            .await
            .unwrap();

        let outcome_before = wait_for_outcome(
            &context,
            &validators,
            first_full_dkg_epoch - 1,
            epoch_length,
        )
        .await;
        assert!(
            outcome_before.is_next_full_dkg,
            "Epoch {} outcome should have is_next_full_dkg=true",
            first_full_dkg_epoch - 1
        );

        wait_for_epoch(&context, first_full_dkg_epoch + 1, how_many_signers).await;
        assert_no_dkg_failures(&context);

        let outcome_after_first =
            wait_for_outcome(&context, &validators, first_full_dkg_epoch, epoch_length).await;
        assert_ne!(
            outcome_before.sharing().public(),
            outcome_after_first.sharing().public(),
            "First full DKG must produce a different group public key"
        );

        // --- Second full DKG ---
        execution_runtime
            .set_next_full_dkg_ceremony(http_url.clone(), second_full_dkg_epoch)
            .await
            .unwrap();

        let outcome_before_second = wait_for_outcome(
            &context,
            &validators,
            second_full_dkg_epoch - 1,
            epoch_length,
        )
        .await;
        assert!(
            outcome_before_second.is_next_full_dkg,
            "Epoch {} outcome should have is_next_full_dkg=true",
            second_full_dkg_epoch - 1
        );

        wait_for_epoch(&context, second_full_dkg_epoch + 1, how_many_signers).await;
        assert_no_dkg_failures(&context);

        let outcome_after_second =
            wait_for_outcome(&context, &validators, second_full_dkg_epoch, epoch_length).await;
        assert_ne!(
            outcome_after_first.sharing().public(),
            outcome_after_second.sharing().public(),
            "Second full DKG must produce a different group public key"
        );

        // --- Test 1: full=false returns only the most recent transition ---
        let http_url_str = http_url.to_string();
        let response_partial = execution_runtime
            .run_async(async move {
                let http_client = HttpClientBuilder::default().build(&http_url_str).unwrap();
                http_client
                    .get_identity_transition_proof(None, Some(false))
                    .await
                    .unwrap()
            })
            .await
            .unwrap();

        assert_eq!(
            response_partial.transitions.len(),
            1,
            "full=false should return only the most recent transition"
        );
        assert_eq!(
            response_partial.transitions[0].transition_epoch, second_full_dkg_epoch,
            "Most recent transition should be from the second full DKG"
        );

        // --- Test 2: full=true returns both transitions plus genesis ---
        let http_url_str = http_url.to_string();
        let response_full = execution_runtime
            .run_async(async move {
                let http_client = HttpClientBuilder::default().build(&http_url_str).unwrap();
                http_client
                    .get_identity_transition_proof(None, Some(true))
                    .await
                    .unwrap()
            })
            .await
            .unwrap();

        assert_eq!(
            response_full.transitions.len(),
            3,
            "full=true should return 2 transitions + genesis marker"
        );

        // Transitions should be ordered newest to oldest
        assert_eq!(
            response_full.transitions[0].transition_epoch, second_full_dkg_epoch,
            "First transition should be from second full DKG"
        );
        assert_eq!(
            response_full.transitions[1].transition_epoch, first_full_dkg_epoch,
            "Second transition should be from first full DKG"
        );
        assert_eq!(
            response_full.transitions[2].transition_epoch, 0,
            "Third entry should be the genesis marker"
        );

        // Genesis marker should have no proof
        assert!(
            response_full.transitions[2].proof.is_none(),
            "Genesis marker should have no proof"
        );

        // Identity chain should be consistent
        assert_eq!(
            response_full.identity, response_full.transitions[0].new_identity,
            "Identity should match newest transition's new_identity"
        );
        assert_eq!(
            response_full.transitions[0].old_identity, response_full.transitions[1].new_identity,
            "Transition chain should be linked"
        );

        // Verify a BLS signature on the most recent transition
        let old_pubkey_bytes = hex::decode(&response_full.transitions[0].old_identity).unwrap();
        let old_pubkey = <MinSig as Variant>::Public::read(&mut old_pubkey_bytes.as_slice())
            .expect("valid BLS public key");
        let proof = response_full.transitions[0]
            .proof
            .as_ref()
            .expect("non-genesis transition should have proof");
        let finalization = Finalization::<Scheme<PublicKey, MinSig>, Digest>::read(
            &mut hex::decode(&proof.finalization_certificate)
                .unwrap()
                .as_slice(),
        )
        .expect("valid finalization");

        assert!(
            finalization.verify(
                &mut context,
                &Scheme::certificate_verifier(tempo_commonware_node::NAMESPACE, old_pubkey),
                &commonware_parallel::Sequential
            ),
            "BLS signature verification failed"
        );

        // --- Test 3: Repeated full=true call returns same result (cache correctness) ---
        let http_url_str = http_url.to_string();
        let response_cached = execution_runtime
            .run_async(async move {
                let http_client = HttpClientBuilder::default().build(&http_url_str).unwrap();
                http_client
                    .get_identity_transition_proof(None, Some(true))
                    .await
                    .unwrap()
            })
            .await
            .unwrap();

        assert_eq!(
            response_full.identity, response_cached.identity,
            "Cached response identity should match"
        );
        assert_eq!(
            response_full.transitions.len(),
            response_cached.transitions.len(),
            "Cached response should have same number of transitions"
        );

        // --- Test 4: Query from epoch 0 - no transitions ---
        let http_url_str = http_url.to_string();
        let response_epoch0 = execution_runtime
            .run_async(async move {
                let http_client = HttpClientBuilder::default().build(&http_url_str).unwrap();
                http_client
                    .get_identity_transition_proof(Some(0), Some(false))
                    .await
                    .unwrap()
            })
            .await
            .unwrap();

        assert!(
            response_epoch0.transitions.is_empty(),
            "Should have no transitions when querying from epoch 0"
        );
        assert_eq!(
            response_epoch0.identity, response_full.transitions[1].old_identity,
            "Identity at epoch 0 should be the original genesis key"
        );
    });
}
