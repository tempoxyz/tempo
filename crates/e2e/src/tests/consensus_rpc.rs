//! Tests for the consensus RPC namespace.
//!
//! These tests verify that the consensus RPC endpoints work correctly,
//! including subscriptions and queries.

use std::{net::SocketAddr, time::Duration};

use super::dkg::common::{assert_no_dkg_failures, wait_for_epoch, wait_for_outcome};
use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};
use alloy::transports::http::reqwest::Url;
use alloy_primitives::hex;
use commonware_codec::{Encode, ReadExt as _};
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{
    bls12381::primitives::{
        ops::verify_message,
        variant::{MinSig, Variant},
    },
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

/// Test that `get_identity_transition_proof` returns valid proofs after a full DKG ceremony.
///
/// This verifies:
/// 1. After a full DKG, the RPC returns a transition with different old/new public keys
/// 2. The transition epoch matches where the full DKG occurred
/// 3. The proof contains a valid header and certificate
#[test_traced]
fn get_identity_transition_proof_after_full_dkg() {
    let _ = tempo_eyre::install();

    let how_many_signers = 1;
    let epoch_length = 10;
    let full_dkg_epoch: u64 = 1;

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

        // Schedule full DKG for epoch 1
        execution_runtime
            .set_next_full_dkg_ceremony(http_url.clone(), full_dkg_epoch)
            .await
            .unwrap();

        // Wait for is_next_full_dkg flag
        let outcome_before =
            wait_for_outcome(&context, &validators, full_dkg_epoch - 1, epoch_length).await;
        assert!(
            outcome_before.is_next_full_dkg,
            "Epoch {} outcome should have is_next_full_dkg=true",
            full_dkg_epoch - 1
        );
        let pubkey_before = *outcome_before.sharing().public();

        // Wait for full DKG to complete
        wait_for_epoch(&context, full_dkg_epoch + 1, how_many_signers).await;
        assert_no_dkg_failures(&context);

        // Verify the full DKG created a new public key
        let outcome_after =
            wait_for_outcome(&context, &validators, full_dkg_epoch, epoch_length).await;
        let pubkey_after = *outcome_after.sharing().public();
        assert_ne!(
            pubkey_before, pubkey_after,
            "Full DKG must produce a DIFFERENT group public key"
        );

        // Test 1: Query from latest epoch (after full DKG) - should have transition
        // Run on execution runtime's tokio runtime since jsonrpsee requires tokio
        let http_url_str = http_url.to_string();
        let response = execution_runtime
            .run_async(async move {
                let http_client = HttpClientBuilder::default().build(&http_url_str).unwrap();
                http_client
                    .get_identity_transition_proof(None, Some(false))
                    .await
                    .unwrap()
            })
            .await
            .unwrap();

        assert!(
            !response.identity.is_empty(),
            "Identity should always be present"
        );
        assert_eq!(
            response.transitions.len(),
            1,
            "Expected exactly one transition"
        );

        let transition = &response.transitions[0];
        assert_eq!(
            transition.transition_epoch, full_dkg_epoch,
            "Transition epoch should match full DKG epoch"
        );
        assert_ne!(
            transition.old_identity, transition.new_identity,
            "Old and new public keys should be different"
        );
        assert_eq!(
            response.identity, transition.new_identity,
            "Identity should match the new public key from the latest transition"
        );

        // Decode and verify the BLS signature
        let old_pubkey_bytes = hex::decode(&transition.old_identity).unwrap();
        let old_pubkey = <MinSig as Variant>::Public::read(&mut old_pubkey_bytes.as_slice())
            .expect("valid BLS public key");
        let proof = transition
            .proof
            .as_ref()
            .expect("non-genesis transition should have proof");
        let finalization = Finalization::<Scheme<PublicKey, MinSig>, Digest>::read(
            &mut hex::decode(&proof.finalization_certificate)
                .unwrap()
                .as_slice(),
        )
        .expect("valid finalization");

        // Verify the certificate was signed by the old network identity
        let namespace = b"TEMPO_FINALIZE";
        let message = finalization.proposal.encode();
        verify_message::<MinSig>(
            &old_pubkey,
            namespace,
            &message,
            &finalization.certificate.vote_signature,
        )
        .expect("BLS signature verification failed");

        // Test 2: Query from epoch 0 (before full DKG) - should have identity but no transitions
        let old_identity = transition.old_identity.clone();
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
            !response_epoch0.identity.is_empty(),
            "Identity should be present even at epoch 0"
        );
        assert!(
            response_epoch0.transitions.is_empty(),
            "Should have no transitions when querying from epoch 0"
        );
        assert_eq!(
            response_epoch0.identity, old_identity,
            "Identity at epoch 0 should be the old public key (before full DKG)"
        );
    });
}
