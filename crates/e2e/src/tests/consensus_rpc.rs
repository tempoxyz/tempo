//! Tests for the consensus RPC namespace.
//!
//! These tests verify that the consensus RPC endpoints work correctly,
//! including subscriptions and queries.

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use jsonrpsee::ws_client::WsClientBuilder;
use tempo_node::rpc::consensus::{Event, Query, TempoConsensusApiClient};

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

/// Test that subscribing to consensus events works and that finalization
/// can be queried via HTTP after receiving a finalization event.
#[test_traced]
fn consensus_subscribe_and_query_finalization() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(1).epoch_length(100);
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let (mut validators, _execution_runtime) = setup_validators(context.clone(), setup).await;
        validators[0].start().await;
        wait_for_height(&context, 3).await;

        // get the RPC addresses from execution node
        let execution = validators[0].execution();
        let http_addr = execution
            .rpc_server_handles
            .rpc
            .http_local_addr()
            .expect("http rpc server should be running");
        let ws_addr = execution
            .rpc_server_handles
            .rpc
            .ws_local_addr()
            .expect("ws rpc server should be running");

        // connect to WebSocket and subscribe to consensus events
        let ws_url = format!("ws://{ws_addr}");
        let ws_client = WsClientBuilder::default()
            .build(&ws_url)
            .await
            .expect("should connect to ws");

        let mut subscription = ws_client
            .subscribe_events()
            .await
            .expect("should subscribe to consensus events");

        // build HTTP client for queries
        let http_url = format!("http://{http_addr}");
        let http_client = jsonrpsee::http_client::HttpClientBuilder::default()
            .build(&http_url)
            .expect("should build http client");

        // track that we've seen both event types
        let mut saw_notarized = false;
        let mut saw_finalized = false;

        // wait for both notarized and finalized events
        while !saw_notarized || !saw_finalized {
            let event = tokio::time::timeout(Duration::from_secs(2), subscription.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();

            match event {
                Event::Notarized { .. } => {
                    saw_notarized = true;
                }
                Event::Finalized { block, .. } => {
                    let queried_block = http_client
                        .get_finalization(Query::Height(block.height))
                        .await
                        .unwrap()
                        .unwrap();

                    assert_eq!(queried_block, block);

                    saw_finalized = true;
                }
                Event::Nullified { .. } => {}
            }
        }

        let _latest_block = http_client
            .get_finalization(Query::Latest)
            .await
            .unwrap()
            .unwrap();

        let state = http_client
            .get_latest()
            .await
            .expect("should query consensus state");

        assert!(state.finalized.is_some());
    });
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
