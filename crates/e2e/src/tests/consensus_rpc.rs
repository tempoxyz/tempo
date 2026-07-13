//! Tests for the consensus RPC namespace.
//!
//! These tests verify that the consensus RPC endpoints work correctly,
//! including subscriptions and queries.

use std::{net::SocketAddr, time::Duration};

use crate::{Setup, metrics::wait_for_height, setup_validators};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{self, Runner},
};
use futures::channel::oneshot;
use jsonrpsee::{http_client::HttpClientBuilder, ws_client::WsClientBuilder};
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
            wait_for_height(&context, &validators[0], initial_height).await;

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
    let mut notarized_height = initial_height;
    let mut finalized_height = initial_height;

    while !saw_notarized || !saw_finalized {
        let event = tokio::time::timeout(Duration::from_secs(10), subscription.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        match event {
            Event::Notarized { block, .. } => {
                let height = block.block.inner.number;
                assert!(height > notarized_height);

                notarized_height = height;
                saw_notarized = true;
            }
            Event::Finalized { block, .. } => {
                let height = block.block.inner.number;
                assert!(height > finalized_height);

                let queried_block = http_client
                    .get_finalization(Query::Height(height))
                    .await
                    .unwrap();

                assert_eq!(queried_block, block);

                finalized_height = height;
                saw_finalized = true;
            }
            Event::Nullified { .. } => {}
        }
    }

    let _ = http_client.get_finalization(Query::Latest).await.unwrap();

    let state = http_client.get_latest().await.unwrap();

    assert!(state.finalized.is_some());

    drop(done_tx);
    executor_handle.join().unwrap();
}
