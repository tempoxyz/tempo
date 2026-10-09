use std::time::Duration;

use alloy::consensus::BlockHeader as _;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic, tokio as runtime};
use reth_db::Database as _;
use reth_ethereum::provider::{
    BlockNumReader as _, ChainStateBlockReader as _, DatabaseProviderFactory as _,
    RocksDBProviderFactory as _,
};
use tempo_node::rpc::consensus::{ConsensusFeed as _, Query};

use crate::{
    ExecutionNodeConfig, Setup, execution_runtime::test_db_args, metrics::wait_for_height,
    setup_validators,
};

#[test_traced]
fn historical_bootstrap_restores_certified_head_offline() {
    let _ = tempo_eyre::install();
    deterministic::Runner::default().start(|mut context| async move {
        let setup = Setup::new(crate::VERIFICATION_MODE)
            .how_many_signers(1)
            .epoch_length(100);
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;
        let reference = &mut validators[0];
        reference.start(&context).await;
        wait_for_height(&context, reference, 30).await;
        reference.stop_consensus().await;
        let floor = reference
            .feed_state
            .get_finalization(Query::Latest)
            .await
            .unwrap();
        let upstream = reference.execution().rpc_server_handle().ws_url().unwrap();
        let handle = execution_runtime.handle();
        let config = ExecutionNodeConfig::generate();
        let path = handle.nodes_dir().join("history").join("db");
        std::fs::create_dir_all(&path).unwrap();
        let database = reth_db::init_db(path, test_db_args())
            .unwrap()
            .with_metrics();
        let mut target = Some(
            handle
                .spawn_node("history", config.clone(), database.clone(), None)
                .await
                .unwrap(),
        );
        target
            .as_ref()
            .unwrap()
            .connect_peer(reference.execution_node.as_ref().unwrap())
            .await;
        let rocksdb = target.as_ref().unwrap().node.provider.rocksdb_provider();
        let storage = tempfile::tempdir().unwrap();

        for offline in [false, true] {
            let node = target.as_ref().unwrap().node.clone();
            let identity = reference.network_identity.clone();
            let url = if offline {
                "ws://127.0.0.1:0".to_owned()
            } else {
                upstream.clone()
            };
            let cfg = runtime::Config::default().with_storage_directory(storage.path());
            std::thread::spawn(move || {
                runtime::Runner::new(cfg).start(|context| async move {
                    tokio::time::timeout(
                        Duration::from_secs(60),
                        tempo_consensus::storage::bootstrap(
                            context,
                            Some(identity),
                            &node,
                            &url,
                            Duration::from_secs(5),
                        ),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                });
            })
            .join()
            .unwrap();

            let provider = &target.as_ref().unwrap().node.provider;
            let head = provider.canonical_in_memory_state().get_canonical_head();
            assert_eq!(
                (head.number(), head.hash()),
                (floor.block.number(), floor.digest)
            );
            let durable = provider.database_provider_ro().unwrap();
            assert!(
                durable.last_finalized_block_number().unwrap().unwrap()
                    <= durable.best_block_number().unwrap()
            );
            // This fixture stays below Reth's bulk-sync threshold, leaving a tail to recover.
            assert!(durable.best_block_number().unwrap() < floor.block.number());
            drop(durable);
            target.take().unwrap().shutdown().await;
            drop(database.tx_mut().unwrap());

            if !offline {
                reference.execution_node.take().unwrap().shutdown().await;
                target = Some(
                    handle
                        .spawn_node(
                            "history",
                            config.clone(),
                            database.clone(),
                            Some(rocksdb.clone()),
                        )
                        .await
                        .unwrap(),
                );
            }
        }
        execution_runtime.stop().unwrap();
    });
}
