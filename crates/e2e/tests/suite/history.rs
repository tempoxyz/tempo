use std::time::Duration;

use alloy::consensus::BlockHeader as _;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic, tokio as runtime};
use reth_db::Database as _;
use reth_ethereum::provider::{
    BlockNumReader as _, ChainStateBlockReader as _, DatabaseProviderFactory as _,
};
use tempo_node::rpc::consensus::{ConsensusFeed as _, Query};

use crate::{
    ExecutionNodeConfig, Setup, execution_runtime::test_db_args, metrics::wait_for_height,
    setup_validators,
};

#[test_traced]
fn historical_bootstrap_recovers_cached_tail_offline() {
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
        let storage = tempfile::tempdir().unwrap();

        for (name, offline) in [("history", false), ("history-replay", true)] {
            let database =
                reth_db::init_db(handle.nodes_dir().join(name).join("db"), test_db_args())
                    .unwrap()
                    .with_metrics();
            let target = handle
                .spawn_node(name, config.clone(), database.clone(), None)
                .await
                .unwrap();
            if !offline {
                target
                    .connect_peer(reference.execution_node.as_ref().unwrap())
                    .await;
            }
            let node = target.node.clone();
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

            let provider = &target.node.provider;
            let head = provider.canonical_in_memory_state().get_canonical_head();
            assert_eq!(
                (head.number(), head.hash()),
                (floor.block.number(), floor.digest)
            );
            let durable = provider.database_provider_ro().unwrap();
            let finish = durable.best_block_number().unwrap();
            assert!(durable.last_finalized_block_number().unwrap().unwrap() <= finish);
            if !offline {
                // A fresh genesis DB reproduces this state without Reth's shutdown flush.
                assert_eq!(finish, 0);
            }
            drop(durable);
            target.shutdown().await;
            drop(database.tx_mut().unwrap());

            if !offline {
                reference.execution_node.take().unwrap().shutdown().await;
            }
        }
        execution_runtime.stop().unwrap();
    });
}
