use commonware_macros::test_traced;
use reth_ethereum::{rpc::types::engine::ForkchoiceState, storage::BlockReader as _};

use crate::ExecutionRuntime;

mod backfill;
mod dkg;
mod linkage;
mod restart;
mod subblocks;

#[test_traced]
fn spawning_execution_node_works() {
    //
    //
    // NOTE / DEBUG:
    //
    //
    // To debug the node instance running in tokio, it is useful to
    // isolate the tracing subscriber and install it globally (the
    // `test_traced` tests defined by commonware are thread-local
    //
    // #[test]
    // fn spawning_execution_node_works() {
    // let _telemetry = tracing_subscriber::fmt()
    //     .with_max_level(Level::DEBUG)
    //     .with_test_writer()
    //     .try_init();
    // <rest>

    let runtime = ExecutionRuntime::new();
    let handle = runtime.handle();

    futures::executor::block_on(async move {
        let node = handle
            .spawn_node("node-1")
            .await
            .expect("a running execution runtime must be able to spawn nodes");

        let block = node.node.provider.block_by_number(0).unwrap().unwrap();
        let hash = alloy_primitives::Sealable::hash_slow(&block.header);
        let forkchoice_state = ForkchoiceState {
            head_block_hash: hash,
            safe_block_hash: hash,
            finalized_block_hash: hash,
        };
        let updated = node
            .node
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(
                forkchoice_state,
                None,
                reth_node_builder::EngineApiMessageVersion::V3,
            )
            .await
            .expect("if the node runs it must be able to serve fork-choice updates");
        assert!(
            updated.is_valid(),
            "setting the forkchoice state to genesis should always work; response\n{updated:?}"
        );
    });

    runtime.stop().expect("runtime must stop");
}
