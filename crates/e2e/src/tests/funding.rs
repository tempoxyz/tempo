//! Owner funding through signed RPC transactions and four-validator finalization.
use crate::{Setup, execution_runtime::TEST_MNEMONIC, setup_validators};
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;
use std::time::Duration;
#[path = "../../examples/support/funding.rs"]
mod demo;

#[test]
fn owner_funding_finalization_and_gas() {
    let _ = tempo_eyre::install();
    Runner::from(Config::default().with_seed(1120)).start(|mut context| async move {
        let (mut nodes, runtime) = setup_validators(
            &mut context,
            Setup::new()
                .how_many_signers(4)
                .epoch_length(1000)
                .seed(1120),
        )
        .await;
        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;
        let urls = nodes
            .iter()
            .map(|node| {
                node.execution()
                    .rpc_server_handle()
                    .http_url()
                    .unwrap()
                    .parse()
                    .unwrap()
            })
            .collect();
        runtime
            .run_async(async move {
                tokio::time::timeout(
                    Duration::from_secs(180),
                    demo::run_demo(
                        urls,
                        alloy::signers::local::MnemonicBuilder::from_phrase(TEST_MNEMONIC)
                            .build()
                            .unwrap(),
                    ),
                )
                .await
                .expect("funding network test timed out")
            })
            .await
            .unwrap()
            .unwrap();
    });
}
