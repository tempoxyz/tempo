use crate::{Setup, setup_validators};
use alloy::providers::{Provider, ProviderBuilder};
use commonware_p2p::simulated::Link;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use std::time::Duration;
use tokio::sync::{oneshot, oneshot::Sender};

enum Message {
    Stop(Sender<()>),
    Start(Sender<std::net::SocketAddr>),
}

/// Start node and verify RPC is accessible
async fn start_and_verify(tx_msg: &tokio::sync::mpsc::UnboundedSender<Message>) -> String {
    let (tx_rpc_addr, rx_rpc_addr) = oneshot::channel();
    let _ = tx_msg.send(Message::Start(tx_rpc_addr));
    let rpc_addr = rx_rpc_addr.await.unwrap();
    let rpc_url = format!("http://{rpc_addr}");

    // Verify RPC is accessible
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
    let block_number = provider.get_block_number().await;
    assert!(block_number.is_ok(), "RPC should be accessible after start");

    rpc_url
}

#[tokio::test]
async fn just_restart() {
    // Ensures that the node can be stopped completely and brought up inside a test.
    let _ = tempo_eyre::install();

    let runner = Runner::from(Config::default().with_seed(0));
    let (tx_msg, mut rx_msg) = tokio::sync::mpsc::unbounded_channel::<Message>();

    std::thread::spawn(move || {
        runner.start(|mut context| async move {
            let setup = Setup::new(crate::VERIFICATION_MODE)
                .how_many_signers(1)
                .linkage(Link {
                    latency: Duration::from_millis(10),
                    jitter: Duration::from_millis(1),
                    success_rate: commonware_utils::probability!(1.0),
                })
                .epoch_length(100);

            let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;

            let mut node = nodes.pop().unwrap();

            loop {
                match rx_msg.blocking_recv() {
                    Some(Message::Stop(tx_stopped)) => {
                        node.stop().await;
                        assert!(!node.is_running(), "node should not be running after stop");
                        assert!(
                            !node.is_consensus_running(),
                            "consensus should not be running after stop"
                        );
                        assert!(
                            !node.is_execution_running(),
                            "execution should not be running after stop"
                        );

                        let _ = tx_stopped.send(());
                    }
                    Some(Message::Start(tx_rpc_addr)) => {
                        node.start(&context).await;
                        assert!(node.is_running(), "node should be running after start");

                        // Get the RPC HTTP address while running
                        let rpc_addr = node
                            .execution()
                            .rpc_server_handles
                            .rpc
                            .http_local_addr()
                            .expect("http rpc server should be running");

                        let _ = tx_rpc_addr.send(rpc_addr);
                    }
                    None => {
                        break;
                    }
                }
            }
        });
    });

    // Start the node initially
    let rpc_url = start_and_verify(&tx_msg).await;

    // Signal to stop the node
    let (tx_stopped, rx_stopped) = oneshot::channel();
    let _ = tx_msg.send(Message::Stop(tx_stopped));
    rx_stopped.await.unwrap();

    // Verify RPC is no longer accessible after stopping
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
    let result =
        tokio::time::timeout(Duration::from_millis(500), provider.get_block_number()).await;
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "RPC should not be accessible after stopping"
    );

    // Start the node again
    start_and_verify(&tx_msg).await;
}
