//! Private RPC over existing, read-only chain storage.
//!
//! This command is reusable by wrappers and development tools. It runs the binary's ordinary EVM
//! and RPC implementation without consensus, networking, or a transaction pool.

use alloy_primitives::U256;
use clap::Parser;
use eyre::{Context, ensure};
use reth_chainspec::EthChainSpec as _;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_ethereum::{
    network::api::noop::NoopNetwork,
    pool::noop::NoopTransactionPool,
    provider::{
        BlockHashReader as _,
        providers::{BlockchainProvider, RocksDBProvider},
    },
    rpc::{
        builder::{
            RethRpcModule, RpcModuleBuilder, RpcModuleConfig, RpcServerConfig, RpcServerHandle,
            TransportRpcModuleConfig,
        },
        eth::EthConfig,
    },
    tasks::Runtime,
};
use reth_rpc_eth_api::{
    RpcConverter,
    helpers::config::{EthConfigApiServer, EthConfigHandler},
};
use reth_rpc_server_types::constants::DEFAULT_HTTP_RPC_PORT;
use std::{net::SocketAddr, path::PathBuf};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_node::{
    TempoPooledTransaction,
    node::TempoNode,
    rpc::{
        TempoEthApi, TempoEthExt, TempoEthExtApiServer, TempoForkScheduleApiServer,
        TempoForkScheduleRpc, TempoReceiptConverter, TempoSimulate, TempoSimulateApiServer,
        TempoToken, TempoTokenApiServer, execution_info::install_execution_info,
    },
};
use tracing::info;

/// Private, read-only RPC server bound to loopback.
#[derive(Debug, Parser)]
pub struct RpcOnly {
    /// Existing chain storage and chain specification.
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,

    /// Loopback HTTP port. Zero selects an unused port.
    #[arg(long, alias = "http.port", default_value_t = DEFAULT_HTTP_RPC_PORT)]
    port: u16,

    /// Execution settings resolved from the parent node's existing RPC arguments.
    #[arg(long, hide = true)]
    rpc_config: Option<PathBuf>,
}

impl RpcOnly {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        let _worker = self.start(runtime).await?;
        std::future::pending().await
    }

    async fn start(self, runtime: Runtime) -> eyre::Result<RpcServerHandle> {
        let mut rpc_config: EthConfig = match &self.rpc_config {
            Some(path) => serde_json::from_slice(
                &std::fs::read(path)
                    .wrap_err_with(|| format!("reading private RPC config {}", path.display()))?,
            )
            .wrap_err_with(|| format!("invalid private RPC config {}", path.display()))?,
            None => EthConfig::default(),
        };
        // Match TempoEthApiBuilder's gas oracle configuration.
        rpc_config.gas_oracle.default_suggested_fee = Some(U256::ZERO);
        let chain_spec = self.env.chain.clone();
        let data_dir = self.env.datadir.clone().resolve_datadir(chain_spec.chain());
        // Reth's RO environment initializer creates a missing RocksDB directory. Reject missing
        // storage before calling it so rpc-only can never initialize a database as a side effect.
        ensure!(
            data_dir.db().is_dir(),
            "rpc-only requires an existing chain database"
        );
        ensure!(
            data_dir.static_files().is_dir(),
            "rpc-only requires existing static files"
        );
        ensure!(
            RocksDBProvider::exists(data_dir.rocksdb()),
            "rpc-only requires existing RocksDB storage; initialize it with the node first"
        );

        let Environment {
            provider_factory, ..
        } = self
            .env
            .init::<TempoNode>(AccessRights::RO, runtime.clone())?;
        // Environment::init(RO) does not enable the factory's on-demand synchronization.
        // Catch up RocksDB secondary state and static-file indexes after opening each MDBX
        // read transaction, so concurrent persistence cannot leave historical RPCs stale.
        let provider_factory = provider_factory.with_read_only_sync(false);

        let provider = BlockchainProvider::new(provider_factory)?;
        ensure!(
            provider.block_hash(0)? == Some(chain_spec.genesis_hash()),
            "rpc-only chain specification does not match the database genesis"
        );
        let evm = TempoEvmConfig::new(chain_spec.clone());
        let eth_config = EthConfigHandler::new(provider.clone(), evm.clone());
        let module_builder = RpcModuleBuilder::default()
            .with_provider(provider.clone())
            .with_pool(NoopTransactionPool::<TempoPooledTransaction>::new())
            .with_network(NoopNetwork::default().with_chain_id(chain_spec.chain_id()))
            .with_executor(runtime.clone())
            .with_evm_config(evm)
            .with_consensus(TempoConsensus::new(chain_spec.clone()));
        let eth_api = module_builder
            .eth_api_builder()
            // Keep this mapping aligned with the SDK's EthApiCtx::eth_api_builder. The
            // serialized EthConfig preserves ordinary node CLI options across workers.
            .task_spawner(runtime)
            .eth_state_cache_config(rpc_config.cache)
            .gas_cap(rpc_config.rpc_gas_cap.into())
            .max_simulate_blocks(rpc_config.rpc_max_simulate_blocks)
            .compute_state_root_for_eth_simulate(rpc_config.compute_state_root_for_eth_simulate)
            .eth_proof_window(rpc_config.eth_proof_window)
            .fee_history_cache_config(rpc_config.fee_history_cache)
            .proof_permits(rpc_config.proof_permits)
            .gas_oracle_config(rpc_config.gas_oracle)
            .max_batch_size(rpc_config.max_batch_size)
            .max_blocking_io_requests(rpc_config.max_blocking_io_requests)
            .pending_block_kind(rpc_config.pending_block_kind)
            .raw_tx_forwarder(rpc_config.raw_tx_forwarder.clone())
            .evm_memory_limit(rpc_config.rpc_evm_memory_limit)
            .force_blob_sidecar_upcasting(rpc_config.force_blob_sidecar_upcasting)
            .map_converter(|_| {
                RpcConverter::new(TempoReceiptConverter::new(chain_spec.clone())).erased()
            })
            .build();
        let eth_api = TempoEthApi::new(eth_api);

        let mut modules = module_builder.build(
            TransportRpcModuleConfig::default()
                .with_config(RpcModuleConfig::new(rpc_config))
                .with_http([
                    RethRpcModule::Eth,
                    RethRpcModule::Debug,
                    RethRpcModule::Trace,
                    RethRpcModule::Reth,
                    RethRpcModule::Ots,
                    RethRpcModule::Mev,
                ]),
            eth_api.clone(),
            Default::default(),
        );
        modules.merge_http(TempoToken::new(eth_api.clone()).into_rpc())?;
        modules.merge_http(TempoEthExt::new(eth_api.clone()).into_rpc())?;
        modules.merge_http(TempoSimulate::new(eth_api).into_rpc())?;
        modules.merge_http(TempoForkScheduleRpc::new(provider).into_rpc())?;
        modules.merge_http(eth_config.into_rpc())?;

        // Subscriptions and transaction submission require live node components. Do not advertise
        // or register these callbacks on the private read-only worker.
        modules.remove_http_methods([
            "eth_subscribe",
            "eth_unsubscribe",
            "eth_sendRawTransaction",
            "eth_sendRawTransactionSync",
            "eth_sendRawTransactionConditional",
            "eth_sendTransaction",
            "eth_sign",
            "eth_signTransaction",
            "eth_signTypedData",
            "debug_subscribe",
            "debug_unsubscribe",
            "debug_clearTxpool",
            "debug_chaindbCompact",
            "debug_setHead",
            "debug_setGCPercent",
            "debug_setTrieFlushInterval",
            "debug_standardTraceBadBlockToFile",
            "debug_standardTraceBlockToFile",
        ]);
        install_execution_info(
            &mut modules,
            chain_spec.chain_id(),
            chain_spec.genesis_hash(),
            true,
        )?;

        // This transport is private. The ordinary node's existing public servers enforce the
        // operator's request, response, and batch limits after routing; avoid imposing a second,
        // smaller default limit between the node and its worker.
        let handle = RpcServerConfig::http(
            jsonrpsee::server::ServerConfig::builder()
                .max_request_body_size(u32::MAX)
                .max_response_body_size(u32::MAX)
                .max_connections(u32::MAX),
        )
        .with_http_address(SocketAddr::from(([127, 0, 0, 1], self.port)))
        .start(&modules)
        .await?;
        info!(endpoint = ?handle.http_url(), "Serving private read-only RPC");
        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U64};
    use alloy_rpc_types_eth::TransactionRequest;
    use jsonrpsee::{core::client::ClientT, rpc_params};
    use serde_json::{Value, json};
    use tempo_metabinary::handshake::WorkerIdentity;
    use tempo_node::rpc::execution_info::{EXECUTION_INFO_METHOD, ExecutionInfo};

    fn command(datadir: &std::path::Path) -> RpcOnly {
        RpcOnly::parse_from([
            "rpc-only",
            "--chain=dev",
            "--port=0",
            "--datadir",
            datadir.to_str().unwrap(),
        ])
    }

    #[tokio::test]
    async fn missing_storage_is_rejected_without_creating_files() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("missing");
        assert!(command(&path).start(Runtime::test()).await.is_err());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn read_only_rpc_preserves_native_methods_config_and_shutdown() {
        let runtime = Runtime::test();
        let call = TransactionRequest::default()
            .to(Address::ZERO)
            .gas_limit(5_000_000)
            .gas_price(0)
            .input(vec![1; 100].into());
        // Separate DBs avoid reopening MDBX concurrently in this process.
        for gas_cap in [None, Some(21_000)] {
            let dir = tempfile::tempdir().unwrap();
            let mut cmd = command(dir.path());
            let chain = cmd.env.chain.clone();
            drop(
                cmd.env
                    .init::<TempoNode>(AccessRights::RW, runtime.clone())
                    .unwrap(),
            );
            let config = tempfile::NamedTempFile::new().unwrap();
            if let Some(cap) = gas_cap {
                serde_json::to_writer(config.as_file(), &EthConfig::default().rpc_gas_cap(cap))
                    .unwrap();
                cmd.rpc_config = Some(config.path().to_owned());
            }
            let worker = cmd.start(runtime.clone()).await.unwrap();
            let client = worker.http_client().unwrap();
            let result = client
                .request::<String, _>("eth_call", rpc_params![call.clone(), "0x0"])
                .await;
            if gas_cap.is_some() {
                let error = result.unwrap_err();
                assert!(
                    matches!(
                        error,
                        jsonrpsee::core::client::Error::Call(ref error)
                            if error.message().to_ascii_lowercase().contains("gas")
                    ),
                    "{error}"
                );
            } else {
                assert_eq!(result.unwrap(), "0x");
                let info: ExecutionInfo = client
                    .request(EXECUTION_INFO_METHOD, rpc_params![])
                    .await
                    .unwrap();
                info.validate(
                    WorkerIdentity {
                        chain_id: U64::from(chain.chain_id()),
                        genesis_hash: chain.genesis_hash(),
                        read_only: true,
                    },
                    std::process::id(),
                )
                .unwrap();
                for method in [
                    "eth_call",
                    "debug_traceCall",
                    "trace_block",
                    "tempo_simulateV1",
                ] {
                    assert!(
                        info.methods.iter().any(|name| name == method),
                        "missing {method}"
                    );
                }
                assert!(!info.methods.iter().any(|name| name.starts_with("eth_send")));
                assert_eq!(
                    client
                        .request::<String, _>("eth_blockNumber", rpc_params![])
                        .await
                        .unwrap(),
                    "0x0"
                );
                let trace: Value = client
                    .request(
                        "debug_traceCall",
                        rpc_params![call.clone(), "0x0", json!({"tracer":"callTracer"})],
                    )
                    .await
                    .unwrap();
                assert_eq!(trace["type"], "CALL");
                assert!(matches!(
                    client
                        .request::<Value, _>("eth_sendRawTransaction", rpc_params!["0x00"])
                        .await,
                    Err(jsonrpsee::core::client::Error::Call(error)) if error.code() == -32601
                ));
            }
            drop(worker);
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while client
                    .request::<String, _>("eth_blockNumber", rpc_params![])
                    .await
                    .is_ok()
                {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("dropping the RPC handle must stop the server");
        }
    }
}
