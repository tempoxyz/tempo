//! Private RPC over existing, read-only chain storage.
//!
//! This command is reusable by wrappers and development tools. It runs the binary's ordinary EVM
//! and RPC implementation without consensus, networking, or a transaction pool.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use alloy_primitives::U256;
use clap::Parser;
use eyre::{Context, ensure};
use reth_chainspec::EthChainSpec as _;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_ethereum::{
    network::api::noop::NoopNetwork,
    pool::noop::NoopTransactionPool,
    provider::{
        BlockHashReader as _, StaticFileProviderFactory as _,
        providers::{BlockchainProvider, RocksDBProvider},
    },
    rpc::{
        EthApiBuilder,
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
use tracing::{info, warn};

/// Private, read-only RPC server bound to loopback.
#[derive(Debug, Parser)]
pub struct RpcOnly {
    /// Existing chain storage and chain specification.
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,

    /// Loopback HTTP port. Zero selects an unused port.
    #[arg(long, alias = "http.port", default_value_t = 8545)]
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

    async fn start(self, runtime: Runtime) -> eyre::Result<RpcOnlyHandle> {
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
        let static_files = provider_factory.static_file_provider();

        let provider = BlockchainProvider::new(provider_factory)?;
        ensure!(
            provider.block_hash(0)? == Some(chain_spec.genesis_hash()),
            "rpc-only chain specification does not match the database genesis"
        );
        let evm = TempoEvmConfig::new(chain_spec.clone());
        let pool = NoopTransactionPool::<TempoPooledTransaction>::new();
        let network = NoopNetwork::default().with_chain_id(chain_spec.chain_id());
        let eth_api =
            EthApiBuilder::new(provider.clone(), pool.clone(), network.clone(), evm.clone())
                // Keep this mapping aligned with the SDK's EthApiCtx::eth_api_builder. The
                // serialized EthConfig preserves ordinary node CLI options across workers.
                .task_spawner(runtime.clone())
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
        let eth_config = EthConfigHandler::new(provider.clone(), evm.clone());

        let mut modules = RpcModuleBuilder::default()
            .with_provider(provider.clone())
            .with_pool(pool)
            .with_network(network)
            .with_executor(runtime)
            .with_evm_config(evm)
            .with_consensus(TempoConsensus::new(chain_spec.clone()))
            .build(
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
        for method in [
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
        ] {
            modules.remove_http_method(method);
        }
        install_execution_info(
            &mut modules,
            chain_spec.chain_id(),
            chain_spec.genesis_hash(),
            true,
        )?;

        let address = SocketAddr::from(([127, 0, 0, 1], self.port));
        // This transport is private. The ordinary node's existing public servers enforce the
        // operator's request, response, and batch limits after routing; avoid imposing a second,
        // smaller default limit between the node and its worker.
        let handle = RpcServerConfig::http(
            jsonrpsee::server::ServerConfig::builder()
                .max_request_body_size(u32::MAX)
                .max_response_body_size(u32::MAX)
                .max_connections(u32::MAX),
        )
        .with_http_address(address)
        .start(&modules)
        .await?;
        info!(endpoint = ?handle.http_url(), "Serving private read-only RPC");
        let refresh = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                if let Err(err) = static_files.initialize_index() {
                    warn!(%err, "Failed refreshing read-only static-file index");
                }
            }
        });
        Ok(RpcOnlyHandle {
            server: Some(handle),
            refresh,
        })
    }
}

struct RpcOnlyHandle {
    server: Option<RpcServerHandle>,
    refresh: tokio::task::JoinHandle<()>,
}

impl Drop for RpcOnlyHandle {
    fn drop(&mut self) {
        self.refresh.abort();
        if let Some(server) = self.server.take() {
            let _ = server.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::{core::client::ClientT, rpc_params};
    use tempo_node::rpc::execution_info::{EXECUTION_INFO_METHOD, ExecutionInfo};

    fn command(datadir: &std::path::Path) -> RpcOnly {
        RpcOnly::parse_from([
            "rpc-only",
            "--chain",
            "dev",
            "--datadir",
            datadir.to_str().unwrap(),
            "--port",
            "0",
        ])
    }

    #[tokio::test]
    async fn missing_storage_is_rejected_without_creating_files() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("missing");
        let result = command(&path).start(Runtime::test()).await;
        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn serves_initialized_database_without_live_node_components() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Runtime::test();
        let cmd = command(dir.path());
        let chain_id = cmd.env.chain.chain_id();
        let genesis_hash = cmd.env.chain.genesis_hash();
        let environment = cmd
            .env
            .init::<TempoNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        drop(environment);

        let worker = cmd.start(runtime).await.unwrap();
        let client = worker.server.as_ref().unwrap().http_client().unwrap();
        let info: ExecutionInfo = client
            .request(EXECUTION_INFO_METHOD, rpc_params![])
            .await
            .unwrap();
        assert!(info.read_only);
        assert_eq!(info.chain_id, format!("0x{chain_id:x}"));
        assert_eq!(info.genesis_hash, genesis_hash);
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
        let block_number: String = client
            .request("eth_blockNumber", rpc_params![])
            .await
            .unwrap();
        assert_eq!(block_number, "0x0");
        let call = serde_json::json!({
            "to": "0x0000000000000000000000000000000000000000",
            "gas": "0x4c4b40",
            "gasPrice": "0x0"
        });
        let output: String = client
            .request("eth_call", rpc_params![call.clone(), "0x0"])
            .await
            .unwrap();
        assert_eq!(output, "0x");
        let trace: serde_json::Value = client
            .request(
                "debug_traceCall",
                rpc_params![call, "0x0", serde_json::json!({ "tracer": "callTracer" })],
            )
            .await
            .unwrap();
        assert_eq!(trace["type"], "CALL");
        let result = client
            .request::<serde_json::Value, _>("eth_sendRawTransaction", rpc_params!["0x00"])
            .await;
        assert!(
            matches!(result, Err(jsonrpsee::core::client::Error::Call(err)) if err.code() == -32601)
        );
    }

    #[tokio::test]
    async fn private_config_preserves_the_nodes_execution_gas_cap() {
        let dir = tempfile::tempdir().unwrap();
        let capped_dir = tempfile::tempdir().unwrap();
        let runtime = Runtime::test();
        let environment = command(dir.path())
            .env
            .init::<TempoNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        drop(environment);
        let call = serde_json::json!({
            "to": "0x0000000000000000000000000000000000000000",
            "gas": "0x4c4b40", "gasPrice": "0x0",
            "input": format!("0x{}", "01".repeat(100))
        });
        let ordinary = command(dir.path()).start(runtime.clone()).await.unwrap();
        let client = ordinary.server.as_ref().unwrap().http_client().unwrap();
        let output: String = client
            .request("eth_call", rpc_params![call.clone(), "0x0"])
            .await
            .unwrap();
        assert_eq!(output, "0x");
        drop(ordinary);

        // MDBX environments cannot be reopened concurrently in the same process. Native
        // workers are separate processes; use another identical genesis DB for this fixture.
        let environment = command(capped_dir.path())
            .env
            .init::<TempoNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        drop(environment);
        let config_file = tempfile::NamedTempFile::new().unwrap();
        let config = EthConfig::default().rpc_gas_cap(21_000);
        serde_json::to_writer(config_file.as_file(), &config).unwrap();
        let mut capped = command(capped_dir.path());
        capped.rpc_config = Some(config_file.path().to_owned());
        let capped = capped.start(runtime).await.unwrap();
        let client = capped.server.as_ref().unwrap().http_client().unwrap();
        let error = client
            .request::<String, _>("eth_call", rpc_params![call, "0x0"])
            .await
            .unwrap_err();
        assert!(
            matches!(error, jsonrpsee::core::client::Error::Call(ref error)
            if error.message().to_ascii_lowercase().contains("gas")),
            "{error}"
        );
    }
}
