//! `tempo rpc-only`: the private read-only RPC server frozen era workers run.

use alloy_primitives::{U64, U256};
use clap::Parser;
use eyre::{WrapErr as _, ensure};
use jsonrpsee::{RpcModule, server::ServerConfig};
use reth_chainspec::EthChainSpec as _;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_ethereum::{
    network::api::noop::NoopNetwork,
    pool::noop::NoopTransactionPool,
    provider::providers::{BlockchainProvider, RocksDBProvider},
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
use reth_provider::BlockHashReader as _;
use reth_rpc_eth_api::{
    RpcConverter,
    helpers::config::{EthConfigApiServer as _, EthConfigHandler},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_metabinary::handshake::{
    EXECUTION_INFO_METHOD, EXECUTION_INFO_PROTOCOL_VERSION, ExecutionInfo,
};
use tempo_node::{
    TempoPooledTransaction,
    node::TempoNode,
    rpc::{
        TempoEthApi, TempoEthExt, TempoEthExtApiServer as _, TempoForkScheduleApiServer as _,
        TempoForkScheduleRpc, TempoReceiptConverter, TempoSimulate, TempoSimulateApiServer as _,
        TempoToken, TempoTokenApiServer as _,
    },
};
use tracing::info;

/// Methods that write, sign, or need a pool or live subscriptions.
const REMOVED_METHODS: &[&str] = &[
    "eth_subscribe",
    "eth_unsubscribe",
    "eth_sendRawTransaction",
    "eth_sendRawTransactionSync",
    "eth_sendRawTransactionConditional",
    "eth_sendTransaction",
    "eth_sign",
    "eth_signTransaction",
    "eth_signTypedData",
    "debug_clearTxpool",
    "debug_chaindbCompact",
    "debug_setHead",
    "debug_setGCPercent",
    "debug_setTrieFlushInterval",
    "debug_standardTraceBadBlockToFile",
    "debug_standardTraceBlockToFile",
];

/// Serve private read-only RPC over existing storage, without consensus, networking, or a pool.
#[derive(Debug, Parser)]
pub struct RpcOnly {
    /// Chain and storage to serve.
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,

    /// Loopback port serving HTTP and WebSocket. `0` picks a free port.
    #[arg(long, alias = "http.port", default_value_t = 8545)]
    port: u16,

    /// Serialized RPC configuration inherited from the live node.
    #[arg(long, hide = true)]
    rpc_config: Option<PathBuf>,
}

impl RpcOnly {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        let handle = self.start(runtime).await?;
        info!(addr = ?handle.http_local_addr(), "serving read-only RPC");
        // Serves until shutdown drops this future, and with it the handle that stops the server.
        std::future::pending().await
    }

    /// Opens storage read-only and starts the server. Dropping the handle stops it.
    async fn start(self, runtime: Runtime) -> eyre::Result<RpcServerHandle> {
        let mut eth_config = match &self.rpc_config {
            Some(path) => serde_json::from_slice::<EthConfig>(
                &std::fs::read(path)
                    .wrap_err_with(|| format!("failed to read {}", path.display()))?,
            )
            .wrap_err_with(|| format!("invalid RPC config {}", path.display()))?,
            None => EthConfig::default(),
        };
        // Matches Tempo's eth API builder.
        eth_config.gas_oracle.default_suggested_fee = Some(U256::ZERO);

        let chain = self.env.chain.clone();
        // Reth's read-only open would create missing RocksDB storage.
        let data_dir = self.env.datadir.clone().resolve_datadir(chain.chain());
        for (exists, missing) in [
            (data_dir.db().exists(), "an existing chain database"),
            (data_dir.static_files().exists(), "existing static files"),
            (
                RocksDBProvider::exists(data_dir.rocksdb()),
                "existing RocksDB storage; initialize it with the node first",
            ),
        ] {
            ensure!(exists, "rpc-only requires {missing}");
        }
        let Environment {
            provider_factory, ..
        } = self
            .env
            // The live node keeps writing, so storage can look transiently inconsistent.
            .init::<TempoNode>(AccessRights::RoInconsistent, runtime.clone())?;
        // Each read catches up with the live node's RocksDB and static-file writes.
        let provider_factory = provider_factory.with_read_only_sync(false);
        ensure!(
            provider_factory.block_hash(0)? == Some(chain.genesis_hash()),
            "rpc-only chain specification does not match the database genesis"
        );

        let provider = BlockchainProvider::new(provider_factory)?;
        let evm_config = TempoEvmConfig::new(chain.clone());
        let pool = NoopTransactionPool::<TempoPooledTransaction>::new();
        let network = NoopNetwork::default().with_chain_id(chain.chain_id());
        let eth_api = TempoEthApi::new(
            EthApiBuilder::new(
                provider.clone(),
                pool.clone(),
                network.clone(),
                evm_config.clone(),
            )
            .eth_state_cache_config(eth_config.cache)
            .task_spawner(runtime.clone())
            .gas_cap(eth_config.rpc_gas_cap.into())
            .max_simulate_blocks(eth_config.rpc_max_simulate_blocks)
            .compute_state_root_for_eth_simulate(eth_config.compute_state_root_for_eth_simulate)
            .eth_proof_window(eth_config.eth_proof_window)
            .fee_history_cache_config(eth_config.fee_history_cache)
            .proof_permits(eth_config.proof_permits)
            .gas_oracle_config(eth_config.gas_oracle)
            .max_batch_size(eth_config.max_batch_size)
            .max_blocking_io_requests(eth_config.max_blocking_io_requests)
            .pending_block_kind(eth_config.pending_block_kind)
            .raw_tx_forwarder(eth_config.raw_tx_forwarder.clone())
            .evm_memory_limit(eth_config.rpc_evm_memory_limit)
            .force_blob_sidecar_upcasting(eth_config.force_blob_sidecar_upcasting)
            .map_converter(|_| {
                RpcConverter::new(TempoReceiptConverter::new(chain.clone())).erased()
            })
            .build(),
        );

        let selection = [
            RethRpcModule::Eth,
            RethRpcModule::Debug,
            RethRpcModule::Trace,
            RethRpcModule::Reth,
            RethRpcModule::Ots,
            RethRpcModule::Mev,
        ];
        let module_config = TransportRpcModuleConfig::set_http(selection.clone())
            .with_ws(selection)
            .with_config(RpcModuleConfig::new(eth_config));
        let mut modules = RpcModuleBuilder::default()
            .with_provider(provider.clone())
            .with_pool(pool)
            .with_network(network)
            .with_executor(runtime)
            .with_evm_config(evm_config.clone())
            .with_consensus(TempoConsensus::new(chain.clone()))
            .build(module_config, eth_api.clone(), Default::default());

        let info = ExecutionInfo {
            protocol_version: EXECUTION_INFO_PROTOCOL_VERSION,
            chain_id: U64::from(chain.chain_id()),
            genesis_hash: chain.genesis_hash(),
            read_only: true,
            process_id: std::process::id(),
        };
        let mut execution_info = RpcModule::new(());
        execution_info.register_method(EXECUTION_INFO_METHOD, move |_, _, _| {
            jsonrpsee::core::RpcResult::Ok(info.clone())
        })?;
        modules.merge_configured(execution_info)?;
        modules.merge_configured(TempoToken::new(eth_api.clone()).into_rpc())?;
        modules.merge_configured(TempoEthExt::new(eth_api.clone()).into_rpc())?;
        modules.merge_configured(TempoSimulate::new(eth_api).into_rpc())?;
        modules.merge_configured(TempoForkScheduleRpc::new(provider.clone()).into_rpc())?;
        modules.merge_configured(EthConfigHandler::new(provider, evm_config).into_rpc())?;
        for method in REMOVED_METHODS {
            modules.remove_method_from_configured(method);
        }

        // The public node enforces operator limits; the worker only serves it.
        let server = ServerConfig::builder()
            .max_request_body_size(u32::MAX)
            .max_response_body_size(u32::MAX)
            .max_connections(u32::MAX)
            .max_subscriptions_per_connection(u32::MAX);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        RpcServerConfig::http(server.clone())
            .with_ws(server)
            .with_http_address(addr)
            .with_ws_address(addr)
            .start(&modules)
            .await
            .wrap_err("failed to start the read-only RPC server")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::{
        core::{
            ClientError,
            client::{ClientT as _, SubscriptionClientT as _},
        },
        http_client::{HttpClient, HttpClientBuilder},
        rpc_params,
        ws_client::WsClientBuilder,
    };
    use serde_json::{Value, json};
    use std::{path::Path, time::Duration};
    use tempo_chainspec::{hardfork::TempoHardfork, spec::DEV};
    use tempo_metabinary::handshake::WorkerIdentity;

    const WAIT: Duration = Duration::from_secs(30);

    fn rpc_only(chain: &str, datadir: &Path, extra: &[&str]) -> RpcOnly {
        let datadir = datadir.to_str().unwrap();
        let args = [
            "rpc-only",
            "--chain",
            chain,
            "--datadir",
            datadir,
            "--port",
            "0",
        ];
        RpcOnly::try_parse_from(args.iter().chain(extra)).unwrap()
    }

    /// Creates a database holding only genesis and serves it.
    async fn serve(chain: &str, datadir: &Path, extra: &[&str]) -> (RpcServerHandle, HttpClient) {
        let env = rpc_only(chain, datadir, &[]).env;
        drop(
            env.init::<TempoNode>(AccessRights::RW, Runtime::test())
                .unwrap(),
        );
        let start = rpc_only(chain, datadir, extra).start(Runtime::test());
        let handle = tokio::time::timeout(WAIT, start).await.unwrap().unwrap();
        let client = HttpClientBuilder::default()
            .build(handle.http_url().unwrap())
            .unwrap();
        (handle, client)
    }

    fn call_error(err: ClientError) -> (i32, String) {
        match err {
            ClientError::Call(err) => (err.code(), err.message().to_owned()),
            err => panic!("unexpected error: {err}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn requires_existing_storage_without_creating_it() {
        let dir = tempfile::tempdir().unwrap();
        let datadir = dir.path().join("missing");
        for (create, expected) in [
            (None, "rpc-only requires an existing chain database"),
            (Some("db"), "rpc-only requires existing static files"),
            (
                Some("static_files"),
                "rpc-only requires existing RocksDB storage; initialize it with the node first",
            ),
        ] {
            if let Some(create) = create {
                std::fs::create_dir_all(datadir.join(create)).unwrap();
            }
            let err = rpc_only("dev", &datadir, &[])
                .start(Runtime::test())
                .await
                .unwrap_err();
            assert_eq!(err.to_string(), expected);
        }
        let mut entries: Vec<_> = std::fs::read_dir(&datadir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, ["db", "static_files"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serves_read_only_rpc_with_the_inherited_config() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("rpc.json");
        let eth_config = EthConfig::default().rpc_gas_cap(1_000_000);
        std::fs::write(&config, serde_json::to_vec(&eth_config).unwrap()).unwrap();
        let datadir = dir.path().join("db");
        let (handle, client) =
            serve("dev", &datadir, &["--rpc-config", config.to_str().unwrap()]).await;

        let info: ExecutionInfo = client
            .request(EXECUTION_INFO_METHOD, rpc_params![])
            .await
            .unwrap();
        let identity = WorkerIdentity {
            chain_id: U64::from(DEV.chain_id()),
            genesis_hash: DEV.genesis_hash(),
        };
        info.validate(&identity, std::process::id()).unwrap();
        let number: String = client
            .request("eth_blockNumber", rpc_params![])
            .await
            .unwrap();
        assert_eq!(number, "0x0");
        let call = json!({"to": "0x0000000000000000000000000000000000000001"});
        let output: String = client
            .request("eth_call", rpc_params![&call, "0x0"])
            .await
            .unwrap();
        assert_eq!(output, "0x");
        let tracer = json!({"tracer": "callTracer"});
        let trace: Value = client
            .request("debug_traceCall", rpc_params![&call, "0x0", tracer])
            .await
            .unwrap();
        assert_eq!(trace["type"], "CALL");

        // The inherited gas cap rejects calls whose calldata alone exceeds it.
        let heavy = json!({"to": call["to"], "input": format!("0x{}", "ff".repeat(100_000))});
        let err = client
            .request::<String, _>("eth_call", rpc_params![heavy, "0x0"])
            .await
            .unwrap_err();
        let (_, message) = call_error(err);
        assert!(message.contains("gas"), "{message}");
        let err = client
            .request::<Value, _>("eth_sendRawTransaction", rpc_params!["0x00"])
            .await
            .unwrap_err();
        assert_eq!(call_error(err).0, -32601);

        // WebSocket shares the port and keeps `debug_subscribe`.
        let ws = WsClientBuilder::default()
            .build(handle.ws_url().unwrap())
            .await
            .unwrap();
        let params = rpc_params!["traceChain", "0x0", "0x0"];
        let err = ws
            .subscribe::<Value, _>("debug_subscribe", params, "debug_unsubscribe")
            .await
            .unwrap_err();
        let expected = (
            -32602,
            "end block (#0) needs to come after start block (#0)".to_owned(),
        );
        assert_eq!(call_error(err), expected);

        drop(handle);
        let stopped = tokio::time::timeout(WAIT, async {
            while client
                .request::<String, _>("eth_blockNumber", rpc_params![])
                .await
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        assert!(
            stopped.await.is_ok(),
            "server kept serving after its handle dropped"
        );
    }

    /// Block overrides keep the base block's fork, which era routing relies on.
    #[tokio::test(flavor = "multi_thread")]
    async fn block_overrides_keep_the_base_fork() {
        let dir = tempfile::tempdir().unwrap();
        // The signature verifier precompile exists from T3.
        let call = json!({
            "to": tempo_contracts::precompiles::SIGNATURE_VERIFIER_ADDRESS,
            "input": "0xdeadbeef",
        });
        let mut outcomes = Vec::new();
        for (name, t3_time) in [("pre_t3", 10_000), ("t3", 0)] {
            let mut genesis = DEV.genesis().clone();
            for fork in TempoHardfork::VARIANTS.iter().filter(|fork| fork.is_t3()) {
                let key = fork.genesis_key().unwrap().to_owned();
                genesis.config.extra_fields.insert(key, json!(t3_time));
            }
            let chain = dir.path().join(format!("{name}.json"));
            std::fs::write(&chain, serde_json::to_vec(&genesis).unwrap()).unwrap();
            let (_handle, client) =
                serve(chain.to_str().unwrap(), &dir.path().join(name), &[]).await;
            let mut outcome = Vec::new();
            for overrides in [Value::Null, json!({"time": "0x4e20"})] {
                let params = rpc_params![call.clone(), "0x0", Value::Null, overrides];
                let result = client.request::<Value, _>("eth_call", params).await;
                outcome.push(result.map_err(|err| call_error(err).1));
            }
            assert_eq!(outcome[0], outcome[1], "{name}");
            outcomes.push(outcome.remove(0));
        }
        assert_ne!(
            outcomes[0], outcomes[1],
            "the precompile must be fork-dependent"
        );
    }
}
