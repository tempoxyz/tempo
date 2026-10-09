//! Adapt the execution-independent era router to the ordinary Tempo node launcher.

use std::{sync::Arc, time::Duration};

use alloy_primitives::{Bytes, U64};
use alloy_rlp::Decodable;
use futures::future::BoxFuture;
use jsonrpsee::core::{
    RpcResult,
    server::{Methods, MethodsError},
};
use reth_ethereum::{
    chainspec::EthChainSpec as _,
    rpc::{builder::TransportRpcModules, eth::EthConfig},
};
use reth_rpc_server_types::result::internal_rpc_err;
use serde_json::{Value, value::RawValue};
use tempo_chainspec::spec::TempoChainSpec;
use tempo_metabinary::{
    catalog::{Catalog, ChainEras},
    decorate::decorate,
    routing::{Backend, Router, RpcParams, invalid},
    workers::{HistoricalWorkers, WorkerContext},
};

/// Load chain-bound metadata bundled with the release. Development builds have no frozen eras.
/// A packaged catalog next to the executable supersedes the built-in catalog; it contains only
/// release artifacts and activation times, never the operator's node configuration.
pub(crate) fn release_catalog() -> eyre::Result<Catalog> {
    let executable = std::env::current_exe()?;
    let path = executable
        .parent()
        .expect("executable has parent")
        .join("tempo-eras.json");
    match std::fs::metadata(&path) {
        Ok(_) => Catalog::load(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let catalog: Catalog = serde_json::from_str(include_str!("../eras.json"))?;
            catalog.validate()?;
            Ok(catalog)
        }
        Err(error) => Err(error.into()),
    }
}

/// A custom genesis can keep a built-in chain's block hash while changing its fork schedule.
/// Only apply packaged eras when the runtime rules still match the release's built-in rules.
pub(crate) fn supports_release_catalog(spec: &TempoChainSpec) -> bool {
    use tempo_chainspec::spec::{DEV, MODERATO, PRESTO};
    [&**PRESTO, &**MODERATO, &**DEV].into_iter().any(|known| {
        spec.chain_id() == known.chain_id()
            && spec.genesis().config == known.genesis().config
            && spec.inner.hardforks == known.inner.hardforks
            && spec.info == known.info
    })
}

pub(crate) struct EraRuntime {
    schedule: ChainEras,
    workers: Arc<HistoricalWorkers>,
    // Frozen releases parse exactly the live chain's genesis, including custom fork schedules.
    _chain_file: tempfile::NamedTempFile,
    _rpc_config_file: tempfile::NamedTempFile,
}

impl EraRuntime {
    pub(crate) fn new(
        schedule: ChainEras,
        chain: &TempoChainSpec,
        datadir: std::path::PathBuf,
        static_files_path: Option<std::path::PathBuf>,
        rocksdb_path: Option<std::path::PathBuf>,
        rpc_config: EthConfig,
    ) -> eyre::Result<Arc<Self>> {
        schedule.validate()?;
        let mut chain_file = tempfile::Builder::new().suffix(".json").tempfile()?;
        serde_json::to_writer(chain_file.as_file_mut(), chain.genesis())?;
        let mut rpc_config_file = tempfile::NamedTempFile::new()?;
        serde_json::to_writer(rpc_config_file.as_file_mut(), &rpc_config)?;
        let eras = schedule.eras[..schedule.eras.len() - 1].to_vec();
        let workers = HistoricalWorkers::new(
            WorkerContext {
                chain: chain_file.path().to_string_lossy().into_owned(),
                datadir,
                static_files_path,
                rocksdb_path,
                rpc_config: Some(rpc_config_file.path().to_owned()),
                chain_id: U64::from(chain.chain_id()),
                genesis_hash: chain.genesis_hash(),
                startup_timeout: Duration::from_secs(120),
            },
            eras,
        )?;
        Ok(Arc::new(Self {
            schedule,
            workers,
            _chain_file: chain_file,
            _rpc_config_file: rpc_config_file,
        }))
    }

    pub(crate) fn install(
        self: &Arc<Self>,
        modules: &mut TransportRpcModules,
        resolver: Methods,
    ) -> eyre::Result<()> {
        let router = Arc::new(Router::new(
            self.schedule.clone(),
            Arc::new(NativeBackend {
                resolver,
                runtime: self.clone(),
            }),
        )?);
        // Replace callbacks in-place, retaining the existing server configuration and transports.
        if let Some(methods) = modules.http_methods(|_| true) {
            modules.replace_http(decorate(methods, router.clone())?)?;
        }
        if let Some(methods) = modules.ws_methods(|_| true) {
            modules.replace_ws(decorate(methods, router.clone())?)?;
        }
        if let Some(methods) = modules.ipc_methods(|_| true) {
            modules.replace_ipc(decorate(methods, router)?)?;
        }
        Ok(())
    }

    pub(crate) async fn shutdown(&self) -> eyre::Result<()> {
        self.workers.shutdown().await
    }
}

struct NativeBackend {
    resolver: Methods,
    runtime: Arc<EraRuntime>,
}

impl Backend for NativeBackend {
    fn resolve<'a>(
        &'a self,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Value>> {
        Box::pin(async move {
            self.resolver
                .call(method, params)
                .await
                .map_err(|error| match error {
                    MethodsError::JsonRpc(error) => error,
                    error => internal_rpc_err(error.to_string()),
                })
        })
    }

    fn forward<'a>(
        &'a self,
        era: usize,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Box<RawValue>>> {
        Box::pin(self.runtime.workers.request(era, method, params))
    }

    fn raw_block_timestamp<'a>(&'a self, params: &'a RpcParams) -> BoxFuture<'a, RpcResult<u64>> {
        Box::pin(async move {
            let value = match &params.0 {
                Value::Array(values) => values.first(),
                Value::Object(values) => values.get("rlp_block").or_else(|| values.get("rlpBlock")),
                _ => None,
            }
            .ok_or_else(|| invalid("missing raw block"))?;
            let bytes: Bytes = serde::Deserialize::deserialize(value)
                .map_err(|error| invalid(error.to_string()))?;
            let mut raw = bytes.as_ref();
            let mut payload = alloy_rlp::Header::decode_bytes(&mut raw, true)
                .map_err(|error| invalid(error.to_string()))?;
            // The selected executor validates the body using its era's transaction codec.
            let header = tempo_primitives::TempoHeader::decode(&mut payload)
                .map_err(|error| invalid(error.to_string()))?;
            if !raw.is_empty() {
                return Err(invalid("trailing raw block data"));
            }
            Ok(header.inner.timestamp)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn custom_fork_schedule_does_not_inherit_builtin_eras() {
        let known = &*tempo_chainspec::spec::PRESTO;
        assert!(supports_release_catalog(known));
        let mut genesis = known.genesis().clone();
        genesis
            .config
            .extra_fields
            .insert("t11Time".into(), json!(2000000000));
        let custom = TempoChainSpec::from_genesis(genesis);
        assert_eq!(custom.genesis_hash(), known.genesis_hash());
        assert!(!supports_release_catalog(&custom));
    }

    #[tokio::test]
    async fn native_registry_routes_with_eth_disabled_and_decodes_tempo_blocks() {
        let chain = &*tempo_chainspec::spec::DEV;
        let runtime = EraRuntime::new(
            serde_json::from_value(json!({
                "chain_id": format!("0x{:x}", chain.chain_id()),
                "genesis_hash": chain.genesis_hash().to_string(),
                "eras": [
                    {"name":"old", "start_timestamp":0, "binary":"/missing/frozen-tempo"},
                    {"name":"live", "start_timestamp":100}
                ]
            }))
            .unwrap(),
            chain,
            "/unused".into(),
            None,
            None,
            EthConfig::default(),
        )
        .unwrap();
        let mut resolver = jsonrpsee::RpcModule::new(());
        resolver.register_method("eth_getBlockByNumber", |_, _, _| json!({"number":"0x1", "hash":format!("0x{}", "11".repeat(32)), "timestamp":"0x64"})).unwrap();
        let mut debug = jsonrpsee::RpcModule::new(());
        debug
            .register_method("debug_traceCall", |_, _, _| "native")
            .unwrap();
        let mut modules = TransportRpcModules::default().with_http(debug);
        runtime.install(&mut modules, resolver.into()).unwrap();
        let methods = modules.http_methods(|_| true).unwrap();
        assert!(methods.method("eth_getBlockByNumber").is_none());
        let value: String = methods
            .call(
                "debug_traceCall",
                jsonrpsee::rpc_params![json!({}), "latest"],
            )
            .await
            .unwrap();
        assert_eq!(value, "native");
        let backend = NativeBackend {
            resolver: Methods::new(),
            runtime,
        };
        let mut header = chain.genesis_header().clone();
        header.inner.timestamp = 123;
        let block = tempo_primitives::Block::new(header, Default::default());
        let mut bytes = alloy_rlp::encode(block);
        assert_eq!(
            backend
                .raw_block_timestamp(&RpcParams(json!([Bytes::copy_from_slice(&bytes)])))
                .await
                .unwrap(),
            123
        );
        // Routing must not validate the body with the current release's codec.
        let mut opaque_body = bytes.clone();
        *opaque_body.last_mut().unwrap() = 0xff;
        assert!(tempo_primitives::Block::decode(&mut opaque_body.as_slice()).is_err());
        assert_eq!(
            backend
                .raw_block_timestamp(&RpcParams(json!([Bytes::from(opaque_body)])))
                .await
                .unwrap(),
            123
        );
        for malformed in [vec![0xc0], bytes[..bytes.len() - 1].to_vec()] {
            assert_eq!(
                backend
                    .raw_block_timestamp(&RpcParams(json!([Bytes::from(malformed)])))
                    .await
                    .unwrap_err()
                    .code(),
                -32602
            );
        }
        bytes.push(0);
        let error = backend
            .raw_block_timestamp(&RpcParams(json!([Bytes::from(bytes)])))
            .await
            .unwrap_err();
        assert_eq!(error.code(), -32602);
        assert_eq!(error.message(), "trailing raw block data");
    }
}
