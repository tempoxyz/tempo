//! Adapt the execution-independent era router to the ordinary Tempo node launcher.

use std::{sync::Arc, time::Duration};

use alloy_primitives::Bytes;
use alloy_rlp::Decodable;
use futures::future::BoxFuture;
use jsonrpsee::{
    core::{
        RpcResult,
        server::{Methods, MethodsError},
    },
    types::{ErrorObjectOwned, error::INTERNAL_ERROR_CODE},
};
use reth_ethereum::{chainspec::EthChainSpec as _, rpc::builder::TransportRpcModules};
use serde_json::Value;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_metabinary::{
    catalog::{Catalog, ChainEras},
    decorate::decorate,
    routing::{Backend, Router, RpcParams},
    workers::{HistoricalWorkers, WorkerContext, WorkerEra},
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
    workers: HistoricalWorkers,
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
        rpc_config: Value,
    ) -> eyre::Result<Arc<Self>> {
        schedule.validate()?;
        let mut chain_file = tempfile::Builder::new().suffix(".json").tempfile()?;
        serde_json::to_writer(chain_file.as_file_mut(), chain.genesis())?;
        let mut rpc_config_file = tempfile::NamedTempFile::new()?;
        serde_json::to_writer(rpc_config_file.as_file_mut(), &rpc_config)?;
        let eras = schedule.eras[..schedule.eras.len() - 1]
            .iter()
            .map(|era| WorkerEra {
                name: era.name.clone(),
                binary: era.binary.clone().expect("validated frozen executable"),
            })
            .collect();
        let workers = HistoricalWorkers::new(
            WorkerContext {
                chain: chain_file.path().to_string_lossy().into_owned(),
                datadir,
                static_files_path,
                rocksdb_path,
                rpc_config: Some(rpc_config_file.path().to_owned()),
                chain_id: format!("0x{:x}", chain.chain_id()),
                genesis_hash: chain.genesis_hash().to_string(),
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
        let router = Arc::new(Router::with_backend(
            self.schedule.clone(),
            Arc::new(NativeBackend {
                resolver,
                runtime: self.clone(),
            }),
            Default::default(),
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
    fn request<'a>(
        &'a self,
        era: usize,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Value>> {
        Box::pin(async move {
            if era + 1 == self.runtime.schedule.eras.len() {
                self.resolver
                    .call(method, params)
                    .await
                    .map_err(|error| match error {
                        MethodsError::JsonRpc(error) => error,
                        error => ErrorObjectOwned::owned(
                            INTERNAL_ERROR_CODE,
                            error.to_string(),
                            None::<()>,
                        ),
                    })
            } else {
                self.runtime.workers.request(era, method, params).await
            }
        })
    }

    fn raw_block_timestamp<'a>(&'a self, params: &'a RpcParams) -> BoxFuture<'a, RpcResult<u64>> {
        Box::pin(async move {
            let value = match &params.0 {
                Value::Array(values) => values.first(),
                Value::Object(values) => values.get("rlp_block").or_else(|| values.get("rlpBlock")),
                _ => None,
            }
            .ok_or_else(|| ErrorObjectOwned::owned(-32602, "missing raw block", None::<()>))?;
            let bytes: Bytes = serde_json::from_value(value.clone())
                .map_err(|error| ErrorObjectOwned::owned(-32602, error.to_string(), None::<()>))?;
            let mut raw = bytes.as_ref();
            let block = tempo_primitives::Block::decode(&mut raw)
                .map_err(|error| ErrorObjectOwned::owned(-32602, error.to_string(), None::<()>))?;
            if !raw.is_empty() {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    "trailing raw block data",
                    None::<()>,
                ));
            }
            Ok(block.header.inner.timestamp)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempo_metabinary::catalog::ReleaseEra;

    #[test]
    fn custom_fork_schedule_does_not_inherit_builtin_eras() {
        let known = &*tempo_chainspec::spec::PRESTO;
        assert!(supports_release_catalog(known));
        let mut genesis = known.genesis().clone();
        let original_hash = known.genesis_hash();
        genesis
            .config
            .extra_fields
            .insert("t11Time".into(), json!(2000000000));
        let custom = TempoChainSpec::from_genesis(genesis);
        assert_eq!(custom.genesis_hash(), original_hash);
        assert!(!supports_release_catalog(&custom));
    }

    #[tokio::test]
    async fn native_registry_routes_with_eth_disabled_and_decodes_tempo_blocks() {
        let chain = &*tempo_chainspec::spec::DEV;
        let runtime = EraRuntime::new(
            ChainEras {
                chain_id: format!("0x{:x}", chain.chain_id()),
                genesis_hash: chain.genesis_hash().to_string(),
                eras: vec![
                    ReleaseEra {
                        name: "old".into(),
                        start_timestamp: 0,
                        binary: Some("/missing/frozen-tempo".into()),
                    },
                    ReleaseEra {
                        name: "live".into(),
                        start_timestamp: 100,
                        binary: None,
                    },
                ],
            },
            chain,
            "/unused".into(),
            None,
            None,
            serde_json::to_value(reth_ethereum::rpc::eth::EthConfig::default()).unwrap(),
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
            runtime: runtime.clone(),
        };
        let mut header = chain.genesis_header().clone();
        header.inner.timestamp = 123;
        let block = tempo_primitives::Block::new(header, Default::default());
        let mut bytes = alloy_rlp::encode(block);
        let timestamp = backend
            .raw_block_timestamp(&RpcParams(json!([Bytes::copy_from_slice(&bytes)])))
            .await
            .unwrap();
        assert_eq!(timestamp, 123);
        bytes.push(0);
        let error = backend
            .raw_block_timestamp(&RpcParams(json!([Bytes::from(bytes)])))
            .await
            .unwrap_err();
        assert_eq!(error.code(), -32602);
        assert_eq!(error.message(), "trailing raw block data");
        runtime.shutdown().await.unwrap();
    }
}
