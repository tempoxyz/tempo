//! Adapt the execution-independent era router to the ordinary Tempo node launcher.

use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy_consensus::BlockHeader as _;
use alloy_primitives::{B256, Bytes, U64};
use alloy_rlp::Decodable;
use futures::future::BoxFuture;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use reth_ethereum::{
    chainspec::EthChainSpec as _,
    rpc::{
        builder::TransportRpcModules,
        eth::{EthConfig, TransactionSource},
    },
};
use reth_rpc_eth_api::{
    FromEthApiError,
    helpers::{FullEthApi, LoadTransaction},
};
use reth_storage_api::BlockReaderIdExt as _;
use serde::Deserialize;
use serde_json::{Value, value::RawValue};
use std::{sync::Arc, time::Duration};
use tempo_chainspec::spec::TempoChainSpec;
use tempo_metabinary::{
    catalog::{Catalog, ChainEras},
    decorate::decorate,
    routing::{Backend, BlockMetadata, Router, RpcParams, invalid},
    workers::{DEFAULT_STARTUP_TIMEOUT_SECS, HistoricalWorkers, WorkerContext},
};

/// Load the bundled Genesis–T10 schedule, resolving workers beside the executable.
/// A packaged catalog next to the executable supersedes the built-in catalog; it contains only
/// release artifacts and activation times, never the operator's node configuration.
pub(crate) fn release_catalog() -> eyre::Result<Catalog> {
    let executable = std::env::current_exe()?;
    let parent = executable.parent().expect("executable has parent");
    let path = parent.join("tempo-eras.json");
    match std::fs::metadata(&path) {
        Ok(_) => Catalog::load(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut catalog: Catalog = serde_json::from_str(include_str!("../eras.json"))?;
            catalog.validate()?;
            catalog.resolve_binaries(parent);
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

/// Installs era routing on native RPC transports and owns the historical workers' configuration.
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
        let workers = HistoricalWorkers::new(
            WorkerContext {
                chain: chain_file.path().to_string_lossy().into_owned(),
                datadir,
                static_files_path,
                rocksdb_path,
                rpc_config: Some(rpc_config_file.path().to_owned()),
                chain_id: U64::from(chain.chain_id()),
                genesis_hash: chain.genesis_hash(),
                startup_timeout: Duration::from_secs(DEFAULT_STARTUP_TIMEOUT_SECS),
            },
            schedule.eras[..schedule.eras.len() - 1].to_vec(),
        )?;
        Ok(Arc::new(Self {
            schedule,
            workers,
            _chain_file: chain_file,
            _rpc_config_file: rpc_config_file,
        }))
    }

    pub(crate) fn install<E: FullEthApi>(
        self: &Arc<Self>,
        modules: &mut TransportRpcModules,
        eth_api: E,
    ) -> eyre::Result<()> {
        let router = Arc::new(Router::new(
            self.schedule.clone(),
            Arc::new(NativeBackend {
                eth_api,
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

struct NativeBackend<E> {
    eth_api: E,
    runtime: Arc<EraRuntime>,
}

impl<E: FullEthApi> Backend for NativeBackend<E> {
    fn block<'a>(&'a self, selector: &'a Value) -> BoxFuture<'a, RpcResult<BlockMetadata>> {
        Box::pin(async move {
            // Match native RPC resolution; canonicality belongs to the original execution params.
            let id: BlockId =
                if let Some(hash) = selector.get("blockHash").filter(|hash| hash.is_string()) {
                    B256::deserialize(hash).map(BlockId::from)
                } else if let Some(number) = selector.get("blockNumber") {
                    BlockNumberOrTag::deserialize(number).map(BlockId::Number)
                } else {
                    BlockId::deserialize(selector)
                }
                .map_err(|error| invalid(error.to_string()))?;
            let header = if id.is_pending() {
                self.eth_api
                    .recovered_block(id)
                    .await
                    .map(|block| block.map(|block| block.clone_sealed_header()))
            } else {
                self.eth_api
                    .spawn_blocking_io(move |api| {
                        api.provider()
                            .sealed_header_by_id(id)
                            .map_err(E::Error::from_eth_err)
                    })
                    .await
            }
            .map_err(Into::<ErrorObjectOwned>::into)?
            .ok_or_else(|| ErrorObjectOwned::owned(-32001, "unknown block", None::<()>))?;
            Ok(BlockMetadata {
                number: header.number(),
                hash: header.hash(),
                timestamp: header.timestamp(),
            })
        })
    }

    fn transaction_timestamp<'a>(
        &'a self,
        hash: &'a Value,
    ) -> BoxFuture<'a, RpcResult<Option<u64>>> {
        Box::pin(async move {
            let hash = B256::deserialize(hash).map_err(|error| invalid(error.to_string()))?;
            LoadTransaction::transaction_by_hash(&self.eth_api, hash)
                .await
                .map(|source| match source {
                    Some(TransactionSource::Block {
                        block_timestamp, ..
                    }) => Some(block_timestamp),
                    _ => None,
                })
                .map_err(Into::into)
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

    fn raw_block_timestamp(&self, params: &RpcParams) -> RpcResult<u64> {
        raw_block_timestamp(params)
    }
}

fn raw_block_timestamp(params: &RpcParams) -> RpcResult<u64> {
    let value = match &params.0 {
        Value::Array(values) => values.first(),
        Value::Object(values) => values.get("rlp_block").or_else(|| values.get("rlpBlock")),
        _ => None,
    }
    .ok_or_else(|| invalid("missing raw block"))?;
    let bytes = Bytes::deserialize(value).map_err(|error| invalid(error.to_string()))?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bundled_history_matches_builtin_chains() {
        let mut catalog: Catalog = serde_json::from_str(include_str!("../eras.json")).unwrap();
        catalog.validate().unwrap();
        catalog.resolve_binaries(std::path::Path::new("/tempo"));
        for spec in [
            &**tempo_chainspec::spec::PRESTO,
            &**tempo_chainspec::spec::MODERATO,
        ] {
            let chain = catalog
                .for_chain(spec.chain_id(), spec.genesis_hash())
                .unwrap();
            let boundary = spec
                .info
                .fork_time(tempo_chainspec::TempoHardfork::T11)
                .unwrap();
            assert_eq!(
                chain.eras[0].binary.as_deref(),
                Some(std::path::Path::new("/tempo/eras/tempo-genesis-t10"))
            );
            for (timestamp, era) in [(0, 0), (boundary - 1, 0), (boundary, 1)] {
                assert_eq!(chain.era_for_timestamp(timestamp), era);
            }
        }
    }

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

    #[test]
    fn raw_block_routing_decodes_only_tempo_headers() {
        let chain = &*tempo_chainspec::spec::DEV;
        let decode =
            |bytes: &[u8]| raw_block_timestamp(&RpcParams(json!([Bytes::copy_from_slice(bytes)])));
        let mut header = chain.genesis_header().clone();
        header.inner.timestamp = 123;
        let block = tempo_primitives::Block::new(header, Default::default());
        let mut bytes = alloy_rlp::encode(block);
        assert_eq!(decode(&bytes).unwrap(), 123);
        // Routing must not validate the body with the current release's codec.
        let mut opaque_body = bytes.clone();
        *opaque_body.last_mut().unwrap() = 0xff;
        assert!(tempo_primitives::Block::decode(&mut opaque_body.as_slice()).is_err());
        assert_eq!(decode(&opaque_body).unwrap(), 123);
        for malformed in [vec![0xc0], bytes[..bytes.len() - 1].to_vec()] {
            assert_eq!(decode(&malformed).unwrap_err().code(), -32602);
        }
        bytes.push(0);
        let error = decode(&bytes).unwrap_err();
        assert_eq!(error.code(), -32602);
        assert_eq!(error.message(), "trailing raw block data");
    }
}
