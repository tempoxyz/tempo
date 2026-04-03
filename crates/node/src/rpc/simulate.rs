use alloy_primitives::{Address, B256, keccak256};
use alloy_rpc_types_eth::simulate::SimulatedBlock;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_ethereum::evm::revm::database::StateProviderDatabase;
use reth_provider::ChainSpecProvider;
use reth_rpc_eth_api::{
    EthApiTypes, RpcBlock,
    helpers::{EthCall, LoadState, SpawnBlocking},
};
use reth_tracing::tracing;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::LazyLock};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_evm::TempoStateAccess;
use tempo_precompiles::{
    error::TempoPrecompileError,
    tip20::{TIP20Token, is_tip20_prefix},
};

/// keccak256("Transfer(address,address,uint256)")
static TRANSFER_TOPIC: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"Transfer(address,address,uint256)"));

/// TIP-20 token metadata returned alongside simulation results.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tip20TokenMetadata {
    pub name: String,
    pub symbol: String,
    #[serde(with = "alloy_serde::quantity")]
    pub decimals: u8,
    pub currency: String,
}

/// Response for `tempo_simulateV1`.
///
/// Wraps the standard `eth_simulateV1` response with a top-level `tokenMetadata` map
/// containing TIP-20 token info for all tokens involved in transfer logs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TempoSimulateV1Response<B> {
    /// Standard simulation results (one per simulated block).
    pub blocks: Vec<SimulatedBlock<B>>,
    /// Token metadata for TIP-20 addresses that appear in Transfer logs.
    pub token_metadata: BTreeMap<Address, Tip20TokenMetadata>,
}

#[rpc(server, namespace = "tempo")]
pub trait TempoSimulateApi {
    /// Simulates transactions like `eth_simulateV1` but enriches the response with
    /// TIP-20 token metadata for all tokens involved in Transfer events.
    ///
    /// This eliminates the need for a second roundtrip to fetch token symbols/decimals
    /// after simulation.
    #[method(name = "simulateV1")]
    async fn simulate_v1(
        &self,
        payload: alloy_rpc_types_eth::simulate::SimulatePayload<
            tempo_alloy::rpc::TempoTransactionRequest,
        >,
        block: Option<alloy_eips::BlockId>,
    ) -> RpcResult<TempoSimulateV1Response<RpcBlock<tempo_alloy::TempoNetwork>>>;
}

/// Implementation of `tempo_simulateV1`.
#[derive(Debug, Clone)]
pub struct TempoSimulate<EthApi> {
    eth_api: EthApi,
}

impl<EthApi> TempoSimulate<EthApi> {
    pub fn new(eth_api: EthApi) -> Self {
        Self { eth_api }
    }
}

#[async_trait::async_trait]
impl<EthApi> TempoSimulateApiServer for TempoSimulate<EthApi>
where
    EthApi: EthCall
        + SpawnBlocking
        + LoadState
        + EthApiTypes<NetworkTypes = tempo_alloy::TempoNetwork>
        + Clone
        + 'static,
    EthApi::Provider: ChainSpecProvider<ChainSpec = TempoChainSpec>,
    EthApi::Error: Into<jsonrpsee::types::ErrorObject<'static>>,
{
    async fn simulate_v1(
        &self,
        payload: alloy_rpc_types_eth::simulate::SimulatePayload<
            tempo_alloy::rpc::TempoTransactionRequest,
        >,
        block: Option<alloy_eips::BlockId>,
    ) -> RpcResult<TempoSimulateV1Response<RpcBlock<tempo_alloy::TempoNetwork>>> {
        let blocks = EthCall::simulate_v1(&self.eth_api, payload, block)
            .await
            .map_err(|e| {
                let err: jsonrpsee::types::ErrorObject<'static> = e.into();
                err
            })?;

        // Collect unique TIP-20 addresses from Transfer logs
        let mut tip20_addresses = std::collections::BTreeSet::new();
        for sim_block in &blocks {
            for call in &sim_block.calls {
                for log in &call.logs {
                    if is_tip20_prefix(log.address())
                        && log.topics().first() == Some(&*TRANSFER_TOPIC)
                    {
                        tip20_addresses.insert(log.address());
                    }
                }
            }
        }

        let token_metadata = if tip20_addresses.is_empty() {
            BTreeMap::new()
        } else {
            let addresses: Vec<Address> = tip20_addresses.into_iter().collect();
            self.resolve_token_metadata(addresses).await
        };

        Ok(TempoSimulateV1Response {
            blocks,
            token_metadata,
        })
    }
}

impl<EthApi> TempoSimulate<EthApi>
where
    EthApi: SpawnBlocking + LoadState + EthApiTypes + Clone + 'static,
    EthApi::Provider: ChainSpecProvider<ChainSpec = TempoChainSpec>,
{
    /// Resolves TIP-20 token metadata for the given addresses using the latest state.
    async fn resolve_token_metadata(
        &self,
        addresses: Vec<Address>,
    ) -> BTreeMap<Address, Tip20TokenMetadata> {
        let result = self
            .eth_api
            .spawn_blocking_io(move |this| {
                let state = this.latest_state()?;
                let spec = this.provider().chain_spec().tempo_hardfork_at(u64::MAX);
                let mut db = StateProviderDatabase::new(state);

                let mut metadata = BTreeMap::new();
                for addr in &addresses {
                    let result = db.with_read_only_storage_ctx(spec, || {
                        let token = TIP20Token::from_address(*addr)?;
                        Ok::<_, TempoPrecompileError>((
                            token.name()?,
                            token.symbol()?,
                            token.decimals()?,
                            token.currency()?,
                        ))
                    });

                    match result {
                        Ok((name, symbol, decimals, currency)) => {
                            metadata.insert(
                                *addr,
                                Tip20TokenMetadata {
                                    name,
                                    symbol,
                                    decimals,
                                    currency,
                                },
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                token = %addr,
                                error = %e,
                                "failed to resolve TIP-20 metadata, skipping"
                            );
                        }
                    }
                }

                Ok::<_, EthApi::Error>(metadata)
            })
            .await;

        match result {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = ?e, "failed to resolve token metadata");
                BTreeMap::new()
            }
        }
    }
}
