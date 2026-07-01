use crate::{node::TempoNode, rpc::TempoEthApi};
use alloy_eips::BlockId;
use alloy_primitives::{Address, B256, keccak256};
use alloy_rpc_types_eth::simulate::SimulatedBlock;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_ethereum::evm::revm::database::StateProviderDatabase;
use reth_node_api::FullNodeTypes;
use reth_node_builder::NodeAdapter;
use reth_primitives_traits::AlloyBlockHeader as _;
use reth_provider::{ChainSpecProvider, DatabaseProviderFactory, HashedPostStateProvider};
use reth_rpc_eth_api::{
    RpcBlock, RpcNodeCore,
    helpers::{EthCall, LoadBlock, LoadState, SpawnBlocking},
};
use reth_rpc_eth_types::EthApiError;
use reth_tracing::tracing;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    sync::LazyLock,
};
use tempo_chainspec::hardfork::TempoHardforks;
use tempo_evm::TempoStateAccess;
use tempo_precompiles::{error::TempoPrecompileError, storage::StorageActions, tip20::TIP20Token};
use tempo_primitives::TempoAddressExt;

/// keccak256("Transfer(address,address,uint256)")
static TRANSFER_TOPIC: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"Transfer(address,address,uint256)"));

/// TIP-20 token metadata returned alongside simulation results.
///
/// `decimals` is omitted because all TIP-20 tokens use a fixed decimal count.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tip20TokenMetadata {
    pub name: String,
    pub symbol: String,
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
pub struct TempoSimulate<N>
where
    N: FullNodeTypes<Types = TempoNode>,
    <N::Provider as DatabaseProviderFactory>::Provider: HashedPostStateProvider,
{
    eth_api: TempoEthApi<NodeAdapter<N>>,
}

impl<N> TempoSimulate<N>
where
    N: FullNodeTypes<Types = TempoNode>,
    <N::Provider as DatabaseProviderFactory>::Provider: HashedPostStateProvider,
{
    pub fn new(eth_api: TempoEthApi<NodeAdapter<N>>) -> Self {
        Self { eth_api }
    }
}

/// Extract TIP-20 addresses from the simulation request's call targets.
///
/// This allows metadata resolution to start before simulation completes.
fn extract_tip20_targets(
    payload: &alloy_rpc_types_eth::simulate::SimulatePayload<
        tempo_alloy::rpc::TempoTransactionRequest,
    >,
) -> Vec<Address> {
    let mut addrs = std::collections::BTreeSet::new();
    for block in &payload.block_state_calls {
        for call in &block.calls {
            // Standard `to` field
            if let Some(to) = call.to.as_ref().and_then(|k| k.to())
                && to.is_tip20()
            {
                addrs.insert(*to);
            }
            // AA calls array
            for c in &call.calls {
                if let Some(to) = c.to.to()
                    && to.is_tip20()
                {
                    addrs.insert(*to);
                }
            }
            // Fee token
            if let Some(ft) = call.fee_token
                && ft.is_tip20()
            {
                addrs.insert(ft);
            }
        }
    }
    addrs.into_iter().collect()
}

#[async_trait::async_trait]
impl<N> TempoSimulateApiServer for TempoSimulate<N>
where
    N: FullNodeTypes<Types = TempoNode>,
    <N::Provider as DatabaseProviderFactory>::Provider: HashedPostStateProvider,
{
    async fn simulate_v1(
        &self,
        payload: alloy_rpc_types_eth::simulate::SimulatePayload<
            tempo_alloy::rpc::TempoTransactionRequest,
        >,
        block: Option<alloy_eips::BlockId>,
    ) -> RpcResult<TempoSimulateV1Response<RpcBlock<tempo_alloy::TempoNetwork>>> {
        // Pre-extract TIP-20 addresses from call targets so we can start
        // metadata resolution concurrently with the simulation.
        let prefetched = extract_tip20_targets(&payload);

        let block = block.unwrap_or_default();
        let base_block = self
            .eth_api
            .recovered_block(block)
            .await?
            .ok_or(EthApiError::HeaderNotFound(block))?;
        let base_block_timestamp = base_block.timestamp();
        let block = BlockId::hash(base_block.hash());

        // Run simulation and metadata prefetch concurrently against the same block.
        let (sim_result, mut token_metadata) = tokio::join!(
            self.eth_api.simulate_v1(payload, Some(block)),
            self.resolve_token_metadata(prefetched, block, base_block_timestamp),
        );

        let blocks = sim_result?;

        // Scan simulation logs for any additional TIP-20 addresses not in the
        // prefetched set (e.g. tokens touched indirectly via contract calls).
        let mut extra = HashSet::new();
        for sim_block in &blocks {
            for call in &sim_block.calls {
                for log in &call.logs {
                    if log.address().is_tip20()
                        && log.topics().first() == Some(&*TRANSFER_TOPIC)
                        && !token_metadata.contains_key(&log.address())
                    {
                        extra.insert(log.address());
                    }
                }
            }
        }

        if !extra.is_empty() {
            let extra_metadata = self
                .resolve_token_metadata(extra.into_iter().collect(), block, base_block_timestamp)
                .await;
            token_metadata.extend(extra_metadata);
        }

        Ok(TempoSimulateV1Response {
            blocks,
            token_metadata,
        })
    }
}

impl<N> TempoSimulate<N>
where
    N: FullNodeTypes<Types = TempoNode>,
    <N::Provider as DatabaseProviderFactory>::Provider: HashedPostStateProvider,
{
    /// Resolves TIP-20 token metadata for the given addresses using state at the target block.
    async fn resolve_token_metadata(
        &self,
        addresses: Vec<Address>,
        block: BlockId,
        timestamp: u64,
    ) -> BTreeMap<Address, Tip20TokenMetadata> {
        if addresses.is_empty() {
            return BTreeMap::new();
        }

        let result = self
            .eth_api
            .spawn_blocking_io_fut(async move |this| {
                let state = this.state_at_block_id(block).await?;
                let spec = this.provider().chain_spec().tempo_hardfork_at(timestamp);
                let mut db = StateProviderDatabase::new(state);

                let metadata =
                    db.with_read_only_storage_ctx(spec, StorageActions::disabled(), || {
                        let mut metadata = BTreeMap::new();

                        for addr in &addresses {
                            let result = (|| {
                                let token = TIP20Token::from_address(*addr)?;
                                Ok::<_, TempoPrecompileError>((
                                    token.name()?,
                                    token.symbol()?,
                                    token.currency()?,
                                ))
                            })();

                            match result {
                                Ok((name, symbol, currency)) => {
                                    metadata.insert(
                                        *addr,
                                        Tip20TokenMetadata {
                                            name,
                                            symbol,
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

                        metadata
                    });

                Ok(metadata)
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
