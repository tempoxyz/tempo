use crate::node::TempoNode;
use alloy::{network::Ethereum, primitives::U256};
use reth_ethereum::tasks::{
    TaskSpawner,
    pool::{BlockingTaskGuard, BlockingTaskPool},
};
use reth_node_api::{FullNodeComponents, FullNodeTypes, HeaderTy, PrimitivesTy, TxTy};
use reth_node_builder::{
    NodeAdapter,
    rpc::{EthApiBuilder, EthApiCtx},
};
use reth_node_ethereum::EthereumEthApiBuilder;
use reth_rpc::eth::{EthApi, core::EthRpcConverterFor};
use reth_rpc_eth_api::{
    EthApiTypes, RpcNodeCore, RpcNodeCoreExt,
    helpers::{
        AddDevSigners, Call, EthApiSpec, EthBlocks, EthCall, EthFees, EthState, EthTransactions,
        LoadBlock, LoadFee, LoadPendingBlock, LoadReceipt, LoadState, LoadTransaction,
        SpawnBlocking, Trace,
        estimate::EstimateCall,
        pending_block::PendingEnvBuilder,
        spec::{SignersForApi, SignersForRpc},
    },
};
use reth_rpc_eth_types::{
    EthApiError, EthStateCache, FeeHistoryCache, GasPriceOracle, PendingBlock,
    builder::config::PendingBlockKind,
};
use std::ops::Deref;
use tokio::sync::Mutex;

/// Tempo `Eth` API implementation.
///
/// This type provides the functionality for handling `eth_` related requests.
///
/// This wraps a default `Eth` implementation, and provides additional functionality where the
/// Tempo spec deviates from the default ethereum spec, e.g. gas estimation denominated in
/// `feeToken`
///
/// This type implements the [`FullEthApi`](reth_rpc_eth_api::helpers::FullEthApi) by implemented
/// all the `Eth` helper traits and prerequisite traits.
#[derive(Clone)]
pub struct TempoEthApi<N: FullNodeTypes<Types = TempoNode>> {
    /// Gateway to node's core components.
    inner: EthApi<NodeAdapter<N>, EthRpcConverterFor<NodeAdapter<N>>>,
}

impl<N: FullNodeTypes<Types = TempoNode>> TempoEthApi<N> {
    /// Creates a new `TempoEthApi`.
    pub fn new(eth_api: EthApi<NodeAdapter<N>, EthRpcConverterFor<NodeAdapter<N>>>) -> Self {
        Self { inner: eth_api }
    }
}

// Delegate all methods to the inner EthApi
impl<N: FullNodeTypes<Types = TempoNode>> Deref for TempoEthApi<N> {
    type Target = EthApi<NodeAdapter<N>, EthRpcConverterFor<NodeAdapter<N>>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> EthApiTypes for TempoEthApi<N> {
    type Error = EthApiError;
    type NetworkTypes = Ethereum;
    type RpcConvert = EthRpcConverterFor<NodeAdapter<N>>;

    fn tx_resp_builder(&self) -> &Self::RpcConvert {
        self.inner.tx_resp_builder()
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> RpcNodeCore for TempoEthApi<N> {
    type Primitives = PrimitivesTy<N::Types>;
    type Provider = N::Provider;
    type Pool = <NodeAdapter<N> as FullNodeComponents>::Pool;
    type Evm = <NodeAdapter<N> as FullNodeComponents>::Evm;
    type Network = <NodeAdapter<N> as FullNodeComponents>::Network;

    #[inline]
    fn pool(&self) -> &Self::Pool {
        self.inner.pool()
    }

    #[inline]
    fn evm_config(&self) -> &Self::Evm {
        self.inner.evm_config()
    }

    #[inline]
    fn network(&self) -> &Self::Network {
        self.inner.network()
    }

    #[inline]
    fn provider(&self) -> &Self::Provider {
        self.inner.provider()
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> RpcNodeCoreExt for TempoEthApi<N> {
    #[inline]
    fn cache(&self) -> &EthStateCache<PrimitivesTy<N::Types>> {
        self.inner.cache()
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> EthApiSpec for TempoEthApi<N> {
    type Transaction = TxTy<N::Types>;
    type Rpc = Ethereum;

    #[inline]
    fn starting_block(&self) -> U256 {
        self.inner.starting_block()
    }

    #[inline]
    fn signers(&self) -> &SignersForApi<Self> {
        EthApiSpec::signers(&self.inner)
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> SpawnBlocking for TempoEthApi<N> {
    #[inline]
    fn io_task_spawner(&self) -> impl TaskSpawner {
        self.inner.task_spawner()
    }

    #[inline]
    fn tracing_task_pool(&self) -> &BlockingTaskPool {
        self.inner.blocking_task_pool()
    }

    #[inline]
    fn tracing_task_guard(&self) -> &BlockingTaskGuard {
        self.inner.blocking_task_guard()
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> LoadPendingBlock for TempoEthApi<N> {
    #[inline]
    fn pending_block(&self) -> &Mutex<Option<PendingBlock<Self::Primitives>>> {
        self.inner.pending_block()
    }

    #[inline]
    fn pending_env_builder(&self) -> &dyn PendingEnvBuilder<Self::Evm> {
        self.inner.pending_env_builder()
    }

    #[inline]
    fn pending_block_kind(&self) -> PendingBlockKind {
        self.inner.pending_block_kind()
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> LoadFee for TempoEthApi<N> {
    #[inline]
    fn gas_oracle(&self) -> &GasPriceOracle<Self::Provider> {
        self.inner.gas_oracle()
    }

    #[inline]
    fn fee_history_cache(&self) -> &FeeHistoryCache<HeaderTy<N::Types>> {
        self.inner.fee_history_cache()
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> LoadState for TempoEthApi<N> {}

impl<N: FullNodeTypes<Types = TempoNode>> EthState for TempoEthApi<N> {
    #[inline]
    fn max_proof_window(&self) -> u64 {
        self.inner.eth_proof_window()
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> EthFees for TempoEthApi<N> {}

impl<N: FullNodeTypes<Types = TempoNode>> Trace for TempoEthApi<N> {}

impl<N: FullNodeTypes<Types = TempoNode>> EthCall for TempoEthApi<N> {}

impl<N: FullNodeTypes<Types = TempoNode>> Call for TempoEthApi<N> {
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.max_simulate_blocks()
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> EstimateCall for TempoEthApi<N> {}

impl<N: FullNodeTypes<Types = TempoNode>> AddDevSigners for TempoEthApi<N> {
    fn with_dev_accounts(&self) {
        self.inner.with_dev_accounts()
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> LoadBlock for TempoEthApi<N> {}
impl<N: FullNodeTypes<Types = TempoNode>> LoadReceipt for TempoEthApi<N> {}
impl<N: FullNodeTypes<Types = TempoNode>> EthBlocks for TempoEthApi<N> {}
impl<N: FullNodeTypes<Types = TempoNode>> LoadTransaction for TempoEthApi<N> {}

impl<N: FullNodeTypes<Types = TempoNode>> EthTransactions for TempoEthApi<N> {
    fn signers(&self) -> &SignersForRpc<Self::Provider, Self::NetworkTypes> {
        EthTransactions::signers(&self.inner)
    }

    async fn send_raw_transaction(
        &self,
        tx: alloy::primitives::Bytes,
    ) -> Result<alloy::primitives::B256, Self::Error> {
        self.inner.send_raw_transaction(tx).await
    }
}

#[derive(Debug, Default)]
pub struct TempoEthApiBuilder {
    inner: EthereumEthApiBuilder,
}

impl<N> EthApiBuilder<NodeAdapter<N>> for TempoEthApiBuilder
where
    N: FullNodeTypes<Types = TempoNode>,
{
    type EthApi = TempoEthApi<N>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, NodeAdapter<N>>) -> eyre::Result<Self::EthApi> {
        let eth_api_inner: EthApi<NodeAdapter<N>, _> = self.inner.build_eth_api(ctx).await?;
        Ok(TempoEthApi::new(eth_api_inner))
    }
}
