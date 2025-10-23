pub mod dex;

mod request;

pub use dex::TempoDexApiServer;
pub use request::TempoTransactionRequest;

use crate::{TempoNetwork, node::TempoNode};
use alloy::{consensus::TxReceipt, primitives::U256};
use alloy_primitives::Address;
use reth_ethereum::tasks::{
    TaskSpawner,
    pool::{BlockingTaskGuard, BlockingTaskPool},
};
use reth_evm::{
    EvmEnvFor, TxEnvFor,
    revm::{Database, context::result::EVMError},
};
use reth_node_api::{FullNodeComponents, FullNodeTypes, HeaderTy, PrimitivesTy};
use reth_node_builder::{
    NodeAdapter,
    rpc::{EthApiBuilder, EthApiCtx},
};
use reth_provider::ChainSpecProvider;
use reth_rpc::{DynRpcConverter, eth::EthApi};
use reth_rpc_eth_api::{
    EthApiTypes, RpcConverter, RpcNodeCore, RpcNodeCoreExt,
    helpers::{
        AddDevSigners, Call, EthApiSpec, EthBlocks, EthCall, EthFees, EthState, EthTransactions,
        LoadBlock, LoadFee, LoadPendingBlock, LoadReceipt, LoadState, LoadTransaction,
        SpawnBlocking, Trace, estimate::EstimateCall, pending_block::PendingEnvBuilder,
        spec::SignersForRpc,
    },
};
use reth_rpc_eth_types::{
    EthApiError, EthStateCache, FeeHistoryCache, GasPriceOracle, PendingBlock,
    builder::config::PendingBlockKind, receipt::EthReceiptConverter,
};
use tempo_evm::TempoEvmConfig;
use tempo_precompiles::provider::TIPFeeDatabaseExt;
use tempo_primitives::TempoReceipt;
use tempo_revm::TempoTxEnv;
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
    inner: EthApi<NodeAdapter<N>, DynRpcConverter<TempoEvmConfig, TempoNetwork>>,
}

impl<N: FullNodeTypes<Types = TempoNode>> TempoEthApi<N> {
    /// Creates a new `TempoEthApi`.
    pub fn new(
        eth_api: EthApi<NodeAdapter<N>, DynRpcConverter<TempoEvmConfig, TempoNetwork>>,
    ) -> Self {
        Self { inner: eth_api }
    }

    /// Returns the feeToken balance of the tx caller in the token's native decimals
    pub fn caller_fee_token_allowance<DB>(
        &self,
        db: &mut DB,
        env: &TempoTxEnv,
        validator: Address,
    ) -> Result<U256, EthApiError>
    where
        DB: Database<Error: Into<EthApiError>>,
    {
        db.get_fee_token_balance(
            env.fee_payer().map_err(EVMError::<DB::Error>::from)?,
            validator,
            env.fee_token,
        )
        .map_err(Into::into)
    }
}

impl<N: FullNodeTypes<Types = TempoNode>> EthApiTypes for TempoEthApi<N> {
    type Error = EthApiError;
    type NetworkTypes = TempoNetwork;
    type RpcConvert = DynRpcConverter<TempoEvmConfig, TempoNetwork>;

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
    #[inline]
    fn starting_block(&self) -> U256 {
        self.inner.starting_block()
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

    /// Returns the max gas limit that the caller can afford given a transaction environment.
    fn caller_gas_allowance(
        &self,
        mut db: impl Database<Error: Into<EthApiError>>,
        evm_env: &EvmEnvFor<Self::Evm>,
        tx_env: &TxEnvFor<Self::Evm>,
    ) -> Result<u64, Self::Error> {
        let fee_token_balance =
            self.caller_fee_token_allowance(&mut db, tx_env, evm_env.block_env.beneficiary)?;

        Ok(fee_token_balance
            // Calculate the amount of gas the caller can afford with the specified gas price.
            .checked_div(U256::from(tx_env.inner.gas_price))
            // This will be 0 if gas price is 0. It is fine, because we check it before.
            .unwrap_or_default()
            .saturating_to())
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

    fn send_raw_transaction_sync_timeout(&self) -> std::time::Duration {
        self.inner.send_raw_transaction_sync_timeout()
    }

    fn send_raw_transaction(
        &self,
        tx: alloy::primitives::Bytes,
    ) -> impl Future<Output = Result<alloy::primitives::B256, Self::Error>> + Send {
        self.inner.send_raw_transaction(tx)
    }
}

#[derive(Debug, Default)]
pub struct TempoEthApiBuilder;

impl<N> EthApiBuilder<NodeAdapter<N>> for TempoEthApiBuilder
where
    N: FullNodeTypes<Types = TempoNode>,
{
    type EthApi = TempoEthApi<N>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, NodeAdapter<N>>) -> eyre::Result<Self::EthApi> {
        let chain_spec = ctx.components.provider.chain_spec();
        let eth_api = ctx
            .eth_api_builder()
            .modify_gas_oracle_config(|config| config.default_suggested_fee = Some(U256::ZERO))
            .map_converter(|_| {
                RpcConverter::<TempoNetwork, TempoEvmConfig, _>::new(
                    EthReceiptConverter::new(chain_spec).with_builder(
                        |receipt: TempoReceipt, next_log_index, meta| {
                            receipt.into_rpc(next_log_index, meta).into_with_bloom()
                        },
                    ),
                )
                .erased()
            })
            .build();

        Ok(TempoEthApi::new(eth_api))
    }
}
