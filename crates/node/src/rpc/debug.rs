use alloy_eips::eip7685::Requests;
use alloy_primitives::BlockNumber;
use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_evm::{
    ConfigureEvm,
    execute::{BlockExecutionError, Executor},
    revm::database::BundleState,
};
use reth_node_api::{Block as _, NodePrimitives};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_primitives_traits::SignedTransaction;
use reth_provider::{
    BlockReader, ExecutionOutcome, HeaderProvider, StateProviderFactory, TransactionVariant,
};
use reth_ethereum::evm::revm::database::StateProviderDatabase;
use serde::{Deserialize, Serialize};
use tempo_primitives::TempoReceipt;

const MAX_BLOCK_RANGE: u64 = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcExecutionOutcome {
    pub first_block: BlockNumber,
    pub bundle: BundleState,
    pub receipts: Vec<Vec<TempoReceipt>>,
    pub requests: Vec<Requests>,
}

impl From<ExecutionOutcome<TempoReceipt>> for RpcExecutionOutcome {
    fn from(outcome: ExecutionOutcome<TempoReceipt>) -> Self {
        Self {
            first_block: outcome.first_block,
            bundle: outcome.bundle,
            receipts: outcome.receipts,
            requests: outcome.requests,
        }
    }
}

#[rpc(server, namespace = "debug")]
pub trait TempoDebugApi {
    #[method(name = "executeBlockRange")]
    async fn execute_block_range(
        &self,
        from: BlockNumber,
        to: BlockNumber,
    ) -> RpcResult<RpcExecutionOutcome>;
}

pub struct TempoDebugRpc<E, P> {
    evm_config: E,
    provider: P,
}

impl<E, P> TempoDebugRpc<E, P> {
    pub fn new(evm_config: E, provider: P) -> Self {
        Self {
            evm_config,
            provider,
        }
    }
}

#[async_trait]
impl<E, P> TempoDebugApiServer for TempoDebugRpc<E, P>
where
    E: ConfigureEvm<Primitives: NodePrimitives<Block = P::Block, Receipt = TempoReceipt>>
        + 'static,
    P: BlockReader<Transaction: SignedTransaction>
        + HeaderProvider
        + StateProviderFactory
        + Clone
        + 'static,
{
    async fn execute_block_range(
        &self,
        from: BlockNumber,
        to: BlockNumber,
    ) -> RpcResult<RpcExecutionOutcome> {
        if from == 0 {
            return Err(internal_rpc_err("`from` must be >= 1"));
        }
        if from > to {
            return Err(internal_rpc_err("`from` must be <= `to`"));
        }
        let len = to
            .checked_sub(from)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| internal_rpc_err("invalid block range"))?;
        if len > MAX_BLOCK_RANGE {
            return Err(internal_rpc_err(format!(
                "block range too large (max {MAX_BLOCK_RANGE})"
            )));
        }

        let provider = self.provider.clone();
        let evm_config = self.evm_config.clone();

        let outcome = tokio::task::spawn_blocking(move || {
            execute_range(&evm_config, &provider, from, to)
        })
        .await
        .map_err(|e| internal_rpc_err(format!("task join error: {e}")))?
        .map_err(|e| internal_rpc_err(format!("{e}")))?;

        Ok(outcome.into())
    }
}

fn execute_range<E, P>(
    evm_config: &E,
    provider: &P,
    from: BlockNumber,
    to: BlockNumber,
) -> Result<ExecutionOutcome<TempoReceipt>, BlockExecutionError>
where
    E: ConfigureEvm<Primitives: NodePrimitives<Block = P::Block, Receipt = TempoReceipt>>,
    P: BlockReader<Transaction: SignedTransaction> + HeaderProvider + StateProviderFactory,
{
    let state_provider = provider
        .history_by_block_number(from.saturating_sub(1))
        .map_err(BlockExecutionError::other)?;

    let mut executor = evm_config.batch_executor(StateProviderDatabase::new(state_provider));

    let mut results = Vec::new();

    for block_number in from..=to {
        let block = provider
            .sealed_block_with_senders(block_number.into(), TransactionVariant::WithHash)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| {
                BlockExecutionError::other(reth_provider::ProviderError::HeaderNotFound(
                    block_number.into(),
                ))
            })?;

        let (block, senders) = block.split_sealed();
        let (header, body) = block.split_sealed_header_body();
        let block = P::Block::new_sealed(header, body).with_senders(senders);

        results.push(executor.execute_one(&block)?);
    }

    Ok(ExecutionOutcome::from_blocks(
        from,
        executor.into_state().take_bundle(),
        results,
    ))
}
