//! Recover AA CREATE receipt addresses from execution rather than transaction nonces.

use super::{TempoEthApi, TempoEthApiBounds};
use alloy::consensus::{BlockHeader, Transaction, TxReceipt};
use alloy_eips::BlockId;
use alloy_primitives::Address;
use reth_primitives_traits::{Recovered, RecoveredBlock, TransactionMeta, transaction::TxHashRef};
use reth_revm::{
    Inspector,
    interpreter::{CreateInputs, CreateOutcome, interpreter_types::InterpreterTypes},
};
use reth_rpc_eth_api::{
    EthApiTypes, RpcConvert, RpcNodeCoreExt,
    helpers::{Call, EthBlocks, LoadReceipt, Trace, block::BlockReceiptsResult},
    transaction::ConvertReceiptInput,
};
use reth_rpc_eth_types::EthApiError;
use std::sync::Arc;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_primitives::{Block, TempoReceipt, TempoTxEnvelope};

impl<N> LoadReceipt for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    async fn build_transaction_receipt(
        &self,
        tx: Recovered<TempoTxEnvelope>,
        meta: TransactionMeta,
        receipt: TempoReceipt,
        all_receipts: Option<Arc<Vec<TempoReceipt>>>,
        block: Option<Arc<RecoveredBlock<Block>>>,
    ) -> Result<TempoTransactionReceipt, Self::Error> {
        let recover_address = is_aa_create(&tx);
        let tx_hash = meta.tx_hash;
        let block_hash = meta.block_hash;
        let tx_index = meta.index as usize;
        let replay = if recover_address {
            Some(
                self.cache()
                    .get_recovered_block_and_maybe_bal(block_hash)
                    .await?
                    .ok_or(EthApiError::HeaderNotFound(block_hash.into()))?,
            )
        } else {
            None
        };
        let mut receipt = self
            .inner
            .build_transaction_receipt(tx, meta, receipt, all_receipts, block)
            .await?;

        if let Some((block, bal)) = replay {
            receipt.inner.contract_address = self
                .spawn_with_state_at_block(block.parent_hash(), move |this, mut db| {
                    let tx = block
                        .transactions_recovered()
                        .nth(tx_index)
                        .ok_or(EthApiError::InternalEthError)?;
                    if *tx.tx_hash() != tx_hash {
                        return Err(EthApiError::InternalEthError.into());
                    }
                    let mut inspector = CreateReceiptInspector::default();
                    let (result, _) = this.inspect_transaction_in_block(
                        &block,
                        &mut db,
                        &mut inspector,
                        tx_index,
                        tx,
                        bal.as_deref(),
                    )?;
                    Ok(result
                        .result
                        .is_success()
                        .then_some(inspector.address)
                        .flatten())
                })
                .await?;
        }

        Ok(receipt)
    }
}

impl<N> EthBlocks for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    async fn block_receipts(
        &self,
        block_id: BlockId,
    ) -> BlockReceiptsResult<Self::NetworkTypes, Self::Error> {
        let Some((block, receipts)) = self.load_block_and_receipts(block_id).await? else {
            return Ok(None);
        };
        let last_create = block
            .transactions_recovered()
            .enumerate()
            .filter_map(|(index, tx)| is_aa_create(&tx).then_some(index as u64))
            .last();
        let block_hash = block.hash();
        let mut gas_used = 0;
        let mut next_log_index = 0;
        let inputs = block
            .transactions_recovered()
            .zip(receipts.into_vec())
            .enumerate()
            .map(|(index, (tx, receipt))| {
                let cumulative_gas_used = receipt.cumulative_gas_used();
                let logs_len = receipt.logs().len();
                let input = ConvertReceiptInput {
                    tx,
                    gas_used: cumulative_gas_used - gas_used,
                    next_log_index,
                    meta: TransactionMeta {
                        tx_hash: *tx.tx_hash(),
                        index: index as u64,
                        block_hash,
                        block_number: block.number(),
                        base_fee: block.base_fee_per_gas(),
                        excess_blob_gas: block.excess_blob_gas(),
                        timestamp: block.timestamp(),
                    },
                    receipt,
                };
                gas_used = cumulative_gas_used;
                next_log_index += logs_len;
                input
            })
            .collect();
        let mut receipts = self
            .converter()
            .convert_receipts_with_block(inputs, block.sealed_block())?;

        if let Some(last_create) = last_create {
            let addresses = self
                .trace_block_until_with_inspector(
                    block_id,
                    Some(block),
                    Some(last_create),
                    CreateReceiptInspector::default,
                    |_, mut context| {
                        let recover_address = is_aa_create(&context.tx);
                        let inspector = context.take_inspector();
                        Ok((
                            recover_address,
                            context
                                .result
                                .is_success()
                                .then_some(inspector.address)
                                .flatten(),
                        ))
                    },
                )
                .await?
                .ok_or(EthApiError::HeaderNotFound(block_hash.into()))?;
            for (receipt, (recover_address, address)) in receipts.iter_mut().zip(addresses) {
                if recover_address {
                    receipt.inner.contract_address = address;
                }
            }
        }

        Ok(Some(receipts))
    }
}

fn is_aa_create(tx: &TempoTxEnvelope) -> bool {
    tx.as_aa().is_some() && tx.kind().is_create()
}

#[derive(Clone, Debug, Default)]
struct CreateReceiptInspector {
    address: Option<Address>,
    create_depth: usize,
}

impl<Context, Interpreter: InterpreterTypes, FrameInput, FrameResult>
    Inspector<Context, Interpreter, FrameInput, FrameResult> for CreateReceiptInspector
{
    fn create(
        &mut self,
        _context: &mut Context,
        _inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        self.create_depth += 1;
        None
    }

    fn create_end(
        &mut self,
        _context: &mut Context,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        self.create_depth -= 1;
        if self.create_depth == 0 && self.address.is_none() {
            self.address = outcome.address;
        }
    }
}
