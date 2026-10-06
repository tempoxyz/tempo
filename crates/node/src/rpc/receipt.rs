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
    EthApiTypes, RpcConvert,
    helpers::{EthBlocks, LoadReceipt, Trace},
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
        let mut receipt = self
            .inner
            .build_transaction_receipt(tx, meta, receipt, all_receipts, block)
            .await?;

        if recover_address {
            receipt.inner.contract_address = self
                .spawn_trace_transaction_in_block_with_inspector(
                    tx_hash,
                    CreateReceiptInspector::default(),
                    |_, inspector, result, _| {
                        Ok(result
                            .result
                            .is_success()
                            .then_some(inspector.address)
                            .flatten())
                    },
                )
                .await?
                .ok_or(EthApiError::HeaderNotFound(block_hash.into()))?;
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
    ) -> Result<Option<Vec<TempoTransactionReceipt>>, Self::Error> {
        let Some((block, receipts)) = self.load_block_and_receipts(block_id).await? else {
            return Ok(None);
        };
        let recover_addresses = block.transactions_recovered().any(|tx| is_aa_create(&tx));
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

        if recover_addresses {
            let addresses = self
                .trace_block_inspector(
                    block_id,
                    Some(block),
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
