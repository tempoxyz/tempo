//! Reth provider adapter that normalizes finalized blocks into monitor input facts.

use alloy_consensus::{BlockHeader as _, TxReceipt, transaction::TxHashRef as _};
use alloy_eips::BlockHashOrNumber;
use reth_primitives_traits::BlockBody as _;
use reth_storage_api::{BlockIdReader, BlockReader, ReceiptProvider, TransactionVariant};
use tempo_hardfork::TempoHardfork;
use tempo_primitives::{Block as TempoBlock, TempoReceipt};

use crate::{
    input::{
        facts::{BlockNumHash, BlockWithParent, FactValue, OrderedLog, ReceiptFacts},
        normalize::{block_facts_from_tempo_header, tx_facts_from_tempo_envelope},
    },
    processor::FinalizedBlockInput,
    reth::{AdapterError, AdapterResult, FinalizedBlockSource},
};

#[derive(Clone, Debug)]
pub struct RethFinalizedBlockSource<P> {
    provider: P,
    hardfork: TempoHardfork,
}

impl<P> RethFinalizedBlockSource<P> {
    pub const fn new(provider: P, hardfork: TempoHardfork) -> Self {
        Self { provider, hardfork }
    }

    pub const fn provider(&self) -> &P {
        &self.provider
    }
}

impl<P> FinalizedBlockSource for RethFinalizedBlockSource<P>
where
    P: BlockIdReader
        + BlockReader<Block = TempoBlock>
        + ReceiptProvider<Receipt = TempoReceipt>
        + Clone
        + Send
        + Sync,
{
    fn finalized_watermark(&self) -> AdapterResult<Option<BlockNumHash>> {
        self.provider.finalized_block_num_hash().map_err(|err| {
            AdapterError::Retry(format!("failed reading finalized watermark: {err}"))
        })
    }

    fn finalized_block_by_number(&self, number: u64) -> AdapterResult<BlockNumHash> {
        let hash = self
            .provider
            .block_hash(number)
            .map_err(|err| {
                AdapterError::Retry(format!("failed reading block hash {number}: {err}"))
            })?
            .ok_or_else(|| AdapterError::Retry(format!("missing finalized block hash {number}")))?;
        Ok(BlockNumHash { number, hash })
    }

    fn block_input(&self, block: BlockNumHash) -> AdapterResult<FinalizedBlockInput> {
        let recovered = self
            .provider
            .recovered_block(
                BlockHashOrNumber::Hash(block.hash),
                TransactionVariant::NoHash,
            )
            .map_err(|err| {
                AdapterError::Retry(format!("failed reading recovered block {block:?}: {err}"))
            })?
            .ok_or_else(|| AdapterError::Retry(format!("missing recovered block {block:?}")))?;

        if recovered.number() != block.number || recovered.hash() != block.hash {
            return Err(AdapterError::Halt(format!(
                "recovered block identity mismatch: expected {block:?}, got {:?}",
                recovered.num_hash()
            )));
        }

        let header = recovered.header();
        let reference = BlockWithParent::new(header.parent_hash(), block);
        let block_facts =
            block_facts_from_tempo_header(header, block.number, block.hash, self.hardfork);
        let transactions = recovered.body().transactions_iter().collect::<Vec<_>>();
        let senders = recovered.senders();
        if senders.len() != transactions.len() {
            return Err(AdapterError::Retry(format!(
                "sender count {} does not match transaction count {} for {block:?}",
                senders.len(),
                transactions.len()
            )));
        }

        let receipts = self
            .provider
            .receipts_by_block(BlockHashOrNumber::Hash(block.hash))
            .map_err(|err| {
                AdapterError::Retry(format!("failed reading receipts {block:?}: {err}"))
            })?
            .ok_or_else(|| AdapterError::Retry(format!("missing receipts {block:?}")))?;
        if receipts.len() != transactions.len() {
            return Err(AdapterError::Retry(format!(
                "receipt count {} does not match transaction count {} for {block:?}",
                receipts.len(),
                transactions.len()
            )));
        }

        let tx_facts = transactions
            .iter()
            .zip(senders.iter().copied())
            .enumerate()
            .map(|(tx_index, (tx, sender))| {
                tx_facts_from_tempo_envelope(
                    block,
                    tx_index as u64,
                    *tx.tx_hash(),
                    tx,
                    Some(sender),
                )
            })
            .collect::<Vec<_>>();

        let mut previous_cumulative_gas_used = 0;
        let mut receipt_facts = Vec::with_capacity(receipts.len());
        let mut ordered_logs = Vec::new();
        for (tx_index, (tx, receipt)) in transactions.iter().zip(receipts.iter()).enumerate() {
            let tx_hash = *tx.tx_hash();
            receipt_facts.push(ReceiptFacts::from_tempo_receipt(
                block,
                tx_hash,
                tx_index as u64,
                receipt,
                previous_cumulative_gas_used,
            ));
            previous_cumulative_gas_used = receipt.cumulative_gas_used();

            for (receipt_log_index, log) in receipt.logs().iter().enumerate() {
                ordered_logs.push(OrderedLog {
                    block,
                    tx_hash,
                    tx_index: tx_index as u64,
                    log_index: receipt_log_index as u64,
                    emitter: log.address,
                    topics: log.data.topics().to_vec(),
                    data: log.data.data.clone(),
                });
            }
        }

        if tx_facts
            .iter()
            .any(|tx| matches!(tx.sender, FactValue::Missing { .. }))
        {
            return Err(AdapterError::Retry(format!(
                "recovered block produced missing senders for {block:?}"
            )));
        }

        Ok(FinalizedBlockInput {
            reference,
            block_facts,
            tx_facts,
            receipt_facts,
            ordered_logs,
        })
    }

    fn is_known_canonical(&self, block: BlockNumHash) -> AdapterResult<bool> {
        let hash = self.provider.block_hash(block.number).map_err(|err| {
            AdapterError::Retry(format!("failed checking canonical block {block:?}: {err}"))
        })?;
        Ok(hash == Some(block.hash))
    }
}
