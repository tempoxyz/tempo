//! Derive AA CREATE receipt addresses from the sender's pre-transaction account nonce.

use super::{TempoEthApi, TempoEthApiBounds};
use alloy::consensus::{BlockHeader, Transaction, TxReceipt};
use alloy_eips::BlockId;
use reth_ethereum::tasks::cancel::is_cancelled;
use reth_evm::{ConfigureEvm, Evm};
use reth_primitives_traits::{Recovered, RecoveredBlock, TransactionMeta, transaction::TxHashRef};
use reth_revm::Database;
use reth_rpc_eth_api::{
    EthApiTypes, RpcConvert, RpcNodeCore, RpcNodeCoreExt,
    helpers::{Call, EthBlocks, LoadReceipt, LoadState, Trace, block::BlockReceiptsResult},
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
        let successful_create = recover_address && receipt.success;
        let tx_hash = meta.tx_hash;
        let block_hash = meta.block_hash;
        let tx_index = meta.index as usize;
        let replay = if successful_create {
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

        if recover_address {
            receipt.inner.contract_address = None;
        }

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
                    this.replay_block_until(&mut db, &block, tx_index, bal.as_deref())?;
                    let nonce = db
                        .basic(tx.signer())
                        .map_err(EthApiError::from)?
                        .map_or(0, |account| account.nonce);
                    Ok(Some(tx.signer().create(nonce)))
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
                .spawn_with_state_at_block(block.parent_hash(), move |this, mut db| {
                    this.apply_pre_execution_changes(&block, &mut db)?;
                    let env = this.evm_env_for_header(block.sealed_block().sealed_header())?;
                    let mut evm = this.evm_config().evm_with_env(&mut db, env);
                    let mut addresses = Vec::new();
                    for tx in block
                        .transactions_recovered()
                        .take(last_create as usize + 1)
                    {
                        if is_cancelled() {
                            return Err(EthApiError::InternalEthError.into());
                        }
                        let recover_address = is_aa_create(&tx);
                        let address = if recover_address {
                            let nonce = evm
                                .db_mut()
                                .basic(tx.signer())
                                .map_err(EthApiError::from)?
                                .map_or(0, |account| account.nonce);
                            Some(tx.signer().create(nonce))
                        } else {
                            None
                        };
                        let result = evm.transact_commit(this.evm_config().tx_env(tx))?;
                        addresses.push((
                            recover_address,
                            result.is_success().then_some(address).flatten(),
                        ));
                    }
                    Ok(addresses)
                })
                .await?;
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
