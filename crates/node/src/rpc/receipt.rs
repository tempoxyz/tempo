//! Recover AA CREATE addresses from the account nonce used by execution.

use super::{TempoEthApi, TempoEthApiBounds, error::TempoEthApiError};
use alloy::consensus::{BlockHeader, Transaction, TxReceipt};
use alloy_eips::BlockId;
use alloy_primitives::Address;
use reth_evm::{ConfigureEvm, Evm};
use reth_primitives_traits::{Recovered, RecoveredBlock, TransactionMeta, transaction::TxHashRef};
use reth_revm::{Database, state::AccountInfo};
use reth_rpc_eth_api::{
    EthApiTypes, RpcConvert, RpcNodeCore, RpcNodeCoreExt,
    helpers::{Call, EthBlocks, LoadReceipt, LoadState, Trace, block::BlockReceiptsResult},
    transaction::ConvertReceiptInput,
};
use reth_rpc_eth_types::EthApiError;
use std::sync::Arc;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_primitives::{Block, TempoReceipt, TempoTxEnvelope, TempoTxType};

impl<N: TempoEthApiBounds> LoadReceipt for TempoEthApi<N> {
    async fn build_transaction_receipt(
        &self,
        tx: Recovered<TempoTxEnvelope>,
        meta: TransactionMeta,
        receipt: TempoReceipt,
        all_receipts: Option<Arc<Vec<TempoReceipt>>>,
        block: Option<Arc<RecoveredBlock<Block>>>,
    ) -> Result<TempoTransactionReceipt, Self::Error> {
        let needs_address = tx.kind().is_create()
            && tx
                .as_aa()
                .is_some_and(|tx| !receipt.success || !tx.tx().nonce_key.is_zero());
        let mut receipt = self
            .inner
            .build_transaction_receipt(tx, meta, receipt, all_receipts, block)
            .await?;
        if needs_address {
            self.set_create_addresses(std::slice::from_mut(&mut receipt), None)
                .await?;
        }
        Ok(receipt)
    }
}

impl<N: TempoEthApiBounds> EthBlocks for TempoEthApi<N> {
    async fn block_receipts(
        &self,
        block_id: BlockId,
    ) -> BlockReceiptsResult<Self::NetworkTypes, Self::Error> {
        let Some((block, receipts)) = self.load_block_and_receipts(block_id).await? else {
            return Ok(None);
        };
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
                        block_hash: block.hash(),
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
        self.set_create_addresses(&mut receipts, Some(block))
            .await?;
        Ok(Some(receipts))
    }
}

impl<N: TempoEthApiBounds> TempoEthApi<N> {
    async fn set_create_addresses(
        &self,
        receipts: &mut [TempoTransactionReceipt],
        block: Option<Arc<RecoveredBlock<Block>>>,
    ) -> Result<(), TempoEthApiError> {
        let mut creates = Vec::new();
        for receipt in receipts {
            if receipt.inner.inner.receipt.tx_type == TempoTxType::AA && receipt.to.is_none() {
                if receipt.inner.inner.receipt.success {
                    creates.push(receipt);
                } else {
                    // The entire batch is atomic, including a successful CREATE followed by a revert.
                    receipt.contract_address = None;
                }
            }
        }
        let Some(first) = creates.first() else {
            return Ok(());
        };
        let block_hash = first.block_hash.ok_or(EthApiError::InternalEthError)?;
        let (block, bal) = match block {
            Some(block) => (block, None),
            None => self
                .cache()
                .get_recovered_block_and_maybe_bal(block_hash)
                .await?
                .ok_or(EthApiError::HeaderNotFound(block_hash.into()))?,
        };
        // Protocol-nonce CREATEs already have the correct address from the normal converter.
        creates.retain(|receipt| {
            block.body().transactions[receipt.transaction_index.unwrap() as usize]
                .as_aa()
                .is_some_and(|tx| !tx.tx().nonce_key.is_zero())
        });
        let targets = creates
            .iter()
            .map(|receipt| (receipt.transaction_index.unwrap() as usize, receipt.from))
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return Ok(());
        }
        let addresses = self
            .spawn_with_state_at_block(block.parent_hash(), move |this, mut db| {
                // Inspect parent state before replay mutates the database.
                let mut nonces = targets
                    .into_iter()
                    .map(|(index, sender)| {
                        let account = db
                            .basic(sender)
                            .map_err(EthApiError::from)?
                            .unwrap_or_default();
                        let nonce = unchanged_parent_nonce(
                            &account,
                            sender,
                            block.transactions_recovered().take(index),
                        );
                        Ok((index, sender, nonce))
                    })
                    .collect::<Result<Vec<_>, TempoEthApiError>>()?;
                if let Some(&(first_index, _, _)) =
                    nonces.iter().find(|(_, _, nonce)| nonce.is_none())
                {
                    this.replay_block_until(&mut db, &block, first_index, bal.as_deref())?;
                    let env = this.evm_env_for_header(block.sealed_block().sealed_header())?;
                    let mut evm = this.evm_config().evm_with_env(&mut db, env);
                    let mut transactions = block.transactions_recovered().skip(first_index);
                    let mut next_index = first_index;
                    for (index, sender, nonce) in
                        nonces.iter_mut().filter(|(_, _, nonce)| nonce.is_none())
                    {
                        // Advance once through the block, stopping before each requested CREATE.
                        let count = *index - next_index;
                        this.replay_transactions_until_with_evm(
                            &mut evm,
                            transactions.by_ref().take(count),
                            count,
                        )?;
                        *nonce = Some(
                            evm.db_mut()
                                .basic(*sender)
                                .map_err(EthApiError::from)?
                                .map_or(0, |account| account.nonce),
                        );
                        next_index = *index;
                    }
                }
                // CREATE cannot carry authorizations, so its address uses the pre-transaction nonce.
                Ok(nonces
                    .into_iter()
                    .map(|(_, sender, nonce)| sender.create(nonce.unwrap()))
                    .collect::<Vec<_>>())
            })
            .await?;
        for (receipt, address) in creates.into_iter().zip(addresses) {
            receipt.contract_address = Some(address);
        }
        Ok(())
    }
}

/// A plain account's nonce cannot change without a transaction or authorization from it.
fn unchanged_parent_nonce<'a>(
    account: &AccountInfo,
    sender: Address,
    mut preceding: impl Iterator<Item = Recovered<&'a TempoTxEnvelope>>,
) -> Option<u64> {
    if !account.is_empty_code_hash()
        || preceding.any(|tx| {
            tx.signer() == sender
                || tx.authorization_list().into_iter().flatten().any(|auth| {
                    auth.recover_authority()
                        .is_ok_and(|authority| authority == sender)
                })
                || tx
                    .tempo_authorization_list()
                    .into_iter()
                    .flatten()
                    .any(|auth| {
                        auth.recover_authority()
                            .is_ok_and(|authority| authority == sender)
                    })
        })
    {
        return None;
    }
    Some(account.nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        consensus::{SignableTransaction, TxEip1559, TxEip7702},
        primitives::{Signature, U256},
        signers::{SignerSync, local::PrivateKeySigner},
    };
    use alloy_eips::eip7702::Authorization;
    use reth_revm::bytecode::Bytecode;
    use tempo_primitives::{TempoTransaction, transaction::TempoSignedAuthorization};

    fn relayed_authorizations(authority: &PrivateKeySigner) -> [Recovered<TempoTxEnvelope>; 2] {
        // Clearing delegation also increments the authority's nonce.
        let auth = Authorization {
            chain_id: U256::from(1),
            address: Address::ZERO,
            nonce: 7,
        };
        let signature = authority.sign_hash_sync(&auth.signature_hash()).unwrap();
        let relayer = Address::repeat_byte(1);
        [
            Recovered::new_unchecked(
                TxEip7702 {
                    authorization_list: vec![auth.clone().into_signed(signature)],
                    ..Default::default()
                }
                .into_signed(Signature::test_signature())
                .into(),
                relayer,
            ),
            Recovered::new_unchecked(
                TempoTransaction {
                    tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
                        auth,
                        signature.into(),
                    )],
                    ..Default::default()
                }
                .into_signed(Signature::test_signature().into())
                .into(),
                relayer,
            ),
        ]
    }

    #[test]
    fn parent_nonce_fast_path_ignores_unrelated_authorizations() {
        let account = AccountInfo {
            nonce: 7,
            ..Default::default()
        };
        let sender = Address::repeat_byte(2);
        let preceding = relayed_authorizations(&PrivateKeySigner::random());
        assert_eq!(
            unchanged_parent_nonce(
                &account,
                sender,
                preceding.iter().map(Recovered::as_recovered_ref)
            ),
            Some(7),
        );
    }

    #[test]
    fn parent_nonce_falls_back_for_possible_nonce_changes() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        let account = AccountInfo {
            nonce: 7,
            ..Default::default()
        };
        for tx in relayed_authorizations(&signer) {
            assert_eq!(
                unchanged_parent_nonce(&account, sender, std::iter::once(tx.as_recovered_ref())),
                None
            );
        }

        let tx: TempoTxEnvelope = TxEip1559::default()
            .into_signed(Signature::test_signature())
            .into();
        let preceding = Recovered::new_unchecked(tx.clone(), sender);
        assert_eq!(
            unchanged_parent_nonce(
                &account,
                sender,
                std::iter::once(preceding.as_recovered_ref())
            ),
            None
        );

        // A third party can call delegated code that executes CREATE in the sender's context.
        let delegated = account.with_code(Bytecode::new_eip7702(Address::repeat_byte(3)));
        let preceding = Recovered::new_unchecked(tx, Address::repeat_byte(1));
        assert_eq!(
            unchanged_parent_nonce(
                &delegated,
                sender,
                std::iter::once(preceding.as_recovered_ref())
            ),
            None
        );
    }
}
