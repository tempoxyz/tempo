use crate::{TempoEvmConfig, TempoTxEnv};
use alloy_consensus::{
    crypto::RecoveryError,
    transaction::{Recovered, TxHashRef},
};
use alloy_primitives::Address;
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnvFor, ExecutableTxIterator, ExecutableTxParts,
    ExecutionCtxFor, RecoveredTx, SenderRecoveryCache,
};
use reth_primitives_traits::{SealedOrRecoveredBlock, SignedTransaction};
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::{Block, TempoTxEnvelope};

impl ConfigureEngineEvm<TempoExecutionData> for TempoEvmConfig {
    fn evm_env_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.evm_env(payload.block.header())
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a TempoExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        let TempoExecutionData { block } = payload;
        self.context_for_block(block)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let block = payload.block.clone();
        let sender_recovery_cache = self.sender_recovery_cache.clone();
        let mut transactions = Vec::with_capacity(block.body().transactions.len());
        let mut expiring_nonce_idx = 0;

        for (idx, tx) in block.body().transactions.iter().enumerate() {
            if tx.is_expiring_nonce() {
                transactions.push((idx, Some(expiring_nonce_idx)));
                expiring_nonce_idx += 1;
            } else {
                transactions.push((idx, None));
            }
        }

        Ok((transactions, move |(index, expiring_nonce_idx)| {
            RecoveredInBlock::new(
                block.clone(),
                index,
                expiring_nonce_idx,
                sender_recovery_cache.as_ref(),
            )
        }))
    }
}

/// A [`reth_evm::execute::ExecutableTxFor`] implementation that contains a pointer to the
/// block and the transaction index, allowing to prepare a [`TempoTxEnv`] without having to
/// clone block or transaction.
#[derive(Clone)]
struct RecoveredInBlock {
    block: SealedOrRecoveredBlock<Block>,
    index: usize,
    sender: Address,
    expiring_nonce_idx: Option<usize>,
}

impl RecoveredInBlock {
    fn new(
        block: SealedOrRecoveredBlock<Block>,
        index: usize,
        expiring_nonce_idx: Option<usize>,
        sender_recovery_cache: Option<&SenderRecoveryCache>,
    ) -> Result<Self, RecoveryError> {
        let recovered_sender = block
            .recovered_block()
            .and_then(|block| block.senders().get(index).copied());
        let tx = &block.body().transactions[index];
        let sender = if let Some(sender) = recovered_sender {
            sender
        } else if tx.is_system_tx() {
            tx.try_recover()?
        } else if let Some(cache) = sender_recovery_cache
            // Recovering keychain and configurable account signatures caches the access key id and
            // verified owner quorums on the transaction, which execution reuses. A sender cache hit
            // would skip that and leave the work to serial execution.
            && !tx.as_aa().is_some_and(|aa| {
                aa.signature().is_keychain() || aa.has_configurable_approvals()
            })
        {
            cache.recover(tx)?
        } else {
            tx.try_recover()?
        };
        Ok(Self {
            block,
            index,
            sender,
            expiring_nonce_idx,
        })
    }
}

impl RecoveredTx<TempoTxEnvelope> for RecoveredInBlock {
    fn tx(&self) -> &TempoTxEnvelope {
        &self.block.body().transactions[self.index]
    }

    fn signer(&self) -> &alloy_primitives::Address {
        &self.sender
    }
}

impl ExecutableTxParts<Recovered<TempoTxEnv>, TempoTxEnvelope> for RecoveredInBlock {
    type Recovered = Self;

    fn into_parts(self) -> (Recovered<TempoTxEnv>, Self::Recovered) {
        let signer = *self.signer();
        // Populate the original envelope's lazy hash before cloning it into the EVM transaction
        // environment so both copies carry the cached value.
        let _ = self.tx().tx_hash();
        let recovered = Recovered::new_unchecked(self.tx().clone(), signer);
        let mut tx_env = TempoTxEnv::from(recovered);
        tx_env.set_expiring_nonce_idx(self.expiring_nonce_idx);
        (Recovered::new_unchecked(tx_env, signer), self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockHeader, SignableTransaction, TxLegacy, transaction::TxHashRef};
    use alloy_primitives::{B256, Bytes, Signature, TxKind, U256};
    use alloy_rlp::{Encodable, bytes::BytesMut};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use rayon::iter::{IntoParallelIterator, ParallelIterator};
    use reth_chainspec::EthChainSpec;
    use reth_evm::{ConfigureEngineEvm, ConvertTx, ExecutableTxTuple};
    use reth_primitives_traits::SealedBlock;
    use std::sync::Arc;
    use tempo_chainspec::{TempoChainSpec, spec::MODERATO};
    use tempo_primitives::{
        AASigned, BlockBody, SubBlockMetadata, TempoHeader, TempoTransaction,
        transaction::{
            ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
            KeychainSignature, PrimitiveSignature, TempoSignature, configurable_account_digest,
            envelope::TEMPO_SYSTEM_TX_SIGNATURE,
        },
    };

    fn create_legacy_tx() -> TempoTxEnvelope {
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 0,
            gas_price: 1,
            gas_limit: 21000,
            to: TxKind::Call(Address::repeat_byte(0x01)),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        TempoTxEnvelope::Legacy(tx.into_signed(Signature::test_signature()))
    }

    fn create_subblock_metadata_tx(chain_id: u64, block_number: u64) -> TempoTxEnvelope {
        let metadata: Vec<SubBlockMetadata> = vec![];
        let mut input = BytesMut::new();
        metadata.encode(&mut input);
        input.extend_from_slice(&U256::from(block_number).to_be_bytes::<32>());

        TempoTxEnvelope::Legacy(
            TxLegacy {
                chain_id: Some(chain_id),
                nonce: 0,
                gas_price: 0,
                gas_limit: 0,
                to: TxKind::Call(Address::ZERO),
                value: U256::ZERO,
                input: input.freeze().into(),
            }
            .into_signed(TEMPO_SYSTEM_TX_SIGNATURE),
        )
    }

    fn create_test_block(transactions: Vec<TempoTxEnvelope>) -> Arc<SealedBlock<Block>> {
        let header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 1,
                timestamp: 1000,
                gas_limit: 30_000_000,
                parent_beacon_block_root: Some(B256::ZERO),
                ..Default::default()
            },
            general_gas_limit: 10_000_000,
            timestamp_millis_part: 500,
            shared_gas_limit: 3_000_000,
            ..Default::default()
        };

        let body = BlockBody {
            transactions,
            ommers: vec![],
            withdrawals: None,
        };

        let block = Block { header, body };
        Arc::new(SealedBlock::seal_slow(block))
    }

    #[test]
    fn test_tx_iterator_for_payload() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(MODERATO.genesis().clone()));
        let sender_recovery_cache = SenderRecoveryCache::new(4);
        let evm_config = TempoEvmConfig::new(chainspec.clone())
            .with_sender_recovery_cache(sender_recovery_cache.clone());

        let tx1 = create_legacy_tx();
        let tx2 = create_legacy_tx();
        let system_tx = create_subblock_metadata_tx(chainspec.chain_id(), 1);
        let tx_hash = *tx1.tx_hash();
        let system_tx_hash = *system_tx.tx_hash();

        let block = create_test_block(vec![tx1, tx2, system_tx]);

        let payload = TempoExecutionData {
            block: block.into(),
        };

        let result = evm_config.tx_iterator_for_payload(&payload);
        assert!(result.is_ok());

        let tuple = result.unwrap();
        let (iter, recover_fn) = tuple.into_parts();
        let items: Vec<_> = iter.into_par_iter().collect();

        // Should have 3 transactions
        assert_eq!(items.len(), 3);

        // Test the recovery function works on all items
        for item in items {
            let recovered = recover_fn.convert(item);
            let recovered = recovered.unwrap();
            let (env, _) = recovered.into_parts();
            assert!(matches!(
                env.execution_context(),
                crate::ExecutionContext::Transaction { .. }
            ));
        }

        assert!(sender_recovery_cache.get(&tx_hash).is_some());
        assert_eq!(sender_recovery_cache.get(&system_tx_hash), None);
    }

    #[test]
    fn test_context_for_payload() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(MODERATO.genesis().clone()));
        let evm_config = TempoEvmConfig::new(chainspec.clone());

        let system_tx = create_subblock_metadata_tx(chainspec.chain_id(), 1);
        let block = create_test_block(vec![system_tx]);
        let payload = TempoExecutionData {
            block: block.into(),
        };

        let result = evm_config.context_for_payload(&payload);
        assert!(result.is_ok());

        let context = result.unwrap();

        // Verify context fields
        assert_eq!(context.general_gas_limit, 10_000_000);
        assert_eq!(context.shared_gas_limit, 3_000_000);
    }

    #[test]
    fn test_evm_env_for_payload() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(MODERATO.genesis().clone()));
        let evm_config = TempoEvmConfig::new(chainspec.clone());

        let system_tx = create_subblock_metadata_tx(chainspec.chain_id(), 1);
        let block = create_test_block(vec![system_tx]);

        let payload = TempoExecutionData {
            block: block.clone().into(),
        };

        let result = evm_config.evm_env_for_payload(&payload);
        assert!(result.is_ok());

        let evm_env = result.unwrap();

        // Verify EVM environment fields
        assert_eq!(evm_env.block.number, U256::from(block.number()));
        assert_eq!(evm_env.block.timestamp, U256::from(block.timestamp()));
        assert_eq!(
            evm_env.block.gas_limit,
            U256::from(block.header().gas_limit())
        );
        assert_eq!(evm_env.block.ext.timestamp_millis_part, 500);
    }

    #[test]
    fn test_sender_cache_skipped_for_keychain_and_configurable_account() {
        let transaction = TempoTransaction {
            chain_id: 1,
            gas_limit: 1_000_000,
            ..Default::default()
        };
        let sig_hash = transaction.signature_hash();
        let signer = PrivateKeySigner::random();

        let holder = Address::repeat_byte(0x11);
        let keychain_tx = TempoTxEnvelope::AA(AASigned::new_unhashed(
            transaction.clone(),
            TempoSignature::Keychain(KeychainSignature::new(
                holder,
                PrimitiveSignature::Secp256k1(
                    signer
                        .sign_hash_sync(&KeychainSignature::signing_hash(sig_hash, holder))
                        .unwrap(),
                ),
            )),
        ));

        let config = ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![ConfigurableAccountOwner {
                owner: signer.address(),
                weight: 1,
            }],
        };
        let account = config.derive_account().unwrap();
        let approval = signer
            .sign_hash_sync(&configurable_account_digest(sig_hash, account, 0))
            .unwrap();
        let configurable_tx = TempoTxEnvelope::AA(AASigned::new_unhashed(
            transaction,
            TempoSignature::ConfigurableAccount(
                ConfigurableAccountSignature::try_new(
                    account,
                    config,
                    vec![PrimitiveSignature::Secp256k1(approval)],
                )
                .unwrap(),
            ),
        ));
        let legacy_tx = create_legacy_tx();

        // Seed the cache with a sender none of the transactions recovers to.
        let cache = SenderRecoveryCache::new(4);
        let cached = Address::repeat_byte(0x22);
        for tx in [&keychain_tx, &configurable_tx, &legacy_tx] {
            assert_eq!(cache.recover_with(tx, |_| Ok(cached)).unwrap(), cached);
        }

        let block: SealedOrRecoveredBlock<Block> =
            create_test_block(vec![keychain_tx, configurable_tx, legacy_tx]).into();
        let sender = |index| {
            RecoveredInBlock::new(block.clone(), index, None, Some(&cache))
                .unwrap()
                .sender
        };

        assert_eq!(sender(0), holder);
        assert_eq!(sender(1), account);
        assert_eq!(sender(2), cached);
    }
}
