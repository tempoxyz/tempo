use crate::TempoEvmConfig;
use alloy_consensus::crypto::RecoveryError;
use alloy_evm::block::ExecutableTxParts;
use alloy_primitives::Address;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    FromRecoveredTx, RecoveredTx, ToTxEnv,
};
use reth_primitives_traits::{SealedBlock, SignedTransaction};
use std::sync::Arc;
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::{Block, TempoTxEnvelope};
use tempo_revm::TempoTxEnv;

impl ConfigureEngineEvm<TempoExecutionData> for TempoEvmConfig {
    fn evm_env_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.evm_env(&payload.block)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a TempoExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        let TempoExecutionData {
            block,
            validator_set,
        } = payload;
        let mut context = self.context_for_block(block)?;

        context.validator_set = validator_set.clone();

        Ok(context)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let block = payload.block.clone();
        let transactions = (0..payload.block.body().transactions.len())
            .into_par_iter()
            .map(move |i| (block.clone(), i));

        Ok((transactions, RecoveredInBlock::new))
    }
}

/// A [`reth_evm::execute::ExecutableTxFor`] implementation that contains a pointer to the
/// block and the transaction index, allowing to prepare a [`TempoTxEnv`] without having to
/// clone block or transaction.
#[derive(Clone)]
struct RecoveredInBlock {
    block: Arc<SealedBlock<Block>>,
    index: usize,
    sender: Address,
}

impl RecoveredInBlock {
    fn new((block, index): (Arc<SealedBlock<Block>>, usize)) -> Result<Self, RecoveryError> {
        let sender = block.body().transactions[index].try_recover()?;
        Ok(Self {
            block,
            index,
            sender,
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

impl ToTxEnv<TempoTxEnv> for RecoveredInBlock {
    fn to_tx_env(&self) -> TempoTxEnv {
        TempoTxEnv::from_recovered_tx(self.tx(), *self.signer())
    }
}

impl ExecutableTxParts<TempoTxEnv, TempoTxEnvelope> for RecoveredInBlock {
    type Recovered = Self;

    fn into_parts(self) -> (TempoTxEnv, Self::Recovered) {
        (self.to_tx_env(), self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockHeader, Signed, TxLegacy};
    use alloy_primitives::{B256, Bytes, Signature, TxKind, U256};
    use alloy_rlp::{Encodable, bytes::BytesMut};
    use rayon::iter::ParallelIterator;
    use reth_chainspec::EthChainSpec;
    use reth_evm::ConfigureEngineEvm;
    use tempo_chainspec::{TempoChainSpec, spec::ANDANTINO};
    use tempo_primitives::{
        BlockBody, SubBlockMetadata, TempoHeader, transaction::envelope::TEMPO_SYSTEM_TX_SIGNATURE,
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
        TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
    }

    fn create_subblock_metadata_tx(chain_id: u64, block_number: u64) -> TempoTxEnvelope {
        let metadata: Vec<SubBlockMetadata> = vec![];
        let mut input = BytesMut::new();
        metadata.encode(&mut input);
        input.extend_from_slice(&U256::from(block_number).to_be_bytes::<32>());

        TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(chain_id),
                nonce: 0,
                gas_price: 0,
                gas_limit: 0,
                to: TxKind::Call(Address::ZERO),
                value: U256::ZERO,
                input: input.freeze().into(),
            },
            TEMPO_SYSTEM_TX_SIGNATURE,
        ))
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
        let chainspec = Arc::new(TempoChainSpec::from_genesis(ANDANTINO.genesis().clone()));
        let evm_config = TempoEvmConfig::new_with_default_factory(chainspec.clone());

        let tx1 = create_legacy_tx();
        let tx2 = create_legacy_tx();
        let system_tx = create_subblock_metadata_tx(chainspec.chain().id(), 1);

        let block = create_test_block(vec![tx1, tx2, system_tx]);

        let payload = TempoExecutionData {
            block,
            validator_set: None,
        };

        let result = evm_config.tx_iterator_for_payload(&payload);
        assert!(result.is_ok());

        let tuple = result.unwrap();
        let (iter, recover_fn): (_, _) = tuple.into();
        let items: Vec<_> = iter.into_par_iter().collect();

        // Should have 3 transactions
        assert_eq!(items.len(), 3);

        // Test the recovery function works on all items
        for item in items {
            let recovered = recover_fn(item);
            assert!(recovered.is_ok());
        }
    }

    #[test]
    fn test_context_for_payload() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(ANDANTINO.genesis().clone()));
        let evm_config = TempoEvmConfig::new_with_default_factory(chainspec.clone());

        let system_tx = create_subblock_metadata_tx(chainspec.chain().id(), 1);
        let block = create_test_block(vec![system_tx]);
        let validator_set = Some(vec![B256::repeat_byte(0x01), B256::repeat_byte(0x02)]);

        let payload = TempoExecutionData {
            block,
            validator_set: validator_set.clone(),
        };

        let result = evm_config.context_for_payload(&payload);
        assert!(result.is_ok());

        let context = result.unwrap();

        // Verify context fields
        assert_eq!(context.general_gas_limit, 10_000_000);
        assert_eq!(context.shared_gas_limit, 3_000_000);
        assert_eq!(context.validator_set, validator_set);
        assert!(context.subblock_fee_recipients.is_empty());
    }

    #[test]
    fn test_evm_env_for_payload() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(ANDANTINO.genesis().clone()));
        let evm_config = TempoEvmConfig::new_with_default_factory(chainspec.clone());

        let system_tx = create_subblock_metadata_tx(chainspec.chain().id(), 1);
        let block = create_test_block(vec![system_tx]);

        let payload = TempoExecutionData {
            block: block.clone(),
            validator_set: None,
        };

        let result = evm_config.evm_env_for_payload(&payload);
        assert!(result.is_ok());

        let evm_env = result.unwrap();

        // Verify EVM environment fields
        assert_eq!(evm_env.block_env.inner.number, U256::from(block.number()));
        assert_eq!(
            evm_env.block_env.inner.timestamp,
            U256::from(block.timestamp())
        );
        assert_eq!(
            evm_env.block_env.inner.gas_limit,
            block.header().gas_limit()
        );
        assert_eq!(evm_env.block_env.timestamp_millis_part, 500);
    }
}
