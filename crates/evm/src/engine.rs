use crate::TempoEvmConfig;
use alloy_consensus::crypto::RecoveryError;
use alloy_primitives::{Address, TxKind, U256, keccak256};
use alloy_sol_types::SolCall;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    FromRecoveredTx, RecoveredTx, ToTxEnv, block::ExecutableTxParts,
};
use reth_primitives_traits::{SealedBlock, SignedTransaction};
use std::sync::Arc;
use tempo_contracts::precompiles::ITIP20;
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::{Block, TempoTxEnvelope, transaction::envelope::TIP20_PAYMENT_PREFIX};
use tempo_revm::TempoTxEnv;

/// TIP-20 `balances` mapping slot index in the contract storage layout.
const TIP20_BALANCES_SLOT: U256 = U256::from_limbs([9, 0, 0, 0]);

/// Computes the storage slot for `TIP20Token.balances[account]`.
///
/// Equivalent to `TIP20Token::from_address(token).balances[account].slot()` from
/// `tempo-precompiles`, inlined here to avoid pulling in that dependency.
/// Uses the same `keccak256(left_pad(key, 32) || slot)` layout as
/// [`StorageKey::mapping_slot`](tempo_precompiles::storage::StorageKey::mapping_slot).
#[inline]
fn tip20_balance_slot(account: Address) -> U256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(account.as_slice());
    buf[32..].copy_from_slice(&TIP20_BALANCES_SLOT.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

/// Warms the global `keccak256` cache with TIP-20 balance storage slots
/// for sender and recipient by decoding transfer-like calldata.
///
/// Called during parallel tx recovery so that subsequent `keccak256` calls
/// at execution time hit the cache instead of rehashing.
fn warm_tip20_balance_slot_keccaks(tx: &TempoTxEnvelope, sender: Address) {
    for (kind, input) in tx.calls() {
        let TxKind::Call(token) = kind else { continue };

        // Only process TIP-20 contracts
        if !token.as_slice().starts_with(&TIP20_PAYMENT_PREFIX) {
            continue;
        }

        let Some(&selector) = input.first_chunk::<4>() else {
            continue;
        };

        match selector {
            // transfer(address to, uint256 amount)
            // transferWithMemo(address to, uint256 amount, bytes32 memo)
            ITIP20::transferCall::SELECTOR | ITIP20::transferWithMemoCall::SELECTOR => {
                if input.len() >= 36 {
                    let recipient = Address::from_slice(&input[16..36]);
                    tip20_balance_slot(sender);
                    tip20_balance_slot(recipient);
                }
            }
            // transferFrom(address from, address to, uint256 amount)
            // transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo)
            ITIP20::transferFromCall::SELECTOR | ITIP20::transferFromWithMemoCall::SELECTOR => {
                if input.len() >= 68 {
                    let from = Address::from_slice(&input[16..36]);
                    let to = Address::from_slice(&input[48..68]);
                    tip20_balance_slot(from);
                    tip20_balance_slot(to);
                }
            }
            _ => {}
        }
    }
}

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

        // Warm the global keccak256 cache with TIP-20 balance storage slots
        // while we're already running in parallel during tx recovery.
        let tx = &block.body().transactions[index];
        warm_tip20_balance_slot_keccaks(tx, sender);

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
        let evm_config = TempoEvmConfig::new(chainspec.clone());

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
        let evm_config = TempoEvmConfig::new(chainspec.clone());

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
        let evm_config = TempoEvmConfig::new(chainspec.clone());

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

    #[test]
    fn test_tip20_balance_slot_matches_mapping_layout() {
        // The balance slot for an account should be keccak256(left_pad(account, 32) || U256(9))
        let account = Address::repeat_byte(0xAB);
        let slot = tip20_balance_slot(account);

        // Manually compute expected value
        let mut buf = [0u8; 64];
        buf[12..32].copy_from_slice(account.as_slice());
        buf[32..].copy_from_slice(&U256::from(9).to_be_bytes::<32>());
        let expected = U256::from_be_bytes(keccak256(buf).0);

        assert_eq!(slot, expected);
    }

    #[test]
    fn test_warm_tip20_balance_slot_keccaks_does_not_panic() {
        use alloy_sol_types::SolCall as _;
        use tempo_contracts::precompiles::ITIP20;

        let sender = Address::repeat_byte(0x01);
        let recipient = Address::repeat_byte(0x02);
        // TIP-20 token address with the 0x20C0 prefix
        let token = Address::new([
            0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);

        // transfer to TIP-20 contract
        let calldata = ITIP20::transferCall {
            to: recipient,
            amount: U256::from(1000),
        }
        .abi_encode();

        let tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(1),
                nonce: 0,
                gas_price: 1,
                gas_limit: 100_000,
                to: TxKind::Call(token),
                value: U256::ZERO,
                input: calldata.into(),
            },
            Signature::test_signature(),
        ));

        // Should not panic — just warms the keccak cache
        warm_tip20_balance_slot_keccaks(&tx, sender);

        // Non-TIP20 target — should be a no-op
        let contract = Address::repeat_byte(0xFF);
        let calldata2 = ITIP20::transferCall {
            to: recipient,
            amount: U256::from(1000),
        }
        .abi_encode();

        let tx2 = TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(1),
                nonce: 0,
                gas_price: 1,
                gas_limit: 100_000,
                to: TxKind::Call(contract),
                value: U256::ZERO,
                input: calldata2.into(),
            },
            Signature::test_signature(),
        ));

        warm_tip20_balance_slot_keccaks(&tx2, sender);

        // Empty calldata — should be a no-op
        let tx3 = TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(1),
                nonce: 0,
                gas_price: 1,
                gas_limit: 21_000,
                to: TxKind::Call(token),
                value: U256::from(1),
                input: Bytes::new(),
            },
            Signature::test_signature(),
        ));

        warm_tip20_balance_slot_keccaks(&tx3, sender);
    }
}
