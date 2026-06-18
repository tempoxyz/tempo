use alloy_consensus::BlockHeader as _;
use alloy_eips::eip2718::Typed2718;
use alloy_primitives::{Address, B256, Bloom, Bytes};
use alloy_rlp::Encodable;
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use std::{sync::Arc, time::Instant};
use tempo_payload_types::EncodedBlock;
use tempo_primitives::TempoTxEnvelope;
use tracing::{info, warn};

#[derive(Debug)]
pub(crate) struct RootsTaskResult {
    /// The root hash of the transaction trie.
    pub(crate) transactions_root: B256,
    /// The root hash of the receipts trie.
    pub(crate) receipts_root: B256,
    /// The receipts bloom filter.
    pub(crate) receipts_bloom: Bloom,
    /// The transactions included in the block.
    pub(crate) transactions: Vec<TempoTxEnvelope>,
    /// The senders of the transactions.
    pub(crate) senders: Vec<Address>,
    /// The RLP encoded transaction list for the block body.
    ///
    /// Since roots task already encodes every transaction for the transaction trie,
    /// we can reuse those bytes for the [`ExecutionBlockEncoder`].
    pub(crate) encoded_block_transactions: EncodedBlockTransactionList,
}

/// RLP transaction-list bytes for the execution block.
///
/// The roots task already encodes every transaction in EIP-2718 form for the transaction trie. This
/// stores those bytes in the form required by the block body transaction list, so the later full
/// block encoder can copy the transaction-list RLP instead of encoding every transaction again.
#[derive(Clone, Debug)]
pub(crate) struct EncodedBlockTransactionList {
    transaction_count: usize,
    rlp: Bytes,
}

/// Incrementally builds the RLP transaction-list bytes used inside the execution block body.
#[derive(Debug, Default)]
pub(crate) struct EncodedBlockTransactionsBuilder {
    transaction_count: usize,
    payload: Vec<u8>,
}

impl EncodedBlockTransactionsBuilder {
    pub(crate) fn push(&mut self, transaction: &TempoTxEnvelope, encoded_2718: &[u8]) {
        self.transaction_count += 1;
        if !transaction.is_legacy() {
            alloy_rlp::Header {
                list: false,
                payload_length: encoded_2718.len(),
            }
            .encode(&mut self.payload);
        }
        self.payload.extend_from_slice(encoded_2718);
    }

    pub(crate) fn finish(self) -> EncodedBlockTransactionList {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.payload.len(),
        };
        let mut rlp = Vec::with_capacity(header.length_with_payload());
        header.encode(&mut rlp);
        rlp.extend_from_slice(&self.payload);
        EncodedBlockTransactionList {
            transaction_count: self.transaction_count,
            rlp: rlp.into(),
        }
    }
}

/// Fills the shared encoded execution block cache from a builder background task.
///
/// The payload builder creates this after assembling a recovered block, passes a clone of
/// `encoded_block` into `TempoBuiltPayload`, then moves the encoder into a blocking task. Dropping
/// the encoder performs the actual block RLP encoding unless another consumer has already filled
/// the cache. When available, the encoder reuses transaction-list bytes produced by the roots task
/// instead of encoding every transaction again.
#[derive(Debug)]
pub(crate) struct ExecutionBlockEncoder {
    block: Arc<RecoveredBlock<tempo_primitives::Block>>,
    estimated_rlp_block_size: usize,
    encoded_transactions: EncodedBlockTransactionList,
    encoded_block: EncodedBlock,
}

impl ExecutionBlockEncoder {
    pub(crate) fn new(
        block: Arc<RecoveredBlock<tempo_primitives::Block>>,
        estimated_rlp_block_size: usize,
        encoded_transactions: EncodedBlockTransactionList,
    ) -> Self {
        Self {
            block,
            estimated_rlp_block_size,
            encoded_transactions,
            encoded_block: EncodedBlock::default(),
        }
    }

    pub(crate) fn encoded_block(&self) -> EncodedBlock {
        self.encoded_block.clone()
    }

    pub(crate) fn encode_block(&self) -> &Bytes {
        self.encoded_block.get_or_encode_with(|| {
            let block = self.block.sealed_block();
            let mut encoded = Vec::with_capacity(self.estimated_rlp_block_size);
            let encode_start = Instant::now();
            let reused_encoded_transactions =
                encode_block_with_transactions(block, &self.encoded_transactions, &mut encoded);
            let encode_elapsed = encode_start.elapsed();
            info!(
                block_number = block.number(),
                block_hash = ?block.hash(),
                encoded_size_bytes = encoded.len(),
                reused_encoded_transactions,
                ?encode_elapsed,
                "encoded execution block rlp"
            );
            encoded.into()
        })
    }
}

/// Encodes the block with the given already encoded transactions when the transaction count matches.
///
/// Falls back to a full block encoding if the transaction count does not match.
///
/// Returns `true` if the cached transactions were reused.
fn encode_block_with_transactions(
    block: &SealedBlock<tempo_primitives::Block>,
    transactions: &EncodedBlockTransactionList,
    out: &mut Vec<u8>,
) -> bool {
    let body = block.body();
    if body.transactions.len() != transactions.transaction_count {
        warn!(
            block_number = block.number(),
            block_hash = ?block.hash(),
            block_transactions = body.transactions.len(),
            encoded_transactions = transactions.transaction_count,
            "cached execution block transaction list did not match block body"
        );
        block.encode(out);
        return false;
    }

    let payload_length = block.header().length()
        + transactions.rlp.len()
        + body.ommers.length()
        + body.withdrawals.as_ref().map_or(0, Encodable::length);

    alloy_rlp::Header {
        list: true,
        payload_length,
    }
    .encode(out);
    block.header().encode(out);
    out.extend_from_slice(&transactions.rlp);
    body.ommers.encode(out);
    if let Some(withdrawals) = &body.withdrawals {
        withdrawals.encode(out);
    }

    true
}

impl Drop for ExecutionBlockEncoder {
    fn drop(&mut self) {
        let _ = self.encode_block();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockBody, Signed, TxEip1559, TxLegacy};
    use alloy_eips::{
        eip2718::Encodable2718,
        eip4895::{Withdrawal, Withdrawals},
    };
    use alloy_primitives::{Address, Bytes, Signature, U256};
    use alloy_rlp::Encodable;
    use reth_primitives_traits::SealedBlock;
    use tempo_primitives::{Block, TempoHeader};

    fn legacy_tx(input: Bytes) -> TempoTxEnvelope {
        TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(1),
                nonce: 0,
                gas_price: 1,
                gas_limit: 21_000,
                to: Address::random().into(),
                value: U256::ZERO,
                input,
            },
            Signature::test_signature(),
        ))
    }

    fn eip1559_tx(input: Bytes) -> TempoTxEnvelope {
        TempoTxEnvelope::Eip1559(Signed::new_unhashed(
            TxEip1559 {
                chain_id: 1,
                nonce: 1,
                gas_limit: 21_000,
                max_fee_per_gas: 2,
                max_priority_fee_per_gas: 1,
                to: Address::random().into(),
                value: U256::ZERO,
                access_list: Default::default(),
                input,
            },
            Signature::test_signature(),
        ))
    }

    fn encoded_block_transactions(transactions: &[TempoTxEnvelope]) -> EncodedBlockTransactionList {
        let mut builder = EncodedBlockTransactionsBuilder::default();
        let mut buf = Vec::new();
        for transaction in transactions {
            buf.clear();
            transaction.encode_2718(&mut buf);
            builder.push(transaction, &buf);
        }
        builder.finish()
    }

    #[test]
    fn encoded_block_transaction_list_matches_alloy_encoding() {
        let transactions = vec![
            legacy_tx(Bytes::from_static(b"legacy")),
            eip1559_tx(Bytes::from_static(b"typed")),
        ];

        let encoded_transactions = encoded_block_transactions(&transactions);
        let expected = alloy_rlp::encode(&transactions);

        assert_eq!(encoded_transactions.transaction_count, transactions.len());
        assert_eq!(encoded_transactions.rlp.as_ref(), expected.as_slice());
    }

    #[test]
    fn cached_transaction_list_block_encoding_matches_full_block_encoding() {
        let transactions = vec![
            legacy_tx(Bytes::from_static(b"legacy")),
            eip1559_tx(Bytes::from_static(b"typed")),
        ];
        let encoded_transactions = encoded_block_transactions(&transactions);
        let block = SealedBlock::seal_slow(Block {
            header: TempoHeader::default(),
            body: BlockBody {
                transactions,
                ommers: vec![TempoHeader::default()],
                withdrawals: Some(Withdrawals::new(vec![Withdrawal {
                    index: 1,
                    validator_index: 2,
                    address: Address::random(),
                    amount: 3,
                }])),
            },
        });

        let mut encoded_from_cache = Vec::new();
        assert!(encode_block_with_transactions(
            &block,
            &encoded_transactions,
            &mut encoded_from_cache
        ));

        let mut expected = Vec::new();
        block.encode(&mut expected);

        assert_eq!(encoded_from_cache, expected);
    }

    #[test]
    fn cached_transaction_list_block_encoding_falls_back_on_count_mismatch() {
        let cached_transactions =
            encoded_block_transactions(&[legacy_tx(Bytes::from_static(b"cached"))]);
        let block_transactions = vec![
            legacy_tx(Bytes::from_static(b"legacy")),
            eip1559_tx(Bytes::from_static(b"typed")),
        ];
        let block = SealedBlock::seal_slow(Block {
            header: TempoHeader::default(),
            body: BlockBody {
                transactions: block_transactions,
                ommers: vec![TempoHeader::default()],
                withdrawals: None,
            },
        });

        let mut encoded = Vec::new();
        assert!(!encode_block_with_transactions(
            &block,
            &cached_transactions,
            &mut encoded
        ));

        let mut expected = Vec::new();
        block.encode(&mut expected);

        assert_eq!(encoded, expected);
    }
}
