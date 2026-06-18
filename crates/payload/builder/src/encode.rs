//! Execution block encoding helpers for the payload builder.
//!
//! This module carries transaction-list bytes produced by the roots task into the asynchronous
//! block encoder so payload construction can reuse already encoded transactions while preserving
//! byte-for-byte compatibility with regular RLP block encoding.

use alloy_consensus::BlockHeader as _;
use alloy_eips::eip2718::Typed2718;
use alloy_primitives::Bytes;
use alloy_rlp::Encodable;
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use std::sync::Arc;
use tempo_payload_types::EncodedBlock;
use tempo_primitives::TempoTxEnvelope;
use tracing::warn;

/// RLP transaction-list bytes for the execution block.
///
/// The roots task already encodes every transaction in EIP-2718 form for the transaction trie. This
/// stores those bytes in the form required by the block body transaction list, so the later full
/// block encoder can copy the transaction-list RLP instead of encoding every transaction again.
#[derive(Clone, Debug)]
pub(crate) struct EncodedBlockTransactionList {
    transaction_count: usize,
    /// Complete RLP list for the block body transactions field.
    ///
    /// Legacy transactions are list elements and typed EIP-2718 transactions are string elements.
    rlp: Bytes,
}

impl EncodedBlockTransactionList {
    /// Encodes the block with these already encoded transactions when the transaction count matches.
    ///
    /// Falls back to a full block encoding if the transaction count does not match.
    ///
    /// Returns `true` if the cached transactions were reused.
    fn encode_block_with_transactions(
        &self,
        block: &SealedBlock<tempo_primitives::Block>,
        out: &mut Vec<u8>,
    ) -> bool {
        let body = block.body();
        if body.transactions.len() != self.transaction_count {
            warn!(
                block_number = block.number(),
                block_hash = ?block.hash(),
                block_transactions = body.transactions.len(),
                encoded_transactions = self.transaction_count,
                "cached execution block transaction list did not match block body"
            );
            block.encode(out);
            return false;
        }

        let payload_length = block.header().length()
            + self.rlp.len()
            + body.ommers.length()
            + body.withdrawals.as_ref().map_or(0, Encodable::length);

        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);
        block.header().encode(out);
        // The remaining fields are the block body encoding: transactions, ommers, withdrawals.
        out.extend_from_slice(&self.rlp);
        body.ommers.encode(out);
        if let Some(withdrawals) = &body.withdrawals {
            withdrawals.encode(out);
        }

        true
    }
}

/// Incrementally builds the RLP transaction-list bytes used inside the execution block body.
#[derive(Debug, Default)]
pub(crate) struct EncodedBlockTransactionsBuilder {
    transaction_count: usize,
    payload: Vec<u8>,
}

impl EncodedBlockTransactionsBuilder {
    /// Appends one encoded transaction as a block-body transaction-list element.
    ///
    /// Legacy transaction bytes are already RLP list elements. Typed EIP-2718 transaction bytes are
    /// wrapped as an RLP string so the final transaction list matches regular block encoding.
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

/// Encodes the execution block into the shared cache when dropped.
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
            self.encoded_transactions
                .encode_block_with_transactions(block, &mut encoded);
            encoded.into()
        })
    }
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
    use alloy_primitives::{Address, B256, Bytes, Signature, U256};
    use alloy_rlp::Encodable;
    use proptest::prelude::*;
    use reth_primitives_traits::{RecoveredBlock, SealedBlock};
    use std::sync::Arc;
    use tempo_primitives::{Block, Header, TempoHeader};

    fn arb_address() -> impl Strategy<Value = Address> {
        any::<[u8; 20]>().prop_map(Address::from)
    }

    fn arb_b256() -> impl Strategy<Value = B256> {
        any::<[u8; 32]>().prop_map(B256::from)
    }

    fn arb_bytes(max_len: usize) -> impl Strategy<Value = Bytes> {
        prop::collection::vec(any::<u8>(), 0..=max_len).prop_map(Bytes::from)
    }

    fn arb_u256() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(U256::from_limbs)
    }

    fn arb_legacy_tx() -> impl Strategy<Value = TempoTxEnvelope> {
        (
            prop::option::of(any::<u64>()),
            any::<u64>(),
            any::<u128>(),
            any::<u64>(),
            arb_address(),
            arb_u256(),
            arb_bytes(128),
        )
            .prop_map(
                |(chain_id, nonce, gas_price, gas_limit, to, value, input)| {
                    TempoTxEnvelope::Legacy(Signed::new_unhashed(
                        TxLegacy {
                            chain_id,
                            nonce,
                            gas_price,
                            gas_limit,
                            to: to.into(),
                            value,
                            input,
                        },
                        Signature::test_signature(),
                    ))
                },
            )
    }

    fn arb_eip1559_tx() -> impl Strategy<Value = TempoTxEnvelope> {
        (
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u128>(),
            any::<u128>(),
            arb_address(),
            arb_u256(),
            arb_bytes(128),
        )
            .prop_map(
                |(
                    chain_id,
                    nonce,
                    gas_limit,
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    to,
                    value,
                    input,
                )| {
                    TempoTxEnvelope::Eip1559(Signed::new_unhashed(
                        TxEip1559 {
                            chain_id,
                            nonce,
                            gas_limit,
                            max_fee_per_gas,
                            max_priority_fee_per_gas,
                            to: to.into(),
                            value,
                            access_list: Default::default(),
                            input,
                        },
                        Signature::test_signature(),
                    ))
                },
            )
    }

    fn arb_tx() -> impl Strategy<Value = TempoTxEnvelope> {
        prop_oneof![arb_legacy_tx(), arb_eip1559_tx()]
    }

    fn arb_header() -> impl Strategy<Value = TempoHeader> {
        (
            (
                arb_b256(),
                arb_address(),
                arb_b256(),
                arb_b256(),
                arb_b256(),
            ),
            (
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                arb_bytes(32),
            ),
            (
                prop::option::of(any::<u64>()),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
            ),
        )
            .prop_map(
                |(
                    (parent_hash, beneficiary, state_root, transactions_root, receipts_root),
                    (number, gas_limit, gas_used, timestamp, extra_data),
                    (base_fee_per_gas, general_gas_limit, shared_gas_limit, timestamp_millis_part),
                )| TempoHeader {
                    general_gas_limit,
                    shared_gas_limit,
                    timestamp_millis_part,
                    inner: Header {
                        parent_hash,
                        beneficiary,
                        state_root,
                        transactions_root,
                        receipts_root,
                        number,
                        gas_limit,
                        gas_used,
                        timestamp,
                        extra_data,
                        base_fee_per_gas,
                        ..Default::default()
                    },
                    consensus_context: None,
                },
            )
    }

    fn arb_withdrawals() -> impl Strategy<Value = Option<Withdrawals>> {
        prop::option::of(
            prop::collection::vec(
                (any::<u64>(), any::<u64>(), arb_address(), any::<u64>()),
                0..=4,
            )
            .prop_map(|withdrawals| {
                Withdrawals::new(
                    withdrawals
                        .into_iter()
                        .map(|(index, validator_index, address, amount)| Withdrawal {
                            index,
                            validator_index,
                            address,
                            amount,
                        })
                        .collect(),
                )
            }),
        )
    }

    fn arb_block() -> impl Strategy<Value = Block> {
        (
            arb_header(),
            prop::collection::vec(arb_tx(), 0..=8),
            prop::collection::vec(arb_header(), 0..=2),
            arb_withdrawals(),
        )
            .prop_map(|(mut header, transactions, ommers, withdrawals)| {
                header.inner.withdrawals_root = withdrawals.as_ref().map(|_| B256::ZERO);
                Block {
                    header,
                    body: BlockBody {
                        transactions,
                        ommers,
                        withdrawals,
                    },
                }
            })
    }

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

    fn full_block_encoding(block: &SealedBlock<Block>) -> Vec<u8> {
        let mut expected = Vec::new();
        block.encode(&mut expected);
        expected
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
        assert!(
            encoded_transactions.encode_block_with_transactions(&block, &mut encoded_from_cache)
        );

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
        assert!(!cached_transactions.encode_block_with_transactions(&block, &mut encoded));

        let mut expected = Vec::new();
        block.encode(&mut expected);

        assert_eq!(encoded, expected);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn proptest_encoded_block_transaction_list_matches_alloy_encoding(
            transactions in prop::collection::vec(arb_tx(), 0..=16),
        ) {
            let encoded_transactions = encoded_block_transactions(&transactions);
            let expected = alloy_rlp::encode(&transactions);

            prop_assert_eq!(encoded_transactions.transaction_count, transactions.len());
            prop_assert_eq!(encoded_transactions.rlp.as_ref(), expected.as_slice());
        }

        #[test]
        fn proptest_cached_transaction_list_block_encoding_matches_full_block_encoding(
            block in arb_block(),
        ) {
            let encoded_transactions = encoded_block_transactions(&block.body.transactions);
            let block = SealedBlock::seal_slow(block);
            let expected = full_block_encoding(&block);

            let mut encoded = Vec::new();
            prop_assert!(encoded_transactions.encode_block_with_transactions(
                &block,
                &mut encoded
            ));

            prop_assert_eq!(encoded, expected);
        }

        #[test]
        fn proptest_cached_transaction_list_block_encoding_falls_back_to_full_block_encoding(
            block in arb_block(),
            cached_transactions in prop::collection::vec(arb_tx(), 0..=8),
        ) {
            prop_assume!(cached_transactions.len() != block.body.transactions.len());
            let encoded_transactions = encoded_block_transactions(&cached_transactions);
            let block = SealedBlock::seal_slow(block);
            let expected = full_block_encoding(&block);

            let mut encoded = Vec::new();
            prop_assert!(!encoded_transactions.encode_block_with_transactions(
                &block,
                &mut encoded
            ));

            prop_assert_eq!(encoded, expected);
        }

        #[test]
        fn proptest_execution_block_encoder_matches_full_block_encoding(block in arb_block()) {
            let encoded_transactions = encoded_block_transactions(&block.body.transactions);
            let expected_block = SealedBlock::seal_slow(block.clone());
            let expected = full_block_encoding(&expected_block);
            let senders = vec![Address::ZERO; block.body.transactions.len()];
            let recovered_block = Arc::new(RecoveredBlock::new_unhashed(block, senders));
            let encoder = ExecutionBlockEncoder::new(
                recovered_block,
                expected.len(),
                encoded_transactions,
            );

            prop_assert_eq!(encoder.encode_block().as_ref(), expected.as_slice());
        }
    }
}
