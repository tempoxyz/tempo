use alloy_rlp::{Encodable, Header as RlpHeader};
use reth_primitives_traits::RecoveredBlock;
use tempo_primitives::{Block as TempoBlock, RecoveredSubBlock};

/// Conservative allowance for non-transaction block RLP overhead used while the
/// final header is not available yet.
const NON_TRANSACTION_SIZE_ESTIMATE: usize = 2048;

/// Tracks payload RLP size while a block is being built.
///
/// During payload construction this starts with a conservative estimate for the
/// non-transaction portion of the final block. That estimate is used with the
/// recorded transaction payload length to decide whether another candidate
/// transaction can fit under the RLP block size limit.
///
/// Each included transaction's encoded length is recorded as the payload is
/// assembled. Once the block is built, [`Self::finalize`] combines those
/// recorded transaction lengths with the block's actual header, ommers, and
/// withdrawals lengths so the final payload can reuse the tracked size instead
/// of recomputing every transaction length.
#[derive(Debug, Clone)]
pub struct PayloadSizeTracker {
    /// Exact sum of the RLP lengths for transactions already selected for the block.
    ///
    /// This excludes the surrounding RLP transaction-list header. During payload
    /// filling, it is wrapped as a transaction list and combined with
    /// [`Self::estimated_non_transaction_length`] to estimate how much of the
    /// block-size budget remains. At finalization, this is reused as the
    /// transaction list payload length when the tracked transaction count still
    /// matches the built block.
    transactions_payload_length: usize,
    /// Number of transactions represented by [`Self::transactions_payload_length`].
    ///
    /// This is the cheap consistency check that tells [`Self::finalize`] whether
    /// the recorded transaction lengths still describe the built block's
    /// transaction list. If it does not match, finalization falls back to
    /// computing the block's actual RLP length.
    transaction_count: usize,
    /// Conservative fill-time allowance for every non-transaction part of the block.
    ///
    /// Unlike [`Self::transactions_payload_length`], this is not the final exact
    /// header/ommers/withdrawals size. It is the known withdrawals and
    /// `extra_data` RLP length plus a fixed overhead estimate, used only while
    /// deciding whether another candidate transaction can fit within the
    /// remaining RLP block-size budget.
    estimated_non_transaction_length: usize,
}

impl PayloadSizeTracker {
    /// Creates a tracker with the RLP lengths known before transactions are selected.
    ///
    /// `withdrawals_length` must be the RLP encoded withdrawals field length, or
    /// zero when withdrawals are absent. `extra_data_length` must be the RLP
    /// encoded header `extra_data` field length.
    pub fn new(withdrawals_length: usize, extra_data_length: usize) -> Self {
        Self {
            transactions_payload_length: 0,
            transaction_count: 0,
            estimated_non_transaction_length: NON_TRANSACTION_SIZE_ESTIMATE
                + withdrawals_length
                + extra_data_length,
        }
    }

    /// Adds one already-encoded transaction length to the tracked transaction list payload.
    ///
    /// The length must match [`Encodable::length`] for the transaction that will
    /// be included in the final block.
    pub fn add_transaction_length(&mut self, transaction_length: usize) {
        self.transactions_payload_length += transaction_length;
        self.transaction_count += 1;
    }

    /// Adds all transaction lengths from a recovered subblock.
    ///
    /// This records each transaction in the subblock exactly once, which lets
    /// [`Self::finalize`] use the tracked length when the built block has the
    /// same transaction count.
    pub fn add_subblock(&mut self, subblock: &RecoveredSubBlock) {
        self.transaction_count += subblock.transactions.len();
        self.transactions_payload_length += subblock
            .transactions
            .iter()
            .map(Encodable::length)
            .sum::<usize>();
    }

    /// Returns a conservative block size estimate for the transactions tracked so far.
    ///
    /// This is intended for in-progress payload building, before the final
    /// header and exact non-transaction fields are available.
    pub fn estimated_block_size(&self) -> usize {
        self.estimated_block_size_with_transaction_length(0)
    }

    /// Returns a conservative block size estimate including a candidate transaction.
    ///
    /// `transaction_length` is included only in the returned estimate and is not
    /// recorded in the tracker.
    pub fn estimated_block_size_with_transaction_length(&self, transaction_length: usize) -> usize {
        self.estimated_non_transaction_length
            + RlpHeader {
                list: true,
                payload_length: self.transactions_payload_length + transaction_length,
            }
            .length_with_payload()
    }

    /// Returns the final block RLP length using the tracked transaction payload length.
    ///
    /// This uses the built block's actual header, ommers, and withdrawals
    /// lengths, then combines them with the tracked transaction list payload.
    /// If the tracked transaction count does not match the built block, this
    /// falls back to computing the block's actual RLP length.
    pub fn finalize(&self, block: &RecoveredBlock<TempoBlock>) -> usize {
        let body = block.body();
        if self.transaction_count != body.transactions.len() {
            return block.rlp_length();
        }

        Self::block_length(
            block.header().length(),
            self.transactions_payload_length,
            body.ommers.length(),
            body.withdrawals.as_ref().map_or(0, Encodable::length),
        )
    }

    /// Computes the outer block RLP list length from encoded field lengths.
    fn block_length(
        header_length: usize,
        transactions_payload_length: usize,
        ommers_length: usize,
        withdrawals_length: usize,
    ) -> usize {
        let payload_length = header_length
            + RlpHeader {
                list: true,
                payload_length: transactions_payload_length,
            }
            .length_with_payload()
            + ommers_length
            + withdrawals_length;
        RlpHeader {
            list: true,
            payload_length,
        }
        .length_with_payload()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockBody, Signed, TxLegacy};
    use alloy_primitives::{Address, Bytes, U256};
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb_sized;
    use reth_primitives_traits::RecoveredBlock;
    use tempo_primitives::{
        Block, TempoHeader, TempoTxEnvelope, transaction::envelope::TEMPO_SYSTEM_TX_SIGNATURE,
    };

    fn legacy_tx(input: Bytes) -> TempoTxEnvelope {
        TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: None,
                nonce: 0,
                gas_price: 0,
                gas_limit: 0,
                to: Address::random().into(),
                value: U256::ZERO,
                input,
            },
            TEMPO_SYSTEM_TX_SIGNATURE,
        ))
    }

    fn block_with_transactions(transactions: Vec<TempoTxEnvelope>) -> RecoveredBlock<Block> {
        let senders = vec![Address::ZERO; transactions.len()];
        RecoveredBlock::new_unhashed(
            Block {
                header: TempoHeader::default(),
                body: BlockBody {
                    transactions,
                    ommers: vec![],
                    withdrawals: None,
                },
            },
            senders,
        )
    }

    fn arb_block() -> impl Strategy<Value = RecoveredBlock<Block>> {
        // `RecoveredBlock<Block>` has an `Arbitrary` impl, but it recovers arbitrary
        // transaction signatures and can panic. The tracker only needs the body,
        // so wrap an arbitrary block with dummy senders.
        arb_sized::<Block>(4096).prop_map(|block| {
            let senders = vec![Address::ZERO; block.body.transactions.len()];
            RecoveredBlock::new_unhashed(block, senders)
        })
    }

    #[test]
    fn final_size_matches_block_rlp_length() {
        let transactions = vec![
            legacy_tx(Bytes::from(vec![1; 8])),
            legacy_tx(Bytes::from(vec![2; 128])),
            legacy_tx(Bytes::from(vec![3; 1024])),
        ];
        let mut tracker = PayloadSizeTracker::new(0, 0);
        for tx in &transactions {
            tracker.add_transaction_length(tx.length());
        }

        let block = block_with_transactions(transactions);
        assert_eq!(tracker.finalize(&block), block.rlp_length());
    }

    #[test]
    fn final_size_falls_back_when_transaction_count_mismatches() {
        let block = block_with_transactions(vec![legacy_tx(Bytes::from(vec![1; 8]))]);

        assert_eq!(
            PayloadSizeTracker::new(0, 0).finalize(&block),
            block.rlp_length()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn proptest_final_size_matches_rlp_length_for_random_blocks(block in arb_block()) {
            let body = block.body();
            let mut tracker = PayloadSizeTracker::new(
                body.withdrawals.as_ref().map_or(0, Encodable::length),
                block.header().inner.extra_data.length(),
            );

            for tx in &body.transactions {
                tracker.add_transaction_length(tx.length());
            }

            prop_assert_eq!(tracker.transaction_count, body.transactions.len());
            prop_assert_eq!(tracker.finalize(&block), block.rlp_length());
            let sealed = block.clone_sealed_block();
            let mut encoded = Vec::new();
            sealed.encode(&mut encoded);
            prop_assert_eq!(tracker.finalize(&block), encoded.len());
        }
    }
}
