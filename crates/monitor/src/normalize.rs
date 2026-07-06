//! Normalization helpers from canonical Tempo protocol types into monitor-owned facts.

use alloy_primitives::{Address, B256};
use tempo_hardfork::TempoHardfork;
use tempo_primitives::{TempoHeader, TempoReceipt, TempoTxEnvelope};

use crate::facts::{
    BlockFacts, BlockNumHash, BlockWithParent, FactValue, HeaderFacts, ReceiptFacts,
    TxEnvelopeFacts, TxFacts,
};

pub fn block_facts_from_tempo_header(
    header: &TempoHeader,
    number: u64,
    hash: B256,
    hardfork: TempoHardfork,
) -> BlockFacts {
    BlockFacts {
        reference: BlockWithParent::new(header.inner.parent_hash, BlockNumHash { number, hash }),
        hardfork,
        header: HeaderFacts::from(header),
    }
}

pub fn receipt_facts_from_tempo_receipt(
    block: BlockNumHash,
    tx_hash: B256,
    tx_index: u64,
    receipt: &TempoReceipt,
    previous_cumulative_gas_used: u64,
) -> ReceiptFacts {
    ReceiptFacts::from_tempo_receipt(
        block,
        tx_hash,
        tx_index,
        receipt,
        previous_cumulative_gas_used,
    )
}

pub fn tx_facts_from_tempo_envelope(
    block: BlockNumHash,
    tx_index: u64,
    tx_hash: B256,
    tx: &TempoTxEnvelope,
    sender: Option<Address>,
) -> TxFacts {
    let sender_status = sender.map_or_else(
        || FactValue::Missing {
            reason: "sender unavailable".into(),
        },
        FactValue::Available,
    );
    let fee_payer = sender.map_or_else(
        || FactValue::Missing {
            reason: "sender unavailable".into(),
        },
        |sender| match tx.fee_payer(sender) {
            Ok(fee_payer) => FactValue::Available(fee_payer),
            Err(err) => FactValue::Missing {
                reason: format!("fee payer recovery failed: {err}"),
            },
        },
    );
    let unique_intent = sender.map_or_else(
        || FactValue::Missing {
            reason: "sender unavailable".into(),
        },
        |sender| FactValue::Available(tx.unique_tx_identifier(sender)),
    );

    TxFacts {
        block,
        tx_index,
        tx_hash,
        sender: sender_status,
        is_system: tx.is_system_tx(),
        fee_payer,
        unique_intent,
        envelope: TxEnvelopeFacts::from(tx),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use alloy_consensus::Transaction;
    use alloy_primitives::{B256, Signature, TxKind, U256, address};
    use tempo_hardfork::TempoHardfork;
    use tempo_primitives::{
        TempoHeader, TempoReceipt, TempoTransaction, TempoTxEnvelope,
        transaction::{TEMPO_EXPIRING_NONCE_KEY, envelope::TEMPO_SYSTEM_TX_SENDER},
    };

    use super::*;

    #[test]
    fn block_facts_match_tempo_header_projection() {
        let mut header = TempoHeader::default();
        header.inner.number = 42;
        header.inner.parent_hash = B256::repeat_byte(0x11);
        header.inner.timestamp = 123;
        header.inner.gas_used = 456;
        header.inner.gas_limit = 789;
        header.inner.base_fee_per_gas = Some(10);
        header.inner.beneficiary = address!("0x0000000000000000000000000000000000000001");
        header.general_gas_limit = 100;
        header.shared_gas_limit = 20;
        header.timestamp_millis_part = 321;

        let hash = B256::repeat_byte(0x22);
        let facts =
            block_facts_from_tempo_header(&header, header.inner.number, hash, TempoHardfork::T1);

        assert_eq!(
            facts.reference.block,
            BlockNumHash::new(header.inner.number, hash)
        );
        assert_eq!(facts.reference.parent, header.inner.parent_hash);
        assert_eq!(facts.hardfork, TempoHardfork::T1);
        assert_eq!(facts.header, HeaderFacts::from(&header));
    }

    #[test]
    fn tx_facts_match_tempo_envelope_projection() {
        let sender = address!("0x0000000000000000000000000000000000000002");
        let fee_token = address!("0x0000000000000000000000000000000000000003");
        let to = address!("0x0000000000000000000000000000000000000004");
        let tx = TempoTransaction {
            fee_token: Some(fee_token),
            gas_limit: 55_000,
            nonce_key: TEMPO_EXPIRING_NONCE_KEY,
            nonce: 7,
            valid_before: Some(NonZeroU64::new(1000).unwrap()),
            valid_after: Some(NonZeroU64::new(900).unwrap()),
            calls: vec![tempo_primitives::transaction::Call {
                to: TxKind::Call(to),
                value: U256::from(42),
                input: Default::default(),
            }],
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::AA(tx.into_signed(Signature::test_signature().into()));
        let block = BlockNumHash::new(1, B256::repeat_byte(0xaa));
        let tx_hash = B256::repeat_byte(0xbb);

        let facts = tx_facts_from_tempo_envelope(block, 3, tx_hash, &envelope, Some(sender));

        assert_eq!(facts.block, block);
        assert_eq!(facts.tx_index, 3);
        assert_eq!(facts.tx_hash, tx_hash);
        assert_eq!(facts.sender, FactValue::Available(sender));
        assert_eq!(facts.envelope, TxEnvelopeFacts::from(&envelope));
        assert_eq!(facts.envelope.tx_type, envelope.tx_type());
        assert_eq!(facts.envelope.action, TxKind::Call(to));
        assert!(!facts.is_system);
        assert_eq!(facts.envelope.gas_limit, envelope.gas_limit());
        assert_eq!(facts.envelope.nonce, envelope.nonce());
        assert_eq!(facts.envelope.value, envelope.value());
        assert_eq!(facts.envelope.nonce_key, Some(TEMPO_EXPIRING_NONCE_KEY));
        assert_eq!(facts.envelope.valid_before, NonZeroU64::new(1000));
        assert_eq!(facts.envelope.valid_after, NonZeroU64::new(900));
        assert_eq!(facts.envelope.fee_token, Some(fee_token));
        assert_eq!(
            facts.unique_intent,
            FactValue::Available(envelope.unique_tx_identifier(sender))
        );
        assert!(facts.envelope.is_expiring_nonce());
    }

    #[test]
    fn system_flag_uses_canonical_envelope_semantics_not_sender_only() {
        let envelope = TempoTxEnvelope::AA(
            TempoTransaction::default().into_signed(Signature::test_signature().into()),
        );
        let facts = tx_facts_from_tempo_envelope(
            BlockNumHash::new(1, B256::ZERO),
            0,
            B256::ZERO,
            &envelope,
            Some(TEMPO_SYSTEM_TX_SENDER),
        );
        assert!(!facts.is_system);
    }

    #[test]
    fn receipt_facts_match_tempo_receipt_projection() {
        let receipt = TempoReceipt {
            tx_type: tempo_primitives::TempoTxType::AA,
            success: true,
            cumulative_gas_used: 30,
            logs: Vec::new(),
        };
        let block = BlockNumHash::new(1, B256::repeat_byte(0xaa));
        let facts =
            receipt_facts_from_tempo_receipt(block, B256::repeat_byte(0xcc), 2, &receipt, 11);

        assert_eq!(facts.block, block);
        assert_eq!(facts.tx_hash, B256::repeat_byte(0xcc));
        assert_eq!(facts.tx_index, 2);
        assert_eq!(facts.success, receipt.success);
        assert_eq!(facts.gas_used, FactValue::Available(19));
        assert_eq!(facts.cumulative_gas_used, receipt.cumulative_gas_used);
    }
}
