#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use alloy_primitives::{Address, Bytes, B256};
use tempo_payload_builder::{has_expired_transactions, is_more_subblocks};
use tempo_primitives::{
    AASigned, RecoveredSubBlock, SignedSubBlock, SubBlock, SubBlockVersion, TempoSignature,
    TempoTransaction, TempoTxEnvelope,
};

fn make_subblock_with(valid_before: Option<u64>, fee_recipient: Address) -> RecoveredSubBlock {
    let tx = TempoTxEnvelope::AA(AASigned::new_unhashed(
        TempoTransaction {
            valid_before,
            ..Default::default()
        },
        TempoSignature::default(),
    ));
    let signed = SignedSubBlock {
        inner: SubBlock {
            version: SubBlockVersion::V1,
            parent_hash: B256::ZERO,
            fee_recipient,
            transactions: vec![tx],
        },
        signature: Bytes::new(),
    };
    RecoveredSubBlock::new_unchecked(signed, vec![Address::ZERO], B256::ZERO)
}

/// Spec for a subblock in a fuzz scenario.
#[derive(Debug, Arbitrary)]
struct SubblockSpec {
    /// valid_before for the subblock's transaction (None = no expiry).
    valid_before: Option<u16>,
    /// Fee recipient index (mod 4).
    fee_recipient_idx: u8,
}

#[derive(Debug, Arbitrary)]
struct LifecycleInput {
    /// Subblocks in the payload.
    subblocks: Vec<SubblockSpec>,
    /// Block timestamp.
    timestamp: u16,
}

fuzz_target!(|input: LifecycleInput| {
    if input.subblocks.is_empty() || input.subblocks.len() > 50 {
        return;
    }

    let fee_recipients = [
        Address::with_last_byte(1),
        Address::with_last_byte(2),
        Address::with_last_byte(3),
        Address::with_last_byte(4),
    ];

    let ts = input.timestamp as u64;

    let subblocks: Vec<RecoveredSubBlock> = input
        .subblocks
        .iter()
        .map(|spec| {
            let vb = spec.valid_before.map(|v| v as u64);
            let fr = fee_recipients[(spec.fee_recipient_idx % 4) as usize];
            make_subblock_with(vb, fr)
        })
        .collect();

    // Simulate the builder's subblock filtering logic
    let mut retained = Vec::new();
    let mut expired_count = 0;

    for subblock in &subblocks {
        if has_expired_transactions(subblock, ts) {
            expired_count += 1;
        } else {
            retained.push(subblock);
        }
    }

    // Invariant 1: retained + expired = total
    assert_eq!(
        retained.len() + expired_count,
        subblocks.len(),
        "retained {} + expired {} != total {}",
        retained.len(),
        expired_count,
        subblocks.len()
    );

    // Invariant 2: no retained subblock has expired transactions
    for sb in &retained {
        assert!(
            !has_expired_transactions(sb, ts),
            "Retained subblock has expired transactions at timestamp {ts}"
        );
    }

    // Invariant 3: every expired subblock actually has valid_before <= timestamp
    for (i, subblock) in subblocks.iter().enumerate() {
        let expired = has_expired_transactions(subblock, ts);
        let has_vb_le_ts = subblock.transactions.iter().any(|tx| {
            tx.as_aa()
                .is_some_and(|tx| tx.tx().valid_before.is_some_and(|v| v <= ts))
        });
        assert_eq!(
            expired, has_vb_le_ts,
            "Subblock {i}: expired={expired} but has_vb_le_ts={has_vb_le_ts}"
        );
    }

    // Invariant 4: is_more_subblocks(None, _) is always false
    assert!(!is_more_subblocks(None, &subblocks));
});
