#![no_main]

use std::sync::Arc;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use alloy_consensus::{BlockBody, Signed, TxLegacy};
use alloy_primitives::{Address, Bytes, Signature, B256, U256};
use reth_payload_builder::PayloadId;
use reth_primitives_traits::SealedBlock;
use tempo_payload_builder::{has_expired_transactions, is_more_subblocks};
use tempo_payload_types::TempoBuiltPayload;
use tempo_primitives::{
    AASigned, Block, RecoveredSubBlock, SignedSubBlock, SubBlock, SubBlockMetadata,
    SubBlockVersion, TempoHeader, TempoSignature, TempoTransaction, TempoTxEnvelope,
};

#[derive(Debug, Arbitrary)]
struct LimitsInput {
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Arbitrary)]
enum Scenario {
    /// Test subblock expiry: generate subblocks with various valid_before values
    /// and check against a timestamp.
    SubblockExpiry {
        valid_befores: Vec<Option<u16>>,
        timestamp: u16,
    },
    /// Test is_more_subblocks comparison.
    MoreSubblocks { best_count: u8, new_count: u8 },
}

fn make_subblock(valid_before: Option<u64>) -> RecoveredSubBlock {
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
            fee_recipient: Address::ZERO,
            transactions: vec![tx],
        },
        signature: Bytes::new(),
    };
    RecoveredSubBlock::new_unchecked(signed, vec![Address::ZERO], B256::ZERO)
}

fn make_payload_with_metadata(count: usize) -> TempoBuiltPayload {
    let metadata: Vec<SubBlockMetadata> = (0..count)
        .map(|_| SubBlockMetadata {
            version: SubBlockVersion::V1,
            validator: B256::ZERO,
            fee_recipient: Address::ZERO,
            signature: Bytes::new(),
        })
        .collect();
    let input: Bytes = alloy_rlp::encode(&metadata).into();
    let tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
        TxLegacy {
            chain_id: None,
            nonce: 0,
            gas_price: 0,
            gas_limit: 0,
            to: Address::ZERO.into(),
            value: U256::ZERO,
            input,
        },
        Signature::test_signature(),
    ));
    let block = Block {
        header: TempoHeader::default(),
        body: BlockBody {
            transactions: vec![tx],
            ommers: vec![],
            withdrawals: None,
        },
    };
    let sealed = Arc::new(SealedBlock::seal_slow(block));
    let eth =
        reth_ethereum_engine_primitives::EthBuiltPayload::new(PayloadId::default(), sealed, U256::ZERO, None);
    TempoBuiltPayload::new(eth, None)
}

fuzz_target!(|input: LimitsInput| {
    if input.scenarios.is_empty() || input.scenarios.len() > 100 {
        return;
    }

    for scenario in &input.scenarios {
        match scenario {
            Scenario::SubblockExpiry {
                valid_befores,
                timestamp,
            } => {
                if valid_befores.len() > 50 {
                    continue;
                }
                let ts = *timestamp as u64;

                for vb in valid_befores {
                    let vb64 = vb.map(|v| v as u64);
                    let subblock = make_subblock(vb64);
                    let expired = has_expired_transactions(&subblock, ts);

                    match vb64 {
                        None => assert!(!expired, "No valid_before should not be expired"),
                        Some(v) if v <= ts => assert!(
                            expired,
                            "valid_before {v} <= timestamp {ts} should be expired"
                        ),
                        Some(v) => assert!(
                            !expired,
                            "valid_before {v} > timestamp {ts} should NOT be expired"
                        ),
                    }
                }
            }
            Scenario::MoreSubblocks {
                best_count,
                new_count,
            } => {
                let bc = (*best_count % 10) as usize;
                let nc = (*new_count % 10) as usize;

                // None payload always returns false
                let new_subblocks: Vec<_> = (0..nc).map(|_| make_subblock(None)).collect();
                assert!(
                    !is_more_subblocks(None, &new_subblocks),
                    "is_more_subblocks(None, _) should always be false"
                );

                // With a payload: more iff nc > bc
                let payload = make_payload_with_metadata(bc);
                let result = is_more_subblocks(Some(&payload), &new_subblocks);
                if nc > bc {
                    assert!(
                        result,
                        "expected true: {nc} new subblocks > {bc} best metadata"
                    );
                } else {
                    assert!(
                        !result,
                        "expected false: {nc} new subblocks <= {bc} best metadata"
                    );
                }
            }
        }
    }
});
