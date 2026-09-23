use super::*;
use crate::shadow_replay::{ObservedTx, TxOutcome};
use alloy_primitives::{B256, Signature};
use reth_revm::{db::states::StorageSlot, state::AccountInfo};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{AASigned, PrimitiveSignature, TempoSignature},
};

// Synthetic checks exercise the classifier contract; these are NOT TIP-1016 validators.
const GAS: Expectation = Expectation {
    id: "test.gas",
    check: |ctx, field| {
        if field.name != "gas" {
            return None;
        }
        let Boundary::Transaction(index) = ctx.boundary else {
            return None;
        };
        let (real, shadow) = (
            ctx.real.txs[index].as_ref().ok()?,
            ctx.shadow.txs[index].as_ref().ok()?,
        );
        (real.gas_used.checked_add(200) == Some(shadow.gas_used) && real.outcome == shadow.outcome)
            .then_some(())
    },
};

fn block(txs: Vec<TempoTxEnvelope>) -> RecoveredBlock<Block> {
    let mut block = Block::default();
    block.header.inner.base_fee_per_gas = Some(0);
    block.body.transactions = txs;
    let senders = vec![Address::ZERO; block.body.transactions.len()];
    RecoveredBlock::new_unhashed(block, senders)
}

fn evidence(gas: &[u64]) -> Evidence {
    Evidence {
        pre_block: Some(TransitionState::default()),
        post_block: Some(TransitionState::default()),
        txs: gas
            .iter()
            .map(|&gas_used| {
                Ok(ObservedTx {
                    outcome: TxOutcome::Success,
                    gas_used,
                    block_gas_used: 21_000,
                    ..Default::default()
                })
            })
            .collect(),
        failure: None,
    }
}

fn tx_mut(evidence: &mut Evidence, index: usize) -> &mut ObservedTx {
    evidence.txs[index].as_mut().unwrap()
}

fn write_slot(tx: &mut ObservedTx, value: u64, fee: bool) {
    let address = Address::ZERO;
    let slot = U256::ZERO;
    tx.state.transitions.insert(
        address,
        TransitionAccount {
            info: Some(AccountInfo::default()),
            previous_info: Some(AccountInfo::default()),
            storage: [(
                slot,
                StorageSlot::new_changed(U256::from(1_000), U256::from(value)),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    );
    if fee {
        tx.fee.slots.insert((address, slot));
    }
}

#[test]
fn equal_boundaries_do_not_invoke_rules() {
    let rule = Expectation {
        id: "must-not-run",
        check: |_, _| panic!("equal values"),
    };
    let real = evidence(&[21_000, 21_000]);
    let report = Report::analyze(&real, &real, &[&rule], &block(vec![]));
    assert_eq!(report.outcome(&real), ReplayOutcome::Match);
    assert_eq!(report.boundaries_evaluated, 4);
    assert_eq!(report.boundaries_not_evaluated, 0);
}

#[test]
fn accepted_gas_does_not_hide_unrelated_state_at_same_boundary() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_200, 21_000]);
    write_slot(tx_mut(&mut shadow, 0), 800, false);
    let report = Report::analyze(&real, &shadow, &[&GAS], &block(vec![]));
    assert_eq!(report.expected[GAS.id], 1);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.boundaries_not_evaluated, 0);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
}

#[test]
fn fee_provenance_alone_does_not_accept_a_change() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_000, 21_000]);
    write_slot(tx_mut(&mut shadow, 0), 700, true);
    let report = Report::analyze(&real, &shadow, &[], &block(vec![]));
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.boundaries_not_evaluated, 0);
    let field = report.samples[0].1.field;
    assert_eq!(field.name, "storage");
    assert_eq!(field.address, Some(Address::ZERO));
    assert_eq!(field.slot, Some(U256::ZERO));
    assert!(field.fee_associated);
}

#[test]
fn only_verified_fee_amount_is_masked_in_ordered_receipt_logs() {
    let tx: TempoTxEnvelope = AASigned::new_unhashed(
        TempoTransaction {
            max_priority_fee_per_gas: 1_000_000_000_000,
            max_fee_per_gas: 1_000_000_000_000,
            ..Default::default()
        },
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
    )
    .into();
    let original = B256::repeat_byte(1);
    let changed = B256::repeat_byte(2);
    let normalized = B256::repeat_byte(3);
    let mut real = evidence(&[1_000]);
    let mut shadow = evidence(&[1_200]);
    for (tx, amount, hash) in [
        (tx_mut(&mut real, 0), 1_000, original),
        (tx_mut(&mut shadow, 0), 1_200, changed),
    ] {
        tx.receipt_logs_hash = hash;
        tx.fee.log_ranges = std::iter::once(0..1).collect();
        tx.fee_normalized = Some((U256::from(amount), normalized));
    }
    let block = block(vec![tx]);
    let report =
        |shadow: &Evidence, rules: &[&Expectation]| Report::analyze(&real, shadow, rules, &block);
    let accepted = report(&shadow, &[&GAS]);
    assert_eq!(accepted.outcome(&shadow), ReplayOutcome::Expected);
    assert_eq!(accepted.expected[GAS.id], 1);
    assert_eq!(accepted.unexplained, 0);
    // Without a reviewed gas rule, the fee change is still masked, but gas is a finding.
    assert_eq!(report(&shadow, &[]).unexplained, 1);

    let mut wrong = shadow;
    tx_mut(&mut wrong, 0).fee_normalized.as_mut().unwrap().0 += U256::ONE;
    assert_eq!(report(&wrong, &[&GAS]).unexplained, 1);
    tx_mut(&mut wrong, 0).fee_normalized.as_mut().unwrap().0 -= U256::ONE;
    tx_mut(&mut wrong, 0).fee_normalized.as_mut().unwrap().1 = B256::repeat_byte(4);
    assert_eq!(report(&wrong, &[&GAS]).unexplained, 1);
    tx_mut(&mut wrong, 0).fee_normalized.as_mut().unwrap().1 = normalized;
    tx_mut(&mut wrong, 0).fee.log_ranges = std::iter::once(1..2).collect();
    assert_eq!(report(&wrong, &[&GAS]).unexplained, 1);
}

#[test]
fn first_accepting_rule_owns_attribution() {
    let stop = Expectation {
        id: "test.stop-gas",
        check: |_, field| (field.name == "gas").then_some(()),
    };
    let unreachable = Expectation {
        id: "must-not-run",
        check: |_, _| panic!("already accepted"),
    };
    let real = evidence(&[21_000, 21_000]);
    let shadow = evidence(&[21_200, 21_000]);
    for rules in [[&GAS, &stop, &unreachable], [&stop, &GAS, &unreachable]] {
        let report = Report::analyze(&real, &shadow, &rules, &block(vec![]));
        assert_eq!(report.unexplained, 0);
        assert_eq!(report.expected, [(rules[0].id, 1)].into());
    }
}

#[test]
fn rejected_shadow_tx_does_not_hide_later_transaction_findings() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_000, 21_000]);
    shadow.txs[0] = Err("rejected".into());
    tx_mut(&mut shadow, 1).outcome = TxOutcome::Revert;

    let report = Report::analyze(&real, &shadow, &[], &block(vec![]));

    assert_eq!(report.unexplained, 2);
    assert_eq!(report.boundaries_evaluated, 4);
    assert_eq!(report.boundaries_not_evaluated, 0);
    assert_eq!(report.samples[0].1.field.name, "execution");
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
}

#[test]
fn created_code_is_compared_even_when_both_accounts_are_created() {
    let mut real = evidence(&[21_000]);
    let mut shadow = evidence(&[21_000]);
    for (evidence, hash) in [
        (&mut real, B256::repeat_byte(1)),
        (&mut shadow, B256::repeat_byte(2)),
    ] {
        tx_mut(evidence, 0).state.transitions.insert(
            Address::ZERO,
            TransitionAccount {
                info: Some(AccountInfo {
                    code_hash: hash,
                    ..Default::default()
                }),
                previous_info: None,
                ..Default::default()
            },
        );
    }
    let report = Report::analyze(&real, &shadow, &[], &block(vec![]));
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.samples[0].1.field.name, "code");
}

#[test]
fn sampling_does_not_truncate_counts() {
    let real = evidence(&[21_000; 20]);
    let mut shadow = evidence(&[21_000; 20]);
    for tx in &mut shadow.txs {
        tx.as_mut().unwrap().output_hash = B256::repeat_byte(1);
    }
    let report = Report::analyze(&real, &shadow, &[], &block(vec![]));
    assert_eq!(report.unexplained, 20);
    assert_eq!(report.samples.len(), MAX_SAMPLES);
    assert_eq!(report.boundaries_evaluated, 22);
}

#[test]
fn storage_reset_is_compared_without_enumerated_slots() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_000, 21_000]);
    tx_mut(&mut shadow, 0).state.transitions.insert(
        Address::ZERO,
        TransitionAccount {
            info: Some(AccountInfo::default()),
            previous_info: Some(AccountInfo::default()),
            storage_was_destroyed: true,
            ..Default::default()
        },
    );
    let report = Report::analyze(&real, &shadow, &[], &block(vec![]));
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.samples[0].1.field.name, "storage_reset");
    assert_eq!(report.boundaries_not_evaluated, 0);
}

#[test]
fn accepted_post_block_change_is_expected() {
    let real = evidence(&[]);
    let mut shadow = evidence(&[]);
    shadow.post_block.as_mut().unwrap().transitions.insert(
        Address::ZERO,
        TransitionAccount {
            info: Some(AccountInfo {
                balance: U256::from(1),
                ..Default::default()
            }),
            previous_info: Some(AccountInfo::default()),
            ..Default::default()
        },
    );
    let rule = Expectation {
        id: "test.post-block",
        check: |ctx, field| {
            (ctx.boundary == Boundary::PostBlock && field.name == "balance").then_some(())
        },
    };
    let report = Report::analyze(&real, &shadow, &[&rule], &block(vec![]));
    assert_eq!(report.boundaries_not_evaluated, 0);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Expected);
}
