use super::*;
use crate::shadow_replay::ObservedTx;
use alloy_primitives::B256;
use reth_revm::{db::states::StorageSlot, state::AccountInfo};

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
        (real.gas_used.checked_add(200) == Some(shadow.gas_used) && real.success == shadow.success)
            .then_some(())
    },
};

const FEE: Expectation = Expectation {
    id: "test.fee",
    check: |ctx, field| {
        if field.name != "storage" || field.slot != Some(U256::ZERO) {
            return None;
        }
        let Boundary::Transaction(index) = ctx.boundary else {
            return None;
        };
        let (address, slot) = (field.address?, field.slot?);
        let real = ctx.real.txs[index]
            .as_ref()
            .ok()?
            .state
            .transitions
            .get(&address)?
            .storage
            .get(&slot)?;
        let shadow = ctx.shadow.txs[index]
            .as_ref()
            .ok()?
            .state
            .transitions
            .get(&address)?
            .storage
            .get(&slot)?;
        (real.original_value() == shadow.original_value()
            && real.present_value().checked_sub(U256::from(200)) == Some(shadow.present_value()))
        .then_some(())
    },
};

fn evidence(gas: &[u64]) -> Evidence {
    Evidence {
        pre_block: Some(TransitionState::default()),
        post_block: Some(TransitionState::default()),
        txs: gas
            .iter()
            .map(|&gas_used| {
                Ok(ObservedTx {
                    success: true,
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
        tx.fee_slots.insert((address, slot));
    }
}

#[test]
fn equal_boundaries_do_not_invoke_rules() {
    let rule = Expectation {
        id: "must-not-run",
        check: |_, _| panic!("equal values"),
    };
    let real = evidence(&[21_000, 21_000]);
    let report = Report::analyze(&real, &real, &[&rule]);
    assert_eq!(report.outcome(&real), ReplayOutcome::Match);
    assert_eq!(report.boundaries_evaluated, 4);
    assert_eq!(report.boundaries_not_evaluated, 0);
}

#[test]
fn accepted_difference_can_preserve_full_coverage() {
    let real = evidence(&[21_000, 21_000]);
    let shadow = evidence(&[21_200, 21_000]);
    let report = Report::analyze(&real, &shadow, &[&GAS]);
    assert_eq!(report.expected["test.gas"], 1);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Expected);
    assert_eq!(report.boundaries_evaluated, 4);
}

#[test]
fn nearby_incorrect_amount_stays_unexplained() {
    let real = evidence(&[21_000, 21_000]);
    let shadow = evidence(&[21_201, 21_000]);
    let report = Report::analyze(&real, &shadow, &[&GAS]);
    assert!(report.expected.is_empty());
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
}

#[test]
fn accepted_gas_does_not_hide_unrelated_state_at_same_boundary() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_200, 21_000]);
    write_slot(tx_mut(&mut shadow, 0), 800, false);
    let report = Report::analyze(&real, &shadow, &[&GAS]);
    assert_eq!(report.expected[GAS.id], 1);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.boundaries_not_evaluated, 0);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
}

#[test]
fn pre_block_difference_does_not_hide_transaction_findings() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_000, 21_000]);
    shadow.pre_block.as_mut().unwrap().transitions.insert(
        Address::ZERO,
        TransitionAccount {
            info: Some(AccountInfo {
                nonce: 1,
                ..Default::default()
            }),
            previous_info: Some(AccountInfo::default()),
            ..Default::default()
        },
    );
    tx_mut(&mut shadow, 0).success = false;
    let report = Report::analyze(&real, &shadow, &[]);
    assert_eq!(report.unexplained, 2);
    assert_eq!(report.boundaries_evaluated, 4);
    assert_eq!(report.boundaries_not_evaluated, 0);
}

#[test]
fn expected_fee_change_does_not_hide_later_findings() {
    let mut real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_200, 21_000]);
    write_slot(tx_mut(&mut real, 0), 900, true);
    write_slot(tx_mut(&mut shadow, 0), 700, true);
    tx_mut(&mut shadow, 1).success = false;
    let report = Report::analyze(&real, &shadow, &[&GAS, &FEE]);
    assert_eq!(report.expected["test.fee"], 1);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.boundaries_evaluated, 4);
    assert_eq!(report.boundaries_not_evaluated, 0);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
}

#[test]
fn fee_provenance_alone_does_not_accept_a_change() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_000, 21_000]);
    write_slot(tx_mut(&mut shadow, 0), 700, true);
    let report = Report::analyze(&real, &shadow, &[]);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.boundaries_not_evaluated, 0);
    let field = report.samples[0].1.field;
    assert_eq!(field.name, "storage");
    assert_eq!(field.address, Some(Address::ZERO));
    assert_eq!(field.slot, Some(U256::ZERO));
    assert!(field.fee_associated);
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
        let report = Report::analyze(&real, &shadow, &rules);
        assert_eq!(report.unexplained, 0);
        assert_eq!(report.expected, [(rules[0].id, 1)].into());
    }
}

#[test]
fn equal_receipt_gas_does_not_hide_block_gas_divergence() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_000, 21_000]);
    tx_mut(&mut shadow, 0).block_gas_used = 20_000;
    let report = Report::analyze(&real, &shadow, &[&GAS]);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.samples[0].1.field.name, "block_gas");
    assert_eq!(report.samples[0].1.real, "21000");
    assert_eq!(report.samples[0].1.shadow, "20000");
}

#[test]
fn rejected_probe_does_not_hide_later_transaction_findings() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_000, 21_000]);
    shadow.txs[0] = Err("rejected".into());
    tx_mut(&mut shadow, 1).success = false;

    let report = Report::analyze(&real, &shadow, &[]);

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
    let report = Report::analyze(&real, &shadow, &[]);
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
    let report = Report::analyze(&real, &shadow, &[]);
    assert_eq!(report.unexplained, 20);
    assert_eq!(report.samples.len(), MAX_SAMPLES);
    assert_eq!(report.boundaries_evaluated, 22);
}

#[test]
fn equal_and_unsampled_values_are_not_formatted() {
    #[derive(PartialEq, Eq)]
    struct Unformatted(u8);
    impl Debug for Unformatted {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("value should not be formatted");
        }
    }
    let real = evidence(&[21_000; MAX_SAMPLES]);
    let mut shadow = evidence(&[21_000; MAX_SAMPLES]);
    for tx in &mut shadow.txs {
        tx.as_mut().unwrap().output_hash = B256::repeat_byte(1);
    }
    let mut report = Report::analyze(&real, &shadow, &[]);
    let ctx = Context {
        boundary: Boundary::Transaction(0),
        real: &real,
        shadow: &shadow,
    };
    let field = Field {
        name: "output",
        address: None,
        slot: None,
        fee_associated: false,
    };
    report.record(&ctx, field, Unformatted(0), Unformatted(0), &[]);
    let rule = Expectation {
        id: "test.unsampled",
        check: |ctx, field| {
            assert_eq!(ctx.boundary, Boundary::Transaction(0));
            assert_eq!(field.name, "output");
            Some(())
        },
    };
    // Expected samples rank after the full set of unexplained samples, but still count.
    report.record(&ctx, field, Unformatted(0), Unformatted(1), &[&rule]);
    assert_eq!(report.expected[rule.id], 1);
    assert_eq!(report.unexplained, MAX_SAMPLES);
    assert_eq!(report.samples.len(), MAX_SAMPLES);
}

#[test]
fn compares_fee_logs_and_original_log_order_separately() {
    let real = evidence(&[21_000]);
    let rule = Expectation {
        id: "test.application-logs",
        check: |_, field| (field.name == "logs").then_some(()),
    };

    let mut shadow = evidence(&[21_000]);
    tx_mut(&mut shadow, 0).logs_hash = B256::repeat_byte(1);
    tx_mut(&mut shadow, 0).fee_logs_hash = B256::repeat_byte(2);
    let report = Report::analyze(&real, &shadow, &[&rule]);
    assert_eq!(report.expected[rule.id], 1);
    assert_eq!(report.samples[0].1.field.name, "fee_logs");

    let mut shadow = evidence(&[21_000]);
    tx_mut(&mut shadow, 0).receipt_logs_hash = B256::repeat_byte(1);
    let report = Report::analyze(&real, &shadow, &[]);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.samples[0].1.field.name, "receipt_logs");
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
    let report = Report::analyze(&real, &shadow, &[]);
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
    let report = Report::analyze(&real, &shadow, &[&rule]);
    assert_eq!(report.boundaries_not_evaluated, 0);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Expected);
}
