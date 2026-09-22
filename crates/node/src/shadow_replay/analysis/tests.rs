use super::*;
use crate::shadow_replay::{Failure, ObservedTx, ReceiptObservation};
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
        let (real, shadow) = (&ctx.real.txs[index].receipt, &ctx.shadow.txs[index].receipt);
        (real.gas_used.checked_add(200) == Some(shadow.gas_used) && real.success == shadow.success)
            .then_some(false)
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
            .state
            .transitions
            .get(&address)?
            .storage
            .get(&slot)?;
        let shadow = ctx.shadow.txs[index]
            .state
            .transitions
            .get(&address)?
            .storage
            .get(&slot)?;
        (real.original_value() == shadow.original_value()
            && real.present_value().checked_sub(U256::from(200)) == Some(shadow.present_value()))
        .then_some(true)
    },
};

fn evidence(gas: &[u64]) -> Evidence {
    Evidence {
        pre_block: Some(TransitionState::default()),
        post_block: Some(TransitionState::default()),
        txs: gas
            .iter()
            .map(|&gas_used| ObservedTx {
                receipt: ReceiptObservation {
                    success: true,
                    gas_used,
                    logs_hash: B256::ZERO,
                },
                block_gas_used: 21_000,
                output_hash: B256::ZERO,
                logs_hash: B256::ZERO,
                fee_logs_hash: B256::ZERO,
                fee_slots: HashSet::new(),
                state: TransitionState::default(),
            })
            .collect(),
        failure: None,
    }
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
    assert_eq!(report.cutoff, None);
}

#[test]
fn nearby_incorrect_amount_stays_unexplained() {
    let real = evidence(&[21_000, 21_000]);
    let shadow = evidence(&[21_201, 21_000]);
    let report = Report::analyze(&real, &shadow, &[&GAS]);
    assert!(report.expected.is_empty());
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.cutoff, Some(Boundary::Transaction(0)));
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
}

#[test]
fn accepted_gas_does_not_hide_unrelated_state_at_same_boundary() {
    let stop = Expectation {
        id: "test.stop-gas",
        check: |ctx, diff| (GAS.check)(ctx, diff).map(|_| true),
    };
    for rule in [&GAS, &stop] {
        let real = evidence(&[21_000, 21_000]);
        let mut shadow = evidence(&[21_200, 21_000]);
        write_slot(&mut shadow.txs[0], 800, false);
        let report = Report::analyze(&real, &shadow, &[rule]);
        assert_eq!(report.expected[rule.id], 1);
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.boundaries_not_evaluated, 2);
        assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
    }
}

#[test]
fn pre_block_cutoff_invalidates_all_transactions() {
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
    shadow.txs[0].receipt.success = false;
    let report = Report::analyze(&real, &shadow, &[]);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.cutoff, Some(Boundary::PreBlock));
    assert_eq!(report.boundaries_evaluated, 1);
    assert_eq!(report.boundaries_not_evaluated, 3);
}

#[test]
fn expected_fee_change_cuts_off_dependent_findings() {
    let mut real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_200, 21_000]);
    write_slot(&mut real.txs[0], 900, true);
    write_slot(&mut shadow.txs[0], 700, true);
    shadow.txs[1].receipt.success = false;
    let report = Report::analyze(&real, &shadow, &[&GAS, &FEE]);
    assert_eq!(report.expected["test.fee"], 1);
    assert_eq!(report.unexplained, 0);
    assert_eq!(report.boundaries_evaluated, 2);
    assert_eq!(report.boundaries_not_evaluated, 2);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Inconclusive);
}

#[test]
fn fee_provenance_alone_does_not_accept_a_change() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_000, 21_000]);
    write_slot(&mut shadow.txs[0], 700, true);
    let report = Report::analyze(&real, &shadow, &[]);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.cutoff, Some(Boundary::Transaction(0)));
    assert_eq!(report.boundaries_not_evaluated, 2);
    let field = report.samples[0].1.field;
    assert_eq!(field.name, "storage");
    assert_eq!(field.address, Some(Address::ZERO));
    assert_eq!(field.slot, Some(U256::ZERO));
    assert!(field.fee_associated);
}

#[test]
fn first_accepting_rule_owns_attribution_and_continuation() {
    let stop = Expectation {
        id: "test.stop-gas",
        check: |_, field| (field.name == "gas").then_some(true),
    };
    let unreachable = Expectation {
        id: "must-not-run",
        check: |_, _| panic!("already accepted"),
    };
    let real = evidence(&[21_000, 21_000]);
    let shadow = evidence(&[21_200, 21_000]);
    for (rules, cutoff) in [
        ([&GAS, &stop, &unreachable], None),
        ([&stop, &GAS, &unreachable], Some(Boundary::Transaction(0))),
    ] {
        let report = Report::analyze(&real, &shadow, &rules);
        assert_eq!(report.unexplained, 0);
        assert_eq!(report.expected, [(rules[0].id, 1)].into());
        assert_eq!(report.cutoff, cutoff);
    }
}

#[test]
fn equal_receipt_gas_does_not_hide_block_gas_divergence() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_000, 21_000]);
    shadow.txs[0].block_gas_used = 20_000;
    let report = Report::analyze(&real, &shadow, &[&GAS]);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.cutoff, Some(Boundary::Transaction(0)));
    assert_eq!(report.samples[0].1.field.name, "block_gas");
    assert_eq!(report.samples[0].1.real, "21000");
    assert_eq!(report.samples[0].1.shadow, "20000");
}

#[test]
fn rejection_outcome_depends_on_a_prior_cutoff() {
    let rule = Expectation {
        id: "test.gas-cutoff",
        check: |ctx, diff| (GAS.check)(ctx, diff).map(|_| true),
    };
    let real = evidence(&[21_000, 21_000]);
    for (gas, boundary, rules, outcome, missing) in [
        (
            &[21_200][..],
            Boundary::Transaction(1),
            &[&rule][..],
            ReplayOutcome::Inconclusive,
            2,
        ),
        (
            &[][..],
            Boundary::Transaction(0),
            &[][..],
            ReplayOutcome::Findings,
            3,
        ),
    ] {
        let mut shadow = evidence(gas);
        shadow.post_block = None;
        shadow.failure = Some(Failure {
            boundary,
            error: "rejected".into(),
        });
        let report = Report::analyze(&real, &shadow, rules);
        assert_eq!(report.outcome(&shadow), outcome);
        assert_eq!(report.boundaries_not_evaluated, missing);
    }
}

#[test]
fn created_code_is_compared_even_when_both_accounts_are_created() {
    let mut real = evidence(&[21_000]);
    let mut shadow = evidence(&[21_000]);
    for (evidence, hash) in [
        (&mut real, B256::repeat_byte(1)),
        (&mut shadow, B256::repeat_byte(2)),
    ] {
        evidence.txs[0].state.transitions.insert(
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
    assert_eq!(report.cutoff, Some(Boundary::Transaction(0)));
}

#[test]
fn sampling_does_not_truncate_counts() {
    let real = evidence(&[21_000; 20]);
    let mut shadow = evidence(&[21_000; 20]);
    for tx in &mut shadow.txs {
        tx.output_hash = B256::repeat_byte(1);
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
        tx.output_hash = B256::repeat_byte(1);
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
            Some(false)
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
        check: |_, field| (field.name == "logs").then_some(false),
    };

    let mut shadow = evidence(&[21_000]);
    shadow.txs[0].logs_hash = B256::repeat_byte(1);
    shadow.txs[0].fee_logs_hash = B256::repeat_byte(2);
    let report = Report::analyze(&real, &shadow, &[&rule]);
    assert_eq!(report.expected[rule.id], 1);
    assert_eq!(report.samples[0].1.field.name, "fee_logs");

    let mut shadow = evidence(&[21_000]);
    shadow.txs[0].receipt.logs_hash = B256::repeat_byte(1);
    let report = Report::analyze(&real, &shadow, &[]);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.samples[0].1.field.name, "receipt_logs");
}

#[test]
fn storage_reset_invalidates_the_suffix_without_enumerated_slots() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_000, 21_000]);
    shadow.txs[0].state.transitions.insert(
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
    assert_eq!(report.boundaries_not_evaluated, 2);
}

#[test]
fn accepted_post_block_change_has_no_suffix_to_invalidate() {
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
            (ctx.boundary == Boundary::PostBlock && field.name == "balance").then_some(true)
        },
    };
    let report = Report::analyze(&real, &shadow, &[&rule]);
    assert_eq!(report.boundaries_not_evaluated, 0);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Expected);
}
