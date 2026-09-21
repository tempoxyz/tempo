use super::*;
use crate::shadow_replay::{Failure, ReceiptObservation};
use reth_revm::{db::StorageSlot, state::AccountInfo};

// Synthetic checks exercise the classifier contract; these are NOT TIP-1016 validators.
const GAS: Expectation = Expectation {
    id: "test.gas",
    check: |ctx, diff| match diff {
        Difference::Gas(real, shadow) if real.checked_add(200) == Some(*shadow) => {
            let Boundary::Transaction(index) = ctx.boundary else {
                return None;
            };
            (ctx.real.txs[index].receipt.success == ctx.shadow.txs[index].receipt.success)
                .then_some(Continuation::Continue)
        }
        _ => None,
    },
};

const FEE: Expectation = Expectation {
    id: "test.fee",
    check: |_, diff| match diff {
        Difference::Storage {
            slot,
            real: Some((before, after)),
            shadow: Some((other_before, other_after)),
            ..
        } if *slot == U256::ZERO
            && before == other_before
            && after.checked_sub(U256::from(200)) == Some(*other_after) =>
        {
            Some(Continuation::InconclusiveSuffix)
        }
        _ => None,
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
            .into(),
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
fn gas_acceptance_does_not_hide_unrelated_state_at_same_boundary() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_200, 21_000]);
    write_slot(&mut shadow.txs[0], 800, false);
    let report = Report::analyze(&real, &shadow, &[&GAS]);
    assert_eq!(report.expected["test.gas"], 1);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.boundaries_not_evaluated, 2);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
}

#[test]
fn accepted_cutoff_still_checks_the_rest_of_its_boundary() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_200, 21_000]);
    write_slot(&mut shadow.txs[0], 800, false);
    let stop = Expectation {
        id: "test.stop-gas",
        check: |ctx, diff| (GAS.check)(ctx, diff).map(|_| Continuation::InconclusiveSuffix),
    };
    let report = Report::analyze(&real, &shadow, &[&stop]);
    assert_eq!(report.expected["test.stop-gas"], 1);
    assert_eq!(report.unexplained, 1);
    assert_eq!(report.boundaries_not_evaluated, 2);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
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
}

#[test]
fn overlapping_rules_are_ambiguous_in_either_order() {
    let stop = Expectation {
        id: "test.stop-gas",
        check: |_, diff| {
            matches!(diff, Difference::Gas(..)).then_some(Continuation::InconclusiveSuffix)
        },
    };
    let real = evidence(&[21_000, 21_000]);
    let shadow = evidence(&[21_200, 21_000]);
    for rules in [[&GAS, &stop], [&stop, &GAS]] {
        let report = Report::analyze(&real, &shadow, &rules);
        assert_eq!(report.ambiguous, 1);
        assert_eq!(report.unexplained, 1);
        assert!(report.expected.is_empty());
        assert_eq!(report.cutoff, Some(Boundary::Transaction(0)));
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
    assert!(matches!(
        report.samples[0].1,
        Difference::BlockGas(21_000, 20_000)
    ));
}

#[test]
fn failure_after_expected_cutoff_is_inconclusive_not_a_new_finding() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[21_200]);
    shadow.post_block = None;
    shadow.failure = Some(Failure {
        boundary: Boundary::Transaction(1),
        error: "dependent rejection".into(),
    });
    let rule = Expectation {
        id: "test.gas-cutoff",
        check: |ctx, diff| (GAS.check)(ctx, diff).map(|_| Continuation::InconclusiveSuffix),
    };
    let report = Report::analyze(&real, &shadow, &[&rule]);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Inconclusive);
    assert_eq!(report.boundaries_not_evaluated, 2);
}

#[test]
fn rejection_without_prior_cutoff_is_an_unexplained_finding() {
    let real = evidence(&[21_000, 21_000]);
    let mut shadow = evidence(&[]);
    shadow.post_block = None;
    shadow.failure = Some(Failure {
        boundary: Boundary::Transaction(0),
        error: "rejected".into(),
    });
    let report = Report::analyze(&real, &shadow, &[]);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
    assert_eq!(report.boundaries_not_evaluated, 3);
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
    assert!(matches!(report.samples[0].1, Difference::Code { .. }));
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
fn accepted_application_logs_do_not_hide_fee_logs() {
    let real = evidence(&[21_000]);
    let mut shadow = evidence(&[21_000]);
    shadow.txs[0].logs_hash = B256::repeat_byte(1);
    shadow.txs[0].fee_logs_hash = B256::repeat_byte(2);
    let rule = Expectation {
        id: "test.application-logs",
        check: |_, diff| matches!(diff, Difference::Logs(..)).then_some(Continuation::Continue),
    };
    let report = Report::analyze(&real, &shadow, &[&rule]);
    assert_eq!(report.expected["test.application-logs"], 1);
    assert_eq!(report.unexplained, 1);
    assert!(matches!(report.samples[0].1, Difference::FeeLogs(..)));
}

#[test]
fn receipt_log_order_is_compared_even_when_both_subsequences_match() {
    let real = evidence(&[21_000]);
    let mut shadow = evidence(&[21_000]);
    shadow.txs[0].receipt.logs_hash = B256::repeat_byte(1);
    let report = Report::analyze(&real, &shadow, &[]);
    assert_eq!(report.unexplained, 1);
    assert!(matches!(report.samples[0].1, Difference::ReceiptLogs(..)));
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
    assert!(matches!(
        report.samples[0].1,
        Difference::StorageReset { .. }
    ));
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
        check: |ctx, diff| {
            (ctx.boundary == Boundary::PostBlock && matches!(diff, Difference::Balance { .. }))
                .then_some(Continuation::InconclusiveSuffix)
        },
    };
    let report = Report::analyze(&real, &shadow, &[&rule]);
    assert_eq!(report.boundaries_not_evaluated, 0);
    assert_eq!(report.outcome(&shadow), ReplayOutcome::Expected);
}
