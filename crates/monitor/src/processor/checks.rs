//! Built-in finalized-block checks and check-result summaries.

use crate::{
    diagnostics::{
        coverage::{
            CheckOutcome, CheckResult, CoverageGap, CoverageReason, CoverageRecord, CoverageStatus,
        },
        evidence::{
            EvidenceItem, EvidenceRef, EvidenceValue, ExpectedValue, ObservedValue,
            ViolationEvidence,
        },
    },
    input::facts::FactValue,
    invariants::meta::{InvariantId, Severity, ids},
    processor::FinalizedBlockInput,
};
use alloy_primitives::U256;

pub(super) fn run_block_checks(input: &FinalizedBlockInput) -> Vec<CheckResult> {
    vec![check_block_total_gas(input)]
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CheckSummary {
    pub total: usize,
    pub passed: usize,
    pub violations: usize,
    pub inconclusive: usize,
    pub errors: usize,
}

impl CheckSummary {
    pub(super) fn from_results(results: &[CheckResult]) -> Self {
        let mut summary = Self {
            total: results.len(),
            ..Self::default()
        };
        for result in results {
            match &result.outcome {
                CheckOutcome::Pass(_) => summary.passed += 1,
                CheckOutcome::Violation(_) => summary.violations += 1,
                CheckOutcome::Inconclusive(_) => summary.inconclusive += 1,
                CheckOutcome::Error(_) => summary.errors += 1,
            }
        }
        summary
    }
}

pub(super) fn check_outcome_label(outcome: &CheckOutcome) -> &'static str {
    match outcome {
        CheckOutcome::Pass(_) => "pass",
        CheckOutcome::Violation(_) => "violation",
        CheckOutcome::Inconclusive(_) => "inconclusive",
        CheckOutcome::Error(_) => "error",
    }
}

fn check_block_total_gas(input: &FinalizedBlockInput) -> CheckResult {
    let invariant_id = InvariantId::borrowed(ids::BLOCK_TOTAL_GAS);
    let block = input.block();
    let coverage = CoverageRecord {
        invariant_id: invariant_id.clone(),
        block,
        entity: None,
        status: CoverageStatus::Complete,
        reasons: vec![CoverageReason::CompleteInput],
    };

    let outcome = if let Some(reason) = missing_receipt_gas_reason(input) {
        let gap = CoverageGap {
            status: CoverageStatus::Inconclusive,
            reason: CoverageReason::MissingRequiredInput(reason.clone()),
            detail: reason,
        };
        CheckOutcome::Inconclusive(gap)
    } else {
        let header_gas_used = input.block_facts.header.gas_used;
        let gas_limit = input.block_facts.header.gas_limit;
        let receipt_total_gas = input
            .receipt_facts
            .last()
            .map_or(0, |receipt| receipt.cumulative_gas_used);

        if receipt_total_gas == header_gas_used && header_gas_used <= gas_limit {
            CheckOutcome::pass(coverage.clone()).expect("complete coverage constructs pass")
        } else {
            CheckOutcome::Violation(block_total_gas_violation(
                input,
                coverage.clone(),
                receipt_total_gas,
            ))
        }
    };

    let coverage = match &outcome {
        CheckOutcome::Inconclusive(gap) => CoverageRecord {
            status: gap.status.clone(),
            reasons: vec![gap.reason.clone()],
            ..coverage
        },
        _ => coverage,
    };
    let outcome = match outcome {
        CheckOutcome::Inconclusive(gap) => CheckOutcome::Inconclusive(CoverageGap {
            status: coverage.status.clone(),
            reason: coverage.reasons[0].clone(),
            detail: gap.detail,
        }),
        outcome => outcome,
    };

    CheckResult {
        invariant_id,
        block,
        entity: None,
        severity: Severity::Critical,
        coverage,
        outcome,
    }
}

fn missing_receipt_gas_reason(input: &FinalizedBlockInput) -> Option<String> {
    input
        .receipt_facts
        .iter()
        .find_map(|receipt| match &receipt.gas_used {
            FactValue::Missing { reason } => Some(format!(
                "receipt gas_used is missing for tx_index {}: {reason}",
                receipt.tx_index
            )),
            FactValue::Available(_) => None,
            FactValue::NotNeeded => Some(format!(
                "receipt gas_used is not applicable for tx_index {}",
                receipt.tx_index
            )),
        })
}

fn block_total_gas_violation(
    input: &FinalizedBlockInput,
    coverage: CoverageRecord,
    receipt_total_gas: u64,
) -> ViolationEvidence {
    let header_gas_used = input.block_facts.header.gas_used;
    let gas_limit = input.block_facts.header.gas_limit;
    ViolationEvidence {
        invariant_id: InvariantId::borrowed(ids::BLOCK_TOTAL_GAS),
        block: input.reference,
        entity: None,
        expected: ExpectedValue {
            label: "block total gas".into(),
            condition:
                "receipt_total_gas == header.gas_used && header.gas_used <= header.gas_limit".into(),
        },
        observed: vec![
            ObservedValue {
                label: "receipt_total_gas".into(),
                value: EvidenceValue::Uint(U256::from(receipt_total_gas)),
            },
            ObservedValue {
                label: "header_gas_used".into(),
                value: EvidenceValue::Uint(U256::from(header_gas_used)),
            },
            ObservedValue {
                label: "header_gas_limit".into(),
                value: EvidenceValue::Uint(U256::from(gas_limit)),
            },
        ],
        items: vec![
            EvidenceItem::ChainRef(EvidenceRef::Block(input.block())),
            EvidenceItem::Json(serde_json::json!({
                "receipt_total_gas": receipt_total_gas,
                "header_gas_used": header_gas_used,
                "header_gas_limit": gas_limit,
            })),
        ],
        coverage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::facts::{
        BlockFacts, BlockNumHash, BlockWithParent, HeaderFacts, ReceiptFacts, TxEnvelopeFacts,
        TxFacts,
    };
    use alloy_primitives::{Address, B256, TxKind};
    use std::num::NonZeroU64;
    use tempo_hardfork::TempoHardfork;
    use tempo_primitives::TempoTxType;

    fn b(n: u8) -> B256 {
        B256::repeat_byte(n)
    }

    fn block(number: u64) -> BlockNumHash {
        BlockNumHash {
            number,
            hash: b(number as u8),
        }
    }

    fn input(
        header_gas_used: u64,
        gas_limit: u64,
        receipt_cumulative_gas: &[u64],
    ) -> FinalizedBlockInput {
        input_with_receipt_gas(header_gas_used, gas_limit, receipt_cumulative_gas, None)
    }

    fn input_with_receipt_gas(
        header_gas_used: u64,
        gas_limit: u64,
        receipt_cumulative_gas: &[u64],
        missing_gas_at_tx_index: Option<u64>,
    ) -> FinalizedBlockInput {
        let block = block(1);
        let reference = BlockWithParent::new(b(0), block);
        let tx_facts = receipt_cumulative_gas
            .iter()
            .enumerate()
            .map(|(tx_index, _)| {
                let tx_index = tx_index as u64;
                let tx_hash = b(tx_index as u8 + 0x10);
                TxFacts {
                    block,
                    tx_index,
                    tx_hash,
                    is_system: false,
                    envelope: TxEnvelopeFacts {
                        tx_type: TempoTxType::AA,
                        action: TxKind::Call(Address::ZERO),
                        gas_limit: 30_000,
                        nonce: tx_index,
                        value: U256::ZERO,
                        nonce_key: None,
                        valid_before: NonZeroU64::new(100),
                        valid_after: None,
                        fee_token: None,
                    },
                    sender: FactValue::Available(Address::ZERO),
                    fee_payer: FactValue::Available(Address::ZERO),
                    unique_intent: FactValue::Available(b(tx_index as u8 + 0x20)),
                }
            })
            .collect::<Vec<_>>();
        let mut previous = 0;
        let receipt_facts = receipt_cumulative_gas
            .iter()
            .enumerate()
            .map(|(tx_index, cumulative_gas_used)| {
                let tx_index = tx_index as u64;
                let tx_hash = b(tx_index as u8 + 0x10);
                let gas_used = if missing_gas_at_tx_index == Some(tx_index) {
                    FactValue::Missing {
                        reason: "test missing gas".into(),
                    }
                } else {
                    FactValue::Available(*cumulative_gas_used - previous)
                };
                previous = *cumulative_gas_used;
                ReceiptFacts {
                    block,
                    tx_hash,
                    tx_index,
                    success: true,
                    gas_used,
                    cumulative_gas_used: *cumulative_gas_used,
                }
            })
            .collect::<Vec<_>>();

        FinalizedBlockInput {
            reference,
            block_facts: BlockFacts {
                reference,
                hardfork: TempoHardfork::Genesis,
                header: HeaderFacts {
                    timestamp: 1,
                    timestamp_millis: 1000,
                    gas_used: header_gas_used,
                    gas_limit,
                    general_gas_limit: gas_limit,
                    shared_gas_limit: 0,
                    base_fee_per_gas: None,
                    beneficiary: Address::ZERO,
                    consensus_context: None,
                },
            },
            tx_facts,
            receipt_facts,
            ordered_logs: Vec::new(),
        }
    }

    #[test]
    fn block_total_gas_pass_emits_check_result() -> eyre::Result<()> {
        let result = check_block_total_gas(&input(21_000, 30_000, &[21_000]));

        assert_eq!(
            result.invariant_id,
            InvariantId::borrowed(ids::BLOCK_TOTAL_GAS)
        );
        assert!(matches!(result.outcome, CheckOutcome::Pass(_)));
        assert_eq!(result.coverage.status, CoverageStatus::Complete);
        Ok(())
    }

    #[test]
    fn block_total_gas_violation_emits_violation_result() -> eyre::Result<()> {
        let result = check_block_total_gas(&input(20_999, 30_000, &[21_000]));

        match &result.outcome {
            CheckOutcome::Violation(evidence) => {
                assert_eq!(
                    evidence.invariant_id,
                    InvariantId::borrowed(ids::BLOCK_TOTAL_GAS)
                );
                assert_eq!(evidence.coverage.status, CoverageStatus::Complete);
            }
            outcome => panic!("expected violation, got {outcome:?}"),
        }
        Ok(())
    }

    #[test]
    fn block_total_gas_emits_coverage_record() -> eyre::Result<()> {
        let result = check_block_total_gas(&input(0, 30_000, &[]));

        assert_eq!(result.coverage.status, CoverageStatus::Complete);
        assert_eq!(result.coverage.reasons, vec![CoverageReason::CompleteInput]);
        Ok(())
    }

    #[test]
    fn block_total_gas_missing_receipt_gas_is_inconclusive() -> eyre::Result<()> {
        let result =
            check_block_total_gas(&input_with_receipt_gas(21_000, 30_000, &[21_000], Some(0)));

        assert_eq!(result.coverage.status, CoverageStatus::Inconclusive);
        assert!(matches!(result.outcome, CheckOutcome::Inconclusive(_)));
        Ok(())
    }
}
