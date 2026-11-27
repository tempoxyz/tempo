//! Counterfactual replay of verified corpus blocks under shadow (candidate) Tempo hardfork rules.
//!
//! Corpus verification has already executed each block and checked every transaction against its
//! stored record. Shadow replay runs the candidate's pre-block changes, then each transaction alone
//! on the canonical state before it plus the candidate's pre-block changes, then the candidate's
//! post-block changes. Only canonical changes carry the state forward, so a candidate difference
//! never cascades into later transactions. Nothing is persisted.
//!
//! The canonical side comes from the verified records. The canonical pre- and post-block changes,
//! and each transaction the candidate executes differently, run again and must reproduce their
//! records; a mismatch means the baseline can't be trusted and is returned as an error. Shadow
//! findings never stop replay.
//!
//! Analysis compares completed pre-block, transaction, and post-block boundaries in order. It
//! compares net effects at each boundary—not complete state equality or write history. Gas-only
//! changes are not findings; fork expectations classify known effects, and incomplete coverage
//! is reported separately.

mod analysis;
mod expectations;
mod fees;

use super::{
    block::{self, Executed},
    db::{Missing, View},
};
use crate::types::{Input, Transaction};
use alloy_consensus::BlockHeader as _;
use alloy_primitives::{B256, U256, keccak256};
use alloy_rlp::{encode_list, list_length};
use alloy_sol_types::SolEvent as _;
use analysis::{Report, StepChanges};
use evm2::AnyError;
use expectations::Expectation;
use eyre::OptionExt as _;
use reth_chainspec::ForkCondition;
use reth_evm::{BlockExecutionError, InternalBlockExecutionError};
use reth_primitives_traits::RecoveredBlock;
use std::sync::Arc;
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{TempoChainSpec, TempoHardforks as _},
};
use tempo_contracts::precompiles::{ITIP20, TIP_FEE_MANAGER_ADDRESS};
use tempo_evm::TempoEvmConfig;
use tempo_precompiles::storage::StorageAction;
use tempo_primitives::{Block, TempoReceipt};
use tracing::{debug, warn};

/// Result of replaying one canonical block under candidate hardfork rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// All boundaries matched without differences.
    Match,
    /// Every difference was accepted and all boundaries were compared.
    Expected,
    /// No unexplained finding, but some boundary could not be compared.
    Inconclusive,
    /// At least one difference or execution failure remains unexplained.
    Findings,
}

/// Replays canonical blocks under candidate rules without changing canonical state.
#[derive(Debug)]
pub struct ShadowReplayer {
    real_config: TempoEvmConfig,
    shadow_config: TempoEvmConfig,
    shadow_hardfork: TempoHardfork,
    rules: Vec<(TempoHardfork, Expectation)>,
}

impl ShadowReplayer {
    /// Compares execution under `real_config` with execution under `shadow_hardfork`'s rules.
    /// Errors if `shadow_hardfork` has no shadow expectations.
    pub fn new(real_config: TempoEvmConfig, shadow_hardfork: TempoHardfork) -> eyre::Result<Self> {
        let shadow_spec = shadow_spec(real_config.chain_spec(), shadow_hardfork);
        Ok(Self {
            real_config,
            shadow_config: TempoEvmConfig::new(Arc::new(shadow_spec)),
            shadow_hardfork,
            rules: expectations::load(shadow_hardfork)?,
        })
    }

    /// The candidate hardfork blocks are replayed under.
    pub const fn shadow_hardfork(&self) -> TempoHardfork {
        self.shadow_hardfork
    }

    /// Replays a verified corpus block, recorded in `input` and `executed`, under the candidate
    /// rules. `None` means the candidate hardfork is already canonical at the block. An error
    /// means the canonical baseline can't be trusted, which callers must treat as fatal.
    pub fn replay(
        &self,
        input: &Arc<Input>,
        block: &RecoveredBlock<Block>,
        executed: &Executed,
    ) -> eyre::Result<Option<ReplayOutcome>> {
        let canonical = self
            .real_config
            .chain_spec()
            .tempo_hardfork_at(block.timestamp());
        if canonical >= self.shadow_hardfork {
            return Ok(None);
        }
        let evidence = self.execute(input, block, executed)?;
        let rules = expectations::between(&self.rules, canonical);
        let report = Report::analyze(&evidence, &rules, block);
        let outcome = report.outcome(&evidence);
        if matches!(outcome, ReplayOutcome::Match | ReplayOutcome::Expected) {
            debug!(target: "shadow_replay", ?outcome, ?report, "Shadow replay compared all boundaries");
            return Ok(Some(outcome));
        }

        let failure = evidence.failure.as_ref();
        let uncaptured_tx = evidence
            .txs
            .iter()
            .enumerate()
            .find_map(|(index, tx)| match tx {
                TxEvidence::Failed(error) if uncaptured(error) => Some((index, error)),
                _ => None,
            });
        warn!(
            target: "shadow_replay",
            block_number = block.number(),
            block_hash = ?block.hash(),
            findings = ?report,
            shadow_failure_boundary = ?failure.map(|f| f.boundary),
            shadow_failure = ?failure.map(|f| &f.error),
            first_uncaptured_tx = ?uncaptured_tx,
            ?outcome,
            shadow_processed_txs = evidence.txs.len(),
            "Shadow replay needs review; differences are not confirmed regressions"
        );
        Ok(Some(outcome))
    }

    /// Runs the candidate's steps of `block` and pairs each with its canonical counterpart.
    fn execute(
        &self,
        input: &Arc<Input>,
        block: &RecoveredBlock<Block>,
        executed: &Executed,
    ) -> eyre::Result<Evidence> {
        let phases = input
            .phases
            .as_ref()
            .ok_or_eyre("missing phase expectations")?;
        let origin = View::new(input.clone());
        let (real_pre, real_pre_state) = block::run_pre_block(&self.real_config, block, &origin)?;
        eyre::ensure!(
            real_pre == phases.pre,
            "canonical pre-block changes differ from their verified record"
        );
        let mut evidence = Evidence::default();
        let (shadow_pre, shadow_pre_state) =
            match block::run_pre_block(&self.shadow_config, block, &origin) {
                Ok(pre) => pre,
                Err(error) => return Ok(evidence.fail(Boundary::PreBlock, error)),
            };
        evidence.pre_block = Some(Arms {
            real: StepChanges::new(&origin, &real_pre)?,
            shadow: StepChanges::new(&origin, &shadow_pre)?,
        });
        let (mut real, mut shadow) = (origin.child(), origin.child());
        real.apply(&real_pre)?;
        shadow.apply(&shadow_pre)?;

        for (index, record) in executed.transactions.iter().enumerate() {
            let run = |config, view| {
                block::run_standalone(
                    config,
                    block,
                    view,
                    record.ordinal,
                    index,
                    &record.before,
                    true,
                )
            };
            let tx = match run(&self.shadow_config, &shadow) {
                Err(error) => TxEvidence::Failed(error),
                Ok((candidate, _)) if candidate == *record => TxEvidence::Same,
                Ok((candidate, shadow_actions)) => {
                    let (canonical, real_actions) = run(&self.real_config, &real)?;
                    eyre::ensure!(
                        canonical == *record,
                        "canonical transaction {} differs from its verified record",
                        record.ordinal
                    );
                    TxEvidence::Differs(Box::new(Arms {
                        real: ObservedTx::new(&real, canonical, real_actions)?,
                        shadow: ObservedTx::new(&shadow, candidate, shadow_actions)?,
                    }))
                }
            };
            evidence.txs.push(tx);
            real.apply(&record.delta)?;
            shadow.apply(&record.delta)?;
        }

        // Post-block changes start from the executor state the last transaction left.
        let after_txs = executed
            .transactions
            .last()
            .map(|record| block::boundary_state(&record.after))
            .transpose()?;
        let real_post = block::run_post_block(
            &self.real_config,
            block,
            &real,
            after_txs.unwrap_or(real_pre_state),
        )?;
        eyre::ensure!(
            real_post == phases.post,
            "canonical post-block changes differ from their verified record"
        );
        match block::run_post_block(
            &self.shadow_config,
            block,
            &shadow,
            after_txs.unwrap_or(shadow_pre_state),
        ) {
            Ok(shadow_post) => {
                evidence.post_block = Some(Arms {
                    real: StepChanges::new(&real, &real_post)?,
                    shadow: StepChanges::new(&shadow, &shadow_post)?,
                });
            }
            Err(error) => evidence = evidence.fail(Boundary::PostBlock, error),
        }
        Ok(evidence)
    }
}

/// What one arm observed of a transaction the candidate executed differently.
#[derive(Debug, Default)]
struct ObservedTx {
    /// Whether execution succeeded and why it stopped. Gas is compared only through fee effects.
    outcome: (u8, String),
    /// Gas charged to the sender.
    charged_gas: u64,
    /// Hash of the unmodified ordered logs.
    receipt_logs_hash: B256,
    /// Hash of the transaction's output bytes (empty when there is no output).
    output_hash: B256,
    /// Hash of the ordered logs with only the verified post-fee transfer amount zeroed.
    fee_normalized: Option<B256>,
    /// The storage actions the transaction recorded, fee hook markers included.
    actions: Vec<StorageAction>,
    /// What the transaction changed.
    changes: StepChanges,
}

impl ObservedTx {
    /// The evidence of `record`, which executed on `before` and recorded `actions`.
    fn new(
        before: &View<'_>,
        record: Transaction,
        actions: Vec<StorageAction>,
    ) -> eyre::Result<Self> {
        let receipt: TempoReceipt = alloy_rlp::decode_exact(&record.receipt)?;
        Ok(Self {
            charged_gas: record.outcome.charged_gas,
            receipt_logs_hash: hash_logs(&receipt.logs),
            output_hash: keccak256(record.outcome.output.as_deref().unwrap_or_default()),
            fee_normalized: normalized_fee_transfer(&receipt.logs, &actions),
            actions,
            changes: StepChanges::new(before, &record.delta)?,
            outcome: (record.outcome.status, record.outcome.reason),
        })
    }
}

/// What each arm did at one boundary.
#[derive(Debug, Default)]
struct Arms<T> {
    real: T,
    shadow: T,
}

/// How the candidate's execution of a transaction compares with its canonical record.
#[derive(Debug)]
enum TxEvidence {
    /// The candidate reproduced the canonical record exactly.
    Same,
    /// The candidate's result differs from the canonical one.
    Differs(Box<Arms<ObservedTx>>),
    /// The candidate could not execute the transaction.
    Failed(eyre::Report),
}

/// A logical execution boundary whose committed effects can be compared independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Boundary {
    PreBlock,
    Transaction(usize),
    PostBlock,
}

/// Why the candidate's pre- or post-block changes failed.
#[derive(Debug)]
struct Failure {
    boundary: Boundary,
    error: eyre::Report,
}

/// Both arms' evidence at each compared boundary, in order.
///
/// `None` for pre/post-block means the candidate did not complete that boundary.
#[derive(Debug, Default)]
struct Evidence {
    pre_block: Option<Arms<StepChanges>>,
    txs: Vec<TxEvidence>,
    post_block: Option<Arms<StepChanges>>,
    failure: Option<Failure>,
}

impl Evidence {
    fn fail(mut self, boundary: Boundary, error: eyre::Report) -> Self {
        self.failure = Some(Failure { boundary, error });
        self
    }
}

/// Whether execution failed because it read state the corpus did not capture, so the boundary
/// cannot be compared.
fn uncaptured(error: &eyre::Report) -> bool {
    // A transaction's EVM error is not exposed as a source, so walk down from the executor's
    // payload. Wrappers such as `HandlerError` and `TempoPrecompileError` sit in between.
    let Some(
        InternalBlockExecutionError::EVM { error, .. } | InternalBlockExecutionError::Other(error),
    ) = error
        .downcast_ref::<BlockExecutionError>()
        .and_then(BlockExecutionError::as_internal)
    else {
        return false;
    };
    std::iter::successors(Some(error as &(dyn std::error::Error + 'static)), |error| {
        error.source()
    })
    .any(|error| {
        error
            .downcast_ref::<AnyError>()
            .is_some_and(|error| error.downcast_ref::<Missing>().is_some())
    })
}

/// Only the post-fee hook's expected TIP-20 transfer amount can be normalized. Every other
/// byte and the log positions remain committed by the returned full-receipt hash.
fn normalized_fee_transfer(
    logs: &[alloy_primitives::Log],
    actions: &[StorageAction],
) -> Option<B256> {
    let fee = fees::post_tx_fee(actions)?;
    let log = logs.get(fee.log)?;
    if log.address != fee.token {
        return None;
    }
    let mut transfer = ITIP20::Transfer::decode_log_validate(log).ok()?;
    if transfer.data.from != fee.payer
        || transfer.data.to != TIP_FEE_MANAGER_ADDRESS
        || transfer.data.amount != fee.charged
        || transfer.data.encode_log_data() != log.data
    {
        return None;
    }
    transfer.data.amount = U256::ZERO;
    let mut normalized = logs.to_vec();
    normalized[fee.log] = ITIP20::Transfer::encode_log(&transfer);
    Some(hash_logs(&normalized))
}

fn hash_logs<T: alloy_rlp::Encodable>(logs: &[T]) -> B256 {
    let mut encoded = Vec::with_capacity(list_length(logs));
    encode_list(logs, &mut encoded);
    keccak256(encoded)
}

fn shadow_spec(canonical: &TempoChainSpec, hardfork: TempoHardfork) -> TempoChainSpec {
    // Production replay starts after T10; mainnet genesis is at timestamp 0.
    // Activate candidate rules at timestamp 1 so candidate fork is not mistaken for a genesis.
    let mut spec = canonical.clone();
    for &fork in TempoHardfork::VARIANTS
        .iter()
        .filter(|&&fork| fork != TempoHardfork::Genesis && fork <= hardfork)
    {
        spec.inner
            .hardforks
            .insert(fork, ForkCondition::Timestamp(1));
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};
    use evm2::{DatabaseError, registry::HandlerError};
    use tempo_precompiles::{error::TempoPrecompileError, storage::FeeHook};

    /// A system call's error from reading an account the corpus did not capture.
    pub(super) fn missing_account() -> eyre::Report {
        BlockExecutionError::other(DatabaseError::new(missing(), true)).into()
    }

    fn missing() -> Missing {
        Missing("uncaptured account 0x00".into())
    }

    /// A transaction's error from `database_error`.
    fn transaction(database_error: impl std::error::Error + Send + Sync + 'static) -> eyre::Report {
        let error = HandlerError::Database(DatabaseError::new(database_error, true));
        BlockExecutionError::from(InternalBlockExecutionError::EVM {
            hash: B256::ZERO,
            error: AnyError::new(error),
        })
        .into()
    }

    #[test]
    fn only_values_the_corpus_lacks_are_uncaptured() {
        assert!(uncaptured(&missing_account()));
        assert!(uncaptured(&transaction(missing())));
        assert!(!uncaptured(&transaction(std::fmt::Error)));
        let precompile = TempoPrecompileError::Database(DatabaseError::new(missing(), true));
        assert!(uncaptured(&BlockExecutionError::other(precompile).into()));
        let other = BlockExecutionError::other(DatabaseError::new(std::fmt::Error, true));
        assert!(!uncaptured(&other.into()));
        assert!(!uncaptured(&eyre::eyre!("uncaptured account 0x00")));
    }

    #[test]
    fn fee_log_normalization_preserves_order_and_non_amount_fields() {
        let token = Address::repeat_byte(1);
        let payer = Address::repeat_byte(2);
        let logs = |amount| {
            vec![
                alloy_primitives::Log::empty(),
                alloy_primitives::Log {
                    address: token,
                    data: ITIP20::Transfer {
                        from: payer,
                        to: TIP_FEE_MANAGER_ADDRESS,
                        amount,
                    }
                    .encode_log_data(),
                },
            ]
        };
        let actions = |amount| {
            vec![
                StorageAction::Marker(FeeHook::PreTx {
                    payer,
                    token,
                    amount,
                }),
                StorageAction::Marker(FeeHook::End),
                StorageAction::Marker(FeeHook::PostTx {
                    refund: U256::ZERO,
                    log: 1,
                }),
                StorageAction::Marker(FeeHook::End),
            ]
        };
        let (canonical, candidate) = (logs(U256::from(85)), logs(U256::from(79)));
        let candidate_actions = actions(U256::from(79));
        let expected = normalized_fee_transfer(&canonical, &actions(U256::from(85))).unwrap();
        let actual = normalized_fee_transfer(&candidate, &candidate_actions).unwrap();
        assert_eq!(actual, expected);
        assert_ne!(hash_logs(&canonical), hash_logs(&candidate));
        assert!(normalized_fee_transfer(&candidate, &actions(U256::from(85))).is_none());

        let mut changed = candidate.clone();
        changed[0] = changed[1].clone();
        let changed_fees = normalized_fee_transfer(&changed, &candidate_actions).unwrap();
        assert_ne!(changed_fees, expected);
        let mut swapped = candidate;
        swapped.swap(0, 1);
        assert!(normalized_fee_transfer(&swapped, &candidate_actions).is_none());
    }
}
