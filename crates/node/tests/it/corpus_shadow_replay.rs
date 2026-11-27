use crate::utils::{ForkSchedule, TestNodeBuilder, t1_account};
use alloy_primitives::Address;
use reth_e2e_test_utils::wallet::Wallet;
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_evm::database::StateProviderDatabase;
use reth_provider::{
    BlockNumReader as _, BlockReader as _, StateProvider as _, StateProviderFactory as _,
    TransactionVariant,
};
use std::sync::Arc;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_corpus::{
    exec::{
        capture::{Captured, capture},
        shadow::{ReplayOutcome, ShadowReplayer},
    },
    types::{Delta, Phases},
};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};

type Outcomes = Vec<Result<Option<ReplayOutcome>, String>>;

/// Captures each block of a chain on `canonical` with two transfers and, once per tamper, applies
/// it and replays the block under `candidate`. Returns each tamper's outcomes, in block order.
async fn replay_captured_blocks(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
    tampers: &[fn(&mut Captured)],
) -> eyre::Result<Vec<Outcomes>> {
    reth_tracing::init_test_tracing();
    let mut node = TestNodeBuilder::new()
        .with_schedule(ForkSchedule::DevnetAt(canonical))
        .build_with_node_access()
        .await?
        .node;
    let chain_spec = node.inner.chain_spec();
    let mut account = t1_account(&Wallet::default().with_chain_id(chain_spec.chain_id()), 0);
    for _ in 0..2 {
        let tx = account.tx().to(Address::ZERO).gas_limit(300_000).await;
        node.inject_and_advance(tx).await?;
    }

    let provider = node.inner.provider.clone();
    let config = TempoEvmConfig::new(chain_spec.clone());
    let consensus = TempoConsensus::new(chain_spec);
    let replayer = ShadowReplayer::new(config.clone(), candidate);
    let mut first_tx = 0;
    let mut outcomes = vec![Outcomes::new(); tampers.len()];
    for number in 1..=provider.best_block_number()? {
        let block = provider
            .recovered_block(number.into(), TransactionVariant::NoHash)?
            .expect("the node built the block");
        for (tamper, outcomes) in tampers.iter().zip(&mut outcomes) {
            let mut captured = capture(
                &config,
                &consensus,
                &provider,
                |at| {
                    Ok(StateProviderDatabase(
                        provider
                            .history_by_block_number(at)?
                            .into_evm_state_provider(),
                    ))
                },
                &block,
                first_tx,
            )?;
            tamper(&mut captured);
            outcomes.push(
                replayer
                    .replay(&captured.input, &block, &captured.executed)
                    .map_err(|error| error.to_string()),
            );
        }
        first_tx += block.body().transactions.len() as u64;
    }
    Ok(outcomes)
}

#[tokio::test(flavor = "multi_thread")]
async fn captured_blocks_compare_under_a_candidate() -> eyre::Result<()> {
    // T12's pre-block setup reads only state the canonical block reads too.
    let outcomes = replay_captured_blocks(TempoHardfork::T11, TempoHardfork::T12, &[|_| {}])
        .await?
        .remove(0);
    assert!(
        outcomes.iter().all(|outcome| matches!(
            outcome,
            Ok(Some(ReplayOutcome::Match | ReplayOutcome::Expected))
        )),
        "{outcomes:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn candidate_reads_of_uncaptured_state_are_inconclusive() -> eyre::Result<()> {
    // T14's pre-block setup reads the configurable account precompile, which no T13 block reads.
    let outcomes = replay_captured_blocks(TempoHardfork::T13, TempoHardfork::T14, &[|_| {}])
        .await?
        .remove(0);
    assert!(
        outcomes
            .iter()
            .all(|outcome| *outcome == Ok(Some(ReplayOutcome::Inconclusive))),
        "{outcomes:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_canonical_side_that_does_not_reproduce_its_record_fails_replay() -> eyre::Result<()> {
    let outcomes = replay_captured_blocks(
        TempoHardfork::T11,
        TempoHardfork::T12,
        &[
            |captured| captured.executed.transactions[0].delta = Delta::default(),
            |captured| {
                // These blocks' post-block steps change nothing, so record a change they don't make.
                let change = captured.executed.transactions[0].delta.clone();
                phases(captured).post = change;
            },
            |captured| phases(captured).pre = Delta::default(),
        ],
    )
    .await?;
    let transaction = |ordinal| {
        Err(format!(
            "canonical transaction {ordinal} differs from its verified record"
        ))
    };
    let phase = |phase| {
        Err(format!(
            "canonical {phase}-block changes differ from their verified record"
        ))
    };
    assert_eq!(
        outcomes,
        [
            vec![transaction(0), transaction(1)],
            vec![phase("post"), phase("post")],
            vec![phase("pre"), phase("pre")],
        ]
    );
    Ok(())
}

fn phases(captured: &mut Captured) -> &mut Phases {
    Arc::get_mut(&mut captured.input)
        .expect("capture shares no input")
        .phases
        .as_mut()
        .expect("capture records phases")
}
