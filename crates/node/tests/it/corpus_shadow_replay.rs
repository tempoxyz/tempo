//! Shadow replay of captured corpus blocks from their recorded pre-state alone.

use crate::utils::{ForkSchedule, TestNodeBuilder, t1_account};
use alloy_primitives::Address;
use reth_e2e_test_utils::wallet::Wallet;
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_evm::database::StateProviderDatabase;
use reth_provider::{
    BlockNumReader as _, BlockReader as _, StateProvider as _, StateProviderFactory as _,
    TransactionVariant,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_corpus::exec::{
    capture::capture,
    shadow::{ReplayOutcome, ShadowReplayer},
};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};

/// Builds blocks with transactions under `canonical` rules, captures each one into the corpus
/// format and shadow replays it under `candidate` rules from the captured pre-state.
async fn replay_captured_blocks(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> eyre::Result<Vec<Option<ReplayOutcome>>> {
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
    let consensus = TempoConsensus::new(chain_spec.clone());
    let replayer = ShadowReplayer::new(chain_spec, candidate);
    let mut first_tx = 0;
    let mut outcomes = Vec::new();
    for number in 1..=provider.best_block_number()? {
        let block = provider
            .recovered_block(number.into(), TransactionVariant::NoHash)?
            .expect("the node built the block");
        let captured = capture(
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
        outcomes.push(
            replayer
                .replay(&captured.input, &block, &captured.executed)
                .map_err(eyre::Report::msg)?,
        );
        first_tx += block.body().transactions.len() as u64;
    }
    Ok(outcomes)
}

#[tokio::test(flavor = "multi_thread")]
async fn captured_blocks_compare_under_a_candidate() -> eyre::Result<()> {
    // T12's pre-block setup reads only state the canonical block reads too.
    let outcomes = replay_captured_blocks(TempoHardfork::T11, TempoHardfork::T12).await?;
    assert!(
        outcomes.iter().all(|outcome| matches!(
            outcome,
            Some(ReplayOutcome::Match | ReplayOutcome::Expected)
        )),
        "{outcomes:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn candidate_reads_of_uncaptured_state_are_inconclusive() -> eyre::Result<()> {
    // T14's pre-block setup reads the configurable account precompile, which no T13 block reads.
    let outcomes = replay_captured_blocks(TempoHardfork::T13, TempoHardfork::T14).await?;
    assert!(
        outcomes
            .iter()
            .all(|outcome| *outcome == Some(ReplayOutcome::Inconclusive)),
        "{outcomes:?}"
    );
    Ok(())
}
