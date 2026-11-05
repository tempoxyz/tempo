//! Shadow replay of captured corpus blocks agrees with shadow replay on the node's database.

use crate::utils::{ForkSchedule, TestNodeBuilder, t1_account};
use alloy_primitives::Address;
use reth_e2e_test_utils::wallet::Wallet;
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_evm::database::StateProviderDatabase;
use reth_provider::{
    BlockNumReader as _, BlockReader as _, ReceiptProvider as _, StateProvider as _,
    StateProviderFactory as _, TransactionVariant,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_corpus::{
    exec::{capture::capture, db::View, replay::verify},
    store,
};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_node::{ReplayOutcome, ShadowReplayer};

/// Captures each block the node built into the corpus format, replays it from the stored record
/// alone, and checks that shadow replay over the record finds what shadow replay over the node's
/// database finds.
#[tokio::test(flavor = "multi_thread")]
async fn corpus_shadow_replay_matches_live_replay() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    // A candidate whose pre-block setup reads only state the canonical block reads too, which the
    // corpus captures.
    let canonical = TempoHardfork::T11;
    let candidate = TempoHardfork::T12;
    assert!(canonical < candidate);

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
    node.advance_block().await?;

    let provider = node.inner.provider.clone();
    let config = TempoEvmConfig::new(chain_spec.clone());
    let consensus = TempoConsensus::new(chain_spec.clone());
    let live = ShadowReplayer::new(provider.clone(), candidate);
    let offline = ShadowReplayer::offline(chain_spec, candidate);
    let mut first_tx = 0;
    let mut outcomes = Vec::new();
    for number in 1..=provider.best_block_number()? {
        let block = provider
            .recovered_block(number.into(), TransactionVariant::NoHash)?
            .expect("the node built the block");
        let receipts = provider
            .receipts_by_block(number.into())?
            .expect("the node stored its receipts");
        let expected = live.replay(&block, &receipts).map_err(eyre::Report::msg)?;

        let captured = capture(
            &config,
            &consensus,
            &provider,
            |at| {
                Ok(StateProviderDatabase::new(
                    provider
                        .history_by_block_number(at)?
                        .into_evm_state_provider(),
                ))
            },
            &block,
            first_tx,
        )?;
        let encoded = captured.encode(first_tx)?;
        let input = store::decode(&encoded.block, &encoded.record)?;
        let cases: Vec<bytes::Bytes> = encoded.cases.into_iter().map(Into::into).collect();
        let (replayed, replayed_receipts) =
            verify(&config, &consensus, &input, &cases, &encoded.record)?;
        assert_eq!(replayed_receipts, receipts, "block {number}");
        let actual = offline
            .replay_on(&replayed, &replayed_receipts, || {
                Ok(View::new(input.clone()))
            })
            .map_err(eyre::Report::msg)?;

        assert_eq!(actual, expected, "block {number}");
        outcomes.push((number, block.body().transactions.len(), actual.0));
        first_tx += block.body().transactions.len() as u64;
    }
    assert!(
        outcomes.iter().all(|&(_, _, outcome)| matches!(
            outcome,
            ReplayOutcome::Match | ReplayOutcome::Expected
        )),
        "{outcomes:?}"
    );
    Ok(())
}
