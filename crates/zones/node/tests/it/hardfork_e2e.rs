//! Hardfork transitions through the running node, payload builder, and native precompiles.
//! L1 headers and portal events are supplied by the same fixture as the other local E2E tests.

use std::time::Duration;

use alloy_consensus::{BlockHeader, Transaction};
use alloy_primitives::{Address, B256, Bytes, U256, address};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{Filter, TransactionRequest};
use alloy_sol_types::{SolCall, SolError, SolEvent};
use tempo_chainspec::{hardfork::TempoHardfork, spec::TempoHardforks};
use tempo_contracts::precompiles::UnknownFunctionSelector;
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::TempoHeader;
use tempo_zone_contracts::{
    IZoneInbox, IZoneOutbox, LegacyTempoAdvanced, TEMPO_STATE_ADDRESS, TempoAdvanced,
    ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, finalizeTempoCall, legacyFinalizeTempoCall,
};
use zone_chainspec::{ZoneChainSpec, test_utils::set_tempo_fork};
use zone_l1::{EnabledToken, L1PortalEvents};

use crate::utils::{
    DEFAULT_TIMEOUT, L1Fixture, ZoneTestNode, now_secs,
    start_local_zone_with_fixture_and_withdrawal_batch_interval,
};

/// TIP-1096 must remain inactive through T12 and switch both dispatch and production at T13.
/// Checkpoint-only blocks must defer deposits/token enablements and must not finalize a batch.
#[tokio::test(flavor = "multi_thread")]
async fn test_t12_to_t13_tip1096_activation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Leave time for startup and the T12 assertions. The engine uses wall time as a timestamp
    // lower bound, and consensus rejects future blocks, so wait for activation before T13.
    let activation = now_secs() + 30;
    let mut genesis = zone_node::genesis::genesis_template()?;
    set_tempo_fork(&mut genesis, TempoHardfork::T13, activation);
    genesis.config.chain_id = zone_primitives::constants::zone_chain_id(1_337, 1096)?;
    let spec = ZoneChainSpec::from_genesis(genesis.clone())?;
    assert_eq!(spec.tempo_hardfork_at(activation - 1), TempoHardfork::T12);
    assert_eq!(spec.tempo_hardfork_at(activation), TempoHardfork::T13);

    let (zone, mut fixture) =
        start_local_zone_with_fixture_and_withdrawal_batch_interval(1096, 4, 1, genesis).await?;
    let provider = zone.provider();
    let inbox = IZoneInbox::new(ZONE_INBOX_ADDRESS, &provider);
    let recipient = address!("0000000000000000000000000000000000001096");

    let t12 = fixture.next_block_at(now_secs());
    fixture.enqueue(
        &t12,
        zone.deposit_queue(),
        vec![L1Fixture::make_deposit_for_block(
            PATH_USD_ADDRESS,
            recipient,
            recipient,
            100,
        )],
    );
    zone.wait_for_block_number(1, DEFAULT_TIMEOUT).await?;
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, recipient).await?,
        U256::from(100)
    );
    assert_eq!(inbox.processedDepositNumber().call().await?, 1);
    let t12_deposit_hash = inbox.processedDepositQueueHash().call().await?;
    assert_ne!(t12_deposit_hash, B256::ZERO);
    assert!(
        assert_full_import(&zone, 1, &t12.header).await? < activation,
        "the first Zone block must execute under T12"
    );
    assert_advance_event::<LegacyTempoAdvanced>(&zone, 1, true).await?;
    assert_advance_event::<TempoAdvanced>(&zone, 1, false).await?;

    // Assert the exact dispatch error, rather than accepting an unrelated RPC/execution failure.
    assert_unknown_selector(
        &zone,
        1,
        ZONE_INBOX_ADDRESS,
        IZoneInbox::processedEnabledTokenCountCall {}.abi_encode(),
    )
    .await?;
    assert_unknown_selector(
        &zone,
        1,
        ZONE_INBOX_ADDRESS,
        IZoneInbox::advanceTempoHeadersCall { headers: vec![] }.abi_encode(),
    )
    .await?;
    assert_unknown_selector(
        &zone,
        1,
        TEMPO_STATE_ADDRESS,
        finalizeTempoCall { headers: vec![] }.abi_encode(),
    )
    .await?;

    let alpha = EnabledToken {
        token: address!("20c0000000000000000000000000000000109601"),
        name: "AlphaUSD".into(),
        symbol: "aUSD".into(),
        currency: "USD".into(),
    };
    tokio::time::sleep(Duration::from_secs(activation.saturating_sub(now_secs()))).await;
    let t13 = fixture.next_block_at(activation);
    fixture.enqueue_events(
        &t13,
        zone.deposit_queue(),
        L1PortalEvents {
            enabled_tokens: vec![alpha],
            ..Default::default()
        },
    );
    zone.wait_for_block_number(2, DEFAULT_TIMEOUT).await?;
    assert_full_import(&zone, 2, &t13.header).await?;
    assert_advance_event::<LegacyTempoAdvanced>(&zone, 2, false).await?;
    assert_advance_event::<TempoAdvanced>(&zone, 2, true).await?;
    assert_eq!(inbox.processedEnabledTokenCount().call().await?, 1);
    assert_eq!(inbox.processedDepositNumber().call().await?, 1);
    assert_eq!(
        inbox.processedDepositQueueHash().call().await?,
        t12_deposit_hash
    );
    assert_unknown_selector(
        &zone,
        2,
        TEMPO_STATE_ADDRESS,
        legacyFinalizeTempoCall {
            header: Bytes::new(),
        }
        .abi_encode(),
    )
    .await?;

    // Announce a later finalized target before enqueueing its prefix, as the L1 subscriber
    // does during backfill. This forces checkpoint mode without racing the engine's queue read.
    tokio::time::sleep(Duration::from_secs(
        (activation + 2).saturating_sub(now_secs()),
    ))
    .await;
    zone.l1_block_tracker().record_finalized_target(4);
    let beta = EnabledToken {
        token: address!("20c0000000000000000000000000000000109602"),
        name: "BetaUSD".into(),
        symbol: "bUSD".into(),
        currency: "USD".into(),
    };
    let checkpoint = fixture.next_block();
    let mut events = fixture.portal_events_from_deposits(&[L1Fixture::make_deposit_for_block(
        beta.token, recipient, recipient, 200,
    )]);
    events.enabled_tokens = vec![beta.clone()];
    fixture.enqueue_events(&checkpoint, zone.deposit_queue(), events);
    zone.wait_for_block_number(3, DEFAULT_TIMEOUT).await?;

    let block = provider
        .get_block_by_number(3.into())
        .full()
        .await?
        .expect("checkpoint block");
    let txs = block
        .transactions
        .as_transactions()
        .expect("full transactions");
    assert_eq!(
        txs.len(),
        1,
        "checkpoint block must contain only advanceTempoHeaders"
    );
    let call = IZoneInbox::advanceTempoHeadersCall::abi_decode(txs[0].input())?;
    assert_eq!(
        call.headers,
        vec![Bytes::from(alloy_rlp::encode(&checkpoint.header))]
    );
    assert_eq!(zone.tempo_block_number().await?, 3);
    assert_eq!(inbox.processedEnabledTokenCount().call().await?, 1);
    assert_eq!(inbox.processedDepositNumber().call().await?, 1);
    assert_eq!(
        inbox.processedDepositQueueHash().call().await?,
        t12_deposit_hash
    );
    assert_advance_event::<LegacyTempoAdvanced>(&zone, 3, false).await?;
    assert_advance_event::<TempoAdvanced>(&zone, 3, false).await?;
    assert!(
        IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &provider)
            .BatchFinalized_filter()
            .select(3)
            .query()
            .await?
            .is_empty()
    );

    let operational = fixture.next_block();
    fixture.enqueue(&operational, zone.deposit_queue(), vec![]);
    zone.l1_block_tracker().mark_finalized_target_ready(4)?;
    zone.wait_for_block_number(4, DEFAULT_TIMEOUT).await?;
    assert_full_import(&zone, 4, &operational.header).await?;
    assert_eq!(zone.tempo_block_number().await?, 4);
    assert_eq!(inbox.processedEnabledTokenCount().call().await?, 2);
    assert_eq!(inbox.processedDepositNumber().call().await?, 2);
    assert_eq!(
        zone.balance_of(beta.token, recipient).await?,
        U256::from(200)
    );
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, recipient).await?,
        U256::from(100)
    );
    let events = provider
        .get_logs(
            &Filter::new()
                .address(ZONE_INBOX_ADDRESS)
                .select(4)
                .event_signature(TempoAdvanced::SIGNATURE_HASH),
        )
        .await?;
    assert_eq!(events.len(), 1);
    let advanced = TempoAdvanced::decode_log(&events[0].inner)?.data;
    assert_eq!(advanced.lastProcessedEnabledTokenCount, 2);
    assert_eq!(advanced.lastProcessedDepositNumber, 2);
    assert_eq!(advanced.depositsProcessed, U256::ONE);
    assert_eq!(advanced.tempoBlockNumber, 4);
    Ok(())
}

async fn assert_full_import(
    zone: &ZoneTestNode,
    number: u64,
    l1_header: &TempoHeader,
) -> eyre::Result<u64> {
    let block = zone
        .provider()
        .get_block_by_number(number.into())
        .full()
        .await?
        .expect("full-import block");
    assert!(block.header.timestamp() >= l1_header.timestamp());
    assert!(
        block.header.timestamp() <= now_secs(),
        "Zone block must not be in the future"
    );
    let txs = block
        .transactions
        .as_transactions()
        .expect("full transactions");
    assert_eq!(
        txs.len(),
        2,
        "full import must advance Tempo and finalize a batch"
    );
    let call = IZoneInbox::advanceTempoCall::abi_decode(txs[0].input())?;
    assert_eq!(call.header, Bytes::from(alloy_rlp::encode(l1_header)));
    IZoneOutbox::finalizeWithdrawalBatchCall::abi_decode(txs[1].input())?;
    Ok(block.header.timestamp())
}

async fn assert_advance_event<E: SolEvent>(
    zone: &ZoneTestNode,
    block: u64,
    expected: bool,
) -> eyre::Result<()> {
    let logs = zone
        .provider()
        .get_logs(
            &Filter::new()
                .address(ZONE_INBOX_ADDRESS)
                .select(block)
                .event_signature(E::SIGNATURE_HASH),
        )
        .await?;
    assert_eq!(
        logs.len(),
        usize::from(expected),
        "unexpected event {} at block {block}",
        E::SIGNATURE
    );
    Ok(())
}

async fn assert_unknown_selector(
    zone: &ZoneTestNode,
    block: u64,
    to: Address,
    calldata: Vec<u8>,
) -> eyre::Result<()> {
    let error = zone
        .provider()
        .call(
            TransactionRequest::default()
                .from(Address::ZERO)
                .to(to)
                .input(Bytes::from(calldata.clone()).into())
                .into(),
        )
        .number(block)
        .await
        .expect_err("selector must be inactive");
    let revert = error
        .as_error_resp()
        .expect("RPC error response")
        .as_revert_data()
        .expect("revert data");
    assert_eq!(
        revert,
        UnknownFunctionSelector {
            selector: calldata[..4].try_into()?,
        }
        .abi_encode()
    );
    Ok(())
}
