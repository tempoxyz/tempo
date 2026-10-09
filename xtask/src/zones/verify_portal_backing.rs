//! Verifies the token-backing invariant for a ZonePortal, including queued flows.

use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::BlockId,
};
use eyre::{WrapErr as _, ensure};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::ITIP20 as TIP20Token;
use tempo_zone_contracts::{
    IZoneInbox, ZONE_FACTORY_ADDRESS, ZONE_INBOX_ADDRESS, ZoneFactory, ZonePortal,
};
use zone_primitives::constants::zone_chain_id;

use crate::zone_utils::normalize_http_rpc;

const LOG_QUERY_BLOCK_CHUNK: u64 = 5_000;

#[derive(Clone, Copy)]
struct EventRanges {
    l1_from: u64,
    l1_to: u64,
    zone_from: u64,
    zone_to: u64,
}

#[derive(Debug, clap::Parser)]
pub(crate) struct VerifyPortalBacking {
    /// Tempo L1 HTTP RPC URL.
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,

    /// Zone HTTP RPC URL.
    #[arg(long, env = "ZONE_RPC_URL")]
    zone_rpc_url: String,

    /// ZonePortal address on Tempo L1.
    #[arg(long)]
    portal: Address,

    /// TIP-20 token address, shared by Tempo L1 and the Zone.
    #[arg(long)]
    token: Address,

    /// First L1 block to scan. Must include the Portal's complete event history.
    #[arg(long, default_value_t = 0)]
    l1_from_block: u64,

    /// First Zone block to scan. Must include the ZoneInbox's complete event history.
    #[arg(long, default_value_t = 0)]
    zone_from_block: u64,
}

impl VerifyPortalBacking {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let l1_rpc_url = normalize_http_rpc(&self.l1_rpc_url);
        let zone_rpc_url = normalize_http_rpc(&self.zone_rpc_url);
        let l1 = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&l1_rpc_url)
            .await
            .wrap_err("failed connecting to Tempo L1")?;
        let zone = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&zone_rpc_url)
            .await
            .wrap_err("failed connecting to Zone RPC")?;

        let (l1_snapshot, zone_snapshot, l1_chain_id, actual_zone_chain_id) = tokio::try_join!(
            l1.get_block_number(),
            zone.get_block_number(),
            l1.get_chain_id(),
            zone.get_chain_id(),
        )
        .wrap_err("failed reading snapshot blocks and chain IDs")?;
        ensure!(
            self.l1_from_block <= l1_snapshot,
            "L1 scan start {} is after snapshot block {l1_snapshot}",
            self.l1_from_block
        );
        ensure!(
            self.zone_from_block <= zone_snapshot,
            "Zone scan start {} is after snapshot block {zone_snapshot}",
            self.zone_from_block
        );
        let l1_block = BlockId::number(l1_snapshot);
        let zone_block = BlockId::number(zone_snapshot);
        let portal = ZonePortal::new(self.portal, &l1);
        let factory = ZoneFactory::new(ZONE_FACTORY_ADDRESS, &l1);
        let l1_token = TIP20Token::new(self.token, &l1);
        let zone_token = TIP20Token::new(self.token, &zone);
        let inbox = IZoneInbox::new(ZONE_INBOX_ADDRESS, &zone);

        let l1_reads = l1
            .multicall()
            .block(l1_block)
            .add(l1_token.balanceOf(self.portal))
            .add(portal.withdrawalQueueHead())
            .add(portal.withdrawalQueueTail())
            .add(portal.depositCount())
            .add(portal.lastProcessedDepositNumber())
            .add(portal.zoneId())
            .add(portal.isTokenEnabled(self.token))
            .add(factory.isZonePortal(self.portal));
        let zone_reads = zone
            .multicall()
            .block(zone_block)
            .add(zone_token.totalSupply())
            .add(inbox.processedDepositNumber())
            .add(inbox.tempoPortal());
        let (
            (
                portal_balance,
                withdrawal_head,
                withdrawal_tail,
                deposit_count,
                l1_processed_deposits,
                portal_zone_id,
                token_enabled,
                portal_registered,
            ),
            (zone_supply, zone_processed_deposits, inbox_portal),
        ) = tokio::try_join!(l1_reads.aggregate(), zone_reads.aggregate())
            .wrap_err("failed reading backing state")?;

        let factory_zone = factory
            .zones(portal_zone_id)
            .block(l1_block)
            .call()
            .await
            .wrap_err("failed reading ZoneFactory registration")?;
        let expected_zone_chain_id =
            zone_chain_id(l1_chain_id, portal_zone_id).wrap_err("failed deriving Zone chain ID")?;

        ensure!(portal_registered, "Portal is not registered in ZoneFactory");
        ensure!(
            factory_zone.portal == self.portal && factory_zone.zoneId == portal_zone_id,
            "Portal does not match ZoneFactory registration for zone {portal_zone_id}"
        );
        ensure!(
            inbox_portal == self.portal,
            "ZoneInbox Portal mismatch: expected {}, got {inbox_portal}",
            self.portal
        );
        ensure!(
            actual_zone_chain_id == expected_zone_chain_id,
            "Zone chain ID mismatch: expected {expected_zone_chain_id} for L1 chain {l1_chain_id} and zone {portal_zone_id}, got {actual_zone_chain_id}"
        );
        ensure!(token_enabled, "Token is not enabled on the Portal");

        ensure!(
            zone_processed_deposits <= deposit_count,
            "Zone processed more deposits than the Portal has recorded: ZoneInbox={zone_processed_deposits}, \
             ZonePortal={deposit_count}"
        );

        let portal_refunds = portal_refund_liability(
            &l1,
            self.portal,
            self.token,
            self.l1_from_block,
            l1_snapshot,
        )
        .await?;
        let inbox_refunds =
            inbox_refund_liability(&zone, self.token, self.zone_from_block, zone_snapshot).await?;
        let pending_deposits = pending_deposit_liability(
            &l1,
            self.portal,
            self.token,
            zone_processed_deposits,
            self.l1_from_block,
            l1_snapshot,
        )
        .await?;
        let pending_withdrawals = withdrawal_liability(
            &l1,
            &zone,
            self.portal,
            self.token,
            EventRanges {
                l1_from: self.l1_from_block,
                l1_to: l1_snapshot,
                zone_from: self.zone_from_block,
                zone_to: zone_snapshot,
            },
        )
        .await?;

        let required_backing = zone_supply
            .checked_add(portal_refunds)
            .and_then(|total| total.checked_add(inbox_refunds))
            .and_then(|total| total.checked_add(pending_deposits))
            .and_then(|total| total.checked_add(pending_withdrawals))
            .ok_or_else(|| eyre::eyre!("required backing overflow"))?;

        println!("Portal backing audit");
        println!("  L1 snapshot block:       {l1_snapshot}");
        println!("  Zone snapshot block:     {zone_snapshot}");
        println!(
            "  L1 refund scan:          {}..={l1_snapshot}",
            self.l1_from_block
        );
        println!(
            "  Zone refund scan:        {}..={zone_snapshot}",
            self.zone_from_block
        );
        println!("  Portal:                  {}", self.portal);
        println!("  Token:                   {}", self.token);
        println!("  Portal balance:          {portal_balance}");
        println!("  Zone total supply:       {zone_supply}");
        println!(
            "  Deposit queue:           portal={deposit_count}, l1-settled={l1_processed_deposits}, zone={zone_processed_deposits}"
        );
        println!("  Withdrawal queue:        head={withdrawal_head}, tail={withdrawal_tail}");
        println!("  Pending deposit liability: {pending_deposits}");
        println!("  Pending withdrawal liability: {pending_withdrawals}");
        println!("  Portal refund liability: {portal_refunds}");
        println!("  Inbox refund liability:  {inbox_refunds}");
        println!("  Required backing:        {required_backing}");

        if portal_balance >= required_backing {
            println!(
                "  PASS: backing surplus    {}",
                portal_balance - required_backing
            );
            Ok(())
        } else {
            let deficit = required_backing - portal_balance;
            println!("  FAIL: backing deficit    {deficit}");
            Err(eyre::eyre!("Portal is underbacked by {deficit} base units"))
        }
    }
}

/// Deposits after the Zone snapshot's processed-deposit watermark have reached the Portal but
/// have not yet been minted on the Zone. `WithdrawalBounceBack` entries are intentionally not
/// counted here: they remain represented by their original outstanding withdrawal until the
/// Inbox either re-mints them or turns them into an Inbox refund.
async fn pending_deposit_liability<P: Provider<TempoNetwork>>(
    provider: &P,
    portal_address: Address,
    token: Address,
    zone_processed_deposits: u64,
    from_block: u64,
    to_block: u64,
) -> eyre::Result<U256> {
    let portal = ZonePortal::new(portal_address, provider);
    let deposits = portal
        .DepositMade_filter()
        .from_block(from_block)
        .to_block(to_block)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK)
        .query()
        .await
        .wrap_err("failed scanning ZonePortal DepositMade events")?;

    deposits
        .into_iter()
        .filter(|(event, _)| event.token == token && event.depositNumber > zone_processed_deposits)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(U256::from(event.netAmount))
                .ok_or_else(|| eyre::eyre!("pending deposit total overflow"))
        })
}

/// Tracks every burned withdrawal until it is paid on L1, re-minted on the Zone, or moved into a
/// Portal or Inbox refund registry. This covers both finalized Portal queue entries and
/// withdrawals still waiting in the Zone outbox.
async fn withdrawal_liability<P: Provider<TempoNetwork>>(
    l1: &P,
    zone: &P,
    portal_address: Address,
    token: Address,
    ranges: EventRanges,
) -> eyre::Result<U256> {
    let portal = ZonePortal::new(portal_address, l1);
    let inbox = IZoneInbox::new(ZONE_INBOX_ADDRESS, zone);
    let outbox =
        tempo_zone_contracts::IZoneOutbox::new(tempo_zone_contracts::ZONE_OUTBOX_ADDRESS, zone);

    let requested_filter = outbox
        .WithdrawalRequested_filter()
        .from_block(ranges.zone_from)
        .to_block(ranges.zone_to)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK);
    let paid_filter = portal
        .WithdrawalProcessed_filter()
        .from_block(ranges.l1_from)
        .to_block(ranges.l1_to)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK);
    let reminted_filter = inbox
        .WithdrawalBounceBackProcessed_filter()
        .from_block(ranges.zone_from)
        .to_block(ranges.zone_to)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK);
    let refunded_filter = inbox
        .WithdrawalBounceBackPending_filter()
        .from_block(ranges.zone_from)
        .to_block(ranges.zone_to)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK);
    let deposit_bounce_back_filter = portal
        .DepositBounceBack_filter()
        .from_block(ranges.l1_from)
        .to_block(ranges.l1_to)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK);
    let portal_refund_filter = portal
        .DepositBounceBackPending_filter()
        .from_block(ranges.l1_from)
        .to_block(ranges.l1_to)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK);
    let (requested, paid, deposit_bounce_backs, portal_refunds, reminted, refunded) =
        tokio::try_join!(
            requested_filter.query(),
            paid_filter.query(),
            deposit_bounce_back_filter.query(),
            portal_refund_filter.query(),
            reminted_filter.query(),
            refunded_filter.query(),
        )
        .wrap_err("failed scanning withdrawal lifecycle events")?;

    let requested = requested
        .into_iter()
        .filter(|(event, _)| event.token == token)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(U256::from(event.amount))
                .ok_or_else(|| eyre::eyre!("requested withdrawal total overflow"))
        })?;
    let paid = paid
        .into_iter()
        .filter(|(event, _)| event.token == token && event.callbackSuccess)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(U256::from(event.amount))
                .ok_or_else(|| eyre::eyre!("paid withdrawal total overflow"))
        })?;
    let deposit_bounce_backs = deposit_bounce_backs
        .into_iter()
        .filter(|(event, _)| event.token == token)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(deposit_bounce_back_retired_amount(
                    event.amount,
                    event.bouncebackFee,
                ))
                .ok_or_else(|| eyre::eyre!("paid deposit bounce-back total overflow"))
        })?;
    let paid = paid
        .checked_add(deposit_bounce_backs)
        .ok_or_else(|| eyre::eyre!("paid withdrawal total overflow"))?;
    let reminted = reminted
        .into_iter()
        .filter(|(event, _)| event.token == token)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(U256::from(event.amount))
                .ok_or_else(|| eyre::eyre!("re-minted withdrawal bounce-back total overflow"))
        })?;
    let portal_refunds = portal_refunds
        .into_iter()
        .filter(|(event, _)| event.token == token)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(deposit_bounce_back_retired_amount(
                    event.amount,
                    event.bouncebackFee,
                ))
                .ok_or_else(|| eyre::eyre!("Portal refund transition total overflow"))
        })?;
    let refunded = refunded
        .into_iter()
        .filter(|(event, _)| event.token == token)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(U256::from(event.amount))
                .ok_or_else(|| eyre::eyre!("refunded withdrawal bounce-back total overflow"))
        })?
        .checked_add(portal_refunds)
        .ok_or_else(|| eyre::eyre!("refunded withdrawal total overflow"))?;

    outstanding_withdrawals(requested, paid, reminted, refunded)
}

fn deposit_bounce_back_retired_amount(amount: u128, bounceback_fee: u128) -> U256 {
    U256::from(amount) + U256::from(bounceback_fee)
}

fn outstanding_withdrawals(
    requested: U256,
    paid: U256,
    reminted: U256,
    refunded: U256,
) -> eyre::Result<U256> {
    requested
        .checked_sub(paid)
        .and_then(|total| total.checked_sub(reminted))
        .and_then(|total| total.checked_sub(refunded))
        .ok_or_else(|| {
            eyre::eyre!(
                "withdrawal event history is incomplete: requested={requested}, paid={paid}, \
                 reminted={reminted}, refunded={refunded}"
            )
        })
}

async fn portal_refund_liability<P: Provider<TempoNetwork>>(
    provider: &P,
    portal: Address,
    token: Address,
    from_block: u64,
    to_block: u64,
) -> eyre::Result<U256> {
    let portal = ZonePortal::new(portal, provider);
    let pending = portal
        .DepositBounceBackPending_filter()
        .from_block(from_block)
        .to_block(to_block)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK)
        .query()
        .await
        .wrap_err("failed scanning ZonePortal DepositBounceBackPending events")?;
    let claimed = portal
        .RefundClaimed_filter()
        .from_block(from_block)
        .to_block(to_block)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK)
        .query()
        .await
        .wrap_err("failed scanning ZonePortal RefundClaimed events")?;

    let pending_total = pending
        .into_iter()
        .filter(|(event, _)| event.token == token)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(U256::from(event.amount))
                .ok_or_else(|| eyre::eyre!("Portal pending refund total overflow"))
        })?;
    let claimed_total = claimed
        .into_iter()
        .filter(|(event, _)| event.token == token)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(U256::from(event.amount))
                .ok_or_else(|| eyre::eyre!("Portal claimed refund total overflow"))
        })?;

    outstanding_refunds("Portal", pending_total, claimed_total)
}

async fn inbox_refund_liability<P: Provider<TempoNetwork>>(
    provider: &P,
    token: Address,
    from_block: u64,
    to_block: u64,
) -> eyre::Result<U256> {
    let inbox = IZoneInbox::new(ZONE_INBOX_ADDRESS, provider);
    let pending = inbox
        .WithdrawalBounceBackPending_filter()
        .from_block(from_block)
        .to_block(to_block)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK)
        .query()
        .await
        .wrap_err("failed scanning ZoneInbox WithdrawalBounceBackPending events")?;
    let claimed = inbox
        .RefundClaimed_filter()
        .from_block(from_block)
        .to_block(to_block)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK)
        .query()
        .await
        .wrap_err("failed scanning ZoneInbox RefundClaimed events")?;

    let pending_total = pending
        .into_iter()
        .filter(|(event, _)| event.token == token)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(U256::from(event.amount))
                .ok_or_else(|| eyre::eyre!("Inbox pending refund total overflow"))
        })?;
    let claimed_total = claimed
        .into_iter()
        .filter(|(event, _)| event.token == token)
        .try_fold(U256::ZERO, |total, (event, _)| {
            total
                .checked_add(U256::from(event.amount))
                .ok_or_else(|| eyre::eyre!("Inbox claimed refund total overflow"))
        })?;

    outstanding_refunds("Inbox", pending_total, claimed_total)
}

fn outstanding_refunds(scope: &str, pending: U256, claimed: U256) -> eyre::Result<U256> {
    pending.checked_sub(claimed).ok_or_else(|| {
        eyre::eyre!(
            "{scope} refund event history is incomplete: claimed {claimed}, pending {pending}"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outstanding_refunds_subtracts_claims() {
        assert_eq!(
            outstanding_refunds("test", U256::from(100), U256::from(35)).unwrap(),
            U256::from(65)
        );
    }

    #[test]
    fn outstanding_refunds_rejects_incomplete_history() {
        assert!(outstanding_refunds("test", U256::from(10), U256::from(11)).is_err());
    }

    #[test]
    fn outstanding_withdrawals_tracks_all_terminal_paths() {
        assert_eq!(
            outstanding_withdrawals(
                U256::from(100),
                U256::from(25),
                U256::from(30),
                U256::from(20),
            )
            .unwrap(),
            U256::from(25)
        );
    }

    #[test]
    fn outstanding_withdrawals_rejects_incomplete_history() {
        assert!(
            outstanding_withdrawals(U256::from(10), U256::from(11), U256::ZERO, U256::ZERO,)
                .is_err()
        );
    }

    #[test]
    fn successful_deposit_bounce_back_retires_refund_and_fee() {
        let retired = deposit_bounce_back_retired_amount(990, 10);

        assert_eq!(
            outstanding_withdrawals(U256::from(1_000), retired, U256::ZERO, U256::ZERO).unwrap(),
            U256::ZERO
        );
    }

    #[test]
    fn pending_deposit_bounce_back_retires_fee_and_tracks_refund() {
        let retired = deposit_bounce_back_retired_amount(990, 10);

        assert_eq!(
            outstanding_withdrawals(U256::from(1_000), U256::ZERO, U256::ZERO, retired).unwrap(),
            U256::ZERO
        );
        assert_eq!(
            outstanding_refunds("Portal", U256::from(990), U256::ZERO).unwrap(),
            U256::from(990)
        );
    }
}
