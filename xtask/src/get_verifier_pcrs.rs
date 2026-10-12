//! Recover PCR measurements from a successful on-chain Nitro batch verification.

use std::{collections::HashSet, sync::Arc};

use alloy::{
    network::ReceiptResponse,
    primitives::{Address, B256, Bytes},
    providers::{Provider, ProviderBuilder, ext::DebugApi},
    rpc::types::{
        Filter,
        trace::geth::{CallConfig, CallFrame, GethDebugTracingOptions},
    },
    sol_types::{SolCall, SolEvent},
};
use alloy_consensus::BlockHeader;
use eyre::{Context, OptionExt, ensure, eyre};
use serde::Serialize;
use tempo_alloy::{TempoNetwork, provider::TempoProviderExt, rpc::ForkSchedule};
use tempo_chainspec::{TempoChainSpec, TempoHardfork};
use tempo_contracts::{
    precompiles::{IZoneVerifier, NITRO_VERIFIER_CONFIG_V1, ZONE_VERIFIER_ADDRESS},
    zones::{BatchSubmitted, submitBatchCall},
};
use tempo_nitro_attestation::parse_attestation;
use tempo_precompiles::zone_factory::portal_address;

#[derive(Debug, clap::Args)]
pub(crate) struct GetVerifierPcrs {
    /// Chain used for the default RPC URL and chain ID check, or a custom genesis JSON path.
    #[arg(long, short, value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Arc<TempoChainSpec>,

    /// RPC endpoint supporting tempo_forkSchedule, eth_getLogs and debug_traceTransaction.
    #[arg(long)]
    rpc_url: Option<String>,

    /// Hardfork to inspect. Defaults to the fork active at --to-block (or the latest block).
    #[arg(long)]
    hardfork: Option<TempoHardfork>,

    /// Earliest block to search, inclusive.
    #[arg(long, default_value_t = 0)]
    from_block: u64,

    /// Latest block to search, inclusive. Defaults to the current head.
    #[arg(long)]
    to_block: Option<u64>,

    /// Restrict the search to this Zone portal.
    #[arg(long)]
    portal: Option<Address>,

    /// Maximum blocks per eth_getLogs request.
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..))]
    chunk_size: u64,
}

#[derive(Debug, Serialize)]
struct VerifierPcrs {
    chain_id: u64,
    hardfork: String,
    block_number: u64,
    block_hash: B256,
    transaction_hash: B256,
    portal: Address,
    zone_id: u32,
    verifier: Address,
    pcrs: [Bytes; 3],
}

impl GetVerifierPcrs {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let rpc_url = self
            .rpc_url
            .or_else(|| self.chain.default_follow_url().map(str::to_owned))
            .ok_or_eyre("selected chain has no default RPC URL; pass --rpc-url")?;
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&rpc_url)
            .await?;
        let chain_id = provider.get_chain_id().await?;
        ensure!(
            chain_id == self.chain.inner.chain.id(),
            "RPC chain ID {chain_id} does not match selected chain {}",
            self.chain.inner.chain.id()
        );
        let schedule = provider
            .get_fork_schedule()
            .await
            .wrap_err("failed reading tempo_forkSchedule")?;
        let head = provider.get_block_number().await?;
        let to = self.to_block.unwrap_or(head);
        ensure!(
            self.from_block <= to && to <= head,
            "expected from-block <= to-block <= RPC head ({head})"
        );
        let hardfork = if let Some(hardfork) = self.hardfork {
            hardfork
        } else {
            hardfork_at(&schedule, block_timestamp(&provider, to).await?)
                .parse::<TempoHardfork>()
                .wrap_err("RPC reports a hardfork unsupported by this xtask version")?
        };
        ensure!(
            hardfork >= TempoHardfork::T13,
            "{hardfork} predates the Nitro verifier (T13); no accepted Nitro PCRs are available"
        );

        // Locate the selected fork's block interval using RPC timestamps and the selected
        // RPC's fork schedule. This avoids scanning unrelated history, including proofless rollouts.
        let from =
            fork_boundary(&provider, &schedule, self.from_block, to, hardfork, false).await?;
        let upper = fork_boundary(&provider, &schedule, from, to, hardfork, true).await?;
        ensure!(
            from < upper,
            "no blocks for {hardfork} in the requested range"
        );
        let mut end = upper - 1;
        loop {
            let mut seen = HashSet::new();
            let start = end.saturating_sub(self.chunk_size - 1).max(from);
            let mut filter = Filter::new()
                .from_block(start)
                .to_block(end)
                .event_signature(BatchSubmitted::SIGNATURE_HASH);
            if let Some(portal) = self.portal {
                filter = filter.address(portal);
            }
            let mut logs = provider.get_logs(&filter).await.wrap_err_with(|| {
                format!("failed to query batch logs in {start}..={end}; try a smaller --chunk-size")
            })?;
            logs.sort_by_key(|log| (log.block_number, log.transaction_index, log.log_index));
            for log in logs.into_iter().rev() {
                if log.removed {
                    continue;
                }
                let hash = log
                    .transaction_hash
                    .ok_or_eyre("batch log has no transaction hash")?;
                let portal = log.address();
                if !seen.insert((hash, portal)) {
                    continue;
                }
                let receipt = provider
                    .get_transaction_receipt(hash)
                    .await?
                    .ok_or_eyre("batch transaction receipt is unavailable")?;
                if !receipt.status() {
                    continue;
                }
                let number = log
                    .block_number
                    .ok_or_eyre("batch log has no block number")?;
                let block_hash = log.block_hash.ok_or_eyre("batch log has no block hash")?;
                ensure!(
                    receipt.block_hash == Some(block_hash),
                    "batch log and receipt disagree on block hash; retry after reorg"
                );
                let trace = provider
                    .debug_trace_transaction_call(
                        hash,
                        GethDebugTracingOptions::call_tracer(CallConfig::default()),
                    )
                    .await
                    .wrap_err("RPC must support debug_traceTransaction with callTracer and retain history for the candidate transaction")?;
                if let Some((zone_id, pcrs)) = batch_pcrs(&trace, portal)? {
                    let block = provider
                        .get_block_by_number(number.into())
                        .await?
                        .ok_or_eyre("batch block is unavailable")?;
                    ensure!(
                        block.header.hash == block_hash,
                        "batch block is no longer canonical; retry after reorg"
                    );
                    ensure!(
                        hardfork_at(&schedule, block.header.timestamp()) == hardfork.to_string(),
                        "batch does not belong to selected hardfork"
                    );
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&VerifierPcrs {
                            chain_id,
                            hardfork: hardfork.to_string(),
                            block_number: number,
                            block_hash,
                            transaction_hash: hash,
                            portal,
                            zone_id,
                            verifier: ZONE_VERIFIER_ADDRESS,
                            pcrs,
                        })?
                    );
                    return Ok(());
                }
            }
            if start == from {
                break;
            }
            end = start - 1;
        }
        Err(eyre!(
            "no successful Nitro batch with PCR0/1/2 found for {hardfork} in blocks {from}..={}",
            upper - 1
        ))
    }
}

async fn block_timestamp(provider: &impl Provider<TempoNetwork>, number: u64) -> eyre::Result<u64> {
    Ok(provider
        .get_block_by_number(number.into())
        .await?
        .ok_or_eyre("block is unavailable")?
        .header
        .timestamp())
}

/// First block at (or strictly after) the requested hardfork, or `to + 1` if absent.
async fn fork_boundary(
    provider: &impl Provider<TempoNetwork>,
    schedule: &ForkSchedule,
    from: u64,
    to: u64,
    fork: TempoHardfork,
    strictly_after: bool,
) -> eyre::Result<u64> {
    let fork_index = schedule
        .schedule
        .iter()
        .position(|entry| entry.name == fork.to_string())
        .ok_or_else(|| eyre!("{fork} is not scheduled by the RPC"))?;
    let mut low = from;
    let mut high = to.checked_add(1).ok_or_eyre("block range overflows")?;
    while low < high {
        let mid = low + (high - low) / 2;
        let timestamp = block_timestamp(provider, mid).await?;
        let active = schedule
            .schedule
            .iter()
            .rposition(|entry| entry.activation_time <= timestamp);
        if active
            .is_some_and(|index| index > fork_index || (!strictly_after && index == fork_index))
        {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    Ok(low)
}

fn hardfork_at(schedule: &ForkSchedule, timestamp: u64) -> &str {
    schedule
        .schedule
        .iter()
        .rev()
        .find(|entry| entry.activation_time <= timestamp)
        .map_or("Genesis", |entry| entry.name.as_str())
}

/// Ignore failed ancestors, including reverted calls caught by a multicall or AA transaction.
fn batch_pcrs(frame: &CallFrame, portal: Address) -> eyre::Result<Option<(u32, [Bytes; 3])>> {
    if frame.error.is_some() {
        return Ok(None);
    }
    if frame.to == Some(portal)
        && frame.typ == "CALL"
        && submitBatchCall::abi_decode(&frame.input).is_ok()
        && let Some(pcrs) = verifier_pcrs(frame, portal)?
    {
        return Ok(Some(pcrs));
    }
    for child in &frame.calls {
        if let Some(pcrs) = batch_pcrs(child, portal)? {
            return Ok(Some(pcrs));
        }
    }
    Ok(None)
}

fn verifier_pcrs(frame: &CallFrame, portal: Address) -> eyre::Result<Option<(u32, [Bytes; 3])>> {
    if frame.error.is_some() {
        return Ok(None);
    }
    if frame.to == Some(ZONE_VERIFIER_ADDRESS)
        && frame.from == portal
        && matches!(frame.typ.as_str(), "CALL" | "STATICCALL")
        && let Ok(call) = IZoneVerifier::verifyCall::abi_decode(&frame.input)
        && portal_address(call.zoneId) == portal
        && call.verifierConfig.as_ref() == NITRO_VERIFIER_CONFIG_V1
        && let Some(output) = &frame.output
        && IZoneVerifier::verifyCall::abi_decode_returns_validate(output)
            .is_ok_and(|accepted| accepted)
    {
        let parsed = parse_attestation(&call.proof)
            .map_err(|error| eyre!("{error}"))
            .wrap_err("accepted Nitro call contains an invalid attestation")?;
        let mut pcrs = [Bytes::new(), Bytes::new(), Bytes::new()];
        for (index, value) in pcrs.iter_mut().enumerate() {
            let pcr = parsed
                .pcrs
                .iter()
                .find(|pcr| usize::from(pcr.index) == index)
                .ok_or_eyre("accepted attestation is missing PCR0/1/2")?;
            ensure!(
                pcr.value.len() == 48 && pcr.value.iter().any(|byte| *byte != 0),
                "accepted attestation contains an invalid PCR{index}"
            );
            *value = Bytes::copy_from_slice(&pcr.value);
        }
        return Ok(Some((call.zoneId, pcrs)));
    }
    for child in &frame.calls {
        if let Some(pcrs) = verifier_pcrs(child, portal)? {
            return Ok(Some(pcrs));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{primitives::U256, rpc::types::Block, transports::mock::Asserter};
    use base64::Engine;
    use tempo_contracts::{
        precompiles::NO_PROOF_FALLBACK_VERIFIER,
        zones::{BlockTransition, DepositQueueTransition, TokenEnablementTransition},
    };

    fn batch() -> (Address, CallFrame, [Bytes; 3]) {
        let encoded: String =
            include_str!("../../crates/nitro-attestation/testdata/aws_attestation_2026_01_03.b64")
                .split_whitespace()
                .collect();
        let proof = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let parsed = parse_attestation(&proof).unwrap();
        let expected =
            std::array::from_fn(|index| Bytes::copy_from_slice(&parsed.pcrs[index].value));
        let portal = portal_address(1);
        let call = IZoneVerifier::verifyCall {
            zoneId: 1,
            tempoBlockNumber: 0,
            anchorBlockNumber: 0,
            anchorBlockHash: B256::ZERO,
            expectedWithdrawalBatchIndex: 0,
            nextZoneHeight: U256::ZERO,
            blockTransition: BlockTransition {
                prevBlockHash: B256::ZERO,
                nextBlockHash: B256::ZERO,
            },
            depositQueueTransition: DepositQueueTransition {
                prevProcessedHash: B256::ZERO,
                nextProcessedHash: B256::ZERO,
                prevDepositNumber: 0,
                nextDepositNumber: 0,
            },
            tokenEnablementTransition: TokenEnablementTransition {
                prevProcessedTokenCount: 0,
                nextProcessedTokenCount: 0,
            },
            withdrawalQueueHash: B256::ZERO,
            verifierConfig: Bytes::copy_from_slice(NITRO_VERIFIER_CONFIG_V1),
            proof: proof.into(),
        };
        let submission = submitBatchCall {
            tempoBlockNumber: 0,
            recentTempoBlockNumber: 0,
            blockTransition: call.blockTransition.clone(),
            depositQueueTransition: call.depositQueueTransition.clone(),
            tokenEnablementTransition: call.tokenEnablementTransition.clone(),
            withdrawalQueueHash: B256::ZERO,
            verifierConfig: call.verifierConfig.clone(),
            proof: call.proof.clone(),
            nextZoneHeight: U256::ZERO,
            signatures: Vec::new(),
        };
        let trace = CallFrame {
            to: Some(portal),
            typ: "CALL".to_owned(),
            input: submission.abi_encode().into(),
            calls: vec![CallFrame {
                from: portal,
                to: Some(ZONE_VERIFIER_ADDRESS),
                typ: "STATICCALL".to_owned(),
                input: call.abi_encode().into(),
                output: Some(IZoneVerifier::verifyCall::abi_encode_returns(&true).into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        (portal, trace, expected)
    }

    #[test]
    fn extracts_accepted_pcrs_in_nested_batch() {
        let (portal, trace, expected) = batch();
        let wrapper = CallFrame {
            calls: vec![trace],
            ..Default::default()
        };
        assert_eq!(batch_pcrs(&wrapper, portal).unwrap(), Some((1, expected)));
    }

    #[test]
    fn skips_fallback_failed_and_unrelated_calls() {
        let (portal, trace, _) = batch();
        for variant in 0..8 {
            let mut trace = trace.clone();
            match variant {
                0 => trace.error = Some("reverted ancestor".to_owned()),
                1 => trace.calls[0].error = Some("verifier reverted".to_owned()),
                2 => trace.calls[0].to = Some(Address::ZERO),
                3 => trace.calls[0].from = Address::ZERO,
                4 => {
                    trace.calls[0].output =
                        Some(IZoneVerifier::verifyCall::abi_encode_returns(&false).into())
                }
                5 => trace.input = Bytes::new(),
                6 => trace.calls[0].typ = "DELEGATECALL".to_owned(),
                7 => {
                    let mut call =
                        IZoneVerifier::verifyCall::abi_decode(&trace.calls[0].input).unwrap();
                    call.verifierConfig = Bytes::copy_from_slice(NO_PROOF_FALLBACK_VERIFIER);
                    call.proof = Bytes::new();
                    trace.calls[0].input = call.abi_encode().into();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                batch_pcrs(&trace, portal).unwrap(),
                None,
                "variant {variant}"
            );
        }
        let failed_wrapper = CallFrame {
            error: Some("reverted wrapper".to_owned()),
            calls: vec![trace],
            ..Default::default()
        };
        assert_eq!(batch_pcrs(&failed_wrapper, portal).unwrap(), None);
    }

    #[test]
    fn skips_reverted_sibling_and_finds_successful_batch() {
        let (portal, trace, expected) = batch();
        let mut failed = trace.clone();
        failed.error = Some("caught revert".to_owned());
        let wrapper = CallFrame {
            calls: vec![failed, trace],
            ..Default::default()
        };
        assert_eq!(batch_pcrs(&wrapper, portal).unwrap(), Some((1, expected)));
    }

    #[test]
    fn rejects_malformed_accepted_attestation() {
        let (portal, mut trace, _) = batch();
        let mut call = IZoneVerifier::verifyCall::abi_decode(&trace.calls[0].input).unwrap();
        call.proof = Bytes::from_static(&[0xff]);
        trace.calls[0].input = call.abi_encode().into();
        assert_eq!(
            batch_pcrs(&trace, portal).unwrap_err().to_string(),
            "accepted Nitro call contains an invalid attestation"
        );
    }

    #[tokio::test]
    async fn bounds_search_to_rpc_fork_including_unknown_successor() {
        let schedule: ForkSchedule = serde_json::from_value(serde_json::json!({
            "active": "T14",
            "schedule": [
                {"name": "T13", "activationTime": 30, "active": true},
                {"name": "T14", "activationTime": 70, "active": true},
                {"name": "FutureFork", "activationTime": 90, "active": false}
            ]
        }))
        .unwrap();
        for (fork, after, timestamps, expected) in [
            (TempoHardfork::T13, false, vec![50, 20, 40, 30], 3),
            (TempoHardfork::T13, true, vec![50, 80, 70, 60], 7),
            (TempoHardfork::T14, true, vec![50, 80, 90], 9),
        ] {
            let asserter = Asserter::new();
            asserter.push_success(&schedule);
            for timestamp in timestamps {
                let mut block = Block::<B256>::default();
                block.header.inner.timestamp = timestamp;
                let mut block = serde_json::to_value(block).unwrap();
                block["timestampMillis"] = serde_json::json!(format!("0x{:x}", timestamp * 1000));
                block["mainBlockGeneralGasLimit"] = serde_json::json!("0x0");
                block["sharedGasLimit"] = serde_json::json!("0x0");
                block["timestampMillisPart"] = serde_json::json!("0x0");
                asserter.push_success(&block);
            }
            let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect_mocked_client(asserter.clone());
            let schedule = provider.get_fork_schedule().await.unwrap();
            assert_eq!(
                fork_boundary(&provider, &schedule, 0, 9, fork, after)
                    .await
                    .unwrap(),
                expected
            );
            assert!(asserter.read_q().is_empty());
        }
    }

    #[test]
    fn historical_hardfork_selection_uses_timestamps_and_preserves_unknown_forks() {
        let schedule: ForkSchedule = serde_json::from_value(serde_json::json!({
            "active": "T13",
            "schedule": [
                {"name": "T13", "activationTime": 30, "active": true},
                {"name": "T14", "activationTime": 70, "active": false},
                {"name": "FutureFork", "activationTime": 90, "active": false}
            ]
        }))
        .unwrap();
        for (timestamp, expected) in [
            (29, "Genesis"),
            (30, "T13"),
            (69, "T13"),
            (70, "T14"),
            (90, "FutureFork"),
        ] {
            assert_eq!(hardfork_at(&schedule, timestamp), expected);
        }
    }

    #[tokio::test]
    async fn rejects_forks_missing_from_rpc_schedule() {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(Asserter::new());
        let schedule = ForkSchedule {
            schedule: Vec::new(),
            active: "Genesis".to_owned(),
        };
        assert_eq!(
            fork_boundary(&provider, &schedule, 0, 9, TempoHardfork::T13, false)
                .await
                .unwrap_err()
                .to_string(),
            "T13 is not scheduled by the RPC"
        );
    }
}
