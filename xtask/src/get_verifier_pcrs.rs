//! Recover PCR measurements from a successful on-chain Nitro batch verification.

use std::sync::Arc;

use alloy::{
    primitives::{Address, B256, Bytes, TxKind},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, TransactionRequest},
    sol_types::{SolCall, SolEvent},
};
use alloy_consensus::BlockHeader;
use eyre::{Context, OptionExt, ensure, eyre};
use serde::Serialize;
use tempo_alloy::{TempoNetwork, provider::TempoProviderExt, rpc::ForkSchedule};
use tempo_chainspec::{TempoChainSpec, TempoHardfork};
use tempo_contracts::{
    precompiles::{
        IZoneFactory, NITRO_VERIFIER_CONFIG_V1, ZONE_FACTORY_ADDRESS, ZONE_VERIFIER_ADDRESS,
    },
    zones::{BatchSubmitted, submitBatchCall},
};
use tempo_nitro_attestation::parse_attestation;
use tempo_precompiles::zone_factory::portal_address;
use tempo_primitives::TempoAddressExt;

#[derive(Debug, clap::Args)]
pub(crate) struct GetVerifierPcrs {
    /// Chain used for the default RPC URL and chain ID check, or a custom genesis JSON path.
    #[arg(long, short, value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Arc<TempoChainSpec>,

    /// RPC endpoint supporting tempo_forkSchedule, eth_getLogs and historical transactions.
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
        let hardfork = match self.hardfork {
            Some(hardfork) => hardfork,
            None => active_fork(&schedule, block_timestamp(&provider, to).await?)
                .map_or("Genesis", |index| schedule.schedule[index].name.as_str())
                .parse::<TempoHardfork>()
                .wrap_err("RPC reports a hardfork unsupported by this xtask version")?,
        };
        ensure!(
            hardfork >= TempoHardfork::T13,
            "{hardfork} predates the Nitro verifier (T13); no accepted Nitro PCRs are available"
        );
        let fork_index = schedule
            .schedule
            .iter()
            .position(|entry| entry.name == hardfork.to_string())
            .ok_or_else(|| eyre!("{hardfork} is not scheduled by the RPC"))?;

        // Only scan the selected fork's blocks, located by timestamp against the RPC's schedule.
        // This skips unrelated history, including proofless rollouts.
        let from = fork_start(&provider, &schedule, self.from_block, to, fork_index).await?;
        let upper = fork_start(&provider, &schedule, from, to, fork_index + 1).await?;
        ensure!(
            from < upper,
            "no blocks for {hardfork} in the requested range"
        );

        // Filter logs by portal address so look-alike BatchSubmitted events from other contracts
        // never reach the client. Factory portals live at deterministic addresses.
        let portals = if let Some(portal) = self.portal {
            ensure!(
                zone_id(portal).is_some(),
                "{portal} is not a canonical Zone portal address"
            );
            vec![portal]
        } else {
            let request = TransactionRequest::default()
                .to(ZONE_FACTORY_ADDRESS)
                .input(IZoneFactory::nextZoneIdCall {}.abi_encode().into());
            let output = provider
                .call(request.into())
                .block(to.into())
                .await
                .wrap_err("failed reading ZoneFactory.nextZoneId")?;
            let next = IZoneFactory::nextZoneIdCall::abi_decode_returns(&output)?;
            (1..next).map(portal_address).collect()
        };
        ensure!(!portals.is_empty(), "no Zone portals exist at block {to}");

        let mut end = upper - 1;
        loop {
            let start = end.saturating_sub(self.chunk_size - 1).max(from);
            let filter = Filter::new()
                .from_block(start)
                .to_block(end)
                .event_signature(BatchSubmitted::SIGNATURE_HASH)
                .address(portals.clone());
            let mut logs = provider.get_logs(&filter).await.wrap_err_with(|| {
                format!("failed to query batch logs in {start}..={end}; try a smaller --chunk-size")
            })?;
            logs.retain(|log| !log.removed);
            logs.sort_by_key(|log| (log.block_number, log.transaction_index, log.log_index));
            // Several batches for one portal in one transaction need a single lookup.
            logs.dedup_by_key(|log| (log.transaction_hash, log.address()));
            for log in logs.into_iter().rev() {
                let (Some(hash), Some(number), Some(block_hash)) =
                    (log.transaction_hash, log.block_number, log.block_hash)
                else {
                    return Err(eyre!("batch log has no transaction or block"));
                };
                let portal = log.address();
                // Reverted transactions keep no logs, so the log alone proves success. The
                // sequencer submits batches directly, so the proof is in the calldata.
                let transaction = provider
                    .get_transaction_by_hash(hash)
                    .await?
                    .ok_or_eyre("batch transaction is unavailable")?;
                let Some(pcrs) = direct_batch_pcrs(transaction.inner.inner().calls(), portal)?
                else {
                    continue;
                };
                let block = provider
                    .get_block_by_number(number.into())
                    .await?
                    .ok_or_eyre("batch block is unavailable")?;
                ensure!(
                    block.header.hash == block_hash,
                    "batch block is no longer canonical; retry after reorg"
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
                        zone_id: zone_id(portal).ok_or_eyre("batch log emitter is not a portal")?,
                        verifier: ZONE_VERIFIER_ADDRESS,
                        pcrs,
                    })?
                );
                return Ok(());
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

/// Index of the schedule entry active at `timestamp`.
fn active_fork(schedule: &ForkSchedule, timestamp: u64) -> Option<usize> {
    schedule
        .schedule
        .iter()
        .rposition(|entry| entry.activation_time <= timestamp)
}

/// First block in `from..=to` at or after schedule entry `fork_index`, or `to + 1` if none is.
async fn fork_start(
    provider: &impl Provider<TempoNetwork>,
    schedule: &ForkSchedule,
    from: u64,
    to: u64,
    fork_index: usize,
) -> eyre::Result<u64> {
    let mut low = from;
    let mut high = to.checked_add(1).ok_or_eyre("block range overflows")?;
    while low < high {
        let mid = low + (high - low) / 2;
        if active_fork(schedule, block_timestamp(provider, mid).await?)
            .is_some_and(|index| index >= fork_index)
        {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    Ok(low)
}

/// Zone ID of a canonical factory portal address, which is the prefix followed by a nonzero u32.
fn zone_id(portal: Address) -> Option<u32> {
    portal
        .zone_portal_id()
        .and_then(|zone_id| u32::try_from(zone_id).ok())
}

/// Read PCRs from a direct `submitBatch` call in the transaction's own calls.
///
/// The portal emits `BatchSubmitted` only after its verifier accepted the proof, and factory
/// portals always use [`ZONE_VERIFIER_ADDRESS`], so an emitted log proves acceptance without a
/// trace. Tempo AA calls are atomic, so every call of a transaction with the log succeeded.
fn direct_batch_pcrs<'a>(
    calls: impl IntoIterator<Item = (TxKind, &'a Bytes)>,
    portal: Address,
) -> eyre::Result<Option<[Bytes; 3]>> {
    calls
        .into_iter()
        .filter(|(to, _)| *to == TxKind::Call(portal))
        .filter_map(|(_, input)| submitBatchCall::abi_decode(input).ok())
        .find(|call| call.verifierConfig.as_ref() == NITRO_VERIFIER_CONFIG_V1)
        .map(|call| attestation_pcrs(&call.proof))
        .transpose()
}

/// PCR0/1/2 of an accepted Nitro attestation.
fn attestation_pcrs(proof: &[u8]) -> eyre::Result<[Bytes; 3]> {
    let parsed = parse_attestation(proof)
        .map_err(|error| eyre!("{error}"))
        .wrap_err("accepted Nitro call contains an invalid attestation")?;
    let pcr = |index: usize| -> eyre::Result<Bytes> {
        let value = &parsed
            .pcrs
            .iter()
            .find(|pcr| usize::from(pcr.index) == index)
            .ok_or_eyre("accepted attestation is missing PCR0/1/2")?
            .value;
        ensure!(
            value.len() == 48 && value.iter().any(|byte| *byte != 0),
            "accepted attestation contains an invalid PCR{index}"
        );
        Ok(Bytes::copy_from_slice(value))
    };
    Ok([pcr(0)?, pcr(1)?, pcr(2)?])
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

    #[test]
    fn reads_pcrs_only_from_direct_nitro_batches() {
        let encoded: String =
            include_str!("../../crates/nitro-attestation/testdata/aws_attestation_2026_01_03.b64")
                .split_whitespace()
                .collect();
        let proof = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let expected: [Bytes; 3] = std::array::from_fn(|index| {
            Bytes::copy_from_slice(&parse_attestation(&proof).unwrap().pcrs[index].value)
        });
        let mut submission = submitBatchCall {
            tempoBlockNumber: 0,
            recentTempoBlockNumber: 0,
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
            nextZoneHeight: U256::ZERO,
            signatures: Vec::new(),
        };
        let nitro = Bytes::from(submission.abi_encode());
        submission.proof = Bytes::from_static(&[0xff]);
        let malformed = Bytes::from(submission.abi_encode());
        submission.verifierConfig = Bytes::copy_from_slice(NO_PROOF_FALLBACK_VERIFIER);
        submission.proof = Bytes::new();
        let no_proof = Bytes::from(submission.abi_encode());
        let unrelated = Bytes::from_static(&[1, 2, 3, 4]);
        let portal = portal_address(1);
        let pcrs = |calls: Vec<(TxKind, &Bytes)>| direct_batch_pcrs(calls, portal);

        assert_eq!(
            pcrs(vec![
                (TxKind::Call(Address::ZERO), &nitro),
                (TxKind::Call(portal), &unrelated),
                (TxKind::Call(portal), &no_proof),
                (TxKind::Call(portal), &nitro),
            ])
            .unwrap(),
            Some(expected)
        );
        for calls in [
            vec![],
            vec![(TxKind::Call(portal), &no_proof)],
            vec![(TxKind::Call(portal_address(2)), &nitro)],
            vec![(TxKind::Create, &nitro)],
        ] {
            assert_eq!(pcrs(calls).unwrap(), None);
        }
        assert_eq!(
            pcrs(vec![(TxKind::Call(portal), &malformed)])
                .unwrap_err()
                .to_string(),
            "accepted Nitro call contains an invalid attestation"
        );
    }

    #[test]
    fn zone_id_accepts_only_canonical_portals() {
        let mut wide = portal_address(1);
        wide.0[12] = 1;
        let mut wrong_prefix = portal_address(1);
        wrong_prefix.0[0] ^= 1;
        for (address, expected) in [
            (portal_address(1), Some(1)),
            (portal_address(u32::MAX), Some(u32::MAX)),
            (portal_address(0), None),
            (wide, None),
            (wrong_prefix, None),
        ] {
            assert_eq!(zone_id(address), expected, "{address}");
        }
    }

    #[tokio::test]
    async fn fork_start_follows_rpc_schedule_including_unknown_forks() {
        let schedule: ForkSchedule = serde_json::from_value(serde_json::json!({
            "active": "T14",
            "schedule": [
                {"name": "T13", "activationTime": 30, "active": true},
                {"name": "T14", "activationTime": 70, "active": true},
                {"name": "FutureFork", "activationTime": 90, "active": false}
            ]
        }))
        .unwrap();
        // Ten blocks at timestamps 0, 10, ..., 90; each case lists the probed timestamps.
        for (fork_index, timestamps, expected) in [
            (0, vec![50, 20, 40, 30], 3),
            (1, vec![50, 80, 70, 60], 7),
            (2, vec![50, 80, 90], 9),
        ] {
            let asserter = Asserter::new();
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
            assert_eq!(
                fork_start(&provider, &schedule, 0, 9, fork_index)
                    .await
                    .unwrap(),
                expected
            );
            assert!(asserter.read_q().is_empty());
        }
        assert_eq!(active_fork(&schedule, 29), None);
        assert_eq!(active_fork(&schedule, 95), Some(2));
    }
}
