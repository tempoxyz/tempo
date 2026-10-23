//! Read-only sampling of direct T13 ZonePortal Nitro submissions per hardfork interval.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    io::{self, Write},
};

use alloy_consensus::BlockHeader;
use alloy_primitives::{Address, FixedBytes, TxKind};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::Filter;
use alloy_sol_types::{SolCall, SolEvent};
use eyre::{OptionExt, WrapErr, ensure, eyre};
use serde::Serialize;
use tempo_alloy::{TempoNetwork, provider::TempoProviderExt, rpc::ForkSchedule};
use tempo_contracts::{
    precompiles::{IZoneFactory, ZONE_FACTORY_ADDRESS},
    zones::{BatchSubmitted, submitBatchCall},
};
use tempo_nitro_attestation::{SHA384_SIZE, parse_attestation, to_measurements};
use tempo_primitives::TempoTxEnvelope;
use tracing::info;

const LOG_QUERY_BLOCKS: u64 = 1_000;

type Pcrs = [FixedBytes<SHA384_SIZE>; 3];

/// Inspect observed PCRs without changing or inferring the approved PCR policy.
#[derive(Debug, clap::Args)]
#[command(after_help = "Samples direct Nitro PCRs by hardfork as JSON from settled zone batches.")]
pub struct ZonePcrHistory {
    /// Historical RPC endpoint serving `tempo_forkSchedule`, transactions, blocks, and logs.
    #[arg(long)]
    rpc_url: String,
    /// ZonePortal to inspect. Defaults to all portals registered in the factory.
    #[arg(long)]
    portal: Option<Address>,
    /// First block to scan (inclusive). Defaults to zero.
    #[arg(long)]
    from_block: Option<u64>,
    /// Last block to scan (inclusive). Defaults to latest at startup.
    #[arg(long)]
    to_block: Option<u64>,
}

impl ZonePcrHistory {
    pub async fn run(self) -> eyre::Result<()> {
        info!("Connecting for PCR history scan");
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&self.rpc_url)
            .await?;
        let intervals = self.scan(&provider).await?;
        let mut output = io::BufWriter::new(io::stdout());
        serde_json::to_writer_pretty(&mut output, &intervals)?;
        writeln!(output)?;
        output.flush()?;
        Ok(())
    }

    async fn scan(
        &self,
        provider: &impl Provider<TempoNetwork>,
    ) -> eyre::Result<Vec<ForkInterval>> {
        let from_block = self.from_block.unwrap_or(0);
        let to_block = match self.to_block {
            Some(to) => to,
            None => provider.get_block_number().await?,
        };
        ensure!(from_block <= to_block, "from-block can't exceed to-block");
        info!(from_block, to_block, "Fetching fork schedule");
        let mut intervals = fork_intervals(
            provider,
            provider.get_fork_schedule().await?,
            from_block,
            to_block,
        )
        .await?;
        if intervals.is_empty() {
            return Ok(intervals);
        }
        let portals = match self.portal {
            Some(portal) => BTreeSet::from([portal]),
            None => discover_portals(provider, to_block).await?,
        };
        if portals.is_empty() {
            info!("no portals to scan");
            return Ok(intervals);
        }
        for interval in &mut intervals {
            info!(hardfork = %interval.hardfork, "sampling hardfork interval");
            interval.observed_pcrs = sample_interval(provider, interval, &portals)
                .await
                .wrap_err_with(|| format!("sampling {} interval", interval.hardfork))?;
        }
        info!(intervals = intervals.len(), "PCR history scan complete");
        Ok(intervals)
    }
}

/// Configured hardfork interval, clipped to the effective requested block range.
#[derive(Debug, Serialize)]
struct ForkInterval {
    hardfork: String,
    #[serde(skip)]
    from_block: u64,
    #[serde(skip)]
    to_block: u64,
    observed_pcrs: Option<Pcrs>,
}

/// Resolve configured activations, including unknown future fork names, to block intervals.
async fn fork_intervals(
    provider: &impl Provider<TempoNetwork>,
    schedule: ForkSchedule,
    from: u64,
    to: u64,
) -> eyre::Result<Vec<ForkInterval>> {
    let mut end = to.checked_add(1).ok_or_eyre("to-block is too large")?;
    let mut forks = schedule.schedule;
    // Stable sorting preserves schedule order for forks activated together at genesis.
    forks.sort_by_key(|fork| fork.activation_time);
    let Some(t13) = forks.iter().position(|fork| fork.name == "T13") else {
        return Ok(Vec::new());
    };
    let mut timestamps = BTreeMap::new();
    let mut intervals = Vec::new();
    // Visit newest first: equal activations naturally leave earlier forks empty.
    for fork in forks.into_iter().skip(t13).rev() {
        if end == from {
            break;
        }
        let first = activation_block(
            provider,
            fork.activation_time,
            from,
            end - 1,
            &mut timestamps,
        )
        .await?;
        if first < end {
            intervals.push(ForkInterval {
                hardfork: fork.name,
                from_block: first,
                to_block: end - 1,
                observed_pcrs: None,
            });
        }
        end = first;
    }
    Ok(intervals)
}

/// Find the first block with timestamp >= activation, or to + 1 if not yet activated.
async fn activation_block(
    provider: &impl Provider<TempoNetwork>,
    timestamp: u64,
    from: u64,
    to: u64,
    timestamps: &mut BTreeMap<u64, u64>,
) -> eyre::Result<u64> {
    let mut low = from;
    let mut high = to.checked_add(1).ok_or_eyre("to-block is too large")?;
    while low < high {
        let middle = low + (high - low) / 2;
        let block_timestamp = match timestamps.entry(middle) {
            Entry::Occupied(timestamp) => *timestamp.get(),
            Entry::Vacant(timestamp) => {
                let block = provider
                    .get_block_by_number(middle.into())
                    .await?
                    .ok_or_eyre(format!("block {middle} is unavailable"))?;
                ensure!(
                    block.header.number() == middle,
                    "RPC returned the wrong block number for {middle}"
                );
                *timestamp.insert(block.header.timestamp())
            }
        };
        if block_timestamp < timestamp {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    Ok(low)
}

async fn sample_interval(
    provider: &impl Provider<TempoNetwork>,
    interval: &ForkInterval,
    portals: &BTreeSet<Address>,
) -> eyre::Result<Option<Pcrs>> {
    let mut filter = Filter::new()
        .address(portals.iter().copied().collect::<Vec<_>>())
        .event_signature(BatchSubmitted::SIGNATURE_HASH);
    for end_block in (interval.from_block..=interval.to_block)
        .rev()
        .step_by(LOG_QUERY_BLOCKS as usize)
    {
        let start = end_block
            .saturating_sub(LOG_QUERY_BLOCKS - 1)
            .max(interval.from_block);
        if ((interval.to_block - end_block) / LOG_QUERY_BLOCKS).is_multiple_of(10) {
            info!(hardfork = %interval.hardfork, from_block = start, to_block = end_block, end_block = end_block, "Sampling progress");
        }
        filter = filter.from_block(start).to_block(end_block);

        // Retain one window only. Hash order within a block is immaterial: PCRs are constant
        // throughout the hardfork interval, across all accepted direct Nitro submissions.
        let mut transactions = BTreeSet::new();
        for log in provider.get_logs(&filter).await? {
            log.log_decode::<BatchSubmitted>()?;
            let number = log
                .block_number
                .ok_or_eyre("BatchSubmitted event is missing its block number")?;
            let tx_hash = log
                .transaction_hash
                .ok_or_eyre("BatchSubmitted event is missing its transaction hash")?;
            transactions.insert((number, tx_hash));
        }
        for (_, hash) in transactions.into_iter().rev() {
            let transaction = provider
                .get_transaction_by_hash(hash)
                .await?
                .ok_or_eyre(format!("transaction {hash} is unavailable"))?;
            // Persisted events establish success; Tempo AA direct calls are atomic.
            if let Some(pcrs) = nitro_submission(transaction.inner.inner(), portals)? {
                info!(hardfork = %interval.hardfork, transaction = %hash, "found Nitro PCRs");
                return Ok(Some(pcrs));
            }
        }
    }
    info!(hardfork = %interval.hardfork, "no Nitro submission found");
    Ok(None)
}

/// Read registered portals at the selected upper block bound.
async fn discover_portals(
    provider: &impl Provider<TempoNetwork>,
    to: u64,
) -> eyre::Result<BTreeSet<Address>> {
    let factory = IZoneFactory::new(ZONE_FACTORY_ADDRESS, provider);
    let next = factory.nextZoneId().block(to.into()).call().await?;
    if next <= 1 {
        return Ok(BTreeSet::new());
    }
    let zones = provider
        .multicall()
        .dynamic::<IZoneFactory::zonesCall>()
        .block(to.into())
        .extend((1..next).map(|id| factory.zones(id)))
        .aggregate()
        .await?;
    Ok(zones.into_iter().map(|zone| zone.portal).collect())
}

/// Find one qualifying direct call; subsequent proofs need not be decoded.
fn nitro_submission(
    envelope: &TempoTxEnvelope,
    portals: &BTreeSet<Address>,
) -> eyre::Result<Option<Pcrs>> {
    for (index, (to, input)) in envelope.calls().enumerate() {
        if !matches!(to, TxKind::Call(portal) if portals.contains(&portal))
            || !input.starts_with(&submitBatchCall::SELECTOR)
        {
            continue;
        }
        let call = submitBatchCall::abi_decode_validate(input)?;
        if call.verifierConfig.as_ref() != [1] {
            continue;
        }
        let attestation = parse_attestation(&call.proof)
            .map_err(|error| eyre!("parsing Nitro proof at call {index}: {error}"))?;
        return to_measurements(&attestation.pcrs)
            .ok_or_eyre("attestation must contain SHA-384 measurements for PCR0/1/2")
            .map(|pcrs| Some(pcrs.map(FixedBytes::from)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
