//! Read-only sampling of direct T13 ZonePortal Nitro submissions per hardfork interval.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    io::{self, Write},
};

use alloy_consensus::BlockHeader;
use alloy_network::TransactionBuilder;
use alloy_primitives::{Address, FixedBytes, TxKind};
use alloy_provider::{CallItem, Provider, ProviderBuilder};
use alloy_rpc_types_eth::Filter;
use alloy_sol_types::{SolCall, SolEvent};
use eyre::{OptionExt, WrapErr, ensure, eyre};
use serde::Serialize;
use tempo_alloy::{
    TempoNetwork,
    provider::TempoProviderExt,
    rpc::{ForkSchedule, TempoHeaderResponse, TempoTransactionRequest},
};
use tempo_contracts::precompiles::{IZoneFactory, IZonePortal, ZONE_FACTORY_ADDRESS};
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
        info!(rpc_url = %self.rpc_url, "Connecting for PCR history scan");
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
        let schedule = provider.get_fork_schedule().await?;

        // Sampling starts at T13, so an unscheduled T13 has no covered intervals.
        if !schedule.schedule.iter().any(|fork| fork.name == "T13") {
            info!("T13 not scheduled yet");
            return Ok(Vec::new());
        }
        let portals = match self.portal {
            Some(portal) => BTreeSet::from([portal]),
            None => discover_portals(provider, to_block).await?,
        };
        if portals.is_empty() {
            info!("no portals to scan");
            return Ok(Vec::new());
        }
        let mut intervals = fork_intervals(provider, schedule, from_block, to_block).await?;
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
    let end = to.checked_add(1).ok_or_eyre("to-block is too large")?;
    let mut forks = schedule.schedule;
    // Stable sorting preserves schedule order for forks activated together at genesis.
    forks.sort_by_key(|fork| fork.activation_time);
    let Some(t13) = forks.iter().position(|fork| fork.name == "T13") else {
        return Ok(Vec::new());
    };
    let mut activations = BTreeMap::new();
    for fork in forks.into_iter().skip(t13) {
        // Earlier forks at the same timestamp have no observable block interval.
        activations.insert(fork.activation_time, fork.name);
    }
    let mut activations = activations.into_iter().peekable();
    let mut timestamps = BTreeMap::new();
    let mut intervals = Vec::new();
    // Finding T13 above guarantees at least one activation.
    let timestamp = activations.peek().unwrap().0;
    let mut first = activation_block(provider, timestamp, from, to, &mut timestamps).await?;
    while let Some((_, name)) = activations.next() {
        if first == end {
            break;
        }
        let next = match activations.peek() {
            Some((timestamp, _)) => {
                activation_block(provider, *timestamp, first, to, &mut timestamps).await?
            }
            None => end,
        };
        if first < next {
            intervals.push(ForkInterval {
                hardfork: name,
                from_block: first,
                to_block: next - 1,
                observed_pcrs: None,
            });
        }
        first = next;
    }
    intervals.reverse();
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
                *timestamp.insert(fetch_header(provider, middle).await?.timestamp())
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

async fn fetch_header(
    provider: &impl Provider<TempoNetwork>,
    number: u64,
) -> eyre::Result<TempoHeaderResponse> {
    let block = provider
        .get_block_by_number(number.into())
        .await?
        .ok_or_eyre(format!("block {number} is unavailable"))?;
    ensure!(
        block.header.number() == number,
        "RPC returned the wrong block number for {number}"
    );
    Ok(block.header)
}

async fn sample_interval(
    provider: &impl Provider<TempoNetwork>,
    interval: &ForkInterval,
    portals: &BTreeSet<Address>,
) -> eyre::Result<Option<Pcrs>> {
    let mut filter = Filter::new()
        .address(portals.iter().copied().collect::<Vec<_>>())
        .event_signature(IZonePortal::BatchSubmitted::SIGNATURE_HASH);
    let mut end_block = interval.to_block;
    loop {
        let start = end_block
            .saturating_sub(LOG_QUERY_BLOCKS - 1)
            .max(interval.from_block);
        if ((interval.to_block - end_block) / LOG_QUERY_BLOCKS) % 10 == 0 {
            info!(hardfork = %interval.hardfork, from_block = start, to_block = end_block, end_block = end_block, "Sampling progress");
        }
        filter = filter.from_block(start).to_block(end_block);

        // Retain one window only. Hash order within a block is immaterial: PCRs are constant
        // throughout the hardfork interval, across all accepted direct Nitro submissions.
        let mut transactions = BTreeSet::new();
        for log in provider.get_logs(&filter).await? {
            log.log_decode::<IZonePortal::BatchSubmitted>()?;
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
        if start == interval.from_block {
            info!(hardfork = %interval.hardfork, "no Nitro submission found");
            return Ok(None);
        }
        end_block = start - 1;
    }
}

/// Read registered portals at the selected upper block bound.
async fn discover_portals(
    provider: &impl Provider<TempoNetwork>,
    to: u64,
) -> eyre::Result<BTreeSet<Address>> {
    let output = provider
        .call(
            TempoTransactionRequest::default()
                .with_to(ZONE_FACTORY_ADDRESS)
                .with_input(IZoneFactory::nextZoneIdCall {}.abi_encode()),
        )
        .block(to.into())
        .await?;
    let next = IZoneFactory::nextZoneIdCall::abi_decode_returns(&output)?;
    let zones = provider
        .multicall()
        .dynamic::<IZoneFactory::zonesCall>()
        .block(to.into())
        .extend_calls((1..next).map(|id| {
            CallItem::new(
                ZONE_FACTORY_ADDRESS,
                IZoneFactory::zonesCall { id }.abi_encode().into(),
            )
        }))
        .aggregate()
        .await?;
    let portals = zones
        .into_iter()
        .map(|zone| zone.portal)
        .collect::<BTreeSet<_>>();
    Ok(portals)
}

/// Find one qualifying direct call; subsequent proofs need not be decoded.
fn nitro_submission(
    envelope: &TempoTxEnvelope,
    portals: &BTreeSet<Address>,
) -> eyre::Result<Option<Pcrs>> {
    for (index, (to, input)) in envelope.calls().enumerate() {
        if !matches!(to, TxKind::Call(portal) if portals.contains(&portal))
            || !input.starts_with(&IZonePortal::submitBatchCall::SELECTOR)
        {
            continue;
        }
        let call = IZonePortal::submitBatchCall::abi_decode_validate(input)?;
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
mod tests {
    use super::*;
    use alloy::transports::mock::Asserter;
    use alloy_consensus::{
        Signed, TxLegacy,
        transaction::{Recovered, TxHashRef},
    };
    use alloy_primitives::{B256, Bytes, Signature, U256, address};
    use alloy_rpc_types_eth::{Block, BlockTransactions, Log, Transaction};
    use base64::Engine;
    use clap::Parser;
    use serde_json::json;
    use tempo_alloy::rpc::ForkInfo;
    use tempo_primitives::{TempoTransaction, transaction::Call};

    const PORTAL: Address = address!("5ad0000000000000000000000000000000000001");

    fn command(from: u64, to: u64) -> ZonePcrHistory {
        ZonePcrHistory {
            rpc_url: String::new(),
            portal: Some(PORTAL),
            from_block: Some(from),
            to_block: Some(to),
        }
    }

    fn proof() -> Bytes {
        let encoded: String = include_str!(
            "../../../crates/nitro-attestation/testdata/aws_attestation_2026_01_03.b64"
        )
        .split_whitespace()
        .collect();
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap()
            .into()
    }

    fn submission(config: &[u8], proof: Bytes) -> Call {
        Call {
            to: TxKind::Call(PORTAL),
            value: U256::ZERO,
            input: IZonePortal::submitBatchCall {
                tempoBlockNumber: 1,
                verifierConfig: config.to_vec().into(),
                proof,
                nextZoneHeight: U256::ONE,
                signatures: Vec::new(),
                ..Default::default()
            }
            .abi_encode()
            .into(),
        }
    }

    fn aa(calls: Vec<Call>) -> TempoTxEnvelope {
        TempoTxEnvelope::AA(
            TempoTransaction {
                calls,
                ..Default::default()
            }
            .into_signed(Signature::test_signature().into()),
        )
    }

    fn transaction(number: u64, envelope: TempoTxEnvelope) -> Transaction<TempoTxEnvelope> {
        Transaction {
            inner: Recovered::new_unchecked(envelope, Address::ZERO),
            block_hash: Some(B256::ZERO),
            block_number: Some(number),
            block_timestamp: Some(number),
            transaction_index: Some(0),
            effective_gas_price: Some(0),
        }
    }

    fn batch_log(number: u64, tx_hash: B256) -> Log {
        let event = IZonePortal::BatchSubmitted::default();
        Log {
            inner: alloy_primitives::Log {
                address: PORTAL,
                data: event.encode_log_data(),
            },
            block_number: Some(number),
            block_hash: Some(B256::ZERO),
            transaction_hash: Some(tx_hash),
            ..Default::default()
        }
    }

    fn header(
        number: u64,
        timestamp: u64,
    ) -> Block<Transaction<TempoTxEnvelope>, TempoHeaderResponse> {
        let mut header = TempoHeaderResponse {
            inner: Default::default(),
            timestamp_millis: timestamp * 1_000 + 500,
        };
        header.inner.inner.inner.number = number;
        header.inner.inner.inner.timestamp = timestamp;
        Block::new(header, BlockTransactions::Hashes(Vec::new()))
    }

    fn schedule(forks: &[(&str, u64)]) -> ForkSchedule {
        ForkSchedule {
            active: "NotUsedForHistoricalQueries".into(),
            schedule: forks
                .iter()
                .map(|(name, time)| ForkInfo {
                    name: (*name).into(),
                    activation_time: *time,
                    active: false,
                    fork_id: None,
                })
                .collect(),
        }
    }

    fn mock_provider(asserter: &Asserter) -> impl Provider<TempoNetwork> {
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone())
    }

    #[tokio::test]
    async fn rpc_sampling() {
        let mut internal = submission(&[1], Bytes::new());
        internal.to = TxKind::Call(Address::ZERO);
        let candidates = [
            (3, aa(vec![submission(&[2], Bytes::new())])),
            (2, aa(vec![internal])),
            (
                1,
                aa(vec![
                    submission(&[1], proof()),
                    submission(&[1], Bytes::new()),
                ]),
            ),
        ];
        for (to, boundary_reads, empty_windows) in [
            (3, vec![2, 1, 0], 0),
            (
                2_500,
                vec![1250, 625, 312, 156, 78, 39, 19, 9, 4, 2, 1, 0],
                2,
            ),
        ] {
            let asserter = Asserter::new();
            asserter.push_success(&schedule(&[("T13", 0)]));
            for number in boundary_reads {
                asserter.push_success(&header(number, number));
            }
            for _ in 0..empty_windows {
                asserter.push_success(&Vec::<Log>::new());
            }
            // Duplicate events and an older malformed candidate must not be fetched again.
            let mut logs = candidates
                .iter()
                .flat_map(|(number, tx)| {
                    let log = batch_log(*number, *tx.tx_hash());
                    [log.clone(), log]
                })
                .collect::<Vec<_>>();
            logs.push(batch_log(0, B256::repeat_byte(0xff)));
            asserter.push_success(&logs);
            for (number, tx) in &candidates {
                asserter.push_success(&transaction(*number, tx.clone()));
            }
            let intervals = command(0, to)
                .scan(&mock_provider(&asserter))
                .await
                .unwrap();
            assert!(asserter.read_q().is_empty());
            assert_eq!(
                serde_json::to_value(intervals).unwrap(),
                json!([{
                    "hardfork": "T13",
                    "observed_pcrs": to_measurements(&parse_attestation(&proof()).unwrap().pcrs).unwrap().map(FixedBytes::from),
                }])
            );
        }
    }

    #[tokio::test]
    async fn fork_boundaries() {
        for (forks, from, to, reads, expected) in [
            (
                vec![("T12", 0), ("T13", 0), ("T14", 0), ("FutureFork", 5)],
                2,
                6,
                vec![4, 3, 2, 6, 5],
                vec![("FutureFork", 5, 6), ("T14", 2, 4)],
            ),
            (
                vec![("T13", 2), ("FutureFork", 5), ("LaterFork", 100)],
                0,
                9,
                vec![5, 2, 1, 6, 4, 7, 9],
                vec![("FutureFork", 5, 9), ("T13", 2, 4)],
            ),
            (vec![("T12", 0)], 0, 3, Vec::new(), Vec::new()),
            (vec![("T13", 10)], 0, 3, vec![2, 3], Vec::new()),
        ] {
            let asserter = Asserter::new();
            for number in reads {
                asserter.push_success(&header(number, number));
            }
            let intervals = fork_intervals(&mock_provider(&asserter), schedule(&forks), from, to)
                .await
                .unwrap();
            assert_eq!(
                intervals
                    .iter()
                    .map(|i| (i.hardfork.as_str(), i.from_block, i.to_block))
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                serde_json::to_value(&intervals).unwrap(),
                json!(
                    expected
                        .iter()
                        .map(|(name, _, _)| json!({
                            "hardfork": name, "observed_pcrs": null
                        }))
                        .collect::<Vec<_>>()
                )
            );
            assert!(asserter.read_q().is_empty());
        }
        let asserter = Asserter::new();
        for (number, seconds) in [(2, 105), (1, 99), (3, 110)] {
            asserter.push_success(&header(number, seconds));
        }
        let mut cache = BTreeMap::new();
        for (time, from, expected) in [(100, 0, 2), (110, 2, 3), (200, 0, 4)] {
            assert_eq!(
                activation_block(&mock_provider(&asserter), time, from, 3, &mut cache)
                    .await
                    .unwrap(),
                expected
            );
        }
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn invalid_rpc_data() {
        let envelope = aa(vec![submission(&[1], proof())]);
        for case in ["schedule", "number", "transaction"] {
            let asserter = Asserter::new();
            if case == "schedule" {
                asserter.push_failure_msg("fork schedule unavailable");
            } else {
                let mut log = batch_log(1, *envelope.tx_hash());
                match case {
                    "number" => log.block_number = None,
                    "transaction" => log.transaction_hash = None,
                    _ => {}
                }
                asserter.push_success(&schedule(&[("T13", 0), ("T14", 2)]));
                asserter.push_success(&header(1, 1));
                asserter.push_success(&vec![log]);
            }
            assert!(
                command(1, 1).scan(&mock_provider(&asserter)).await.is_err(),
                "{case}"
            );
            assert!(asserter.read_q().is_empty(), "{case}");
        }
    }

    #[tokio::test]
    async fn portal_discovery() {
        use alloy_provider::bindings::IMulticall3;
        use tempo_contracts::precompiles::ZoneInfo;
        let zone = ZoneInfo {
            zoneId: 1,
            portal: PORTAL,
            accessMode: false,
            gatewayMode: false,
            admin: Address::ZERO,
            sequencers: vec![],
            threshold: 1,
            verifier: Address::ZERO,
            rpcUrl: String::new(),
        };
        for next in [1u32, 3] {
            let asserter = Asserter::new();
            asserter.push_success(&Bytes::from(
                IZoneFactory::nextZoneIdCall::abi_encode_returns(&next),
            ));
            if next > 1 {
                let encoded = Bytes::from(IZoneFactory::zonesCall::abi_encode_returns(&zone));
                asserter.push_success(&Bytes::from(
                    IMulticall3::aggregateCall::abi_encode_returns(&IMulticall3::aggregateReturn {
                        blockNumber: U256::from(10),
                        returnData: vec![encoded.clone(), encoded],
                    }),
                ));
            }
            let portals = discover_portals(&mock_provider(&asserter), 10)
                .await
                .unwrap();
            assert_eq!(
                portals,
                if next == 1 {
                    BTreeSet::new()
                } else {
                    BTreeSet::from([PORTAL])
                }
            );
            assert!(asserter.read_q().is_empty());
        }
        let asserter = Asserter::new();
        asserter.push_failure_msg("factory unavailable");
        assert!(
            discover_portals(&mock_provider(&asserter), 10)
                .await
                .is_err()
        );
        assert!(asserter.read_q().is_empty());
    }

    #[test]
    fn nitro_decoding() {
        let portals = BTreeSet::from([PORTAL]);
        let parsed = parse_attestation(&proof()).unwrap();
        let expected = to_measurements(&parsed.pcrs).unwrap().map(FixedBytes::from);
        let mut truncated = submission(&[1], proof());
        truncated.input = truncated.input[..4].to_vec().into();
        let mut old = submission(&[1], Bytes::new());
        old.input = alloy_primitives::bytes!("78fb159b");
        let mut unrelated = submission(&[1], Bytes::new());
        unrelated.to = TxKind::Call(Address::ZERO);
        let accepted = Ok(Some(expected));
        let ignored = Ok(None);
        let invalid = Err(());
        for (call, result) in [
            (submission(&[1], proof()), accepted),
            (submission(&[], Bytes::new()), ignored),
            (submission(&[2], Bytes::new()), ignored),
            (submission(&[1, 0], Bytes::new()), ignored),
            (old, ignored),
            (unrelated, ignored),
            (submission(&[1], Bytes::new()), invalid),
            (truncated, invalid),
        ] {
            for tx in [
                aa(vec![call.clone()]),
                TempoTxEnvelope::Legacy(Signed::new_unhashed(
                    TxLegacy {
                        to: call.to,
                        input: call.input,
                        ..Default::default()
                    },
                    Signature::test_signature(),
                )),
            ] {
                assert_eq!(nitro_submission(&tx, &portals).map_err(|_| ()), result);
            }
        }
        let mut pcrs = parsed.pcrs;
        pcrs.reverse();
        assert_eq!(
            to_measurements(&pcrs).unwrap().map(FixedBytes::from),
            expected
        );
        let pcr0 = pcrs.iter().position(|pcr| pcr.index == 0).unwrap();
        pcrs[pcr0].value.pop();
        assert!(to_measurements(&pcrs).is_none());
        pcrs.remove(pcr0);
        assert!(to_measurements(&pcrs).is_none());
    }

    #[tokio::test]
    async fn cli_arguments() {
        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            command: crate::tempo_cmd::TempoSubcommand,
        }
        let portal = PORTAL.to_string();
        for (extra, expected) in [
            (vec![], (None, None, None)),
            (
                vec![
                    "--portal",
                    &portal,
                    "--from-block",
                    "10",
                    "--to-block",
                    "20",
                ],
                (Some(PORTAL), Some(10), Some(20)),
            ),
        ] {
            let args = [
                "tempo",
                "zone-pcr-history",
                "--rpc-url",
                "http://localhost:8545",
            ]
            .into_iter()
            .chain(extra);
            let crate::tempo_cmd::TempoSubcommand::ZonePcrHistory(cmd) =
                Cli::try_parse_from(args).unwrap().command
            else {
                panic!("wrong subcommand")
            };
            assert_eq!((cmd.portal, cmd.from_block, cmd.to_block), expected);
        }
        assert_eq!(
            command(2, 1)
                .scan(&mock_provider(&Asserter::new()))
                .await
                .unwrap_err()
                .to_string(),
            "from-block can't exceed to-block"
        );
    }
}
