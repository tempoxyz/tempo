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
use tempo_alloy::{
    TempoNetwork,
    provider::TempoProviderExt,
    rpc::{ForkSchedule, TempoHeaderResponse},
};
use tempo_contracts::precompiles::{IZoneFactory, IZonePortal, ZONE_FACTORY_ADDRESS};
use tempo_nitro_attestation::{SHA384_SIZE, parse_attestation, to_measurements};
use tempo_primitives::TempoTxEnvelope;

const LOG_QUERY_BLOCKS: u64 = 1_000;

type Pcrs = [FixedBytes<SHA384_SIZE>; 3];

/// Inspect observed PCRs without changing or inferring the approved PCR policy.
#[derive(Debug, clap::Args)]
#[command(after_help = "Samples direct Nitro PCRs by hardfork as JSON from settled zone batches.")]
pub struct PcrHistory {
    /// Historical RPC endpoint serving `tempo_forkSchedule`, transactions, blocks, and logs.
    #[arg(long)]
    rpc_url: String,
    /// ZonePortal to inspect. Defaults to all portals discovered from factory events.
    #[arg(long)]
    portal: Option<Address>,
    /// First block to scan (inclusive). Factory discovery may raise this to the first creation.
    #[arg(long)]
    from_block: Option<u64>,
    /// Last block to scan (inclusive). Defaults to latest at startup.
    #[arg(long)]
    to_block: Option<u64>,
}

impl PcrHistory {
    pub async fn run(self) -> eyre::Result<()> {
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
        let mut from = self.from_block.unwrap_or(0);
        let to = match self.to_block {
            Some(to) => to,
            None => provider.get_block_number().await?,
        };
        ensure!(from <= to, "from-block must not exceed to-block");
        let schedule = provider.get_fork_schedule().await?;

        // With only the T13 topic enabled, an unscheduled T13 has no covered intervals.
        if !schedule.schedule.iter().any(|fork| fork.name == "T13") {
            return Ok(Vec::new());
        }
        let portals = match self.portal {
            Some(portal) => BTreeSet::from([portal]),
            None => {
                let (portals, first_creation) = discover_portals(provider, to).await?;
                from = from.max(first_creation);
                portals
            }
        };
        if portals.is_empty() || from > to {
            return Ok(Vec::new());
        }
        let mut intervals = fork_intervals(provider, schedule, from, to).await?;
        for interval in &mut intervals {
            interval.observed_pcrs = sample_interval(provider, interval, &portals)
                .await
                .wrap_err_with(|| format!("sampling {} interval", interval.hardfork))?;
        }
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
    // Standard RPC returns transaction hashes, not full transactions, with this request.
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
    let mut end = interval.to_block;
    loop {
        let start = end
            .saturating_sub(LOG_QUERY_BLOCKS - 1)
            .max(interval.from_block);
        let filter = Filter::new()
            .address(portals.iter().copied().collect::<Vec<_>>())
            .event_signature(IZonePortal::BatchSubmitted::SIGNATURE_HASH)
            .from_block(start)
            .to_block(end);
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
                return Ok(Some(pcrs));
            }
        }
        if start == interval.from_block {
            return Ok(None);
        }
        end = start - 1;
    }
}

/// Discover portals including creations before the requested submission range.
async fn discover_portals(
    provider: &impl Provider<TempoNetwork>,
    to: u64,
) -> eyre::Result<(BTreeSet<Address>, u64)> {
    let (mut portals, mut first, mut end) = (BTreeSet::new(), to, to);
    loop {
        let start = end.saturating_sub(LOG_QUERY_BLOCKS - 1);
        let filter = Filter::new()
            .address(ZONE_FACTORY_ADDRESS)
            .event_signature(IZoneFactory::ZoneCreated::SIGNATURE_HASH)
            .from_block(start)
            .to_block(end);
        for log in provider.get_logs(&filter).await? {
            let event = log.log_decode::<IZoneFactory::ZoneCreated>()?;
            let block = log
                .block_number
                .ok_or_eyre("ZoneCreated event is missing its block number")?;
            first = first.min(block);
            portals.insert(event.inner.data.portal);
        }
        if start == 0 {
            break;
        }
        end = start - 1;
    }
    Ok((portals, first))
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
    use tempo_contracts::precompiles::IZoneVerifier::{
        BlockTransition, DepositQueueTransition, TokenEnablementTransition,
    };
    use tempo_primitives::{TempoTransaction, transaction::Call};

    const PORTAL: Address = address!("5ad0000000000000000000000000000000000001");

    fn command(from: u64, to: u64) -> PcrHistory {
        PcrHistory {
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
                verifierConfig: config.to_vec().into(),
                proof,
                nextZoneHeight: U256::from(1),
                signatures: Vec::new(),
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
        let event = IZonePortal::BatchSubmitted {
            withdrawalBatchIndex: 0,
            withdrawalQueueIndex: U256::ZERO,
            nextProcessedDepositQueueHash: B256::ZERO,
            nextBlockHash: B256::ZERO,
            withdrawalQueueHash: B256::ZERO,
            lastProcessedDepositNumber: 0,
            lastProcessedEnabledTokenCount: 0,
        };
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
        let event = IZoneFactory::ZoneCreated {
            zoneId: 1,
            portal: PORTAL,
            initialToken: Address::ZERO,
            accessMode: false,
            gatewayMode: false,
            admin: Address::ZERO,
            sequencers: Vec::new(),
            threshold: 1,
            verifier: Address::ZERO,
        };
        let log = Log {
            inner: alloy_primitives::Log {
                address: ZONE_FACTORY_ADDRESS,
                data: event.encode_log_data(),
            },
            block_number: Some(0),
            ..Default::default()
        };
        for number in [Some(0), None] {
            let asserter = Asserter::new();
            let mut log = log.clone();
            log.block_number = number;
            asserter.push_success(&Vec::<Log>::new());
            asserter.push_success(&vec![log.clone(), log]);
            let result = discover_portals(&mock_provider(&asserter), LOG_QUERY_BLOCKS).await;
            if number.is_some() {
                assert_eq!(result.unwrap(), (BTreeSet::from([PORTAL]), 0));
            } else {
                assert!(result.is_err());
            }
            assert!(asserter.read_q().is_empty());
        }
        let asserter = Asserter::new();
        asserter.push_success(&"0xa");
        asserter.push_success(&schedule(&[("T13", 0)]));
        asserter.push_success(&Vec::<Log>::new());
        let cmd = PcrHistory {
            portal: None,
            from_block: None,
            to_block: None,
            ..command(0, 0)
        };
        assert!(
            cmd.scan(&mock_provider(&asserter))
                .await
                .unwrap()
                .is_empty()
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
            let args = ["tempo", "pcr-history", "--rpc-url", "http://localhost:8545"]
                .into_iter()
                .chain(extra);
            let crate::tempo_cmd::TempoSubcommand::PcrHistory(cmd) =
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
            "from-block must not exceed to-block"
        );
    }
}
