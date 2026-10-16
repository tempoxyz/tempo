//! Regression tests for historical Zone PCR queries.

use super::*;
use alloy::transports::mock::Asserter;
use alloy_consensus::{
    Signed, TxLegacy,
    transaction::{Recovered, TxHashRef},
};
use alloy_primitives::{B256, Bytes, Signature, U256, address};
use alloy_provider::bindings::IMulticall3;
use alloy_rpc_types_eth::{Block, BlockTransactions, Log, Transaction};
use base64::Engine;
use serde_json::json;
use tempo_alloy::rpc::{ForkInfo, TempoHeaderResponse};
use tempo_contracts::{
    precompiles::ZoneInfo,
    zones::{BlockTransition, DepositQueueTransition, TokenEnablementTransition},
};
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
        "../../../../crates/nitro-attestation/testdata/aws_attestation_2026_01_03.b64"
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
        input: submitBatchCall {
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
            nextZoneHeight: U256::ONE,
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
    let event = BatchSubmitted {
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

fn header(number: u64, timestamp: u64) -> Block<Transaction<TempoTxEnvelope>, TempoHeaderResponse> {
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

fn mock() -> (Asserter, impl Provider<TempoNetwork>) {
    let rpc = Asserter::new();
    let provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(rpc.clone());
    (rpc, provider)
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
    let (rpc, provider) = mock();
    rpc.push_success(&schedule(&[("T13", 0)]));
    for number in [1250, 625, 312, 156, 78, 39, 19, 9, 4, 2, 1, 0] {
        rpc.push_success(&header(number, number));
    }
    for _ in 0..2 {
        rpc.push_success(&Vec::<Log>::new());
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
    rpc.push_success(&logs);
    for (number, tx) in &candidates {
        rpc.push_success(&transaction(*number, tx.clone()));
    }
    let intervals = command(0, 2_500).scan(&provider).await.unwrap();
    assert!(rpc.read_q().is_empty());
    assert_eq!(
        serde_json::to_value(intervals).unwrap(),
        json!([{
            "hardfork": "T13",
            "observed_pcrs": to_measurements(&parse_attestation(&proof()).unwrap().pcrs).unwrap().map(FixedBytes::from),
        }])
    );
}

#[tokio::test]
async fn fork_boundaries() {
    for (forks, from, to, reads, expected) in [
        (
            vec![("T12", 0), ("T13", 0), ("T14", 0), ("FutureFork", 5)],
            2,
            6,
            vec![4, 6, 5, 3, 2],
            vec![("FutureFork", 5, 6), ("T14", 2, 4)],
        ),
        (
            vec![("T13", 2), ("FutureFork", 5), ("LaterFork", 100)],
            0,
            9,
            vec![5, 8, 9, 2, 4, 1],
            vec![("FutureFork", 5, 9), ("T13", 2, 4)],
        ),
        (vec![("T12", 0)], 0, 3, Vec::new(), Vec::new()),
        (vec![("T13", 10)], 0, 3, vec![2, 3], Vec::new()),
    ] {
        let (rpc, provider) = mock();
        for number in reads {
            rpc.push_success(&header(number, number));
        }
        let intervals = fork_intervals(&provider, schedule(&forks), from, to)
            .await
            .unwrap();
        assert_eq!(
            intervals
                .iter()
                .map(|i| (i.hardfork.as_str(), i.from_block, i.to_block))
                .collect::<Vec<_>>(),
            expected
        );
        assert!(rpc.read_q().is_empty());
    }
    let (rpc, provider) = mock();
    for (number, seconds) in [(2, 105), (1, 99), (3, 110)] {
        rpc.push_success(&header(number, seconds));
    }
    let mut cache = BTreeMap::new();
    for (time, from, expected) in [(100, 0, 2), (110, 2, 3), (200, 0, 4)] {
        assert_eq!(
            activation_block(&provider, time, from, 3, &mut cache)
                .await
                .unwrap(),
            expected
        );
    }
    assert!(rpc.read_q().is_empty());
}

#[tokio::test]
async fn invalid_rpc_data() {
    let envelope = aa(vec![submission(&[1], proof())]);
    for case in ["schedule", "number", "transaction"] {
        let (rpc, provider) = mock();
        if case == "schedule" {
            rpc.push_failure_msg("fork schedule unavailable");
        } else {
            let mut log = batch_log(1, *envelope.tx_hash());
            match case {
                "number" => log.block_number = None,
                "transaction" => log.transaction_hash = None,
                _ => {}
            }
            rpc.push_success(&schedule(&[("T13", 0), ("T14", 2)]));
            rpc.push_success(&header(1, 1));
            rpc.push_success(&vec![log]);
        }
        assert!(command(1, 1).scan(&provider).await.is_err(), "{case}");
        assert!(rpc.read_q().is_empty(), "{case}");
    }
    let (_, provider) = mock();
    let error = command(2, 1).scan(&provider).await.unwrap_err();
    assert_eq!(error.to_string(), "from-block can't exceed to-block");
}

#[tokio::test]
async fn portal_discovery() {
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
    for next in [0u32, 1, 3] {
        let (rpc, provider) = mock();
        rpc.push_success(&Bytes::from(
            IZoneFactory::nextZoneIdCall::abi_encode_returns(&next),
        ));
        if next > 1 {
            let encoded = Bytes::from(IZoneFactory::zonesCall::abi_encode_returns(&zone));
            rpc.push_success(&Bytes::from(
                IMulticall3::aggregateCall::abi_encode_returns(&IMulticall3::aggregateReturn {
                    blockNumber: U256::from(10),
                    returnData: vec![encoded.clone(), encoded],
                }),
            ));
        }
        let portals = discover_portals(&provider, 10).await.unwrap();
        assert_eq!(
            portals,
            if next <= 1 {
                BTreeSet::new()
            } else {
                BTreeSet::from([PORTAL])
            }
        );
        assert!(rpc.read_q().is_empty());
    }
    let (rpc, provider) = mock();
    rpc.push_failure_msg("factory unavailable");
    assert!(discover_portals(&provider, 10).await.is_err());
    assert!(rpc.read_q().is_empty());
}

#[tokio::test]
async fn empty_portal_discovery_preserves_intervals() {
    for next in [0u32, 1] {
        let (rpc, provider) = mock();
        rpc.push_success(&schedule(&[("T13", 0), ("T14", 1)]));
        rpc.push_success(&header(1, 1));
        rpc.push_success(&header(0, 0));
        rpc.push_success(&Bytes::from(
            IZoneFactory::nextZoneIdCall::abi_encode_returns(&next),
        ));
        let mut cmd = command(0, 1);
        cmd.portal = None;
        let intervals = cmd.scan(&provider).await.unwrap();
        assert_eq!(
            serde_json::to_value(intervals).unwrap(),
            json!([
                {"hardfork": "T14", "observed_pcrs": null},
                {"hardfork": "T13", "observed_pcrs": null},
            ])
        );
        assert!(rpc.read_q().is_empty());
    }
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
