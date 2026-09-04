//! Fixed-input receiver benchmark: no block producer and no public Engine API changes.
//! SOURCE RECEIVER GENESIS FROM TO_EXCLUSIVE off|on OUTPUT_JSON [PACE_MS_OR_SOURCE]
//! RECEIVER must be a disposable source clone fully unwound to FROM-1 before launch.
use alloy::consensus::TxReceipt;
use alloy_primitives::Sealable;
use eyre::{OptionExt, ensure};
use reth_db::{mdbx::DatabaseArguments, open_db, open_db_read_only};
use reth_ethereum::{
    primitives::SealedBlock,
    provider::{
        ProviderFactory,
        providers::{BlockchainProvider, RocksDBProvider, StaticFileProvider},
    },
    rpc::types::engine::ForkchoiceState,
    storage::{BlockHashReader, BlockNumReader, BlockReader, ReceiptProvider},
    tasks::{RuntimeBuilder, RuntimeConfig, TokioConfig},
};
use reth_node_builder::NodeTypesWithDBAdapter;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tempo_chainspec::TempoChainSpec;
use tempo_e2e::execution_runtime::{ExecutionNodeConfig, launch_execution_node};
use tempo_node::node::TempoNode;
use tempo_payload_types::TempoExecutionData;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,engine::tree::payload_validator=debug".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let recorder = reth_node_metrics::recorder::install_prometheus_recorder();
    recorder.spawn_upkeep();
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        (7..=8).contains(&args.len()),
        "SOURCE RECEIVER GENESIS FROM TO_EXCLUSIVE off|on OUTPUT_JSON [PACE_MS_OR_SOURCE]"
    );
    let source_path = PathBuf::from(&args[0]).canonicalize()?;
    let receiver_path = PathBuf::from(&args[1]).canonicalize()?;
    ensure!(
        source_path != receiver_path,
        "source and receiver must be different directories"
    );
    ensure!(
        !receiver_path.starts_with(&source_path) && !source_path.starts_with(&receiver_path),
        "source and receiver must not overlap"
    );
    for component in ["db", "static_files", "rocksdb"] {
        let source_component = source_path.join(component).canonicalize()?;
        let receiver_component = receiver_path.join(component).canonicalize()?;
        ensure!(
            source_component != receiver_component
                && !source_component.starts_with(&receiver_component)
                && !receiver_component.starts_with(&source_component),
            "source and receiver {component} paths overlap"
        );
    }
    let from: u64 = args[3].parse()?;
    let to: u64 = args[4].parse()?;
    ensure!(
        from > 0 && to > from,
        "nonempty range and existing parent required"
    );
    let pace = args.get(7).map(String::as_str).unwrap_or("0");
    let source_pacing = pace == "source";
    let pace_ms: u64 = if source_pacing { 0 } else { pace.parse()? };
    let enabled = match args[5].as_str() {
        "off" => false,
        "on" => true,
        _ => eyre::bail!("mode must be off or on"),
    };
    let chain = TempoChainSpec::from_genesis(serde_json::from_slice(&std::fs::read(&args[2])?)?);
    let runtime = RuntimeBuilder::new(RuntimeConfig::default().with_tokio(
        TokioConfig::existing_handle(tokio::runtime::Handle::current()),
    ))
    .build()?;
    let source = BlockchainProvider::new(
        ProviderFactory::<NodeTypesWithDBAdapter<TempoNode, _>>::new(
            open_db_read_only(source_path.join("db"), DatabaseArguments::default())?,
            Arc::new(chain.clone()),
            StaticFileProvider::read_only(source_path.join("static_files"))?,
            RocksDBProvider::builder(source_path.join("rocksdb"))
                .with_read_only(true)
                .build()?,
            runtime.clone(),
        )?,
    )?;
    let parent = source
        .block_hash(from - 1)?
        .ok_or_eyre("missing source parent")?;
    // Preload all inputs and expected receipts before receiver launch/timing. Seal ordinary
    // blocks, retaining normal production signature recovery in the receiving engine.
    let inputs = (from..to)
        .map(|number| -> eyre::Result<_> {
            let block = source
                .block_by_number(number)?
                .ok_or_eyre("missing source block")?;
            let expected = source
                .receipts_by_block(number.into())?
                .ok_or_eyre("missing source receipts")?;
            ensure!(
                expected.len() == block.body.transactions.len(),
                "source receipt count mismatch"
            );
            Ok((SealedBlock::seal_slow(block), expected))
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    drop(source);
    let mut config = ExecutionNodeConfig::generate();
    config.incoming_replay = enabled;
    let node = launch_execution_node(
        runtime,
        chain,
        &receiver_path,
        config,
        open_db(receiver_path.join("db"), DatabaseArguments::default())?,
        None,
    )
    .await?;
    let engine = node.node.add_ons_handle.beacon_engine_handle.clone();
    ensure!(
        node.node.provider.best_block_number()? == from - 1,
        "receiver must be fully unwound to exact parent"
    );
    ensure!(
        node.node.provider.block_hash(from - 1)? == Some(parent),
        "receiver parent mismatch"
    );
    let initial = engine
        .fork_choice_updated(
            ForkchoiceState {
                head_block_hash: parent,
                safe_block_hash: parent,
                finalized_block_hash: parent,
            },
            None,
        )
        .await?;
    ensure!(initial.is_valid(), "initial FCU rejected: {initial:?}");
    let mut rows = Vec::with_capacity(inputs.len());
    let first_timestamp = inputs[0].0.header().timestamp_millis();
    let sequence_start = Instant::now();
    for (index, (block, expected_receipts)) in inputs.into_iter().enumerate() {
        let schedule_lag_us = if source_pacing || pace_ms > 0 {
            let offset_ms = if source_pacing {
                block
                    .header()
                    .timestamp_millis()
                    .checked_sub(first_timestamp)
                    .ok_or_eyre("source timestamp precedes first block")?
            } else {
                pace_ms.saturating_mul(index as u64)
            };
            let scheduled = sequence_start + Duration::from_millis(offset_ms);
            tokio::time::sleep(scheduled.saturating_duration_since(Instant::now())).await;
            Instant::now()
                .saturating_duration_since(scheduled)
                .as_micros()
        } else {
            0
        };
        let number = block.header().inner.number;
        let hash = block.hash();
        let root = block.header().inner.state_root;
        let receipt_root = block.header().inner.receipts_root;
        let timestamp_millis = block.header().timestamp_millis();
        let gas_used = block.header().inner.gas_used;
        let tx_count = block.body().transactions.len();
        // Reject any already-known block before timing; this benchmark must execute.
        ensure!(
            node.node.provider.block_by_number(number)?.is_none(),
            "receiver already knows block {number}"
        );
        let payload = TempoExecutionData {
            block: block.into(),
            block_access_list: None,
            validator_set: None,
        };
        let start = Instant::now();
        let result =
            tokio::time::timeout(Duration::from_secs(60), engine.new_payload(payload)).await??;
        let new_payload_us = start.elapsed().as_micros();
        ensure!(
            result.status.is_valid(),
            "newPayload {number} rejected: {result:?}"
        );
        ensure!(
            result.latest_valid_hash == Some(hash),
            "newPayload latest-valid hash mismatch"
        );
        let start = Instant::now();
        let fcu = tokio::time::timeout(
            Duration::from_secs(60),
            engine.fork_choice_updated(
                ForkchoiceState {
                    head_block_hash: hash,
                    safe_block_hash: parent,
                    finalized_block_hash: parent,
                },
                None,
            ),
        )
        .await??;
        let fcu_us = start.elapsed().as_micros();
        ensure!(fcu.is_valid(), "FCU {number} rejected: {fcu:?}");
        let accepted = node
            .node
            .provider
            .block_by_number(number)?
            .ok_or_eyre("missing accepted canonical block")?;
        ensure!(
            accepted.header.hash_slow() == hash
                && accepted.header.inner.state_root == root
                && accepted.header.inner.receipts_root == receipt_root,
            "canonical root/header mismatch"
        );
        let actual = node
            .node
            .provider
            .receipts_by_block(number.into())?
            .ok_or_eyre("missing receiver receipts")?;
        ensure!(
            actual == expected_receipts,
            "exact receipt vector mismatch at block {number}"
        );
        let successful_transactions = actual.iter().filter(|receipt| receipt.status()).count();
        let failed_transactions = actual.len() - successful_transactions;
        rows.push(serde_json::json!({"number": number, "schedule_lag_us": schedule_lag_us, "hash": hash, "state_root": root, "receipts_root": receipt_root, "transactions": tx_count, "successful_transactions": successful_transactions, "failed_transactions": failed_transactions, "timestamp_millis": timestamp_millis, "gas_used": gas_used, "new_payload_us": new_payload_us, "fcu_us": fcu_us, "exact_receipts": true}));
        eprintln!(
            "receiver block={number} transactions={tx_count} new_payload_us={new_payload_us} fcu_us={fcu_us}"
        );
    }
    std::fs::write(
        format!("{}.metrics.prom", args[6]),
        recorder.handle().render(),
    )?;
    node.shutdown().await;
    std::fs::write(
        &args[6],
        serde_json::to_vec_pretty(
            &serde_json::json!({"source":source_path,"receiver":receiver_path,"from":from,"to_exclusive":to,"parent":parent,"incoming_replay":enabled,"pace":pace,"entrypoint":"BeaconConsensusEngineHandle::new_payload -> EngineApiTreeHandler::on_new_payload -> BasicEngineValidator::execute_transactions", "allocator":"jemalloc", "asm_keccak":true, "keccak_cache_global":true, "prometheus_recorder":true, "available_parallelism":std::thread::available_parallelism()?.get(),"blocks":rows}),
        )?,
    )?;
    Ok(())
}
