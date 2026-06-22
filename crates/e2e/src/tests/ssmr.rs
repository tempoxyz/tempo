use std::time::Duration;

use alloy::{
    eips::eip2718::Encodable2718,
    network::{Ethereum, EthereumWallet, NetworkTransactionBuilder},
    primitives::{Bytes, U256},
    rpc::types::TransactionRequest,
    signers::local::{MnemonicBuilder, PrivateKeySigner},
    sol_types::SolCall,
};
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_ethereum::pool::TransactionPool;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_node::{PoolTransaction, TempoPooledTransaction, TransactionOrigin};
use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};

use crate::{
    Setup, TestingNode,
    execution_runtime::{ExecutionRuntime, TEST_MNEMONIC},
    metrics::{Metrics, MetricsExt},
    setup_validators,
};

#[test_traced]
fn ssmr_streams_real_tip20_transfers() {
    let _ = tempo_eyre::install();

    Runner::from(Config::default().with_seed(42)).start(|mut context| async move {
        let setup = Setup::new()
            .how_many_signers(4)
            .epoch_length(100)
            .seed(42)
            .ssmr(true)
            .ssmr_shard_target_bytes(5 * 1024);
        let (mut nodes, execution_runtime) = setup_validators(&mut context, setup).await;

        for node in &mut nodes {
            node.consensus_config_mut().proposal_return_budget = Duration::from_millis(500);
        }

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;
        wait_for_all_validators_at_height(&context, 4, 3).await;

        let chain_id = nodes[0].execution_provider().chain_spec().chain_id();
        let transfers = sign_tip20_transfers(chain_id).await;
        inject_raw_transactions(&execution_runtime, &nodes, transfers).await;

        wait_for_ssmr_acceptance(&context).await;
    });
}

async fn wait_for_all_validators_at_height(
    context: &commonware_runtime::deterministic::Context,
    validators: usize,
    height: u64,
) {
    for _ in 0..600 {
        let metrics = context.to_metrics();
        metrics.assert_no_blocked_peers();
        if metrics.consensus_at_height(height) == validators {
            return;
        }
        context.sleep(Duration::from_millis(100)).await;
    }

    let metrics = context.to_metrics();
    panic!(
        "expected {validators} validators at height {height}; reached={}, latest_heights={:?}",
        metrics.consensus_at_height(height),
        metrics
            .values::<u64>("marshal_processed_height")
            .collect::<Vec<_>>()
    );
}

async fn sign_tip20_transfers(chain_id: u64) -> Vec<Bytes> {
    let mut signed = Vec::new();
    for i in 0..12 {
        let signer = wallet(10 + i);
        let recipient = crate::execution_runtime::address(40 + i);
        let call = ITIP20::transferCall {
            to: recipient,
            amount: U256::from(100 + i),
        };
        let mut request = TransactionRequest::default()
            .to(PATH_USD_ADDRESS)
            .input(call.abi_encode().into());
        request.nonce = Some(0);
        request.chain_id = Some(chain_id);
        request.gas = Some(1_000_000);
        request.max_fee_per_gas = Some(TEMPO_T1_BASE_FEE as u128);
        request.max_priority_fee_per_gas = Some(TEMPO_T1_BASE_FEE as u128);

        let envelope = <TransactionRequest as NetworkTransactionBuilder<Ethereum>>::build(
            request,
            &EthereumWallet::from(signer),
        )
        .await
        .expect("test transaction signs");
        signed.push(envelope.encoded_2718().into());
    }
    signed
}

async fn inject_raw_transactions(
    execution_runtime: &ExecutionRuntime,
    nodes: &[TestingNode<commonware_runtime::deterministic::Context>],
    transfers: Vec<Bytes>,
) {
    let pools = nodes
        .iter()
        .map(|node| node.execution().pool.clone())
        .collect::<Vec<_>>();
    let recovered = transfers
        .into_iter()
        .map(|tx| {
            <TempoPooledTransaction as PoolTransaction>::recover_raw_transaction(tx.as_ref())
                .expect("test transaction recovers")
        })
        .collect::<Vec<_>>();

    execution_runtime
        .run_async(async move {
            tokio::time::timeout(Duration::from_secs(10), async move {
                for pool in pools {
                    for tx in &recovered {
                        pool.add_transaction(TransactionOrigin::External, tx.clone())
                            .await?;
                    }
                }
                Ok::<_, eyre::Report>(())
            })
            .await
            .map_err(|_| eyre::eyre!("timed out submitting SSMR test transactions"))??;
            Ok::<_, eyre::Report>(())
        })
        .await
        .expect("execution runtime accepts SSMR test transactions")
        .expect("SSMR test transactions enter txpools");
}

async fn wait_for_ssmr_acceptance(context: &commonware_runtime::deterministic::Context) {
    for _ in 0..600 {
        let metrics = context.to_metrics();
        metrics.assert_no_blocked_peers();
        if metric_sum(&metrics, "ssmr_streams_completed_total") > 0
            && metric_sum(&metrics, "ssmr_optimistic_payloads_ready_total") > 0
            && metric_sum(&metrics, "ssmr_final_reconciliations_total") > 0
            && metric_sum(&metrics, "ssmr_shards_sent_total") > 0
            && metric_sum(&metrics, "ssmr_shards_received_total") > 0
            && metric_sum(&metrics, "ssmr_optimistic_payload_failures_total") == 0
            && metric_sum(&metrics, "ssmr_final_reconciliation_mismatches_total") == 0
        {
            return;
        }
        context.sleep(Duration::from_millis(100)).await;
    }

    let metrics = context.to_metrics();
    panic!(
        "expected SSMR metrics to move; sent={}, received={}, completed={}, ready={}, \
         failures={}, reconciliations={}, mismatches={}, fallback={}",
        metric_sum(&metrics, "ssmr_shards_sent_total"),
        metric_sum(&metrics, "ssmr_shards_received_total"),
        metric_sum(&metrics, "ssmr_streams_completed_total"),
        metric_sum(&metrics, "ssmr_optimistic_payloads_ready_total"),
        metric_sum(&metrics, "ssmr_optimistic_payload_failures_total"),
        metric_sum(&metrics, "ssmr_final_reconciliations_total"),
        metric_sum(&metrics, "ssmr_final_reconciliation_mismatches_total"),
        metric_sum(&metrics, "ssmr_fallback_validation_count_total"),
    );
}

fn metric_sum(metrics: &Metrics, suffix: &str) -> u64 {
    metrics.values::<u64>(suffix).sum()
}

fn wallet(index: u32) -> PrivateKeySigner {
    MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(index)
        .expect("test mnemonic index is valid")
        .build()
        .expect("test wallet builds")
}
