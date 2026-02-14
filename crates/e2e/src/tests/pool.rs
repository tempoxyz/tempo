//! E2E tests for transaction pool behavior after T1 hardfork.
//!
//! These tests verify that high-gas-limit transactions (up to 30M, Tempo's T1
//! per-tx cap) are accepted by the pool and successfully mined.
//!
//! Background: The reth `EthTransactionValidator` enforces `MAX_TX_GAS_LIMIT_OSAKA`
//! (EIP-7825, 2^24 ≈ 16.7M) when Osaka is activated. Since all Tempo hardforks map
//! to `SpecId::OSAKA`, this incorrectly rejects transactions with gas limits between
//! ~16.7M and 30M that should be valid under Tempo's T1 rules.

use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use alloy_network::{TxSignerSync, eip2718::Encodable2718};
use alloy_primitives::{Address, TxHash, U256, b256};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use futures::{StreamExt, future::join_all};
use reth_ethereum::{
    chainspec::{ChainSpecProvider, EthChainSpec},
    rpc::eth::EthApiServer,
};
use reth_node_builder::ConsensusEngineEvent;
use reth_node_core::primitives::transaction::TxHashRef;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_node::primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::Call,
};

use crate::{Setup, TestingNode, setup_validators};

/// Submit a pool transaction (non-subblock) with a given gas limit.
///
/// Uses nonce_key = 0 (1D nonce) so the transaction goes through the standard pool path.
async fn submit_pool_tx<TClock: commonware_runtime::Clock>(
    node: &TestingNode<TClock>,
    wallet: &PrivateKeySigner,
    gas_limit: u64,
) -> TxHash {
    let provider = node.execution_provider();
    let gas_price = TEMPO_T1_BASE_FEE as u128;

    let mut tx = TempoTransaction {
        chain_id: provider.chain_spec().chain_id(),
        calls: vec![Call {
            to: Address::ZERO.into(),
            input: Default::default(),
            value: Default::default(),
        }],
        gas_limit,
        nonce_key: U256::ZERO,
        nonce: 0,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price,
        ..Default::default()
    };
    let signature = wallet.sign_transaction_sync(&mut tx).unwrap();

    let tx = TempoTxEnvelope::AA(tx.into_signed(signature.into()));
    let tx_hash = *tx.tx_hash();
    node.execution()
        .eth_api()
        .send_raw_transaction(tx.encoded_2718().into())
        .await
        .expect("transaction with 25M gas should be accepted by the pool");

    tx_hash
}

/// Test that a transaction with 25M gas limit is accepted by the pool and mined
/// after the T1 hardfork.
///
/// This test exposes a bug where the reth EthTransactionValidator enforces the
/// Osaka EIP-7825 limit (MAX_TX_GAS_LIMIT_OSAKA = 2^24 ≈ 16.7M) instead of
/// Tempo's T1 per-transaction gas limit cap (30M).
///
/// The transaction uses 25M gas which is:
/// - Above MAX_TX_GAS_LIMIT_OSAKA (16,777,216) — would be rejected by vanilla reth
/// - Below TEMPO_T1_TX_GAS_LIMIT_CAP (30,000,000) — should be valid on Tempo
#[test_traced]
fn high_gas_limit_tx_accepted_after_t1() {
    let _ = tempo_eyre::install();

    Runner::from(Config::default().with_seed(0)).start(|mut context| async move {
        let how_many_signers = 4;

        let setup = Setup::new()
            .how_many_signers(how_many_signers)
            .epoch_length(10);

        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;

        for node in &mut nodes {
            node.consensus_config_mut().new_payload_wait_time = Duration::from_millis(500);
        }

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        let mut stream = nodes[0]
            .execution()
            .add_ons_handle
            .engine_events
            .new_listener();

        // First signer of the test mnemonic (has funds)
        let wallet = PrivateKeySigner::from_bytes(&b256!(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        ))
        .unwrap();

        let mut submitted = false;
        let mut tx_hash = None;

        while let Some(update) = stream.next().await {
            let block = match update {
                ConsensusEngineEvent::CanonicalBlockAdded(block, _) => block,
                _ => continue,
            };

            // After genesis, submit a tx with 25M gas limit
            if !submitted && block.block_number() >= 1 {
                // 25M gas: above Osaka EIP-7825 limit (16.7M), below Tempo T1 cap (30M)
                let hash = submit_pool_tx(&nodes[0], &wallet, 25_000_000).await;
                tx_hash = Some(hash);
                submitted = true;
            }

            // Check if our tx got included in any block after submission
            if submitted {
                if let Some(hash) = tx_hash {
                    let included = block
                        .sealed_block()
                        .body()
                        .transactions
                        .iter()
                        .any(|t| t.tx_hash() == *hash);
                    if included {
                        // Transaction was mined successfully
                        break;
                    }
                }
            }

            if block.block_number() >= 20 {
                panic!(
                    "transaction with 25M gas limit was never mined after 20 blocks — \
                     likely rejected by pool due to Osaka EIP-7825 MAX_TX_GAS_LIMIT_OSAKA check"
                );
            }
        }
    });
}
