use std::{collections::HashMap, time::Duration};

use alloy::{
    consensus::{Transaction, TxReceipt},
    rlp::Decodable,
    signers::local::PrivateKeySigner,
};
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
use tempo_chainspec::spec::{SYSTEM_TX_COUNT, TEMPO_T1_BASE_FEE};
use tempo_node::primitives::{
    SubBlockMetadata, TempoTransaction, TempoTxEnvelope,
    subblock::{PartialValidatorKey, TEMPO_SUBBLOCK_NONCE_KEY_PREFIX},
    transaction::{Call, calc_gas_balance_spending},
};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, nonce::NonceManager, tip20::TIP20Token,
};

use tempo_node::consensus::TEMPO_SHARED_GAS_DIVISOR;

use crate::{Setup, TestingNode, setup_validators};

#[test_traced]
fn subblocks_are_included() {
    let _ = tempo_eyre::install();

    Runner::from(Config::default().with_seed(0)).start(|mut context| async move {
        let how_many_signers = 4;

        let setup = Setup::new()
            .how_many_signers(how_many_signers)
            .epoch_length(10);

        // Setup and start all nodes.
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup.clone()).await;

        let mut fee_recipients = Vec::new();

        for node in &mut nodes {
            // Due to how Commonware deterministic runtime behaves in CI, we need to bump this timeout
            // to ensure that payload builder has enough time to accumulate subblocks.
            node.consensus_config_mut().new_payload_wait_time = Duration::from_millis(500);

            let fee_recipient = Address::random();
            node.consensus_config_mut().fee_recipient = fee_recipient;
            fee_recipients.push(fee_recipient);
        }

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        let mut stream = nodes[0]
            .execution()
            .add_ons_handle
            .engine_events
            .new_listener();

        let mut expected_transactions: Vec<TxHash> = Vec::new();
        while let Some(update) = stream.next().await {
            let block = match update {
                ConsensusEngineEvent::BlockReceived(_)
                | ConsensusEngineEvent::ForkchoiceUpdated(_, _)
                | ConsensusEngineEvent::CanonicalChainCommitted(_, _) => continue,
                ConsensusEngineEvent::ForkBlockAdded(_, _) => unreachable!("unexpected reorg"),
                ConsensusEngineEvent::InvalidBlock(_) => unreachable!("unexpected invalid block"),
                ConsensusEngineEvent::CanonicalBlockAdded(block, _) => block,
            };

            let receipts = &block.execution_outcome().receipts()[0];

            // Assert that block only contains our subblock transactions and the system transactions
            assert_eq!(
                block.sealed_block().body().transactions.len(),
                SYSTEM_TX_COUNT + expected_transactions.len()
            );

            // Assert that all expected transactions are included in the block.
            for tx in expected_transactions.drain(..) {
                if !block
                    .sealed_block()
                    .body()
                    .transactions
                    .iter()
                    .any(|t| t.tx_hash() == *tx)
                {
                    panic!("transaction {tx} was not included");
                }
            }

            // Assert that all transactions were successful
            for receipt in receipts {
                assert!(receipt.status());
            }

            if !expected_transactions.is_empty() {
                let fee_token_storage = &block
                    .execution_outcome()
                    .state()
                    .account(&DEFAULT_FEE_TOKEN)
                    .unwrap()
                    .storage;

                // Assert that all validators were paid for their subblock transactions
                for fee_recipient in &fee_recipients {
                    let balance_slot = TIP20Token::from_address(DEFAULT_FEE_TOKEN)
                        .unwrap()
                        .balances[*fee_recipient]
                        .slot();
                    let slot = fee_token_storage.get(&balance_slot).unwrap();

                    assert!(slot.present_value > slot.original_value());
                }
            }

            // Exit once we reach height 20.
            if block.block_number() == 20 {
                break;
            }

            // Send subblock transactions to all nodes.
            for node in nodes.iter() {
                for _ in 0..5 {
                    expected_transactions.push(submit_subblock_tx(node).await);
                }
            }
        }
    });
}

#[test_traced]
fn subblocks_are_included_with_failing_txs() {
    let _ = tempo_eyre::install();

    Runner::from(Config::default().with_seed(0)).start(|mut context| async move {
        let how_many_signers = 5;

        let setup = Setup::new()
            .how_many_signers(how_many_signers)
            .epoch_length(10);

        // Setup and start all nodes.
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup.clone()).await;

        let mut fee_recipients = Vec::new();

        for node in &mut nodes {
            // Due to how Commonware deterministic runtime behaves in CI, we need to bump this timeout
            // to ensure that payload builder has enough time to accumulate subblocks.
            node.consensus_config_mut().new_payload_wait_time = Duration::from_millis(500);

            let fee_recipient = Address::random();
            node.consensus_config_mut().fee_recipient = fee_recipient;
            fee_recipients.push(fee_recipient);
        }

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        let mut stream = nodes[0]
            .execution()
            .add_ons_handle
            .engine_events
            .new_listener();

        let mut expected_transactions: Vec<TxHash> = Vec::new();
        let mut failing_transactions: Vec<TxHash> = Vec::new();
        while let Some(update) = stream.next().await {
            let block = match update {
                ConsensusEngineEvent::BlockReceived(_)
                | ConsensusEngineEvent::ForkchoiceUpdated(_, _)
                | ConsensusEngineEvent::CanonicalChainCommitted(_, _) => continue,
                ConsensusEngineEvent::ForkBlockAdded(_, _) => unreachable!("unexpected reorg"),
                ConsensusEngineEvent::InvalidBlock(_) => unreachable!("unexpected invalid block"),
                ConsensusEngineEvent::CanonicalBlockAdded(block, _) => block,
            };
            let receipts = &block.execution_outcome().receipts()[0];

            // Assert that block only contains our subblock transactions and system transactions
            assert_eq!(
                block.sealed_block().body().transactions.len(),
                SYSTEM_TX_COUNT + expected_transactions.len()
            );

            // Assert that all expected transactions are included in the block.
            for tx in expected_transactions.drain(..) {
                if !block
                    .sealed_block()
                    .body()
                    .transactions
                    .iter()
                    .any(|t| t.tx_hash() == *tx)
                {
                    panic!("transaction {tx} was not included");
                }
            }

            let fee_recipients = Vec::<SubBlockMetadata>::decode(
                &mut block
                    .sealed_block()
                    .body()
                    .transactions
                    .last()
                    .unwrap()
                    .input()
                    .as_ref(),
            )
            .unwrap()
            .into_iter()
            .map(|metadata| {
                (
                    PartialValidatorKey::from_slice(&metadata.validator[..15]),
                    metadata.fee_recipient,
                )
            })
            .collect::<HashMap<_, _>>();

            let mut expected_fees = HashMap::new();
            let mut cumulative_gas_used = 0;

            for (receipt, tx) in receipts
                .iter()
                .zip(block.recovered_block().transactions_recovered())
            {
                if !expected_transactions.contains(tx.tx_hash()) {
                    continue;
                }

                let fee_recipient = fee_recipients
                    .get(&tx.subblock_proposer().unwrap())
                    .unwrap();
                *expected_fees.entry(fee_recipient).or_insert(U256::ZERO) +=
                    calc_gas_balance_spending(
                        receipt.cumulative_gas_used - cumulative_gas_used,
                        TEMPO_T1_BASE_FEE as u128,
                    );
                cumulative_gas_used = receipt.cumulative_gas_used;

                if !failing_transactions.contains(tx.tx_hash()) {
                    assert!(receipt.status());
                    assert!(receipt.cumulative_gas_used > 0);
                    continue;
                }

                let sender = tx.signer();
                let nonce_key = tx.as_aa().unwrap().tx().nonce_key;
                let nonce_slot = NonceManager::new().nonces[sender][nonce_key].slot();

                let slot = block
                    .execution_outcome()
                    .state()
                    .account(&NONCE_PRECOMPILE_ADDRESS)
                    .unwrap()
                    .storage
                    .get(&nonce_slot)
                    .unwrap();

                // Assert that all failing transactions have bumped the nonce and resulted in a failing receipt
                assert!(slot.present_value == slot.original_value() + U256::ONE);
                assert!(!receipt.status());
                assert!(receipt.logs().is_empty());
                assert_eq!(receipt.cumulative_gas_used, 0);
            }

            for (fee_recipient, expected_fee) in expected_fees {
                let fee_token_storage = &block
                    .execution_outcome()
                    .state()
                    .account(&DEFAULT_FEE_TOKEN)
                    .unwrap()
                    .storage;

                // Assert that all validators were paid for their subblock transactions
                let balance_slot = TIP20Token::from_address(DEFAULT_FEE_TOKEN)
                    .unwrap()
                    .balances[*fee_recipient]
                    .slot();
                let slot = fee_token_storage.get(&balance_slot).unwrap();

                assert_eq!(slot.present_value, slot.original_value() + expected_fee);
            }

            // Exit once we reach height 20.
            if block.block_number() == 20 {
                break;
            }

            // Send subblock transactions to all nodes.
            // TIP-1000 charges 250k gas for new account creation, so txs from random signers
            // need ~300k intrinsic gas. With 600k per-validator budget (5 validators), we fit 2 txs.
            for node in nodes.iter() {
                for _ in 0..5 {
                    // Randomly submit some of the transactions from a new signer that doesn't have any funds
                    if rand::random::<bool>() {
                        let tx =
                            submit_subblock_tx_from(node, &PrivateKeySigner::random(), 1_000_000)
                                .await;
                        failing_transactions.push(tx);
                        expected_transactions.push(tx);
                        tx
                    } else {
                        let tx = submit_subblock_tx(node).await;
                        expected_transactions.push(tx);
                        tx
                    };
                }
            }
        }
    });
}

#[test_traced]
fn oversized_subblock_txs_are_removed() {
    let _ = tempo_eyre::install();

    Runner::from(Config::default().with_seed(42)).start(|mut context| async move {
        let how_many_signers = 4;

        let setup = Setup::new()
            .how_many_signers(how_many_signers)
            .epoch_length(10);

        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup.clone()).await;

        for node in &mut nodes {
            node.consensus_config_mut().new_payload_wait_time = Duration::from_millis(500);
        }

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        let mut stream = nodes[0]
            .execution()
            .add_ons_handle
            .engine_events
            .new_listener();

        let (mut oversized_tx_hash, mut submitted) = (None, false);

        while let Some(update) = stream.next().await {
            let block = match update {
                ConsensusEngineEvent::CanonicalBlockAdded(block, _) => block,
                _ => continue,
            };

            // After first block, submit an oversized transaction
            if !submitted && block.block_number() >= 1 {
                let block_gas_limit = block.sealed_block().header().inner.gas_limit;
                let gas_budget =
                    block_gas_limit / TEMPO_SHARED_GAS_DIVISOR / how_many_signers as u64;

                oversized_tx_hash = Some(
                    submit_subblock_tx_from(&nodes[0], &PrivateKeySigner::random(), gas_budget + 1)
                        .await,
                );

                submitted = true;
            }

            // Check results after submission - verify oversized tx is never included
            if submitted && block.block_number() >= 3 {
                let txs = &block.sealed_block().body().transactions;

                // Oversized tx should NOT be included in any block
                if let Some(hash) = oversized_tx_hash {
                    assert!(
                        !txs.iter().any(|t| t.tx_hash() == *hash),
                        "oversized transaction should not be included in block"
                    );
                }
            }

            if block.block_number() >= 10 {
                break;
            }
        }
    });
}

async fn submit_subblock_tx<TClock: commonware_runtime::Clock>(
    node: &TestingNode<TClock>,
) -> TxHash {
    // First signer of the test mnemonic
    let wallet = PrivateKeySigner::from_bytes(&b256!(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    ))
    .unwrap();

    submit_subblock_tx_from(node, &wallet, 300_000).await
}

async fn submit_subblock_tx_from<TClock: commonware_runtime::Clock>(
    node: &TestingNode<TClock>,
    wallet: &PrivateKeySigner,
    gas_limit: u64,
) -> TxHash {
    let mut nonce_bytes = rand::random::<[u8; 32]>();
    nonce_bytes[0] = TEMPO_SUBBLOCK_NONCE_KEY_PREFIX;
    nonce_bytes[1..16].copy_from_slice(&node.public_key().as_ref()[..15]);

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
        nonce_key: U256::from_be_bytes(nonce_bytes),
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price,
        ..Default::default()
    };
    assert!(tx.subblock_proposer().unwrap().matches(node.public_key()));
    let signature = wallet.sign_transaction_sync(&mut tx).unwrap();

    let tx = TempoTxEnvelope::AA(tx.into_signed(signature.into()));
    let tx_hash = *tx.tx_hash();
    node.execution()
        .eth_api()
        .send_raw_transaction(tx.encoded_2718().into())
        .await
        .unwrap();

    tx_hash
}
