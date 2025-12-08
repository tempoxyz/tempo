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
    deterministic::{self, Runner},
};
use futures::{StreamExt, future::join_all};
use reth_ethereum::{
    chainspec::{ChainSpecProvider, EthChainSpec},
    primitives::AlloyBlockHeader,
    provider::{CanonStateNotification, CanonStateSubscriptions},
    rpc::eth::EthApiServer,
};
use reth_node_core::primitives::transaction::TxHashRef;
use tempo_chainspec::{hardfork::TempoHardforks, spec::TEMPO_BASE_FEE};
use tempo_node::primitives::{
    SubBlockMetadata, TempoTransaction, TempoTxEnvelope,
    subblock::{PartialValidatorKey, TEMPO_SUBBLOCK_NONCE_KEY_PREFIX},
    transaction::{Call, calc_gas_balance_spending},
};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, NONCE_PRECOMPILE_ADDRESS, nonce,
    storage::{StorageKey, double_mapping_slot, mapping_slot},
    tip20::slots,
};

use crate::{Setup, TestingNode, setup_validators};

#[test_traced]
fn subblocks_are_included() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|context| async move {
        let how_many_signers = 5;

        let setup = Setup::new()
            .how_many_signers(how_many_signers)
            .epoch_length(10);

        // Setup and start all nodes.
        let (mut nodes, _execution_runtime) = setup_validators(context.clone(), setup).await;

        join_all(nodes.iter_mut().map(|node| {
            // Due to how Commonware deterministic runtime behaves in CI, we need to bump this timeout
            // to ensure that payload builder has enough time to accumulate subblocks.
            node.consensus_config_mut().new_payload_wait_time = Duration::from_millis(500);
            node.start()
        }))
        .await;

        let mut stream = nodes[0].execution_provider().canonical_state_stream();

        let mut expected_transactions: Vec<TxHash> = Vec::new();
        while let Some(update) = stream.next().await {
            let CanonStateNotification::Commit { new } = update else {
                unreachable!("unexpected reorg");
            };

            // Assert that all expected transactions are included in the block.
            for tx in expected_transactions.drain(..) {
                if !new.blocks().iter().any(|(_, block)| {
                    block
                        .sealed_block()
                        .body()
                        .transactions
                        .iter()
                        .any(|t| *t.tx_hash() == *tx)
                }) {
                    panic!("transaction {tx} was not included");
                }
            }

            // Exit once we reach height 20.
            if new.tip().number() == 20 {
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
fn subblocks_are_included_post_allegretto() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|context| async move {
        let how_many_signers = 5;

        let setup = Setup::new()
            .how_many_signers(how_many_signers)
            .allegretto_in_seconds(0)
            .epoch_length(10);

        // Setup and start all nodes.
        let (mut nodes, _execution_runtime) =
            setup_validators(context.clone(), setup.clone()).await;

        let mut fee_recipients = Vec::new();

        for node in &mut nodes {
            // Due to how Commonware deterministic runtime behaves in CI, we need to bump this timeout
            // to ensure that payload builder has enough time to accumulate subblocks.
            node.consensus_config_mut().new_payload_wait_time = Duration::from_millis(500);

            let fee_recipient = Address::random();
            node.consensus_config_mut().fee_recipient = fee_recipient;
            fee_recipients.push(fee_recipient);
        }

        join_all(nodes.iter_mut().map(|node| node.start())).await;

        let mut stream = nodes[0].execution_provider().canonical_state_stream();

        let mut expected_transactions: Vec<TxHash> = Vec::new();
        while let Some(update) = stream.next().await {
            let CanonStateNotification::Commit { new } = update else {
                unreachable!("unexpected reorg");
            };

            let block = new.blocks().iter().next().unwrap().1;
            let receipts = new.receipts_by_block_hash(block.hash()).unwrap();

            // Assert that block only contains our subblock transactions and 3 system transactions
            assert_eq!(
                block.sealed_block().body().transactions.len(),
                3 + expected_transactions.len()
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
                let fee_token_storage = &new
                    .execution_outcome()
                    .state()
                    .account(&DEFAULT_FEE_TOKEN_POST_ALLEGRETTO)
                    .unwrap()
                    .storage;

                // Assert that all validators were paid for their subblock transactions
                for fee_recipient in &fee_recipients {
                    let balance_slot = mapping_slot(fee_recipient, slots::BALANCES);
                    let slot = fee_token_storage.get(&balance_slot).unwrap();

                    assert!(slot.present_value > slot.original_value());
                }
            }

            // Exit once we reach height 20.
            if new.tip().number() == 20 {
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
fn subblocks_are_included_post_allegretto_with_failing_txs() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|context| async move {
        let how_many_signers = 5;

        let setup = Setup::new()
            .how_many_signers(how_many_signers)
            .allegretto_in_seconds(0)
            .epoch_length(10);

        // Setup and start all nodes.
        let (mut nodes, _execution_runtime) =
            setup_validators(context.clone(), setup.clone()).await;

        let mut fee_recipients = Vec::new();

        for node in &mut nodes {
            // Due to how Commonware deterministic runtime behaves in CI, we need to bump this timeout
            // to ensure that payload builder has enough time to accumulate subblocks.
            node.consensus_config_mut().new_payload_wait_time = Duration::from_millis(500);

            let fee_recipient = Address::random();
            node.consensus_config_mut().fee_recipient = fee_recipient;
            fee_recipients.push(fee_recipient);
        }

        join_all(nodes.iter_mut().map(|node| node.start())).await;

        let mut stream = nodes[0].execution_provider().canonical_state_stream();

        let mut expected_transactions: Vec<TxHash> = Vec::new();
        let mut failing_transactions: Vec<TxHash> = Vec::new();
        while let Some(update) = stream.next().await {
            let CanonStateNotification::Commit { new } = update else {
                unreachable!("unexpected reorg");
            };

            let block = new.blocks().iter().next().unwrap().1;
            let receipts = new.receipts_by_block_hash(block.hash()).unwrap();

            // Assert that block only contains our subblock transactions and 3 system transactions
            assert_eq!(
                block.sealed_block().body().transactions.len(),
                3 + expected_transactions.len()
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
                &mut block.body().transactions.last().unwrap().input().as_ref(),
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

            for (receipt, tx) in receipts.iter().zip(block.transactions_recovered()) {
                if !expected_transactions.contains(tx.tx_hash()) {
                    continue;
                }

                let fee_recipient = fee_recipients
                    .get(&tx.subblock_proposer().unwrap())
                    .unwrap();
                *expected_fees.entry(fee_recipient).or_insert(U256::ZERO) +=
                    calc_gas_balance_spending(
                        receipt.cumulative_gas_used - cumulative_gas_used,
                        TEMPO_BASE_FEE as u128,
                    );
                cumulative_gas_used = receipt.cumulative_gas_used;

                if !failing_transactions.contains(tx.tx_hash()) {
                    assert!(receipt.status());
                    assert!(receipt.cumulative_gas_used > 0);
                    continue;
                }

                let sender = tx.signer();
                let nonce_key = tx.as_aa().unwrap().tx().nonce_key;
                let nonce_slot =
                    double_mapping_slot(sender, nonce_key.as_storage_bytes(), nonce::slots::NONCES);

                let slot = new
                    .execution_outcome()
                    .account_state(&NONCE_PRECOMPILE_ADDRESS)
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
                let fee_token_storage = &new
                    .execution_outcome()
                    .state()
                    .account(&DEFAULT_FEE_TOKEN_POST_ALLEGRETTO)
                    .unwrap()
                    .storage;

                // Assert that all validators were paid for their subblock transactions
                let balance_slot = mapping_slot(fee_recipient, slots::BALANCES);
                let slot = fee_token_storage.get(&balance_slot).unwrap();

                assert_eq!(slot.present_value, slot.original_value() + expected_fee);
            }

            // Exit once we reach height 20.
            if new.tip().number() == 20 {
                break;
            }

            // Send subblock transactions to all nodes.
            for node in nodes.iter() {
                for _ in 0..5 {
                    // Randomly submit some of the transactions from a new signer that doesn't have any funds
                    if rand::random::<bool>() {
                        let tx = submit_subblock_tx_from(node, &PrivateKeySigner::random()).await;
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

async fn submit_subblock_tx(node: &TestingNode) -> TxHash {
    // First signer of the test mnemonic
    let wallet = PrivateKeySigner::from_bytes(&b256!(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    ))
    .unwrap();

    submit_subblock_tx_from(node, &wallet).await
}

async fn submit_subblock_tx_from(node: &TestingNode, wallet: &PrivateKeySigner) -> TxHash {
    let mut nonce_bytes = rand::random::<[u8; 32]>();
    nonce_bytes[0] = TEMPO_SUBBLOCK_NONCE_KEY_PREFIX;
    nonce_bytes[1..16].copy_from_slice(&node.public_key().as_ref()[..15]);

    let provider = node.execution_provider();

    let gas_price = if provider.chain_spec().is_allegretto_active_at_timestamp(0) {
        TEMPO_BASE_FEE as u128
    } else {
        0
    };

    let mut tx = TempoTransaction {
        chain_id: provider.chain_spec().chain_id(),
        calls: vec![Call {
            to: Address::ZERO.into(),
            input: Default::default(),
            value: Default::default(),
        }],
        gas_limit: 100000,
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
