use crate::utils::with_t1_fees;
use alloy_primitives::{Address, B256};
use alloy_rpc_types_eth::TransactionRequest;
use reth_e2e_test_utils::wallet::Wallet;
use reth_ethereum::{chainspec::EthChainSpec as _, tasks::Runtime};
use reth_node_api::BuiltPayload;
use reth_node_builder::{NodeBuilder, NodeConfig};
use reth_storage_api::{AccountReader as _, StateProviderFactory as _};
use tempo_node::node::TempoNode;

/// One node builds two blocks. A second node only executes them with
/// `newPayload` and never receives a forkchoice update, so its head stays at
/// genesis. The first block becomes the engine's pending block. The second
/// block is neither canonical nor pending, so the provider has no state for
/// it, but [`tempo_node::ExecutedState`] reads it from the engine.
#[test_case::test_case(0, 1; "sequential_singleton")]
#[test_case::test_case(4, 1; "parallel_singleton")]
#[test_case::test_case(0, 2; "sequential_pair")]
#[test_case::test_case(4, 2; "parallel_pair")]
#[tokio::test(flavor = "multi_thread")]
async fn executed_state_reads_blocks_that_are_not_canonical(
    execution_threads: usize,
    transaction_count: u64,
) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut producer = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?
        .node;
    let chain_spec = producer.inner.chain_spec();
    let chain_id = chain_spec.chain().id();

    let mut account = Wallet::default().with_chain_id(chain_id).account(0);
    let sender = account.address();
    let tx = TransactionRequest::default()
        .to(Address::ZERO)
        .gas_limit(300_000);
    for _ in 1..transaction_count {
        producer
            .rpc
            .inject_tx(account.sign_tx_bytes(with_t1_fees(tx.clone())).await)
            .await?;
    }
    let (_, first) = producer
        .inject_and_advance(account.sign_tx_bytes(with_t1_fees(tx)).await)
        .await?;
    let second = producer.advance_block().await?;
    let second_hash = second.block().hash();

    let expected = producer
        .inner
        .provider
        .state_by_block_hash(second_hash)?
        .basic_account(&sender)?;
    assert_eq!(
        expected.map(|account| account.nonce),
        Some(transaction_count),
        "all transfers must be part of the first block",
    );

    let tempo_node = TempoNode::default().with_execution_threads(execution_threads, 32);
    let executed_state = tempo_node.executed_state();
    let runtime = Runtime::test();
    let mut config = NodeConfig::new(chain_spec).with_unused_ports();
    config.network.discovery.disable_discovery = true;
    let observer_handle = NodeBuilder::new(config)
        .testing_node(runtime.clone())
        .node(tempo_node)
        .launch()
        .await?;
    let observer = &observer_handle.node;
    let workers = observer.evm_config.speculative_executor.as_ref();
    assert_eq!(workers.is_some(), execution_threads > 0);
    assert_eq!(
        workers
            .map(|pool| pool.scheduled_transactions())
            .unwrap_or(0),
        0
    );

    for payload in [first, second] {
        let status = observer
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(payload.into())
            .await?;
        assert!(status.is_valid(), "unexpected payload status: {status:?}");
    }

    // This observer has no builder or pool transactions. Only Engine API
    // validation can dispatch work. Singleton blocks should execute directly,
    // while a pair must use workers; canonical root checks alone would also
    // pass if precompile-cache installation silently disabled the scheduler.
    if let Some(workers) = workers {
        assert_eq!(
            workers.scheduled_transactions(),
            if transaction_count > 1 {
                transaction_count
            } else {
                0
            },
        );
    }

    assert!(
        observer.provider.state_by_block_hash(second_hash).is_err(),
        "the provider must not serve state for a block that is neither canonical nor pending",
    );
    let state = executed_state.state_by_block_hash(observer.provider.clone(), second_hash)?;
    assert_eq!(state.basic_account(&sender)?, expected);

    assert!(
        executed_state
            .state_by_block_hash(observer.provider.clone(), B256::repeat_byte(0xab))
            .is_err(),
        "a block that the engine has not executed must not resolve",
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_prewarming_preserves_paid_expiring_transfer_block() -> eyre::Result<()> {
    use crate::{
        tempo_transaction::helpers::{create_basic_aa_tx, sign_aa_tx_secp256k1},
        utils::{ForkSchedule, TestNodeBuilder},
    };
    use alloy::{primitives::U256, sol_types::SolCall};
    use alloy_eips::Encodable2718;
    use alloy_rpc_types_engine::ForkchoiceState;
    use reth_e2e_test_utils::wallet::test_signer;
    use reth_storage_api::{BlockReader as _, ReceiptProvider as _};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
    use tempo_precompiles::{
        NONCE_PRECOMPILE_ADDRESS,
        nonce::slots::EXPIRING_NONCE_RING_PTR,
        storage::StorageKey as _,
        tip20::{ITIP20, slots::BALANCES},
    };
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{Call, TEMPO_EXPIRING_NONCE_KEY},
    };

    reth_tracing::init_test_tracing();
    let mut producer = TestNodeBuilder::new()
        .with_schedule(ForkSchedule::DevnetAt(TempoHardfork::T14))
        .build_with_node_access()
        .await?
        .node;
    // The genesis tip is at zero, so use a deterministic timestamp compatible
    // with both pool expiry admission and the block's expiring-nonce checks.
    producer.set_next_payload_timestamp(1)?;
    // Apply activation-boundary deployments before measuring reuse. A parent
    // snapshot cannot predict new marker code; exact read checks must replay
    // candidates that encounter those first-block metadata changes.
    let activation = producer.advance_block().await?;
    let activation_hash = activation.block().hash();
    producer.set_next_payload_timestamp(2)?;
    let chain_spec = producer.inner.chain_spec();
    let chain_id = chain_spec.chain().id();
    let signers = (0..64).map(test_signer).collect::<Vec<_>>();
    {
        let genesis = producer.inner.provider.latest()?;
        for signer in &signers {
            assert!(
                genesis
                    .storage(
                        DEFAULT_FEE_TOKEN,
                        signer.address().mapping_slot(BALANCES).into()
                    )?
                    .unwrap_or_default()
                    > U256::ZERO,
                "the fixture requires funded TIP20 senders"
            );
        }
    }
    let mut recipients = Vec::new();
    for (index, signer) in signers.iter().enumerate() {
        let recipient = Address::from_word(B256::from(U256::from(0x10000 + index)));
        let mut tx = create_basic_aa_tx(
            chain_id,
            index as u64,
            vec![
                Call {
                    to: DEFAULT_FEE_TOKEN.into(),
                    value: U256::ZERO,
                    input: ITIP20::transferCall {
                        to: recipient,
                        amount: U256::ONE,
                    }
                    .abi_encode()
                    .into(),
                };
                4
            ],
            2_000_000,
        );
        tx.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
        tx.valid_before = std::num::NonZeroU64::new(300);
        let signature = sign_aa_tx_secp256k1(&tx, signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
        producer
            .rpc
            .inject_tx(envelope.encoded_2718().into())
            .await?;
        recipients.push(recipient);
    }
    let payload = producer.advance_block().await?;
    let block_hash = payload.block().hash();
    assert_eq!(
        payload
            .block()
            .body()
            .transactions
            .iter()
            .filter(|tx| !tx.is_system_tx())
            .count(),
        64,
        "all independent transfers must reach the same prewarmed block"
    );
    let expected_receipts = producer
        .inner
        .provider
        .receipts_by_block(block_hash.into())?
        .expect("producer receipts");
    assert!(expected_receipts.iter().all(|receipt| receipt.success));

    let mut expected_output = None;
    for execution_threads in [0, 4] {
        let tempo_node = TempoNode::default().with_execution_threads(execution_threads, 32);
        let executed_state = tempo_node.executed_state();
        let runtime = Runtime::test();
        let mut config = NodeConfig::new(chain_spec.clone()).with_unused_ports();
        config.network.discovery.disable_discovery = true;
        let observer_handle = NodeBuilder::new(config)
            .testing_node(runtime.clone())
            .node(tempo_node)
            .launch()
            .await?;
        let observer = &observer_handle.node;
        let status = observer
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(activation.clone().into())
            .await?;
        assert!(status.is_valid());
        let forkchoice = observer
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(
                ForkchoiceState {
                    head_block_hash: activation_hash,
                    safe_block_hash: activation_hash,
                    finalized_block_hash: activation_hash,
                },
                None,
            )
            .await?;
        assert!(forkchoice.payload_status.is_valid());
        let status = observer
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(payload.clone().into())
            .await?;
        assert!(status.is_valid(), "unexpected payload status: {status:?}");

        // VALID checks both canonical roots. The child of the activation block
        // also exposes actual receipts and full execution output as pending.
        let pending = observer
            .provider
            .pending_block_and_receipts()?
            .expect("the first validated payload is pending");
        assert_eq!(pending.block().hash(), block_hash);
        assert_eq!(
            pending.execution_output().result.receipts,
            expected_receipts
        );
        if let Some(expected) = &expected_output {
            assert_eq!(pending.execution_output(), expected);
        } else {
            expected_output = Some(pending.execution_output().clone());
        }
        let state = executed_state.state_by_block_hash(observer.provider.clone(), block_hash)?;
        for recipient in &recipients {
            assert_eq!(
                state.storage(DEFAULT_FEE_TOKEN, recipient.mapping_slot(BALANCES).into())?,
                Some(U256::from(4))
            );
        }
        assert_eq!(
            state.storage(NONCE_PRECOMPILE_ADDRESS, EXPIRING_NONCE_RING_PTR.into())?,
            Some(U256::from(64))
        );
        if let Some(workers) = &observer.evm_config.speculative_executor {
            // This observer has no pool or builder jobs. A prewarming session
            // must reuse ready results or execute directly, never start the
            // duplicate generic scheduler. Positive capture/reuse is tested
            // deterministically at the EVM boundary, without a timing race.
            assert_eq!(workers.scheduled_transactions(), 0);
            eprintln!(
                "Engine-only prewarming reuses: {}",
                workers.prewarmed_reuses()
            );
        }
    }
    Ok(())
}
