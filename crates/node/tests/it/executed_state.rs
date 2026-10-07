use crate::utils::{t1_account, tempo_test_setup};
use alloy_primitives::{Address, B256};
use reth_e2e_test_utils::wallet::Wallet;
use reth_ethereum::{chainspec::EthChainSpec as _, tasks::Runtime};
use reth_node_api::BuiltPayload;
use reth_node_builder::{NodeBuilder, NodeConfig};
use reth_storage_api::{AccountReader as _, StateProviderFactory as _};
use tempo_evm::parallel::EngineCaptureWindow;
use tempo_node::node::{TempoNode, TempoNodeArgs};
use tempo_primitives::SignatureType;

/// One node builds two blocks. A second node only executes them with
/// `newPayload` and receives no forkchoice update for them, so its head stays
/// at genesis. The first block becomes the engine's pending block. The second
/// block is neither canonical nor pending, so the provider has no state for
/// it, but [`tempo_node::ExecutedState`] reads it from the engine.
#[test_case::test_case(0, 1; "sequential_singleton")]
#[test_case::test_case(4, 1; "parallel_singleton")]
#[test_case::test_case(0, 2; "sequential_pair")]
#[test_case::test_case(4, 2; "parallel_pair")]
#[test_case::test_case(0, 4; "sequential_below_threshold")]
#[test_case::test_case(4, 4; "parallel_below_threshold")]
#[test_case::test_case(0, 5; "sequential_threshold")]
#[test_case::test_case(4, 5; "parallel_threshold")]
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
    let chain_id = chain_spec.chain_id();

    let mut account = t1_account(&Wallet::default().with_chain_id(chain_id), 0);
    let sender = account.address();
    for _ in 1..transaction_count {
        let tx = account.tx().to(Address::ZERO).gas_limit(300_000).await;
        producer.rpc.inject_tx(tx).await?;
    }
    let tx = account.tx().to(Address::ZERO).gas_limit(300_000).await;
    let (_, first) = producer.inject_and_advance(tx).await?;
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
    let (observer, _) = tempo_test_setup(1, chain_spec)
        .with_node(move |_| tempo_node.clone())
        .with_node_config_modifier(move |mut config| {
            // Exercise generic workers at the Engine prewarming boundary;
            // short blocks retain the ordinary Engine configuration.
            config.engine.prewarming_disabled = transaction_count >= 5;
            config
        })
        .build_single()
        .await?;
    let workers = observer.inner.evm_config.speculative_executor.as_ref();
    assert_eq!(workers.is_some(), execution_threads > 0);
    assert_eq!(
        workers
            .map(|pool| pool.scheduled_transactions())
            .unwrap_or(0),
        0
    );
    let provider = &observer.inner.provider;

    for payload in [first, second] {
        let status = observer.submit_payload_with_status(payload).await?;
        assert!(status.is_valid(), "unexpected payload status: {status:?}");
    }

    // This observer has no builder or pool transactions. Only Engine API
    // validation can dispatch work. Short blocks should execute directly,
    // while five transactions must use generic workers; canonical root checks
    // alone would also pass if precompile-cache installation disabled scheduling.
    if let Some(workers) = workers {
        assert_eq!(
            workers.scheduled_transactions(),
            if transaction_count >= 5 {
                transaction_count
            } else {
                0
            },
        );
    }

    assert!(
        provider.state_by_block_hash(second_hash).is_err(),
        "the provider must not serve state for a block that is neither canonical nor pending",
    );
    let state = executed_state.state_by_block_hash(provider.clone(), second_hash)?;
    assert_eq!(state.basic_account(&sender)?, expected);

    assert!(
        executed_state
            .state_by_block_hash(provider.clone(), B256::repeat_byte(0xab))
            .is_err(),
        "a block that the engine has not executed must not resolve",
    );

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PaidBlockWorkload {
    Transfers,
    ReserveOpens,
    DirectMints,
}

#[test_case::test_case(0, 64, 64, 64, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, None, false; "independent")]
#[test_case::test_case(0, 128, 16, 8, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, None, false; "repeated_senders_and_recipients")]
#[test_case::test_case(0, 64, 64, 1, PaidBlockWorkload::ReserveOpens, EngineCaptureWindow::Transactions128, false, None, false; "native_reserve_opens")]
#[test_case::test_case(4, 64, 64, 64, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, None, false; "parallel_builder_independent")]
#[test_case::test_case(4, 128, 16, 8, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, None, false; "parallel_builder_repeated_senders_and_recipients")]
#[test_case::test_case(4, 64, 64, 1, PaidBlockWorkload::ReserveOpens, EngineCaptureWindow::Transactions128, false, None, false; "parallel_builder_native_reserve_opens")]
#[test_case::test_case(4, 520, 64, 8, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, None, false; "window128_paid_aa_beyond_boundary")]
#[test_case::test_case(4, 520, 64, 8, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions512, false, None, false; "window512_paid_aa_beyond_boundary")]
#[test_case::test_case(4, 128, 16, 8, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, true, None, false; "stage_diagnostics_paid_aa")]
#[test_case::test_case(4, 256, 16, 16, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, Some(SignatureType::Secp256k1), false; "signed_secp256k1_keychain")]
#[test_case::test_case(4, 256, 16, 16, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, Some(SignatureType::Secp256k1), true; "signed_secp256k1_keychain_sponsored")]
#[test_case::test_case(4, 256, 16, 16, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, Some(SignatureType::P256), false; "signed_p256_keychain")]
#[test_case::test_case(4, 256, 16, 16, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, Some(SignatureType::P256), true; "signed_p256_keychain_sponsored")]
#[test_case::test_case(4, 256, 16, 16, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, Some(SignatureType::WebAuthn), false; "signed_webauthn_keychain")]
#[test_case::test_case(4, 256, 16, 16, PaidBlockWorkload::Transfers, EngineCaptureWindow::Transactions128, false, Some(SignatureType::WebAuthn), true; "signed_webauthn_keychain_sponsored")]
#[test_case::test_case(0, 256, 16, 256, PaidBlockWorkload::DirectMints, EngineCaptureWindow::Transactions128, false, None, false; "signed_direct_mint_sequential_builder")]
#[test_case::test_case(4, 256, 16, 256, PaidBlockWorkload::DirectMints, EngineCaptureWindow::Transactions128, false, None, false; "signed_direct_mint_parallel_builder")]
#[tokio::test(flavor = "multi_thread")]
async fn engine_prewarming_preserves_paid_expiring_transfer_block(
    builder_threads: usize,
    transaction_count: usize,
    sender_count: usize,
    recipient_count: usize,
    workload: PaidBlockWorkload,
    capture_window: EngineCaptureWindow,
    stage_diagnostics: bool,
    access_key_type: Option<SignatureType>,
    sponsored: bool,
) -> eyre::Result<()> {
    paid_expiring_block_differential(
        builder_threads,
        transaction_count,
        sender_count,
        recipient_count,
        workload,
        capture_window,
        stage_diagnostics,
        access_key_type,
        sponsored,
        2,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_prewarming_preserves_signed_aa_with_32_workers() -> eyre::Result<()> {
    for key_type in [
        SignatureType::Secp256k1,
        SignatureType::P256,
        SignatureType::WebAuthn,
    ] {
        for sponsored in [false, true] {
            paid_expiring_block_differential(
                4,
                256,
                16,
                16,
                PaidBlockWorkload::Transfers,
                EngineCaptureWindow::Transactions128,
                false,
                Some(key_type),
                sponsored,
                32,
            )
            .await?;
        }
    }
    Ok(())
}

fn runtime_with_prewarming_threads(threads: usize) -> eyre::Result<Runtime> {
    use reth_ethereum::tasks::{RayonConfig, RuntimeBuilder, RuntimeConfig, TokioConfig};

    // Match Runtime::test's small pools except for the explicitly tested pool.
    // Keep the test's Tokio handle so teardown cannot drop its own executor.
    let runtime = RuntimeBuilder::new(RuntimeConfig {
        tokio: TokioConfig::existing_handle(tokio::runtime::Handle::current()),
        rayon: RayonConfig {
            cpu_threads: Some(2),
            reserved_cpu_cores: 0,
            rpc_threads: Some(2),
            storage_threads: Some(2),
            max_blocking_tasks: 16,
            proof_storage_worker_threads: Some(2),
            proof_account_worker_threads: Some(2),
            prewarming_threads: Some(threads),
            bal_streaming_threads: Some(2),
            state_trie_overlay_worker_threads: Some(2),
        },
    })
    .build()?;
    assert_eq!(runtime.prewarming_pool().current_num_threads(), threads);
    Ok(runtime)
}

async fn paid_expiring_block_differential(
    builder_threads: usize,
    transaction_count: usize,
    sender_count: usize,
    recipient_count: usize,
    workload: PaidBlockWorkload,
    capture_window: EngineCaptureWindow,
    stage_diagnostics: bool,
    access_key_type: Option<SignatureType>,
    sponsored: bool,
    prewarming_threads: usize,
) -> eyre::Result<()> {
    use crate::{
        tempo_transaction::helpers::{
            create_basic_aa_tx, generate_p256_access_key, sign_aa_tx_secp256k1,
            sign_aa_tx_with_p256_access_key, sign_aa_tx_with_secp256k1_access_key,
            sign_aa_tx_with_webauthn_access_key, sign_fee_payer,
        },
        utils::{ForkSchedule, TestNodeBuilder},
    };
    use alloy::{primitives::U256, signers::SignerSync as _, sol_types::SolCall};
    use alloy_eips::Encodable2718;
    use alloy_rpc_types_engine::ForkchoiceState;
    use reth_e2e_test_utils::wallet::test_signer;
    use reth_storage_api::{BlockReader as _, ReceiptProvider as _};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, ITIP20ChannelReserve};
    use tempo_precompiles::{
        NONCE_PRECOMPILE_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
        nonce::slots::EXPIRING_NONCE_RING_PTR,
        storage::StorageKey as _,
        tip20::{
            IRolesAuth, ISSUER_ROLE, ITIP20,
            slots::{BALANCES, ROLES, SUPPLY_CAP, TOTAL_SUPPLY},
        },
    };
    use tempo_primitives::{
        TempoTxEnvelope, TempoTxType,
        transaction::{
            Call, KeyAuthorization, TEMPO_EXPIRING_NONCE_KEY, tt_signature::PrimitiveSignature,
        },
    };

    let direct_mints = workload == PaidBlockWorkload::DirectMints;
    if direct_mints {
        assert_eq!(
            (transaction_count, sender_count, recipient_count),
            (256, 16, 256)
        );
        assert!(access_key_type.is_none() && !sponsored);
    }
    let issuer_role_slot = |account: Address| ISSUER_ROLE.mapping_slot(account.mapping_slot(ROLES));

    async fn finish_fixture_worker(
        runtime: &Runtime,
        worker: &'static str,
        deadline: tokio::time::Instant,
    ) -> eyre::Result<()> {
        let (done, finished) = tokio::sync::oneshot::channel();
        runtime.spawn_blocking_named(worker, move || {
            let _ = done.send(());
        });
        tokio::time::timeout_at(deadline, finished).await??;
        Ok(())
    }

    async fn shutdown_fixture_node(runtime: &Runtime) -> eyre::Result<()> {
        let timeout = std::time::Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + timeout;
        let manager = runtime.take_task_manager_handle();
        // Keep the Tokio workers free to process the shutdown signal. Dropping
        // node handles alone leaves the engine's self-owned input sender alive.
        // This path awaits engine termination inside the consensus task before
        // it exits, rather than polling the closed tree as a fatal event.
        // The SDK's acknowledgment does not join its detached engine thread.
        let shutdown_runtime = runtime.clone();
        let stopped = tokio::time::timeout_at(
            deadline,
            tokio::task::spawn_blocking(move || {
                shutdown_runtime.graceful_shutdown_with_timeout(
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                )
            }),
        )
        .await??;
        eyre::ensure!(stopped, "fixture runtime shutdown timed out");
        if let Some(manager) = manager {
            tokio::time::timeout_at(deadline, manager).await???;
        }
        // Named jobs are outside Tokio's graceful-task count. Retain this
        // external Runtime and the node's provider handles until they finish,
        // so the last Runtime cannot be dropped on one of its own workers.
        // Producers precede their downstream jobs, and deferred drops run last.
        for worker in [
            "prewarm",
            "prewarm-txs",
            "tx-iterator",
            "payload-convert",
            "builder-bal-task",
            "builder-roots-task",
            "sparse-trie",
            "trie-hashing",
            "account-workers",
            "storage-workers",
            "hash-post-state",
            "receipt-root",
            "deferred-trie",
            "wait-exec-cache",
            "wait-sparse-tri",
            "drop",
        ] {
            finish_fixture_worker(runtime, worker, deadline).await?;
        }
        Ok(())
    }

    async fn close_fixture_database(
        database: reth_e2e_test_utils::TmpDB,
        rocksdb_path: std::path::PathBuf,
    ) -> eyre::Result<()> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let interval = std::time::Duration::from_millis(10);
        while std::sync::Arc::strong_count(&database) > 1 {
            eyre::ensure!(
                tokio::time::Instant::now() < deadline,
                "fixture database is still referenced after runtime shutdown"
            );
            tokio::time::sleep(interval).await;
        }
        // A provider releases its database handle before closing RocksDB.
        // As in the SDK's restartable-node helper, verify its exclusive lock
        // has been released before removing the fixture's temporary directory.
        loop {
            let path = rocksdb_path.clone();
            let opened = tokio::task::spawn_blocking(move || {
                reth_provider::providers::RocksDBProvider::builder(path)
                    .with_default_tables()
                    .build()
                    .map(drop)
            })
            .await?;
            match opened {
                Ok(()) => break,
                Err(err) if tokio::time::Instant::now() >= deadline => {
                    eyre::bail!("fixture RocksDB remained open after runtime shutdown: {err}")
                }
                Err(_) => tokio::time::sleep(interval).await,
            }
        }
        drop(database);
        Ok(())
    }

    reth_tracing::init_test_tracing();
    let (producer_setup, producer_database) = TestNodeBuilder::new()
        .with_node_access_runtime(runtime_with_prewarming_threads(prewarming_threads)?)
        .with_execution_threads(builder_threads)
        .with_execution_stage_diagnostics(stage_diagnostics)
        .with_schedule(ForkSchedule::DevnetAt(TempoHardfork::T14))
        .build_with_node_access_and_database()
        .await?;
    let mut producer = producer_setup.node;
    assert_eq!(
        producer.inner.evm_config.speculative_executor.is_some(),
        builder_threads > 0,
        "the producing payload builder must use the requested executor"
    );
    // The genesis tip is at zero, so use a deterministic timestamp compatible
    // with both pool expiry admission and the block's expiring-nonce checks.
    producer.set_next_payload_timestamp(1)?;
    // Apply activation-boundary deployments before measuring reuse. A parent
    // snapshot cannot predict new marker code; exact read checks must replay
    // candidates that encounter those first-block metadata changes.
    let activation = producer.advance_block().await?;
    assert_eq!(activation.block().header().inner.number, 1);
    assert_eq!(activation.block().header().inner.timestamp, 1);
    let mut parents = vec![activation];
    producer.set_next_payload_timestamp(2)?;
    let chain_spec = producer.inner.chain_spec();
    let chain_id = chain_spec.chain().id();
    let signers = (0..sender_count)
        .map(|index| test_signer(u32::try_from(index).unwrap()))
        .collect::<Vec<_>>();
    let sponsors = (0..if sponsored { sender_count } else { 0 })
        .map(|index| test_signer(u32::try_from(sender_count + index).unwrap()))
        .collect::<Vec<_>>();
    let secp_access_keys = (0..if access_key_type == Some(SignatureType::Secp256k1) {
        sender_count
    } else {
        0
    })
        .map(|index| test_signer(u32::try_from(100 + index).unwrap()))
        .collect::<Vec<_>>();
    let p256_access_keys = (0..if matches!(
        access_key_type,
        Some(SignatureType::P256 | SignatureType::WebAuthn)
    ) {
        sender_count
    } else {
        0
    })
        .map(|_| generate_p256_access_key())
        .collect::<Vec<_>>();
    {
        let genesis = producer.inner.provider.latest()?;
        for signer in signers.iter().chain(&sponsors) {
            assert!(
                genesis
                    .storage(
                        DEFAULT_FEE_TOKEN,
                        signer.address().mapping_slot(BALANCES).into()
                    )?
                    .unwrap_or_default()
                    > U256::ZERO,
                "the fixture requires funded TIP20 senders and sponsors"
            );
        }
    }
    if direct_mints {
        // The default pool permits sixteen pending AA transactions per sender.
        // Grant sixteen funded roots real issuer permissions before their child
        // block, using the genesis admin's ordinary signed transaction path.
        let admin = &signers[0];
        assert_eq!(
            producer
                .inner
                .provider
                .latest()?
                .storage(DEFAULT_FEE_TOKEN, issuer_role_slot(admin.address()).into(),)?,
            Some(U256::ONE),
            "the genesis root must already have the issuer role",
        );
        let calls = signers
            .iter()
            .skip(1)
            .map(|signer| Call {
                to: DEFAULT_FEE_TOKEN.into(),
                value: U256::ZERO,
                input: IRolesAuth::grantRoleCall {
                    role: ISSUER_ROLE,
                    account: signer.address(),
                }
                .abi_encode()
                .into(),
            })
            .collect();
        // Fifteen zero-to-one role writes include native storage-credit gas.
        let tx = create_basic_aa_tx(chain_id, 0, calls, 5_000_000);
        let signature = sign_aa_tx_secp256k1(&tx, admin)?;
        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
        producer
            .rpc
            .inject_tx(envelope.encoded_2718().into())
            .await?;
        let roles = producer.advance_block().await?;
        assert_eq!(roles.block().header().inner.number, 2);
        assert_eq!(roles.block().header().inner.timestamp, 2);
        assert_eq!(
            roles
                .block()
                .body()
                .transactions
                .iter()
                .filter(|tx| !tx.is_system_tx())
                .count(),
            1
        );
        assert!(
            producer
                .inner
                .provider
                .receipts_by_block(roles.block().hash().into())?
                .expect("issuer setup receipts")
                .iter()
                .all(|receipt| receipt.success)
        );
        parents.push(roles);
        producer.set_next_payload_timestamp(3)?;
    }
    let mint_parent_state = if direct_mints {
        let parent = producer.inner.provider.latest()?;
        for signer in &signers {
            assert_eq!(
                parent.storage(DEFAULT_FEE_TOKEN, issuer_role_slot(signer.address()).into())?,
                Some(U256::ONE)
            );
        }
        assert_eq!(
            parent
                .storage(NONCE_PRECOMPILE_ADDRESS, EXPIRING_NONCE_RING_PTR.into())?
                .unwrap_or_default(),
            U256::ZERO,
            "ordinary-nonce issuer setup must not advance the expiring ring",
        );
        let supply = parent
            .storage(DEFAULT_FEE_TOKEN, TOTAL_SUPPLY.into())?
            .unwrap_or_default();
        let cap = parent
            .storage(DEFAULT_FEE_TOKEN, SUPPLY_CAP.into())?
            .unwrap_or_default();
        assert!(
            supply > U256::ZERO,
            "the measured supply write must remain nonzero-to-nonzero"
        );
        assert!(
            supply
                .checked_add(U256::from(transaction_count))
                .expect("mint supply arithmetic")
                <= cap
        );
        Some((supply, cap))
    } else {
        None
    };
    if let Some(key_type) = access_key_type {
        // Pool admission must see the real on-chain authorization. Both its
        // root signature and the enclosing transaction signature are recovered
        // through the normal node path before the measured child is submitted.
        for (index, signer) in signers.iter().enumerate() {
            let key_id = match key_type {
                SignatureType::Secp256k1 => secp_access_keys[index].address(),
                SignatureType::P256 | SignatureType::WebAuthn => p256_access_keys[index].3,
            };
            let authorization = KeyAuthorization::unrestricted(chain_id, key_type, key_id);
            let signature = signer.sign_hash_sync(&authorization.signature_hash())?;
            let mut tx = create_basic_aa_tx(
                chain_id,
                0,
                vec![Call {
                    to: DEFAULT_FEE_TOKEN.into(),
                    value: U256::ZERO,
                    input: ITIP20::balanceOfCall {
                        account: signer.address(),
                    }
                    .abi_encode()
                    .into(),
                }],
                2_000_000,
            );
            tx.key_authorization =
                Some(authorization.into_signed(PrimitiveSignature::Secp256k1(signature)));
            let signature = sign_aa_tx_secp256k1(&tx, signer)?;
            let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
            producer
                .rpc
                .inject_tx(envelope.encoded_2718().into())
                .await?;
        }
        let authorization = producer.advance_block().await?;
        assert_eq!(authorization.block().header().inner.number, 2);
        assert_eq!(authorization.block().header().inner.timestamp, 2);
        assert_eq!(
            authorization
                .block()
                .body()
                .transactions
                .iter()
                .filter(|tx| !tx.is_system_tx())
                .count(),
            sender_count,
        );
        assert!(
            producer
                .inner
                .provider
                .receipts_by_block(authorization.block().hash().into())?
                .expect("authorization receipts")
                .iter()
                .all(|receipt| receipt.success)
        );
        parents.push(authorization);
        producer.set_next_payload_timestamp(3)?;
    }
    let initial_balances = if access_key_type.is_some() || direct_mints {
        let parent = producer.inner.provider.latest()?;
        signers
            .iter()
            .chain(&sponsors)
            .map(|signer| {
                Ok((
                    signer.address(),
                    parent
                        .storage(
                            DEFAULT_FEE_TOKEN,
                            signer.address().mapping_slot(BALANCES).into(),
                        )?
                        .unwrap_or_default(),
                ))
            })
            .collect::<eyre::Result<std::collections::BTreeMap<_, _>>>()?
    } else {
        std::collections::BTreeMap::new()
    };
    let mut expected_balances = std::collections::BTreeMap::<Address, u64>::new();
    let mut expected_transfers = std::collections::BTreeMap::<Address, u64>::new();
    let mut expected_mints = std::collections::BTreeMap::<B256, (Address, Address, U256)>::new();
    for index in 0..transaction_count {
        let sender_index = index % sender_count;
        let signer = &signers[sender_index];
        let (calls, recipient, amount) = if workload == PaidBlockWorkload::ReserveOpens {
            // Deposit and fees both use pathUSD. Opening a channel credits
            // custody, so the balance assertion targets the reserve, not payee.
            (
                vec![Call {
                    to: TIP20_CHANNEL_RESERVE_ADDRESS.into(),
                    value: U256::ZERO,
                    input: ITIP20ChannelReserve::openCall {
                        payee: signers[0].address(),
                        operator: Address::ZERO,
                        token: DEFAULT_FEE_TOKEN,
                        deposit: alloy_primitives::aliases::U96::ONE,
                        salt: B256::from(U256::from(index + 1)),
                        authorizedSigner: Address::ZERO,
                    }
                    .abi_encode()
                    .into(),
                }],
                TIP20_CHANNEL_RESERVE_ADDRESS,
                1,
            )
        } else if direct_mints {
            let recipient = Address::from_word(B256::from(U256::from(0x10000 + index)));
            (
                vec![Call {
                    to: DEFAULT_FEE_TOKEN.into(),
                    value: U256::ZERO,
                    input: ITIP20::mintCall {
                        to: recipient,
                        amount: U256::ONE,
                    }
                    .abi_encode()
                    .into(),
                }],
                recipient,
                1,
            )
        } else {
            let recipient =
                Address::from_word(B256::from(U256::from(0x10000 + index % recipient_count)));
            (
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
                recipient,
                4,
            )
        };
        // A single mint has ample gas for a new recipient balance while the
        // 256 declared limits total only 256M, below the 500M genesis block cap.
        let gas_limit = if direct_mints { 1_000_000 } else { 2_000_000 };
        let mut tx = create_basic_aa_tx(chain_id, index as u64, calls, gas_limit);
        tx.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
        tx.valid_before = std::num::NonZeroU64::new(300);
        if sponsored {
            // Sponsorship commits to the root account, not the access key.
            // Set it before computing the final keychain transaction signature.
            sign_fee_payer(&mut tx, signer.address(), &sponsors[sender_index])?;
        }
        let signature = match access_key_type {
            None => sign_aa_tx_secp256k1(&tx, signer)?,
            Some(SignatureType::Secp256k1) => sign_aa_tx_with_secp256k1_access_key(
                &tx,
                &secp_access_keys[sender_index],
                signer.address(),
            )?,
            Some(SignatureType::P256) => {
                let (key, x, y, _) = &p256_access_keys[sender_index];
                sign_aa_tx_with_p256_access_key(&tx, key, x, y, signer.address())?
            }
            Some(SignatureType::WebAuthn) => {
                let (key, x, y, _) = &p256_access_keys[sender_index];
                sign_aa_tx_with_webauthn_access_key(
                    &tx,
                    key,
                    *x,
                    *y,
                    "https://example.com",
                    signer.address(),
                )?
            }
        };
        assert_eq!(signature.is_keychain(), access_key_type.is_some());
        assert!(!signature.is_legacy_keychain());
        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
        assert_eq!(
            envelope.fee_payer(signer.address())?,
            if sponsored {
                sponsors[sender_index].address()
            } else {
                signer.address()
            },
        );
        if direct_mints {
            assert!(
                expected_mints
                    .insert(
                        *envelope.as_aa().unwrap().hash(),
                        (signer.address(), recipient, U256::from(amount)),
                    )
                    .is_none()
            );
        }
        producer
            .rpc
            .inject_tx(envelope.encoded_2718().into())
            .await?;
        *expected_balances.entry(recipient).or_default() += amount;
        *expected_transfers.entry(signer.address()).or_default() +=
            if direct_mints { 0 } else { amount };
    }
    if direct_mints {
        let parent = producer.inner.provider.latest()?;
        for recipient in expected_balances.keys() {
            assert!(signers.iter().all(|signer| signer.address() != *recipient));
            assert_eq!(
                parent
                    .storage(DEFAULT_FEE_TOKEN, recipient.mapping_slot(BALANCES).into())?
                    .unwrap_or_default(),
                U256::ZERO
            );
        }
    }
    let payload = producer.advance_block().await?;
    // Both producer configurations remain under manual payload control.
    assert_eq!(
        payload.block().header().inner.number,
        parents.len() as u64 + 1
    );
    assert_eq!(
        payload.block().header().inner.timestamp,
        parents.len() as u64 + 1
    );
    let block_hash = payload.block().hash();
    if access_key_type.is_some() || direct_mints {
        for signer in signers.iter().chain(&sponsors) {
            assert_ne!(
                payload.block().header().inner.beneficiary,
                signer.address(),
                "payer balance assertions require a separate validator fee recipient",
            );
        }
    }
    assert_eq!(
        payload
            .block()
            .body()
            .transactions
            .iter()
            .filter(|tx| !tx.is_system_tx())
            .count(),
        transaction_count,
        "all transactions must reach the same prewarmed block"
    );
    let expected_receipts = producer
        .inner
        .provider
        .receipts_by_block(block_hash.into())?
        .expect("producer receipts");
    assert!(expected_receipts.iter().all(|receipt| receipt.success));
    assert_eq!(
        expected_receipts.len(),
        payload.block().body().transactions.len()
    );
    for (tx, receipt) in payload
        .block()
        .body()
        .transactions
        .iter()
        .zip(&expected_receipts)
    {
        if tx.is_system_tx() {
            continue;
        }
        let signed = tx
            .as_aa()
            .expect("the measured cohort contains AA transactions");
        assert_eq!(signed.tx().nonce_key, TEMPO_EXPIRING_NONCE_KEY);
        assert_eq!(signed.tx().fee_payer_signature.is_some(), sponsored);
        assert_eq!(signed.signature().is_keychain(), access_key_type.is_some());
        assert!(!signed.signature().is_legacy_keychain());
        if direct_mints {
            let (issuer, recipient, amount) = expected_mints
                .remove(signed.hash())
                .expect("included signed mint hash");
            assert_eq!(
                signed
                    .signature()
                    .recover_signer(&signed.signature_hash())?,
                issuer
            );
            assert_eq!(
                signed.signature().signature_type(),
                SignatureType::Secp256k1
            );
            assert_eq!(signed.tx().fee_token, Some(DEFAULT_FEE_TOKEN));
            assert!(
                signed.tx().key_authorization.is_none()
                    && signed.tx().tempo_authorization_list.is_empty()
            );
            let [call] = signed.tx().calls.as_slice() else {
                panic!("measured mints must be single calls")
            };
            assert_eq!(call.to, DEFAULT_FEE_TOKEN.into());
            assert!(call.value.is_zero());
            assert_eq!(
                call.input.as_ref(),
                ITIP20::mintCall {
                    to: recipient,
                    amount
                }
                .abi_encode()
                .as_slice()
            );
        }
        if let Some(key_type) = access_key_type {
            assert_eq!(signed.signature().signature_type(), key_type);
            assert!(
                signed.tx().key_authorization.is_none(),
                "authorization belongs in the parent"
            );
        }
        assert_eq!(receipt.tx_type, TempoTxType::AA);
    }
    assert!(
        expected_mints.is_empty(),
        "every submitted mint must be included exactly once"
    );

    // Force an early canonical error in a block larger than the strict capture
    // window, then submit the valid sibling. The 520-transaction cases exceed
    // both the 128- and 512-transaction dispatch and capture windows.
    // Both configurations must reject identically and retire the failed
    // payload's actual prewarming scope before the valid sibling can complete.
    let invalid_payload = if transaction_count > capture_window.transactions() {
        let mut expired = create_basic_aa_tx(
            chain_id,
            0,
            vec![Call {
                to: DEFAULT_FEE_TOKEN.into(),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: signers[0].address(),
                    amount: U256::ONE,
                }
                .abi_encode()
                .into(),
            }],
            2_000_000,
        );
        expired.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
        expired.valid_before = std::num::NonZeroU64::new(1);
        let signature = sign_aa_tx_secp256k1(&expired, &signers[0])?;
        let mut block = payload.clone().into_execution_payload().into_block();
        let first_user = block
            .body
            .transactions
            .iter()
            .position(|tx| !tx.is_system_tx())
            .unwrap();
        block.body.transactions[first_user] = expired.into_signed(signature).into();
        block.header.inner.transactions_root =
            alloy::consensus::proofs::calculate_transaction_root(&block.body.transactions);
        Some(tempo_payload_types::TempoExecutionData {
            block: reth_primitives_traits::SealedBlock::seal_slow(block).into(),
        })
    } else {
        None
    };
    let mut expected_invalid_error = None;
    let mut expected_output = None;
    let mut expected_parent_outputs = std::collections::BTreeMap::new();
    for execution_threads in [0, 4] {
        let tempo_node = TempoNode::new(
            &TempoNodeArgs {
                execution_threads,
                execution_batch_size: 32,
                execution_capture_window: capture_window,
                execution_stage_diagnostics: stage_diagnostics,
                execution_capture_diagnostics: access_key_type.is_some() || direct_mints,
                ..Default::default()
            },
            None,
        );
        let executed_state = tempo_node.executed_state();
        let runtime = runtime_with_prewarming_threads(prewarming_threads)?;
        let mut config = NodeConfig::new(chain_spec.clone()).with_unused_ports();
        config.network.discovery.disable_discovery = true;
        let observer_builder = NodeBuilder::new(config)
            .testing_node(runtime.clone())
            .node(tempo_node);
        // ProviderFactory drops its database field before its RocksDB fields.
        // Retain the datadir while releasing node handles and runtime jobs.
        let observer_database = observer_builder.db().clone();
        let observer_handle = observer_builder.launch().await?;
        let observer = &observer_handle.node;
        let observer_rocksdb_path = observer.data_dir.rocksdb();
        assert_eq!(
            observer.evm_config.speculative_executor.is_some(),
            execution_threads > 0
        );
        for parent in &parents {
            let status = observer
                .add_ons_handle
                .beacon_engine_handle
                .new_payload(parent.clone().into())
                .await?;
            assert!(status.is_valid());
            let parent_hash = parent.block().hash();
            if access_key_type.is_some() || direct_mints {
                let pending = observer
                    .provider
                    .pending_block_and_receipts()?
                    .expect("the validated setup parent is pending");
                assert_eq!(pending.block().hash(), parent_hash);
                assert_eq!(
                    pending.execution_output().result.receipts,
                    producer
                        .inner
                        .provider
                        .receipts_by_block(parent_hash.into())?
                        .expect("producer setup receipts"),
                );
                if let Some(expected) = expected_parent_outputs.get(&parent_hash) {
                    assert_eq!(pending.execution_output(), expected);
                } else {
                    expected_parent_outputs.insert(parent_hash, pending.execution_output().clone());
                }
            }
            let forkchoice = observer
                .add_ons_handle
                .beacon_engine_handle
                .fork_choice_updated(
                    ForkchoiceState {
                        head_block_hash: parent_hash,
                        safe_block_hash: parent_hash,
                        finalized_block_hash: parent_hash,
                    },
                    None,
                )
                .await?;
            assert!(forkchoice.payload_status.is_valid());
        }
        if let Some(invalid) = &invalid_payload {
            let status = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                observer
                    .add_ons_handle
                    .beacon_engine_handle
                    .new_payload(invalid.clone()),
            )
            .await??;
            assert!(
                status.status.is_invalid(),
                "unexpected invalid-payload status: {status:?}"
            );
            let error = status
                .status
                .validation_error()
                .expect("invalid payload error")
                .to_owned();
            assert!(
                error.contains("transaction expired"),
                "unexpected execution error: {error}"
            );
            if let Some(expected) = &expected_invalid_error {
                assert_eq!(&error, expected);
            } else {
                expected_invalid_error = Some(error);
            }
        }
        // Exclude authorization-parent work and the rejected sibling. The
        // observer has no producer jobs that could increment these counters.
        let workers = observer.evm_config.speculative_executor.as_ref();
        let reuses_before = workers.map_or(0, |pool| pool.prewarmed_reuses());
        let scheduled_before = workers.map_or(0, |pool| pool.scheduled_transactions());
        if direct_mints {
            eprintln!(
                "Signed mint differential begin: builder_threads={builder_threads} execution_threads={execution_threads} block_hash={block_hash} transactions={transaction_count} issuer_parent={}",
                parents.last().unwrap().block().hash(),
            );
        }
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            observer
                .add_ons_handle
                .beacon_engine_handle
                .new_payload(payload.clone().into()),
        )
        .await??;
        assert!(status.is_valid(), "unexpected payload status: {status:?}");

        // VALID checks both canonical roots. The child of the last setup block
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
        for (recipient, balance) in &expected_balances {
            assert_eq!(
                state.storage(DEFAULT_FEE_TOKEN, recipient.mapping_slot(BALANCES).into())?,
                Some(U256::from(*balance))
            );
        }
        if let Some((supply, cap)) = mint_parent_state {
            assert_eq!(
                state.storage(DEFAULT_FEE_TOKEN, TOTAL_SUPPLY.into())?,
                Some(supply + U256::from(transaction_count))
            );
            assert_eq!(
                state.storage(DEFAULT_FEE_TOKEN, SUPPLY_CAP.into())?,
                Some(cap)
            );
            for signer in &signers {
                assert_eq!(
                    state.storage(DEFAULT_FEE_TOKEN, issuer_role_slot(signer.address()).into())?,
                    Some(U256::ONE)
                );
            }
        }
        if access_key_type.is_some() || direct_mints {
            for (index, signer) in signers.iter().enumerate() {
                let before = initial_balances[&signer.address()];
                let transferred = U256::from(expected_transfers[&signer.address()]);
                let after = state
                    .storage(
                        DEFAULT_FEE_TOKEN,
                        signer.address().mapping_slot(BALANCES).into(),
                    )?
                    .unwrap_or_default();
                if sponsored {
                    assert_eq!(after, before - transferred, "the root pays transfers only");
                    let sponsor = sponsors[index].address();
                    let sponsor_after = state
                        .storage(DEFAULT_FEE_TOKEN, sponsor.mapping_slot(BALANCES).into())?
                        .unwrap_or_default();
                    assert!(
                        sponsor_after < initial_balances[&sponsor],
                        "the real sponsor pays fees"
                    );
                } else if direct_mints {
                    assert!(transferred.is_zero());
                    assert!(after < before, "the issuer pays mint fees only");
                } else {
                    assert!(
                        after < before - transferred,
                        "the root pays transfers and fees"
                    );
                }
            }
        }
        assert_eq!(
            state.storage(NONCE_PRECOMPILE_ADDRESS, EXPIRING_NONCE_RING_PTR.into())?,
            Some(U256::from(transaction_count))
        );
        if let Some(workers) = &observer.evm_config.speculative_executor {
            assert_eq!(workers.capture_window(), capture_window);
            assert_eq!(workers.batch_size(), 32);
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
        if direct_mints {
            // Retained diagnostics can qualify candidate-specific reuse in this
            // accepted observer interval. Ready results remain scheduling-
            // dependent; the differential oracle needs no waits or retries.
            eprintln!(
                "Signed mint differential complete: builder_threads={builder_threads} execution_threads={execution_threads} block_hash={block_hash} transactions={transaction_count} reuse_delta={} scheduled_delta={} all_oracles_passed=true",
                workers.map_or(0, |pool| pool.prewarmed_reuses()) - reuses_before,
                workers.map_or(0, |pool| pool.scheduled_transactions()) - scheduled_before,
            );
        }
        if let Some(key_type) = access_key_type {
            eprintln!(
                "Signed AA differential: key_type={key_type:?} sponsored={sponsored} \
                 execution_threads={execution_threads} block_hash={block_hash} \
                 transactions={transaction_count} authorization_parent={} \
                 reuse_delta={} scheduled_delta={}",
                parents.last().unwrap().block().hash(),
                workers.map_or(0, |pool| pool.prewarmed_reuses()) - reuses_before,
                workers.map_or(0, |pool| pool.scheduled_transactions()) - scheduled_before,
            );
        }
        drop(state);
        drop(pending);
        // RPC servers run on Tokio directly, outside Runtime's shutdown guard.
        // Request their stop while the database guard and node still exist.
        observer.rpc_server_handle().clone().stop()?;
        observer.auth_server_handle().clone().stop()?;
        shutdown_fixture_node(&runtime).await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            observer_handle.wait_for_node_exit(),
        )
        .await??;
        finish_fixture_worker(
            &runtime,
            "drop",
            tokio::time::Instant::now() + std::time::Duration::from_secs(30),
        )
        .await?;
        drop(runtime);
        close_fixture_database(observer_database, observer_rocksdb_path).await?;
    }
    let producer_runtime = producer.inner.task_executor.clone();
    let producer_rocksdb_path = producer.inner.data_dir.rocksdb();
    producer.inner.rpc_server_handle().clone().stop()?;
    producer.inner.auth_server_handle().clone().stop()?;
    shutdown_fixture_node(&producer_runtime).await?;
    drop(producer);
    finish_fixture_worker(
        &producer_runtime,
        "drop",
        tokio::time::Instant::now() + std::time::Duration::from_secs(30),
    )
    .await?;
    drop(producer_runtime);
    close_fixture_database(producer_database, producer_rocksdb_path).await?;
    Ok(())
}
