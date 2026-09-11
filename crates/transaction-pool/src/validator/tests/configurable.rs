use super::*;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use futures::{FutureExt, StreamExt};
use reth_primitives_traits::{Recovered, RecoveredBlock};
use reth_provider::{CanonStateNotification, Chain, ExecutionOutcome};
use reth_transaction_pool::{
    Pool, PoolConfig, TransactionPool, TransactionPoolExt, TransactionValidationTaskExecutor,
    ValidPoolTransaction,
};
use tempo_primitives::transaction::{
    MultisigConfig, MultisigOwner, MultisigSignature, multisig_digest,
};

const FACTORY: Address = Address::repeat_byte(0x71);
const STALE_EXPIRY: u64 = 12345;

type Provider = MockEthProvider<TempoPrimitives, TempoChainSpec>;
type Entry = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

struct CanonicalPool {
    pool: crate::TempoTransactionPool<Provider>,
    validation: TransactionValidationTaskExecutor<TempoTransactionValidator<Provider>>,
    provider: Provider,
    block: Block,
    transaction: TempoPooledTransaction,
    service: tokio::task::JoinHandle<()>,
}

impl CanonicalPool {
    fn new(transaction: TempoPooledTransaction, commitment: Option<B256>) -> Self {
        let validator = setup_validator(&transaction, 1).with_disable_fee_amm_check(true);
        let provider = validator.client().clone();
        if let Some(commitment) = commitment {
            provider.add_account(
                transaction.sender(),
                ExtendedAccount::new(0, U256::ZERO).with_extension(
                    reth_primitives_traits::AccountExtension::copy_from_slice(
                        &tempo_primitives::account::encode_config_commitment(commitment),
                    ),
                ),
            );
        }
        let mut block = create_mock_block(1).clone_block();
        block.header.inner.number = 1;
        let sealed = SealedBlock::seal_slow(block.clone());
        provider.add_block(sealed.hash(), block.clone());
        validator.on_new_head_block(&sealed);
        let (validation, task) = TransactionValidationTaskExecutor::new(validator);
        let service = tokio::spawn(task.run());
        let pool = crate::TempoTransactionPool::new(
            Pool::new(
                validation.clone(),
                crate::ordering::TempoTipOrdering::default(),
                InMemoryBlobStore::default(),
                PoolConfig::default(),
            ),
            crate::AA2dPool::default(),
        );
        let fixture = Self {
            pool,
            validation,
            provider,
            block,
            transaction,
            service,
        };
        fixture.restore_t12();
        fixture
    }

    // The mock chain's head callback selects a pre-T12 fork.
    fn restore_t12(&self) {
        let validator = self.validation.validator();
        validator
            .active_hardfork
            .store(TempoHardfork::T12.variant_index(), Ordering::Relaxed);
        let mut env = validator.cached_evm_env.write();
        env.cfg_env = env.cfg_env.clone().with_spec_and_gas_params(
            TempoHardfork::T12,
            tempo_revm::gas_params::tempo_gas_params(TempoHardfork::T12),
        );
        env.block_env.multisig_recovery_factory = Some(FACTORY);
    }

    async fn insert_stale(&self, transaction: TempoPooledTransaction) -> Entry {
        let hash = *transaction.hash();
        self.pool
            .add_transaction(TransactionOrigin::External, transaction)
            .await
            .unwrap();
        self.mark_stale(hash)
    }

    fn mark_stale(&self, hash: B256) -> Entry {
        let entry = self.pool.get(&hash).unwrap();
        entry.transaction.set_key_expiry(Some(STALE_EXPIRY));
        entry
    }

    fn chain(
        &self,
        block: Block,
        outcome: ExecutionOutcome<tempo_primitives::TempoReceipt>,
    ) -> Arc<Chain<TempoPrimitives>> {
        let senders = vec![self.transaction.sender(); block.body.transactions.len()];
        Arc::new(Chain::new(
            vec![RecoveredBlock::new_unhashed(block, senders)],
            outcome,
            Default::default(),
        ))
    }

    fn reorg(&self, orphan: bool) -> CanonStateNotification<TempoPrimitives> {
        let mut old = self.block.clone();
        old.header.inner.extra_data = Bytes::from_static(b"orphan");
        if orphan {
            old.body
                .transactions
                .push(self.transaction.inner().inner().clone());
        }
        CanonStateNotification::Reorg {
            old: self.chain(old, Default::default()),
            new: self.chain(self.block.clone(), Default::default()),
        }
    }

    fn resumed_event(&self) -> CanonStateNotification<TempoPrimitives> {
        CanonStateNotification::Commit {
            new: self.chain(self.block.clone(), Default::default()),
        }
    }

    fn assert_refreshed(&self, entry: &Entry, same_entry: bool) {
        let retained = self
            .pool
            .get(entry.hash())
            .expect("same commitment remains valid after reorg");
        assert_eq!(Arc::ptr_eq(entry, &retained), same_entry);
        assert_eq!(
            retained.transaction.key_expiry(),
            None,
            "successful revalidation refreshes metadata in place"
        );
    }
}

impl Drop for CanonicalPool {
    fn drop(&mut self) {
        self.service.abort();
    }
}

struct NativeAccount {
    owner: PrivateKeySigner,
    config: MultisigConfig,
    account: Address,
}

impl NativeAccount {
    fn new() -> Self {
        let owner = PrivateKeySigner::random();
        let config = MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: owner.address(),
                weight: 1,
            }],
        };
        let account = config.derive_account(FACTORY).unwrap();
        Self {
            owner,
            config,
            account,
        }
    }

    fn sign(&self, tx: TempoTransaction) -> TempoPooledTransaction {
        let approval = self
            .owner
            .sign_hash_sync(&multisig_digest(tx.signature_hash(), self.account, 0))
            .unwrap();
        let signature = MultisigSignature::try_new(
            self.account,
            self.config.clone(),
            vec![PrimitiveSignature::Secp256k1(approval)],
        )
        .unwrap();
        TempoPooledTransaction::new(Recovered::new_unchecked(
            TempoTxEnvelope::AA(AASigned::new_unhashed(
                tx,
                TempoSignature::Multisig(signature),
            )),
            self.account,
        ))
    }

    fn transaction(&self, nonce_key: u64) -> TempoPooledTransaction {
        let template = TxBuilder::aa(self.account)
            .nonce_key(U256::from(nonce_key))
            .build();
        self.sign(template.inner().as_aa().unwrap().tx().clone())
    }

    fn pool(&self, nonce_key: u64) -> CanonicalPool {
        CanonicalPool::new(
            self.transaction(nonce_key),
            Some(self.config.commitment().unwrap()),
        )
    }
}

#[tokio::test]
async fn configurable_same_commitment_reorg_retains_entry_and_refreshes_metadata() {
    let fixture = NativeAccount::new().pool(1);
    let entry = fixture.insert_stale(fixture.transaction.clone()).await;
    crate::maintain::maintain_tempo_pool_with_events(
        fixture.pool.clone(),
        futures::stream::iter([fixture.reorg(true)]),
    )
    .await;
    fixture.assert_refreshed(&entry, true);
}

#[tokio::test]
async fn configurable_reorg_resurrects_absent_transaction() {
    let fixture = NativeAccount::new().pool(1);
    let entry = fixture.insert_stale(fixture.transaction.clone()).await;
    fixture.pool.remove_transactions(vec![*entry.hash()]);
    assert!(!fixture.pool.contains(entry.hash()));
    crate::maintain::maintain_tempo_pool_with_events(
        fixture.pool.clone(),
        futures::stream::iter([fixture.reorg(true)]),
    )
    .await;
    fixture.assert_refreshed(&entry, false);
}

#[tokio::test]
async fn configurable_grant_recipient_code_change_invalidates_from_canonical_event() {
    use revm::{
        database::{AccountStatus, BundleAccount},
        state::AccountInfo,
    };
    let native = NativeAccount::new();
    let grant = tempo_primitives::transaction::KeyAuthorization::unrestricted(
        42431,
        tempo_primitives::SignatureType::Multisig,
        native.account,
    );
    let approval = native
        .owner
        .sign_hash_sync(&grant.signature_hash())
        .unwrap();
    let transaction = TxBuilder::aa(native.owner.address())
        .key_authorization(grant.into_signed(approval))
        .build();
    let mut fixture = CanonicalPool::new(transaction, None);
    let entry = fixture.insert_stale(fixture.transaction.clone()).await;
    let recipient = entry.transaction.configurable_grant_recipient().unwrap();
    let code = Bytes::from_static(&[0x00]);
    fixture.provider.add_account(
        recipient,
        ExtendedAccount::new(0, U256::ZERO).with_bytecode(code.clone()),
    );
    let mut outcome = ExecutionOutcome::default();
    outcome.bundle.state.insert(
        recipient,
        BundleAccount::new(
            Some(AccountInfo::default()),
            Some(AccountInfo {
                code_hash: alloy_primitives::keccak256(&code),
                ..Default::default()
            }),
            Default::default(),
            AccountStatus::Changed,
        ),
    );
    fixture.block.header.inner.number += 1;
    let new_tip = SealedBlock::seal_slow(fixture.block.clone());
    fixture
        .provider
        .add_block(new_tip.hash(), fixture.block.clone());
    // Reset the anchored validation cache through the real head callback.
    fixture
        .pool
        .on_canonical_state_change(reth_transaction_pool::CanonicalStateUpdate {
            new_tip: &new_tip,
            pending_block_base_fee: TEMPO_T0_BASE_FEE,
            pending_block_blob_fee: None,
            changed_accounts: Vec::new(),
            mined_transactions: Vec::new(),
            update_kind: reth_transaction_pool::PoolUpdateKind::Commit,
        });
    fixture.restore_t12();
    let event = CanonStateNotification::Commit {
        new: fixture.chain(fixture.block.clone(), outcome),
    };
    crate::maintain::maintain_tempo_pool_with_events(
        fixture.pool.clone(),
        futures::stream::iter([event]),
    )
    .await;
    assert!(
        !fixture.pool.contains(entry.hash()),
        "canonical code change must evict a freshly invalid transaction"
    );
}

#[tokio::test]
async fn configurable_registration_rollback_rechecks_intrinsic_gas() {
    use alloy_evm::FromRecoveredTx;
    let native = NativeAccount::new();
    let transaction = native.transaction(1);
    let signed = transaction.inner().as_aa().unwrap();
    let env = tempo_revm::TempoTxEnv::from_recovered_tx(signed, native.account);
    let gas = tempo_revm::gas_params::tempo_gas_params(TempoHardfork::T12);
    let base = tempo_revm::handler::calculate_aa_batch_intrinsic_gas(
        env.tempo_tx_env.as_ref().unwrap(),
        &gas,
        None::<std::iter::Empty<&alloy_eips::eip2930::AccessListItem>>,
        TempoHardfork::T12,
    )
    .unwrap()
    .initial_total_gas();
    let mut tx = signed.tx().clone();
    // Nonce zero pays the existing new-account intrinsic increment.
    tx.gas_limit = base + gas.get(revm::context_interface::cfg::GasId::new_account_cost());
    let fixture = CanonicalPool::new(native.sign(tx), Some(native.config.commitment().unwrap()));
    let entry = fixture.insert_stale(fixture.transaction.clone()).await;
    fixture
        .provider
        .add_account(native.account, ExtendedAccount::new(0, U256::ZERO));
    // Refresh only state; preserve the explicit T12 fixture environment.
    fixture.validation.validator().cached_state.write().1 = Arc::new(StateCache::default());
    let result = fixture
        .validation
        .validate_transaction(
            TransactionOrigin::External,
            entry.transaction.with_discarded_caches(),
        )
        .await;
    let TransactionValidationOutcome::Invalid(_, error) = result else {
        panic!("expected registration gas rejection: {result:?}")
    };
    let Some(TempoPoolTransactionError::Evm(TempoInvalidTransaction::EthInvalidTransaction(
        InvalidTransaction::CallGasCostMoreThanGasLimit {
            gas_limit,
            initial_gas,
        },
    ))) = error.downcast_other_ref::<TempoPoolTransactionError>()
    else {
        panic!("wrong rejection: {error:?}")
    };
    assert_eq!(*gas_limit, entry.transaction.gas_limit());
    assert_eq!(
        initial_gas - gas_limit,
        20_000
            + tempo_precompiles::native_multisig::keccak_cost(77)
            + tempo_precompiles::native_multisig::keccak_cost(85)
    );
    crate::maintain::maintain_tempo_pool_with_events(
        fixture.pool.clone(),
        futures::stream::iter([fixture.reorg(false)]),
    )
    .await;
    assert!(
        !fixture.pool.contains(entry.hash()),
        "registration change must evict a freshly invalid transaction"
    );
}

#[test_case::test_case(false; "same_origin")]
#[test_case::test_case(true; "mixed_origins")]
#[tokio::test]
async fn configurable_batch_preserves_results_and_origins(mixed_origins: bool) {
    let fixture = NativeAccount::new().pool(1);
    let account = fixture.transaction.sender();
    let hash = *fixture.transaction.hash();
    let ordinary = TxBuilder::aa(account).nonce(1).build();
    let ordinary_hash = *ordinary.hash();
    let invalid = TxBuilder::aa(account).nonce(2).gas_limit(0).build();
    let invalid_hash = *invalid.hash();
    let results = if mixed_origins {
        fixture
            .pool
            .add_transactions_with_origins(vec![
                (TransactionOrigin::Local, ordinary),
                (TransactionOrigin::External, invalid),
                (TransactionOrigin::External, fixture.transaction.clone()),
            ])
            .await
    } else {
        fixture
            .pool
            .add_transactions(
                TransactionOrigin::External,
                vec![ordinary, invalid, fixture.transaction.clone()],
            )
            .await
    };
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].as_ref().unwrap().hash, ordinary_hash);
    assert_eq!(results[1].as_ref().unwrap_err().hash, invalid_hash);
    assert_eq!(results[2].as_ref().unwrap().hash, hash);
    assert!(!fixture.pool.contains(&invalid_hash));
    assert_eq!(
        fixture.pool.get(&hash).unwrap().origin,
        TransactionOrigin::External
    );
    assert_eq!(
        fixture.pool.get(&ordinary_hash).unwrap().origin,
        if mixed_origins {
            TransactionOrigin::Local
        } else {
            TransactionOrigin::External
        }
    );
    assert!(fixture.pool.contains(&ordinary_hash));
    assert!(fixture.pool.contains(&hash));
    let entry = fixture.mark_stale(hash);
    crate::maintain::maintain_tempo_pool_with_events(
        fixture.pool.clone(),
        futures::stream::iter([fixture.reorg(false)]),
    )
    .await;
    fixture.assert_refreshed(&entry, true);
}

#[tokio::test]
async fn configurable_unprocessed_head_retries_without_removing_entry() {
    let fixture = NativeAccount::new().pool(0);
    let entry = fixture.insert_stale(fixture.transaction.clone()).await;
    let hash = *entry.hash();
    let mut listener = fixture.pool.transaction_event_listener(hash).unwrap();
    let processed = fixture.validation.validator().processed_head();
    fixture.validation.validator().cached_state.write().0 = B256::repeat_byte(0x88);

    let ordinary = TxBuilder::aa(fixture.transaction.sender()).nonce(1).build();
    let ordinary_hash = *ordinary.hash();
    let events = futures::stream::iter([fixture.reorg(false), fixture.resumed_event()])
        .enumerate()
        .map(|(index, event)| {
            if index == 1 {
                assert!(
                    fixture.pool.contains(&hash),
                    "unsynchronized event must not alter the candidate"
                );
                assert_eq!(
                    entry.transaction.key_expiry(),
                    Some(STALE_EXPIRY),
                    "first event did not revalidate"
                );
                assert!(
                    listener.next().now_or_never().is_none(),
                    "timeout must retain listener without removal"
                );
            }
            let fixture = &fixture;
            let ordinary = ordinary.clone();
            async move {
                if index == 1 {
                    fixture.insert_stale(ordinary).await;
                    fixture.validation.validator().cached_state.write().0 = processed;
                }
                event
            }
        })
        .buffered(1);
    crate::maintain::maintain_tempo_pool_with_events(fixture.pool.clone(), events).await;
    assert_eq!(
        fixture
            .pool
            .get(&ordinary_hash)
            .unwrap()
            .transaction
            .key_expiry(),
        None,
        "full rescan must include ordinary transactions"
    );
    fixture.assert_refreshed(&entry, true);
}

#[tokio::test]
async fn configurable_pre_barrier_insertion_is_included_in_rescan() {
    let fixture = NativeAccount::new().pool(0);
    let entry = fixture.insert_stale(fixture.transaction.clone()).await;
    let hash = *entry.hash();
    let processed = fixture.validation.validator().processed_head();
    fixture.validation.validator().cached_state.write().0 = B256::repeat_byte(0x88);
    fixture.pool.remove_transactions(vec![hash]);
    let ordinary = TxBuilder::aa(fixture.transaction.sender()).nonce(1).build();
    let ordinary_hash = *ordinary.hash();
    let events = futures::stream::iter([fixture.reorg(false), fixture.resumed_event()])
        .enumerate()
        .map(|(index, event)| {
            if index == 1 {
                assert!(
                    !fixture.pool.contains(&hash),
                    "unsynchronized event must not alter the candidate"
                );
                assert_eq!(
                    entry.transaction.key_expiry(),
                    Some(STALE_EXPIRY),
                    "first event did not revalidate"
                );
            }
            let fixture = &fixture;
            let transaction = entry.transaction.with_discarded_caches();
            let ordinary = ordinary.clone();
            async move {
                if index == 1 {
                    // The H-validated insertion lands after the first event, before its callback.
                    fixture.insert_stale(transaction).await;
                    fixture.insert_stale(ordinary).await;
                    fixture.validation.validator().cached_state.write().0 = processed;
                }
                event
            }
        })
        .buffered(1);
    crate::maintain::maintain_tempo_pool_with_events(fixture.pool.clone(), events).await;
    assert_eq!(
        fixture
            .pool
            .get(&ordinary_hash)
            .unwrap()
            .transaction
            .key_expiry(),
        None,
        "full rescan must include ordinary transactions"
    );
    fixture.assert_refreshed(&entry, false);
}

#[tokio::test]
async fn configurable_idle_rescan_retries_without_another_event() {
    let fixture = NativeAccount::new().pool(0);
    let entry = fixture.insert_stale(fixture.transaction.clone()).await;
    let hash = *entry.hash();
    let mut listener = fixture.pool.transaction_event_listener(hash).unwrap();
    let processed = fixture.validation.validator().processed_head();
    fixture.validation.validator().cached_state.write().0 = B256::repeat_byte(0x88);

    let ordinary = TxBuilder::aa(fixture.transaction.sender()).nonce(1).build();
    let ordinary_hash = *ordinary.hash();
    let events = futures::stream::iter([fixture.reorg(false), fixture.resumed_event()])
        .enumerate()
        .map(|(index, event)| {
            if index == 1 {
                assert!(
                    fixture.pool.contains(&hash),
                    "unsynchronized event must not alter the candidate"
                );
                assert_eq!(
                    entry.transaction.key_expiry(),
                    Some(STALE_EXPIRY),
                    "first event did not revalidate"
                );
                assert!(
                    listener.next().now_or_never().is_none(),
                    "timeout must retain listener without removal"
                );
            }
            let fixture = &fixture;
            let ordinary = ordinary.clone();
            async move {
                if index == 1 {
                    fixture.insert_stale(ordinary).await;
                    fixture.validation.validator().cached_state.write().0 = processed;
                    // Hold the next event pending: only the maintenance wakeup can rescan.
                    tokio::time::timeout(std::time::Duration::from_secs(3), async {
                        while fixture
                            .pool
                            .get(&ordinary_hash)
                            .unwrap()
                            .transaction
                            .key_expiry()
                            .is_some()
                        {
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    })
                    .await
                    .expect("idle maintenance must rescan without another canonical event");
                }
                event
            }
        })
        .buffered(1);
    crate::maintain::maintain_tempo_pool_with_events(fixture.pool.clone(), events).await;
    assert_eq!(
        fixture
            .pool
            .get(&ordinary_hash)
            .unwrap()
            .transaction
            .key_expiry(),
        None,
        "full rescan must include ordinary transactions"
    );
    fixture.assert_refreshed(&entry, true);
}

#[tokio::test]
async fn configurable_open_stream_refills_workers_without_timer() {
    let native = NativeAccount::new();
    let fixture = native.pool(1);
    let entry = fixture.insert_stale(fixture.transaction.clone()).await;
    let mut extra_hashes = Vec::new();
    for nonce_key in 2..14 {
        let mut tx = entry.transaction.inner().as_aa().unwrap().tx().clone();
        tx.nonce_key = U256::from(nonce_key);
        extra_hashes.push(*fixture.insert_stale(native.sign(tx)).await.hash());
    }
    // Keep the stream open and retry clock frozen: successful work must refill slots
    // without relying on shutdown draining or a timer tick.
    tokio::time::pause();
    let events = futures::stream::iter([fixture.reorg(false)]).chain(futures::stream::pending());
    let mut maintenance = Box::pin(crate::maintain::maintain_tempo_pool_with_events(
        fixture.pool.clone(),
        events,
    ));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while extra_hashes.iter().any(|hash| {
        fixture
            .pool
            .get(hash)
            .unwrap()
            .transaction
            .key_expiry()
            .is_some()
    }) {
        assert!(futures::poll!(maintenance.as_mut()).is_pending());
        assert!(
            std::time::Instant::now() < deadline,
            "idle workers must refill"
        );
        tokio::task::yield_now().await;
    }
    for hash in extra_hashes {
        assert_eq!(
            fixture.pool.get(&hash).unwrap().transaction.key_expiry(),
            None,
            "bounded work must drain beyond the first four entries"
        );
    }
    fixture.assert_refreshed(&entry, true);
}
