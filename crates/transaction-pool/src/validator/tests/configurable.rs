use super::*;
use crate::{
    AA2dPool, TempoTransactionPool, maintain::maintain_tempo_pool_with_events,
    ordering::TempoTipOrdering, tt_2d_pool::AA2dPoolConfig,
};
use alloy_evm::FromRecoveredTx;
use alloy_primitives::{IntoLogData, Log, keccak256, map::B256Set};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolEvent;
use futures::{FutureExt, StreamExt};
use reth_primitives_traits::{Recovered, RecoveredBlock};
use reth_provider::{CanonStateNotification, Chain, ExecutionOutcome};
use reth_transaction_pool::{
    CanonicalStateUpdate, FullTransactionEvent, Pool, PoolConfig, PoolUpdateKind, TransactionPool,
    TransactionPoolExt, TransactionValidationTaskExecutor, ValidPoolTransaction,
    validate::ValidationTask,
};
use revm::{
    context_interface::cfg::GasId,
    database::{AccountStatus, BundleAccount},
    state::AccountInfo,
};
use std::time::{Duration, Instant};
use tempo_contracts::precompiles::{IFeeManager, ITIP20};
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS, native_multisig::keccak_cost,
    tip_fee_manager::TipFeeManager,
};
use tempo_primitives::{
    SignatureType, TempoReceipt, TempoTxType,
    account::encode_config_commitment,
    transaction::{
        KeyAuthorization, MultisigConfig, MultisigOwner, MultisigSignature, multisig_digest,
    },
};
use tempo_revm::{
    TempoTxEnv, gas_params::tempo_gas_params, handler::calculate_aa_batch_intrinsic_gas,
};

const FACTORY: Address = Address::repeat_byte(0x71);
const STALE_EXPIRY: u64 = 12345;

type Provider = MockEthProvider<TempoPrimitives, TempoChainSpec>;
type Entry = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

struct CanonicalPool {
    pool: TempoTransactionPool<Provider>,
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
                    AccountExtension::copy_from_slice(&encode_config_commitment(commitment)),
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
        let pool = TempoTransactionPool::new(
            Pool::new(
                validation.clone(),
                TempoTipOrdering::default(),
                InMemoryBlobStore::default(),
                PoolConfig::default(),
            ),
            AA2dPool::new(AA2dPoolConfig {
                max_txs_per_sender: 64,
                ..Default::default()
            }),
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
        env.cfg_env = env
            .cfg_env
            .clone()
            .with_spec_and_gas_params(TempoHardfork::T12, tempo_gas_params(TempoHardfork::T12));
        env.block_env.multisig_recovery_factory = Some(FACTORY);
    }

    fn advance_provider(&mut self) -> SealedBlock<Block> {
        self.block.header.inner.parent_hash = self.provider.chain_info().unwrap().best_hash;
        self.block.header.inner.number += 1;
        let block = SealedBlock::seal_slow(self.block.clone());
        self.provider.add_block(block.hash(), self.block.clone());
        block
    }

    fn apply_head(&self, block: &SealedBlock<Block>) {
        self.pool.on_canonical_state_change(CanonicalStateUpdate {
            new_tip: block,
            pending_block_base_fee: TEMPO_T0_BASE_FEE,
            pending_block_blob_fee: None,
            changed_accounts: Vec::new(),
            mined_transactions: Vec::new(),
            update_kind: PoolUpdateKind::Commit,
        });
        self.restore_t12();
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
        outcome: ExecutionOutcome<TempoReceipt>,
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

    fn assert_refreshed(&self, entry: &Entry, same_entry: bool) {
        let retained = self
            .pool
            .get(entry.hash())
            .expect("revalidated transaction remains in pool");
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
async fn policy_updates_quarantine_until_fresh_validation() {
    for nonce_key in [U256::ZERO, U256::ONE] {
        for event in [
            ITIP20::TransferPolicyUpdate {
                updater: Address::ZERO,
                newPolicyId: 1,
            }
            .into_log_data(),
            ITIP20::QuoteTokenUpdate {
                updater: Address::ZERO,
                newQuoteToken: Address::random(),
            }
            .into_log_data(),
        ] {
            let mut fixture = CanonicalPool::new(
                TxBuilder::aa(Address::random())
                    .nonce_key(nonce_key)
                    .build(),
                None,
            );
            let entry = fixture.insert_stale(fixture.transaction.clone()).await;
            let mut listener = fixture.pool.all_transactions_event_listener();
            let mut live = fixture.pool.best_transactions();
            assert!(fixture.pool.best_transactions().next().is_some());
            let fee_token = entry.transaction.resolved_fee_token().unwrap();
            let outcome = ExecutionOutcome {
                receipts: vec![vec![TempoReceipt {
                    tx_type: TempoTxType::AA,
                    success: true,
                    cumulative_gas_used: 21_000,
                    logs: vec![Log {
                        address: fee_token,
                        data: event,
                    }],
                }]],
                ..Default::default()
            };
            let block = fixture.advance_provider();
            let update = CanonStateNotification::Commit {
                new: fixture.chain(fixture.block.clone(), outcome),
            };
            let mut maintenance = Box::pin(maintain_tempo_pool_with_events(
                fixture.pool.clone(),
                futures::stream::iter([update]),
            ));
            assert!(futures::poll!(maintenance.as_mut()).is_pending());
            assert!(entry.transaction.is_quarantined());
            assert!(fixture.pool.contains(entry.hash()));
            assert!(live.next().is_none());
            assert!(fixture.pool.best_transactions().next().is_none());
            fixture.apply_head(&block);
            tokio::time::timeout(Duration::from_secs(3), maintenance)
                .await
                .unwrap();
            fixture.assert_refreshed(&entry, true);
            assert!(!entry.transaction.is_quarantined());
            assert!(fixture.pool.best_transactions().next().is_some());
            assert!(
                listener.next().now_or_never().is_none(),
                "retained entries emit no discard"
            );
        }
    }
}

#[tokio::test]
async fn policy_revalidation_preserves_same_block_fee_preference_changes() {
    let token_b = address!("20c0000000000000000000000000000000000002");
    for nonce_key in [U256::ZERO, U256::ONE] {
        for policy_event in [
            ITIP20::TransferPolicyUpdate {
                updater: Address::ZERO,
                newPolicyId: 0,
            }
            .into_log_data(),
            ITIP20::QuoteTokenUpdate {
                updater: Address::ZERO,
                newQuoteToken: token_b,
            }
            .into_log_data(),
        ] {
            let sender = Address::random();
            let mut fixture =
                CanonicalPool::new(TxBuilder::aa(sender).nonce_key(nonce_key).build(), None);
            let entry = fixture.insert_stale(fixture.transaction.clone()).await;
            assert_eq!(
                entry.transaction.resolved_fee_token(),
                Some(PATH_USD_ADDRESS)
            );
            // Copy the valid token configuration and funded sender balance to B.
            let token_state = fixture.provider.accounts.lock()[&PATH_USD_ADDRESS].clone();
            fixture.provider.add_account(token_b, token_state);
            let unrelated = fixture
                .insert_stale(
                    TxBuilder::aa(sender)
                        .nonce_key(U256::from(2))
                        .fee_token(token_b)
                        .valid_before(100)
                        .build(),
                )
                .await;
            let mut listener = fixture.pool.all_transactions_event_listener();

            let preference_slot = TipFeeManager::new().user_tokens[sender].slot();
            fixture.provider.add_account(
                TIP_FEE_MANAGER_ADDRESS,
                ExtendedAccount::new(0, U256::ZERO).extend_storage([(
                    preference_slot.into(),
                    U256::from_be_slice(token_b.as_slice()),
                )]),
            );
            // Apply the token change to state as well as its receipt event.
            let transfer_policy_changed =
                policy_event.topics()[0] == ITIP20::TransferPolicyUpdate::SIGNATURE_HASH;
            let slot = if transfer_policy_changed {
                tip20_slots::TRANSFER_POLICY_ID
            } else {
                tip20_slots::QUOTE_TOKEN
            };
            let value = if transfer_policy_changed {
                U256::ZERO
            } else {
                U256::from_be_slice(token_b.as_slice())
            };
            let token_state = fixture.provider.accounts.lock()[&PATH_USD_ADDRESS].clone();
            fixture.provider.add_account(
                PATH_USD_ADDRESS,
                token_state.extend_storage([(slot.into(), value)]),
            );
            let preference_event = IFeeManager::UserTokenSet {
                user: sender,
                token: token_b,
            }
            .into_log_data();
            let outcome = ExecutionOutcome {
                receipts: vec![vec![TempoReceipt {
                    tx_type: TempoTxType::AA,
                    success: true,
                    cumulative_gas_used: 21_000,
                    logs: vec![
                        Log {
                            address: PATH_USD_ADDRESS,
                            data: policy_event,
                        },
                        Log {
                            address: TIP_FEE_MANAGER_ADDRESS,
                            data: preference_event,
                        },
                    ],
                }]],
                ..Default::default()
            };
            fixture.block.header.inner.parent_hash =
                fixture.validation.validator().processed_head();
            fixture.block.header.inner.number += 1;
            fixture.block.header.inner.timestamp = 100;
            let new_tip = SealedBlock::seal_slow(fixture.block.clone());
            fixture
                .provider
                .add_block(new_tip.hash(), fixture.block.clone());
            fixture
                .pool
                .on_canonical_state_change(CanonicalStateUpdate {
                    new_tip: &new_tip,
                    pending_block_base_fee: TEMPO_T0_BASE_FEE,
                    pending_block_blob_fee: None,
                    changed_accounts: Vec::new(),
                    mined_transactions: Vec::new(),
                    update_kind: PoolUpdateKind::Commit,
                });
            fixture.restore_t12();
            let event = CanonStateNotification::Commit {
                new: fixture.chain(fixture.block.clone(), outcome),
            };
            maintain_tempo_pool_with_events(fixture.pool.clone(), futures::stream::iter([event]))
                .await;
            fixture.assert_refreshed(&entry, true);
            assert_eq!(entry.transaction.resolved_fee_token(), Some(token_b));
            assert!(!entry.transaction.is_quarantined());
            while let Some(Some(event)) = listener.next().now_or_never() {
                let removed_hash = match &event {
                    FullTransactionEvent::Discarded(hash) | FullTransactionEvent::Invalid(hash) => {
                        Some(hash)
                    }
                    FullTransactionEvent::Replaced { transaction, .. } => Some(transaction.hash()),
                    _ => None,
                };
                assert!(
                    removed_hash != Some(entry.hash()),
                    "retained entry must not be discarded: {event:?}"
                );
            }
            assert!(
                !fixture.pool.contains(unrelated.hash()),
                "unrelated expired entries still get evicted"
            );
        }
    }
}

#[tokio::test]
async fn configurable_same_commitment_reorg_retains_entry_and_refreshes_metadata() {
    let fixture = NativeAccount::new().pool(1);
    let entry = fixture.insert_stale(fixture.transaction.clone()).await;
    maintain_tempo_pool_with_events(
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
    maintain_tempo_pool_with_events(
        fixture.pool.clone(),
        futures::stream::iter([fixture.reorg(true)]),
    )
    .await;
    fixture.assert_refreshed(&entry, false);
}

#[tokio::test]
async fn configurable_grant_recipient_code_change_invalidates_from_canonical_event() {
    let native = NativeAccount::new();
    let grant = KeyAuthorization::unrestricted(42431, SignatureType::Multisig, native.account);
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
                code_hash: keccak256(&code),
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
        .on_canonical_state_change(CanonicalStateUpdate {
            new_tip: &new_tip,
            pending_block_base_fee: TEMPO_T0_BASE_FEE,
            pending_block_blob_fee: None,
            changed_accounts: Vec::new(),
            mined_transactions: Vec::new(),
            update_kind: PoolUpdateKind::Commit,
        });
    fixture.restore_t12();
    let event = CanonStateNotification::Commit {
        new: fixture.chain(fixture.block.clone(), outcome),
    };
    maintain_tempo_pool_with_events(fixture.pool.clone(), futures::stream::iter([event])).await;
    assert!(
        !fixture.pool.contains(entry.hash()),
        "canonical code change must evict a freshly invalid transaction"
    );
}

#[tokio::test]
async fn configurable_registration_rollback_rechecks_intrinsic_gas() {
    let native = NativeAccount::new();
    let transaction = native.transaction(1);
    let signed = transaction.inner().as_aa().unwrap();
    let env = TempoTxEnv::from_recovered_tx(signed, native.account);
    let gas = tempo_gas_params(TempoHardfork::T12);
    let base = calculate_aa_batch_intrinsic_gas(
        env.tempo_tx_env.as_ref().unwrap(),
        &gas,
        None::<std::iter::Empty<&alloy_eips::eip2930::AccessListItem>>,
        TempoHardfork::T12,
    )
    .unwrap()
    .initial_total_gas();
    let mut tx = signed.tx().clone();
    // Nonce zero pays the existing new-account intrinsic increment.
    tx.gas_limit = base + gas.get(GasId::new_account_cost());
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
        20_000 + keccak_cost(77) + keccak_cost(85)
    );
    maintain_tempo_pool_with_events(
        fixture.pool.clone(),
        futures::stream::iter([fixture.reorg(false)]),
    )
    .await;
    assert!(
        !fixture.pool.contains(entry.hash()),
        "registration change must evict a freshly invalid transaction"
    );
}

#[test_case::test_matrix([false, true], [false, true])]
#[tokio::test]
async fn batch_preserves_results_and_origins(mixed_origins: bool, configurable: bool) {
    let fixture = NativeAccount::new().pool(1);
    let account = fixture.transaction.sender();
    let transaction = if configurable {
        fixture.transaction.clone()
    } else {
        TxBuilder::aa(account).nonce_key(U256::ONE).build()
    };
    let hash = *transaction.hash();
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
                (TransactionOrigin::External, transaction),
            ])
            .await
    } else {
        fixture
            .pool
            .add_transactions(
                TransactionOrigin::External,
                vec![ordinary, invalid, transaction],
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
}

#[tokio::test]
async fn configurable_batch_admits_before_the_tail_and_survives_a_new_head() {
    let native = NativeAccount::new();
    let mut fixture = native.pool(1);
    fixture.service.abort();
    let (sender, service) = ValidationTask::with_capacity(64);
    *fixture.validation.to_validation_task.lock().await = sender;
    let transactions: Vec<_> = (1..=17).map(|key| native.transaction(key)).collect();
    let hashes: Vec<_> = transactions.iter().map(|tx| *tx.hash()).collect();
    let pool = fixture.pool.clone();
    let admission = pool.add_transactions(TransactionOrigin::External, transactions);
    tokio::pin!(admission);
    // Queue the first validation window without letting the worker run it yet.
    assert!(admission.as_mut().now_or_never().is_none());
    let (entered, blocked) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    fixture
        .validation
        .to_validation_task
        .lock()
        .await
        .send(Box::pin(async move {
            entered.send(()).unwrap();
            resume.await.unwrap();
        }))
        .await
        .unwrap();
    fixture.service = tokio::spawn(service.run());
    blocked.await.unwrap();
    assert!(admission.as_mut().now_or_never().is_none());
    assert!(hashes[..16].iter().all(|hash| fixture.pool.contains(hash)));
    assert!(!fixture.pool.contains(&hashes[16]));
    // The tail must acquire the new generation; admitted transactions are not retried.
    let block = fixture.advance_provider();
    fixture.apply_head(&block);
    release.send(()).unwrap();
    let results = admission.await;
    assert_eq!(results.len(), hashes.len());
    for (result, hash) in results.into_iter().zip(hashes) {
        assert_eq!(result.unwrap().hash, hash);
        assert!(fixture.pool.contains(&hash));
    }
}

#[tokio::test]
async fn configurable_rescan_reconciles_2d_nonce_without_replacing_entries() {
    let native = NativeAccount::new();
    let mut fixture = native.pool(1);
    let mut entries = Vec::new();
    for nonce in [1, 2] {
        let mut tx = fixture.transaction.inner().as_aa().unwrap().tx().clone();
        tx.nonce = nonce;
        entries.push(fixture.insert_stale(native.sign(tx)).await);
    }
    let mut listener = fixture.pool.all_transactions_event_listener();
    assert!(fixture.pool.best_transactions().next().is_none());
    // Miss a nonce increase, then a decrease. Neither event carries the nonce slot delta.
    for (nonce, pending) in [(1, true), (0, false), (1, true)] {
        let mut best = fixture.pool.best_transactions();
        fixture.provider.add_account(
            NONCE_PRECOMPILE_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([(
                fixture.transaction.nonce_key_slot().unwrap().into(),
                U256::from(nonce),
            )]),
        );
        let block = fixture.advance_provider();
        fixture.apply_head(&block);
        let events = futures::stream::iter([fixture.reorg(false)]);
        maintain_tempo_pool_with_events(fixture.pool.clone(), events).await;
        for entry in &entries {
            fixture.assert_refreshed(entry, true);
        }
        let all = fixture.pool.all_transactions();
        assert_eq!(all.pending.len(), if pending { 2 } else { 0 });
        assert_eq!(all.queued.len(), if pending { 0 } else { 2 });
        assert_eq!(fixture.pool.best_transactions().next().is_some(), pending);
        if pending {
            assert_eq!(
                best.next().unwrap().hash(),
                entries[0].hash(),
                "live iterator sees promotion"
            );
        }
        let mut notified = B256Set::default();
        for _ in &entries {
            let event = listener
                .next()
                .now_or_never()
                .flatten()
                .expect("nonce transition event");
            match event {
                FullTransactionEvent::Pending(hash) if pending => {
                    notified.insert(hash);
                }
                FullTransactionEvent::Queued(hash, _) if !pending => {
                    notified.insert(hash);
                }
                other => panic!("unexpected nonce transition: {other:?}"),
            }
        }
        assert!(entries.iter().all(|entry| notified.contains(entry.hash())));
        assert!(
            listener.next().now_or_never().is_none(),
            "no duplicate events"
        );
    }
}

#[tokio::test]
async fn callback_lag_rechecks_only_affected_entries_including_late_admissions() {
    for changed in [false, true] {
        for nonce_key in [0, 1] {
            let native = NativeAccount::new();
            let mut fixture = CanonicalPool::new(native.transaction(nonce_key), None);
            let entry = fixture.insert_stale(fixture.transaction.clone()).await;
            let ordinary = fixture
                .insert_stale(
                    TxBuilder::aa(native.account)
                        .nonce_key(U256::from(99))
                        .build(),
                )
                .await;
            let mut live = fixture.pool.best_transactions();
            let mut outcome = ExecutionOutcome::default();
            if changed {
                let extension = AccountExtension::copy_from_slice(&encode_config_commitment(
                    native.config.commitment().unwrap(),
                ));
                fixture.provider.add_account(
                    native.account,
                    ExtendedAccount::new(0, U256::ZERO).with_extension(extension.clone()),
                );
                outcome.bundle.state.insert(
                    native.account,
                    BundleAccount::new(
                        Some(AccountInfo::default()),
                        Some(AccountInfo {
                            extension: revm::state::AccountExtension::from_shared(
                                extension.into_shared(),
                            ),
                            ..Default::default()
                        }),
                        Default::default(),
                        AccountStatus::Changed,
                    ),
                );
            }
            let block = fixture.advance_provider();
            let event = CanonStateNotification::Commit {
                new: fixture.chain(fixture.block.clone(), outcome),
            };
            let mut maintenance = Box::pin(maintain_tempo_pool_with_events(
                fixture.pool.clone(),
                futures::stream::iter([event]),
            ));
            assert!(futures::poll!(maintenance.as_mut()).is_pending());
            assert_eq!(entry.transaction.is_quarantined(), changed);
            assert!(!ordinary.transaction.is_quarantined());
            if changed {
                assert!(live.all(|tx| tx.hash() != entry.hash()));
            }
            // This old-head admission happens after the first affected-entry scan.
            let late = fixture.insert_stale(native.transaction(2)).await;
            fixture.apply_head(&block);
            tokio::time::timeout(Duration::from_secs(3), maintenance)
                .await
                .unwrap();
            for candidate in [&entry, &late] {
                assert_eq!(
                    candidate.transaction.key_expiry(),
                    (!changed).then_some(STALE_EXPIRY)
                );
                assert!(!candidate.transaction.is_quarantined());
                assert!(Arc::ptr_eq(
                    candidate,
                    &fixture.pool.get(candidate.hash()).unwrap()
                ));
            }
            assert_eq!(
                ordinary.transaction.key_expiry(),
                Some(STALE_EXPIRY),
                "ordinary callback lag must not revalidate the whole pool"
            );
        }
    }
}

#[tokio::test]
async fn newer_invalidation_vetoes_both_valid_and_invalid_revalidation() {
    for invalid in [false, true] {
        let native = NativeAccount::new();
        let mut fixture = native.pool(0);
        let entry = fixture.insert_stale(fixture.transaction.clone()).await;
        fixture.provider.add_account(
            native.account,
            ExtendedAccount::new(u64::from(invalid), U256::ZERO).with_extension(
                AccountExtension::copy_from_slice(&encode_config_commitment(
                    native.config.commitment().unwrap(),
                )),
            ),
        );
        let block = fixture.advance_provider();
        fixture.apply_head(&block);
        let mut pending = B256Set::from_iter([*entry.hash()]);
        entry.transaction.quarantine();
        let mut validation = Box::pin(
            fixture
                .pool
                .revalidate_pending_transactions(&mut pending, None),
        );
        assert!(futures::poll!(validation.as_mut()).is_pending());
        entry.transaction.quarantine();
        validation.await;
        assert!(fixture.pool.contains(entry.hash()));
        assert!(entry.transaction.is_quarantined());
        assert!(
            pending.contains(entry.hash()),
            "a superseded rejection must also retry"
        );
        fixture
            .pool
            .revalidate_pending_transactions(&mut pending, None)
            .await;
        assert!(pending.is_empty());
        assert_eq!(fixture.pool.contains(entry.hash()), !invalid);
        if !invalid {
            fixture.assert_refreshed(&entry, true);
            assert!(!entry.transaction.is_quarantined());
        }
    }
}

#[tokio::test]
async fn notification_gap_revalidates_ordinary_entries() {
    let mut fixture = CanonicalPool::new(TxBuilder::aa(Address::random()).build(), None);
    let entry = fixture.insert_stale(fixture.transaction.clone()).await;
    let first = fixture.chain(fixture.block.clone(), Default::default());
    fixture.advance_provider(); // This notification is missed.
    let block = fixture.advance_provider();
    fixture.apply_head(&block);
    let last = fixture.chain(fixture.block.clone(), Default::default());
    tokio::time::timeout(
        Duration::from_secs(3),
        maintain_tempo_pool_with_events(
            fixture.pool.clone(),
            futures::stream::iter([
                CanonStateNotification::Commit { new: first },
                CanonStateNotification::Commit { new: last },
            ]),
        ),
    )
    .await
    .unwrap();
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
    let mut maintenance = Box::pin(maintain_tempo_pool_with_events(
        fixture.pool.clone(),
        events,
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
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
        assert!(Instant::now() < deadline, "idle workers must refill");
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
