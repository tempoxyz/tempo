use super::*;
use alloy_consensus::Header;
use alloy_evm::FromRecoveredTx;
use alloy_primitives::{Signature, bytes, keccak256};
use alloy_sol_types::SolError;
use reth_ethereum_primitives::Block as EthereumBlock;
use reth_evm::ConfigureEvm;
use reth_execution_types::ExecutionOutcome;
use reth_primitives_traits::{Block as _, Recovered};
use reth_provider::{
    BlockExecutionWriter, BlockWriter, OriginalValuesKnown, StateWriter, TrieWriter,
    providers::BlockchainProvider, test_utils::create_test_provider_factory,
};
use reth_stages::{MerkleCheckpoint, StorageRootMerkleCheckpoint, stages::MerkleStage};
use reth_storage_api::{
    AccountReader, ChangeSetReader, DBProvider, HistoryWriter, StateProviderFactory,
    StateRootProvider, StateWriteConfig, StorageSettingsCache,
};
use reth_trie::{HashedPostState, KeccakKeyHasher, StateRoot, StateRootProgress, StoredSubNode};
use reth_trie_db::{
    DatabaseHashedCursorFactory, DatabaseStateRoot, DatabaseTrieCursorFactory, with_adapter,
};
use revm::{
    context::result::{EVMError, ExecutionResult},
    state::EvmStorageSlot,
};
use tempo_chainspec::spec::MODERATO;
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, AccountKeychainError, PATH_USD_ADDRESS,
    account_keychain::IAccountKeychain, tip20::ITIP20,
};
use tempo_evm::{
    StorageActionReplay, StorageActionReplayError, TempoEvmConfig, supports_storage_action_replay,
};
use tempo_precompiles::{error::TempoPrecompileError, tip20::TIP20Token};
use tempo_primitives::{
    Block as TempoBlock, SignatureType, TempoTxEnvelope,
    account::encode_config_commitment,
    transaction::{
        AccountSignature, CallScope, KeyAuthorization, KeychainSignature, SignedKeyAuthorization,
        TokenLimit, calc_gas_balance_spending,
    },
};
use tempo_revm::{TempoInvalidTransaction, TempoTxEnv};

#[test]
fn native_commitment_database_lifecycle() {
    let factory = create_test_provider_factory();
    let mut fixture = Fixture::new();
    let mut roots = Vec::new();
    let mut parent_hash = B256::ZERO;
    for block in 0..=2 {
        if block != 0 {
            let tx = fixture.signed(block + 2, vec![fixture.getter()]);
            let output = fixture
                .evm
                .transact(TempoTxEnv::from_recovered_tx(&tx, fixture.account))
                .unwrap();
            assert!(output.result.is_success(), "{:?}", output.result);
            fixture.evm.db_mut().commit(output.state);
            fixture
                .evm
                .db_mut()
                .merge_transitions(BundleRetention::Reverts);
        }
        let bundle = fixture.evm.db_mut().take_bundle();
        assert!(
            bundle.state().contains_key(&fixture.account),
            "account missing from executed bundle at {block}"
        );
        let hashed = HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle.state());
        let (root, updates) = factory
            .latest()
            .unwrap()
            .state_root_with_updates(hashed.clone())
            .unwrap();
        let mut header = Header {
            number: block,
            state_root: root,
            ..Default::default()
        };
        header.parent_hash = parent_hash;
        let chain_block = EthereumBlock {
            header,
            body: Default::default(),
        }
        .try_into_recovered()
        .unwrap();
        parent_hash = chain_block.hash();
        let provider = factory.provider_rw().unwrap();
        provider.insert_block(&chain_block).unwrap();
        let outcome = ExecutionOutcome::new(bundle, vec![vec![]], block, vec![]);
        provider
            .write_state(
                &outcome,
                OriginalValuesKnown::Yes,
                StateWriteConfig::default(),
            )
            .unwrap();
        provider.write_hashed_state(&hashed.into_sorted()).unwrap();
        provider.write_trie_updates(updates).unwrap();
        provider.update_history_indices(block..=block).unwrap();
        provider.commit().unwrap();
        let latest = factory.latest().unwrap();
        let account = latest
            .basic_account(&fixture.account)
            .unwrap()
            .unwrap_or_else(|| panic!("persisted account missing at {block}"));
        let expected = if block == 0 {
            B256::ZERO
        } else {
            fixture.config.commitment().unwrap()
        };
        assert_eq!(
            decode_config_commitment(&account.extension, true).unwrap(),
            expected
        );
        assert_eq!(latest.state_root(Default::default()).unwrap(), root);
        roots.push(root);
    }
    assert_ne!(roots[0], roots[1]);
    {
        let blockchain = BlockchainProvider::new(factory.clone()).unwrap();
        for block in [0, 1] {
            let historical = blockchain.history_by_block_number(block).unwrap();
            let account = historical.basic_account(&fixture.account).unwrap().unwrap();
            let expected = if block == 0 {
                B256::ZERO
            } else {
                fixture.config.commitment().unwrap()
            };
            assert_eq!(
                decode_config_commitment(&account.extension, true).unwrap(),
                expected
            );
        }
    }
    let before_second = factory
        .provider()
        .unwrap()
        .get_account_before_block(2, fixture.account)
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_config_commitment(&before_second.info.unwrap().extension, true).unwrap(),
        fixture.config.commitment().unwrap()
    );
    for block in [1, 0] {
        let provider = factory.unwind_provider_rw().unwrap();
        provider.remove_block_and_execution_above(block).unwrap();
        provider.commit().unwrap();
        let latest = factory.latest().unwrap();
        let account = latest.basic_account(&fixture.account).unwrap().unwrap();
        let expected = if block == 0 {
            B256::ZERO
        } else {
            fixture.config.commitment().unwrap()
        };
        assert_eq!(
            decode_config_commitment(&account.extension, true).unwrap(),
            expected
        );
        assert_eq!(
            latest.state_root(Default::default()).unwrap(),
            roots[block as usize]
        );
    }
}

/// Exercises the stage's persisted checkpoint codec with real partial storage-trie work.
/// Reopens database transactions, not a process or a full Stage::execute pipeline.
#[test]
fn native_commitment_persisted_storage_trie_resume_and_proof() {
    let factory = create_test_provider_factory();
    let mut fixture = Fixture::new();
    let commitment = fixture.config.commitment().unwrap();
    let mut info = fixture
        .evm
        .db_mut()
        .basic(fixture.account)
        .unwrap()
        .unwrap();
    info.extension = encode_config_commitment(commitment).into();
    let mut account = Account::from(info);
    for slot in 0..128u64 {
        account.storage.insert(
            U256::from(slot),
            EvmStorageSlot::new_changed(U256::ZERO, U256::from(slot + 1), TransactionId::ZERO),
        );
    }
    account.mark_touch();
    fixture
        .evm
        .db_mut()
        .commit([(fixture.account, account)].into_iter().collect());
    fixture
        .evm
        .db_mut()
        .merge_transitions(BundleRetention::Reverts);
    let bundle = fixture.evm.db_mut().take_bundle();
    let hashed = HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle.state());
    let expected_root = factory
        .latest()
        .unwrap()
        .state_root(hashed.clone())
        .unwrap();
    {
        let provider = factory.provider_rw().unwrap();
        provider
            .insert_block(
                &EthereumBlock {
                    header: Header {
                        state_root: expected_root,
                        ..Default::default()
                    },
                    body: Default::default(),
                }
                .try_into_recovered()
                .unwrap(),
            )
            .unwrap();
        provider
            .write_state(
                &ExecutionOutcome::new(bundle, vec![vec![]], 0, vec![]),
                OriginalValuesKnown::Yes,
                StateWriteConfig::default(),
            )
            .unwrap();
        provider.write_hashed_state(&hashed.into_sorted()).unwrap();
        provider.commit().unwrap();
    }

    let stage = MerkleStage::default_execution();
    let mut storage_resumptions = 0;
    let mut completed_root = None;
    for _ in 0..512 {
        // Drop/commit the previous RW transaction before reading its persisted checkpoint.
        let provider = factory.provider_rw().unwrap();
        let checkpoint = stage.get_execution_checkpoint(&*provider).unwrap();
        if let Some(storage) = checkpoint
            .as_ref()
            .filter(|checkpoint| checkpoint.last_account_key == keccak256(fixture.account))
            .and_then(|checkpoint| checkpoint.storage_root_checkpoint.as_ref())
        {
            storage_resumptions += 1;
            assert_eq!(
                decode_config_commitment(&storage.account_extension, true).unwrap(),
                commitment
            );
        }
        let progress = with_adapter!(&provider, |A| {
            StateRoot::<DatabaseTrieCursorFactory<_, A>, DatabaseHashedCursorFactory<_>>::from_tx(
                provider.tx_ref(),
            )
            .with_intermediate_state(checkpoint.map(Into::into))
            .with_threshold(4)
            .root_with_progress()
        })
        .unwrap();
        match progress {
            StateRootProgress::Progress(state, _, updates) => {
                provider.write_trie_updates(updates).unwrap();
                let mut checkpoint = MerkleCheckpoint::new(
                    0,
                    state.account_root_state.last_hashed_key,
                    state
                        .account_root_state
                        .walker_stack
                        .into_iter()
                        .map(StoredSubNode::from)
                        .collect(),
                    state.account_root_state.hash_builder.into(),
                );
                checkpoint.storage_root_checkpoint = state.storage_root_state.map(|storage| {
                    StorageRootMerkleCheckpoint::new(
                        storage.state.last_hashed_key,
                        storage
                            .state
                            .walker_stack
                            .into_iter()
                            .map(StoredSubNode::from)
                            .collect(),
                        storage.state.hash_builder.into(),
                        storage.account,
                    )
                });
                stage
                    .save_execution_checkpoint(&*provider, Some(checkpoint))
                    .unwrap();
            }
            StateRootProgress::Complete(root, _, updates) => {
                provider.write_trie_updates(updates).unwrap();
                stage.save_execution_checkpoint(&*provider, None).unwrap();
                completed_root = Some(root);
            }
        }
        provider.commit().unwrap();
        if completed_root.is_some() {
            break;
        }
    }
    assert!(
        storage_resumptions > 0,
        "must resume inside an account's nonempty storage trie"
    );
    assert_eq!(completed_root, Some(expected_root));
    let latest = factory.latest().unwrap();
    let proof = latest
        .proof(
            Default::default(),
            fixture.account,
            &[B256::ZERO, B256::with_last_byte(127)],
        )
        .unwrap();
    assert_eq!(
        decode_config_commitment(&proof.info.as_ref().unwrap().extension, true).unwrap(),
        commitment
    );
    assert_eq!(proof.storage_proofs.len(), 2);
    for (key, value) in [
        (B256::ZERO, U256::ONE),
        (B256::with_last_byte(127), U256::from(128)),
    ] {
        assert_eq!(
            proof
                .storage_proofs
                .iter()
                .find(|proof| proof.key == key)
                .unwrap()
                .value,
            value
        );
    }
    proof.verify(expected_root).unwrap();
    // Verification must bind the fifth account field, not merely the ordinary account fields.
    let mut wrong_commitment = proof;
    wrong_commitment.info.as_mut().unwrap().extension =
        encode_config_commitment(B256::repeat_byte(0x99)).into();
    assert!(wrong_commitment.verify(expected_root).is_err());
}

#[test]
fn native_first_call_registration_and_retry() {
    let mut f = Fixture::new();
    let reverter = Address::repeat_byte(0x55);
    let code = Bytecode::new_legacy(bytes!("60006000fd"));
    f.evm.db_mut().insert_account(
        reverter,
        AccountInfo {
            code_hash: code.hash_slow(),
            code: Some(code),
            ..Default::default()
        },
    );
    let failed = f.signed(
        3,
        vec![
            f.getter(),
            Call {
                to: TxKind::Call(reverter),
                value: U256::ZERO,
                input: Default::default(),
            },
        ],
    );
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&failed, f.account))
        .unwrap();
    assert!(!output.result.is_success());
    assert_eq!(
        decode_config_commitment(&output.state[&f.account].info.extension, true).unwrap(),
        f.config.commitment().unwrap()
    );
    f.evm.db_mut().commit(output.state);
    let tx = f.signed(4, vec![f.getter()]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(
        decode_config_commitment(&output.state[&f.account].info.extension, true).unwrap(),
        f.config.commitment().unwrap()
    );
    assert_eq!(
        INativeMultisig::getConfigCommitmentCall::abi_decode_returns(
            output.result.output().unwrap()
        )
        .unwrap(),
        f.config.commitment().unwrap()
    );
}

#[test]
fn native_replay_rejects_account_authorization() {
    let mut f = Fixture::new();
    let signed = f.signed(3, vec![f.getter()]);
    let native: TempoTxEnvelope = signed.clone().into();
    assert!(!supports_storage_action_replay(&native));
    let primitive =
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
    let mut ordinary_tx = signed.tx().clone();
    ordinary_tx.calls[0].to = TxKind::Call(PATH_USD_ADDRESS);
    let ordinary: TempoTxEnvelope = ordinary_tx.clone().into_signed(primitive.clone()).into();
    assert!(supports_storage_action_replay(&ordinary));
    let mut rejected = vec![native];
    for target in [ACCOUNT_KEYCHAIN_ADDRESS, NATIVE_MULTISIG_ADDRESS] {
        for index in 0..2 {
            let mut tx = ordinary_tx.clone();
            tx.calls.push(tx.calls[0].clone());
            tx.calls[index].to = TxKind::Call(target);
            let envelope = tx.into_signed(primitive.clone()).into();
            assert!(!supports_storage_action_replay(&envelope));
            rejected.push(envelope);
        }
    }
    let mut tx = ordinary_tx;
    tx.key_authorization = Some(SignedKeyAuthorization::new(
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::repeat_byte(2)),
        signed.signature().as_multisig().unwrap().clone(),
    ));
    assert!(!supports_storage_action_replay(
        &tx.clone().into_signed(primitive.clone()).into()
    ));
    // Even a primitive-signed primitive grant reads parent metadata at T12.
    tx.key_authorization.as_mut().unwrap().signature =
        AccountSignature::try_from(primitive.clone()).unwrap();
    assert!(!supports_storage_action_replay(
        &tx.into_signed(primitive).into()
    ));
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&signed, f.account))
        .unwrap();
    let config = TempoEvmConfig::new(MODERATO.clone());
    let block = TempoBlock::default().seal_slow();
    let mut db = State::builder().with_bundle_update().build();
    let mut executor = config.executor_for_block(&mut db, &block).unwrap();
    for envelope in rejected {
        let recovered = Recovered::new_unchecked(envelope, f.account);
        let error = executor
            .execute_transaction_with_actions(
                &recovered,
                StorageActionReplay {
                    result: output.result.clone(),
                    actions: vec![],
                    expiring_nonce: None,
                    validator_fee: U256::ZERO,
                },
                |_| panic!("unsupported replay must not commit"),
                false,
            )
            .unwrap_err();
        assert_eq!(
            StorageActionReplayError::from_block_execution_error(&error),
            Some(StorageActionReplayError::UnsupportedAuthorization)
        );
    }
}

#[test]
fn native_grant_recipient_code_change_rejects_stale_replay() {
    let mut f = Fixture::with_parent(false);
    f.evm = f.evm.with_actions();
    let recipient = Address::repeat_byte(0x22);
    let grant = KeyAuthorization::unrestricted(1, SignatureType::Multisig, recipient);
    let approval = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
    let tx = TempoTransaction {
        chain_id: 1,
        nonce: 3,
        gas_limit: 1_000_000,
        calls: vec![f.getter()],
        key_authorization: Some(grant.into_signed(approval)),
        ..Default::default()
    };
    let signature = f.owner.sign_hash_sync(&tx.signature_hash()).unwrap();
    let signed = tx.into_signed(signature.into());
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&signed, f.account))
        .unwrap();
    assert!(output.result.is_success());
    let actions = f.evm.take_actions().unwrap();
    assert!(
        !actions.is_empty(),
        "the precomputed grant must have real recorded writes"
    );

    // The precomputed result is not committed. Only its separate recipient gains code.
    let mut account = Account::from(AccountInfo {
        code_hash: keccak256([0x00]),
        code: Some(Bytecode::new_raw(vec![0x00].into())),
        ..Default::default()
    });
    account.mark_touch();
    f.evm
        .db_mut()
        .commit([(recipient, account)].into_iter().collect());
    assert!(
        f.evm
            .transact(TempoTxEnv::from_recovered_tx(&signed, f.account))
            .is_err(),
        "ordinary execution must reject the now-ineligible grant recipient"
    );

    let config = TempoEvmConfig::new(MODERATO.clone());
    let block = TempoBlock::default().seal_slow();
    let mut executor = config.executor_for_block(f.evm.db_mut(), &block).unwrap();
    let recovered = Recovered::new_unchecked(TempoTxEnvelope::AA(signed), f.account);
    let error = executor
        .execute_transaction_with_actions(
            &recovered,
            StorageActionReplay {
                result: output.result,
                actions,
                expiring_nonce: None,
                validator_fee: U256::ZERO,
            },
            |_| panic!("stale grant replay must not commit"),
            false,
        )
        .unwrap_err();
    assert_eq!(
        StorageActionReplayError::from_block_execution_error(&error),
        Some(StorageActionReplayError::UnsupportedAuthorization)
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantOutcome {
    Success,
    RevertAndRetry,
    ScopeRejectionAndRetry,
}

#[test]
fn native_signed_parent_delegate_combinations() {
    native_signed_parent_delegate_case(GrantOutcome::Success, 0);
}

#[test]
fn native_signed_parent_delegate_revert_and_retry() {
    native_signed_parent_delegate_case(GrantOutcome::RevertAndRetry, 0);
}

#[test]
fn native_signed_parent_delegate_scope_rejection_and_retry() {
    native_signed_parent_delegate_case(GrantOutcome::ScopeRejectionAndRetry, 0);
}

#[test]
fn native_signed_parent_delegate_revert_preserves_fees() {
    native_signed_parent_delegate_case(GrantOutcome::RevertAndRetry, 1_000_000_000_000);
}

#[test]
fn native_signed_parent_delegate_scope_rejection_preserves_fees() {
    native_signed_parent_delegate_case(GrantOutcome::ScopeRejectionAndRetry, 1_000_000_000_000);
}

fn native_signed_parent_delegate_case(outcome: GrantOutcome, gas_price: u128) {
    for parent_native in [false, true] {
        for delegate_native in [false, true] {
            let mut f = Fixture::with_parent(parent_native);
            let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap();
            let config = MultisigConfig {
                salt: B256::repeat_byte(2),
                version: 0,
                threshold: 1,
                owners: vec![MultisigOwner {
                    owner: signer.address(),
                    weight: 1,
                }],
            };
            let delegate = if delegate_native {
                config.derive_account(Address::repeat_byte(0x71)).unwrap()
            } else {
                signer.address()
            };
            let parent = f.account;
            // One microdollar per gas in fee cases; fund all three executions up front.
            let fee_budget = if gas_price == 0 { 0 } else { 50_000_000 };
            let initial_balance = 1000 + fee_budget;
            let initial_limit = 100 + fee_budget;
            let reverter = Address::repeat_byte(0x55);
            let revert = f.install_contract(reverter, bytes!("60006000fd").to_vec());
            StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
                TIP20Setup::path_usd(f.owner.address())
                    .with_issuer(f.owner.address())
                    .with_mint(parent, U256::from(initial_balance))
                    .apply()
            })
            .unwrap();
            let state = f.evm.ctx_mut().journaled_state.finalize();
            f.evm.db_mut().commit(state);
            let mut targets = vec![NATIVE_MULTISIG_ADDRESS, PATH_USD_ADDRESS];
            if outcome != GrantOutcome::ScopeRejectionAndRetry {
                targets.push(reverter);
            }
            let authorization = KeyAuthorization::unrestricted(
                1,
                if delegate_native {
                    SignatureType::Multisig
                } else {
                    SignatureType::Secp256k1
                },
                delegate,
            )
            .with_expiry(1000)
            .with_limits(vec![TokenLimit {
                token: PATH_USD_ADDRESS,
                limit: U256::from(initial_limit),
                period: 0,
            }])
            .with_allowed_calls(
                targets
                    .iter()
                    .map(|&target| CallScope {
                        target,
                        selector_rules: vec![],
                    })
                    .collect(),
            );
            let grant_signature = if parent_native {
                AccountSignature::Multisig(
                    MultisigSignature::try_new(
                        f.account,
                        f.config.clone(),
                        vec![PrimitiveSignature::Secp256k1(
                            f.owner
                                .sign_hash_sync(&multisig_digest(
                                    authorization.signature_hash(),
                                    f.account,
                                    0,
                                ))
                                .unwrap(),
                        )],
                    )
                    .unwrap(),
                )
            } else {
                AccountSignature::Primitive(PrimitiveSignature::Secp256k1(
                    f.owner
                        .sign_hash_sync(&authorization.signature_hash())
                        .unwrap(),
                ))
            };
            let transfer = Call {
                to: TxKind::Call(PATH_USD_ADDRESS),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: Address::repeat_byte(0x66),
                    amount: U256::from(10),
                }
                .abi_encode()
                .into(),
            };
            let mut tx = TempoTransaction {
                chain_id: 1,
                nonce: 3,
                gas_limit: 5_000_000,
                max_fee_per_gas: gas_price,
                max_priority_fee_per_gas: gas_price,
                calls: if outcome == GrantOutcome::Success {
                    vec![f.getter()]
                } else {
                    vec![transfer.clone(), revert]
                },
                key_authorization: Some(SignedKeyAuthorization::new(
                    authorization,
                    grant_signature,
                )),
                ..Default::default()
            };
            let sign = |tx: &TempoTransaction| {
                let digest = KeychainSignature::signing_hash(tx.signature_hash(), parent);
                let signature = if delegate_native {
                    AccountSignature::Multisig(
                        MultisigSignature::try_new(
                            delegate,
                            config.clone(),
                            vec![PrimitiveSignature::Secp256k1(
                                signer
                                    .sign_hash_sync(&multisig_digest(digest, delegate, 0))
                                    .unwrap(),
                            )],
                        )
                        .unwrap(),
                    )
                } else {
                    AccountSignature::Primitive(PrimitiveSignature::Secp256k1(
                        signer.sign_hash_sync(&digest).unwrap(),
                    ))
                };
                tx.clone()
                    .into_signed(TempoSignature::Keychain(KeychainSignature::new(
                        parent, signature,
                    )))
            };
            let signed = sign(&tx);
            assert!(!supports_storage_action_replay(&signed.clone().into()));
            let output = f
                .evm
                .transact(TempoTxEnv::from_recovered_tx(&signed, parent))
                .unwrap();
            assert_eq!(
                output.result.is_success(),
                outcome == GrantOutcome::Success,
                "{outcome:?}, parent={parent_native} delegate={delegate_native}: {:?}",
                output.result
            );
            let charged_fee = |gas_used| {
                let fee = calc_gas_balance_spending(gas_used, gas_price).to::<u64>();
                if gas_price != 0 {
                    assert!(fee > 0 && fee < tx.gas_limit, "unused gas must be refunded");
                }
                fee
            };
            let mut total_fees = charged_fee(output.result.tx_gas_used());
            if outcome != GrantOutcome::Success {
                let ExecutionResult::Revert { output, .. } = &output.result else {
                    panic!("expected included revert, got {:?}", output.result);
                };
                let expected = if outcome == GrantOutcome::ScopeRejectionAndRetry {
                    IAccountKeychain::CallNotAllowed {}.abi_encode()
                } else {
                    vec![]
                };
                assert_eq!(output.as_ref(), expected.as_slice());
            }
            for (account, expected) in [
                (
                    f.account,
                    if parent_native {
                        f.config.commitment().unwrap()
                    } else {
                        B256::ZERO
                    },
                ),
                (
                    delegate,
                    if delegate_native {
                        config.commitment().unwrap()
                    } else {
                        B256::ZERO
                    },
                ),
            ] {
                let commitment = output
                    .state
                    .get(&account)
                    .map(|account| decode_config_commitment(&account.info.extension, true).unwrap())
                    .unwrap_or_default();
                assert_eq!(commitment, expected);
            }
            f.evm.db_mut().commit(output.state);
            let assert_grant = |f: &mut Fixture, fees: u64, transferred: u64, nonce: u64| {
                let (key, limit, scopes, balance, recipient_balance) =
                    StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
                        let keychain = AccountKeychain::new();
                        Ok::<_, TempoPrecompileError>((
                            keychain.get_key(IAccountKeychain::getKeyCall {
                                account: parent,
                                keyId: delegate,
                            })?,
                            keychain.get_remaining_limit(
                                IAccountKeychain::getRemainingLimitCall {
                                    account: parent,
                                    keyId: delegate,
                                    token: PATH_USD_ADDRESS,
                                },
                            )?,
                            keychain.get_allowed_calls(IAccountKeychain::getAllowedCallsCall {
                                account: parent,
                                keyId: delegate,
                            })?,
                            TIP20Token::from_address(PATH_USD_ADDRESS)?
                                .balance_of(ITIP20::balanceOfCall { account: parent })?,
                            TIP20Token::from_address(PATH_USD_ADDRESS)?.balance_of(
                                ITIP20::balanceOfCall {
                                    account: Address::repeat_byte(0x66),
                                },
                            )?,
                        ))
                    })
                    .unwrap();
                assert_eq!(key.keyId, delegate);
                assert_eq!(key.expiry, 1000);
                assert!(key.enforceLimits && !key.isRevoked);
                assert_eq!(key.signatureType as u8, if delegate_native { 3 } else { 0 });
                assert_eq!(limit, U256::from(initial_limit - fees - transferred));
                assert_eq!(balance, U256::from(initial_balance - fees - transferred));
                assert_eq!(recipient_balance, U256::from(transferred));
                assert!(scopes.isScoped);
                assert_eq!(scopes.scopes.len(), targets.len());
                for scope in scopes.scopes {
                    assert!(targets.contains(&scope.target));
                    assert!(scope.selectorRules.is_empty());
                }
                f.evm.ctx_mut().journaled_state.finalize();
                assert_eq!(f.evm.db_mut().basic(parent).unwrap().unwrap().nonce, nonce);
            };
            // Calls roll back, but the grant, actual fees and transaction nonce survive.
            assert_grant(&mut f, total_fees, 0, 4);
            if outcome == GrantOutcome::Success {
                continue;
            }
            let accepted_grant = tx.key_authorization.take();
            tx.calls = vec![transfer];
            // Re-sign without the immutable grant. Two uses prove counters do not reset.
            for (nonce, transferred) in [(4, 10), (5, 20)] {
                tx.nonce = nonce;
                let output = f
                    .evm
                    .transact(TempoTxEnv::from_recovered_tx(&sign(&tx), parent))
                    .unwrap();
                assert!(output.result.is_success(), "{:?}", output.result);
                total_fees += charged_fee(output.result.tx_gas_used());
                f.evm.db_mut().commit(output.state);
                assert_grant(&mut f, total_fees, transferred, nonce + 1);
                assert_eq!(
                    f.commitment(),
                    if parent_native {
                        f.config.commitment().unwrap()
                    } else {
                        B256::ZERO
                    }
                );
                let delegate_info = f.evm.db_mut().basic(delegate).unwrap().unwrap_or_default();
                assert_eq!(
                    decode_config_commitment(&delegate_info.extension, true).unwrap(),
                    if delegate_native {
                        config.commitment().unwrap()
                    } else {
                        B256::ZERO
                    },
                );
            }
            tx.nonce = 6;
            tx.key_authorization = accepted_grant;
            let error = f
                .evm
                .transact(TempoTxEnv::from_recovered_tx(&sign(&tx), parent))
                .unwrap_err();
            let EVMError::Transaction(TempoInvalidTransaction::KeychainPrecompileError { reason }) =
                error
            else {
                panic!("expected duplicate-grant validation error, got {error}");
            };
            assert_eq!(
                reason,
                TempoPrecompileError::from(AccountKeychainError::key_already_exists()).to_string()
            );
        }
    }
}

#[test]
fn native_first_registration_preserves_existing_storage() {
    let mut f = Fixture::new();
    let info = f.evm.db_mut().basic(f.account).unwrap().unwrap();
    let slot = U256::from(7);
    let value = U256::from(91);
    f.evm.db_mut().insert_account_with_storage(
        f.account,
        info.clone(),
        [(slot, value)].into_iter().collect(),
    );
    let tx = f.signed(3, vec![f.getter()]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert!(output.result.logs().is_empty());
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    assert_eq!(f.evm.db_mut().storage(f.account, slot).unwrap(), value);
    let after = f.evm.db_mut().basic(f.account).unwrap().unwrap();
    assert_eq!(after.balance, info.balance);
    assert_eq!(after.nonce, info.nonce + 1);
}

#[test]
fn native_registration_survives_caught_reverting_subcall() {
    let mut f = Fixture::new();
    let reverter = Address::repeat_byte(0x55);
    // The child writes slot zero, then reverts. Its parent catches the failed CALL.
    f.install_contract(reverter, bytes!("600160005560006000fd").to_vec());
    let catcher = Address::repeat_byte(0x56);
    let mut code = bytes!("6000600060006000600073").to_vec();
    code.extend_from_slice(reverter.as_slice());
    // GAS CALL ISZERO; persist the caught failure in the parent's slot zero.
    code.extend_from_slice(&bytes!("5af11560005500"));
    let call = f.install_contract(catcher, code);
    let tx = f.signed(3, vec![call]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert!(output.result.logs().is_empty());
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    assert_eq!(
        f.evm.db_mut().storage(reverter, U256::ZERO).unwrap(),
        U256::ZERO
    );
    assert_eq!(
        f.evm.db_mut().storage(catcher, U256::ZERO).unwrap(),
        U256::ONE
    );
}

#[test]
fn native_first_transaction_can_rotate_configuration() {
    let mut f = Fixture::new();
    let next = MultisigConfig {
        version: 1,
        ..f.config.clone()
    };
    let tx = f.signed(3, vec![Fixture::rotation(&f.config, &next), f.getter()]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(output.result.logs().len(), 1);
    assert_eq!(
        INativeMultisig::getConfigCommitmentCall::abi_decode_returns(
            output.result.output().unwrap()
        )
        .unwrap(),
        next.commitment().unwrap()
    );
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), next.commitment().unwrap());
}

#[test]
fn native_rotation_authorizes_next_transaction_in_same_block() {
    let mut f = Fixture::new();
    let block = f.evm.ctx_mut().block.clone();
    let next_owner = PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap();
    let next = MultisigConfig {
        version: 1,
        owners: vec![MultisigOwner {
            owner: next_owner.address(),
            weight: 1,
        }],
        ..f.config.clone()
    };
    let rotate = f.signed(3, vec![Fixture::rotation(&f.config, &next)]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&rotate, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    f.evm.db_mut().commit(output.state);
    let stale = f.signed(4, vec![f.getter()]);
    let error = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&stale, f.account))
        .unwrap_err();
    assert!(error.to_string().contains("commitment mismatch"), "{error}");
    f.config = next;
    f.owner = next_owner;
    let tx = f.signed(4, vec![f.getter()]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    assert_eq!(f.evm.ctx_mut().block.number, block.number);
    assert_eq!(f.evm.ctx_mut().block.timestamp, block.timestamp);
}

#[test]
fn native_batch_rotation_writes_and_events_revert_together() {
    native_batch_rotation_failure(true, false);
}

#[test]
fn native_batch_rotation_writes_and_events_halt_together() {
    native_batch_rotation_failure(true, true);
}

#[test]
fn native_first_rotation_revert_preserves_registration() {
    native_batch_rotation_failure(false, false);
}

#[test]
fn native_first_rotation_halt_preserves_registration() {
    native_batch_rotation_failure(false, true);
}

fn native_batch_rotation_failure(registered: bool, halt: bool) {
    let mut f = Fixture::new();
    let mut nonce = 3;
    if registered {
        let register = f.signed(nonce, vec![f.getter()]);
        let output = f
            .evm
            .transact(TempoTxEnv::from_recovered_tx(&register, f.account))
            .unwrap();
        assert!(output.result.is_success());
        f.evm.db_mut().commit(output.state);
        nonce += 1;
    }
    let v1 = MultisigConfig {
        version: 1,
        owners: vec![MultisigOwner {
            owner: PrivateKeySigner::from_bytes(&B256::repeat_byte(2))
                .unwrap()
                .address(),
            weight: 1,
        }],
        ..f.config.clone()
    };
    let v2 = MultisigConfig {
        version: 2,
        owners: vec![MultisigOwner {
            owner: PrivateKeySigner::from_bytes(&B256::repeat_byte(3))
                .unwrap()
                .address(),
            weight: 1,
        }],
        ..f.config.clone()
    };
    let revert = f.install_contract(
        Address::repeat_byte(0x55),
        if halt {
            bytes!("fe").to_vec()
        } else {
            bytes!("60006000fd").to_vec()
        },
    );
    let rotations = vec![
        Fixture::rotation(&f.config, &v1),
        Fixture::rotation(&v1, &v2),
    ];
    let mut calls = rotations.clone();
    calls.push(revert);
    let tx = f.signed(nonce, calls);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert_eq!(output.result.is_halt(), halt);
    assert_eq!(
        matches!(&output.result, ExecutionResult::Revert { .. }),
        !halt
    );
    assert!(output.result.logs().is_empty());
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    nonce += 1;
    assert_eq!(
        f.evm.db_mut().basic(f.account).unwrap().unwrap().nonce,
        nonce
    );
    // The original witness remains valid. Each successful update must read the
    // previous call's journaled commitment, not the transaction-start leaf.
    let retry = f.signed(nonce, rotations);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&retry, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(output.result.logs().len(), 2);
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), v2.commitment().unwrap());
}
