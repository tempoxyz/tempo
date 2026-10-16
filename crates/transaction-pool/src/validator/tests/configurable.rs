use super::*;
use crate::{
    AA2dPool, TempoTransactionPool, maintain::maintain_tempo_pool_with_events,
    ordering::TempoTipOrdering,
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use futures::stream;
use reth_primitives_traits::Block as _;
use reth_provider::{CanonStateNotification, Chain, ExecutionOutcome};
use reth_transaction_pool::{
    CanonicalStateUpdate, Pool, PoolConfig, PoolUpdateKind, TransactionPool, TransactionPoolExt,
    TransactionValidationTaskExecutor, error::PoolErrorKind, validate::ValidationTask,
};
use revm::{
    database::{AccountStatus, BundleAccount, BundleState},
    state::AccountInfo,
};
use std::time::Duration;
use tempo_primitives::{
    account::encode_config_commitment,
    transaction::{
        MultisigConfig, MultisigOwner, MultisigSignature, TempoSignature, multisig_digest,
    },
};
use tempo_revm::{gas_params::tempo_gas_params, native_multisig::NativeMultisigError};
use tokio::{
    spawn,
    time::{sleep, timeout},
};

const FACTORY: Address = Address::repeat_byte(0x71);

#[tokio::test]
async fn reorg_and_rotation_revalidate_native_transaction() {
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
    let tx = TxBuilder::aa(account)
        .build()
        .inner()
        .as_aa()
        .unwrap()
        .tx()
        .clone();
    let approval = owner
        .sign_hash_sync(&multisig_digest(tx.signature_hash(), account, 0))
        .unwrap();
    let signature = MultisigSignature::try_new(
        account,
        config.clone(),
        vec![PrimitiveSignature::Secp256k1(approval)],
    )
    .unwrap();
    let transaction = TempoPooledTransaction::new(
        TempoTxEnvelope::AA(tx.into_signed(TempoSignature::Multisig(signature)))
            .with_signer(account),
    );

    let validator = setup_validator(&transaction, 1).with_disable_fee_amm_check(true);
    let provider = validator.client().clone();
    let commitment = encode_config_commitment(config.commitment().unwrap());
    provider.add_account(
        account,
        ExtendedAccount::new(0, U256::ZERO)
            .with_extension(AccountExtension::copy_from_slice(&commitment)),
    );
    let mut block = create_mock_block(1).clone_block();
    block.header.inner.number = 1;
    let sealed = block.clone().seal_slow();
    provider.add_block(sealed.hash(), block.clone());
    validator.on_new_head_block(&sealed);

    let (sender, validation_task) = ValidationTask::new();
    let validation = TransactionValidationTaskExecutor {
        validator: Arc::new(validator),
        to_validation_task: Arc::new(sender),
    };
    let service = spawn(validation_task.run());
    let pool = TempoTransactionPool::new(
        Pool::new(
            validation.clone(),
            TempoTipOrdering::default(),
            InMemoryBlobStore::default(),
            PoolConfig::default(),
        ),
        AA2dPool::default(),
    );
    let restore_t14 = || {
        let validator = validation.validator();
        validator
            .active_hardfork
            .store(TempoHardfork::T14.variant_index(), Ordering::Relaxed);
        let mut env = validator.cached_evm_env.write();
        env.cfg_env = env
            .cfg_env
            .clone()
            .with_spec_and_gas_params(TempoHardfork::T14, tempo_gas_params(TempoHardfork::T14));
        env.block_env.multisig_recovery_factory = Some(FACTORY);
    };
    restore_t14();
    let hash = *transaction.hash();
    pool.add_external_transaction(transaction.clone())
        .await
        .unwrap();
    assert!(pool.contains(&hash));

    let chain = |block: Block| {
        Arc::new(Chain::new(
            vec![block.into_recovered_with_signers(vec![])],
            Default::default(),
            Default::default(),
        ))
    };
    let mut old = block.clone();
    old.header.inner.extra_data = Bytes::from_static(b"orphan");
    maintain_tempo_pool_with_events(
        pool.clone(),
        stream::iter([CanonStateNotification::Reorg {
            old: chain(old),
            new: chain(block),
        }]),
    )
    .await;
    assert!(
        !pool.contains(&hash),
        "the old authorization must be withheld"
    );

    // The independent Reth callback unblocks revalidation at the new head.
    pool.on_canonical_state_change(CanonicalStateUpdate {
        new_tip: &sealed,
        pending_block_base_fee: TEMPO_T0_BASE_FEE,
        pending_block_blob_fee: None,
        changed_accounts: vec![],
        mined_transactions: vec![],
        update_kind: PoolUpdateKind::Reorg,
    });
    restore_t14();
    timeout(Duration::from_secs(2), async {
        while !pool.contains(&hash) {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("native transaction should be revalidated and restored");

    let mut rotated_config = config.clone();
    rotated_config.version += 1;
    let new_commitment = encode_config_commitment(rotated_config.commitment().unwrap());
    let old_info = AccountInfo::default().with_extension(commitment);
    let new_info = AccountInfo::default().with_extension(new_commitment.clone());
    provider.add_account(
        account,
        ExtendedAccount::new(0, U256::ZERO)
            .with_extension(AccountExtension::copy_from_slice(&new_commitment)),
    );
    let mut rotated_block = create_mock_block(2).clone_block();
    rotated_block.header.inner.number = 2;
    let sealed_rotated = rotated_block.clone().seal_slow();
    provider.add_block(sealed_rotated.hash(), rotated_block.clone());
    let rotation = Arc::new(Chain::new(
        vec![rotated_block.into_recovered_with_signers(vec![])],
        ExecutionOutcome {
            bundle: BundleState {
                state: std::iter::once((
                    account,
                    BundleAccount::new(
                        Some(old_info),
                        Some(new_info),
                        Default::default(),
                        AccountStatus::Changed,
                    ),
                ))
                .collect(),
                ..Default::default()
            },
            ..Default::default()
        },
        Default::default(),
    ));
    maintain_tempo_pool_with_events(
        pool.clone(),
        stream::iter([CanonStateNotification::Commit { new: rotation }]),
    )
    .await;
    assert!(
        !pool.contains(&hash),
        "rotation must withhold the old signature"
    );

    pool.on_canonical_state_change(CanonicalStateUpdate {
        new_tip: &sealed_rotated,
        pending_block_base_fee: TEMPO_T0_BASE_FEE,
        pending_block_blob_fee: None,
        changed_accounts: vec![],
        mined_transactions: vec![],
        update_kind: PoolUpdateKind::Commit,
    });
    restore_t14();
    let rejection = pool
        .add_external_transaction(transaction)
        .await
        .unwrap_err();
    assert!(
        matches!(
            &rejection.kind,
            PoolErrorKind::InvalidTransaction(error)
                if matches!(
                    error.downcast_other_ref::<TempoPoolTransactionError>(),
                    Some(TempoPoolTransactionError::Evm(
                        TempoInvalidTransaction::NativeMultisig(
                            NativeMultisigError::ConfigurationCommitmentMismatch { .. }
                        )
                    ))
                )
        ),
        "unexpected rejection after rotation: {rejection:?}"
    );
    assert!(
        !pool.contains(&hash),
        "the stale transaction must stay out of the pool"
    );
    service.abort();
}
