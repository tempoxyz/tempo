use super::*;
use crate::{
    AA2dPool, TempoTransactionPool, maintain::maintain_tempo_pool_with_events,
    ordering::TempoTipOrdering,
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use reth_primitives_traits::{AccountExtension, Recovered, RecoveredBlock};
use reth_provider::{CanonStateNotification, Chain};
use reth_transaction_pool::{
    CanonicalStateUpdate, Pool, PoolConfig, PoolUpdateKind, TransactionPool, TransactionPoolExt,
    TransactionValidationTaskExecutor, validate::ValidationTask,
};
use std::time::Duration;
use tempo_primitives::{
    account::encode_config_commitment,
    transaction::{MultisigConfig, MultisigOwner, MultisigSignature, multisig_digest},
};
use tempo_revm::gas_params::tempo_gas_params;

const FACTORY: Address = Address::repeat_byte(0x71);

#[tokio::test]
async fn reorg_revalidates_native_transaction_after_reth_head_update() {
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
    let transaction = TempoPooledTransaction::new(Recovered::new_unchecked(
        TempoTxEnvelope::AA(AASigned::new_unhashed(
            tx,
            TempoSignature::Multisig(signature),
        )),
        account,
    ));

    let validator = setup_validator(&transaction, 1).with_disable_fee_amm_check(true);
    let provider = validator.client().clone();
    provider.add_account(
        account,
        ExtendedAccount::new(0, U256::ZERO).with_extension(AccountExtension::copy_from_slice(
            &encode_config_commitment(config.commitment().unwrap()),
        )),
    );
    let mut block = create_mock_block(1).clone_block();
    block.header.inner.number = 1;
    let sealed = SealedBlock::seal_slow(block.clone());
    provider.add_block(sealed.hash(), block.clone());
    validator.on_new_head_block(&sealed);

    let (sender, validation_task) = ValidationTask::with_capacity(1);
    let validation = TransactionValidationTaskExecutor {
        validator: Arc::new(validator),
        to_validation_task: Arc::new(sender),
    };
    let service = tokio::spawn(validation_task.run());
    let pool = TempoTransactionPool::new(
        Pool::new(
            validation.clone(),
            TempoTipOrdering::default(),
            InMemoryBlobStore::default(),
            PoolConfig::default(),
        ),
        AA2dPool::new(Default::default()),
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
    pool.add_transaction(TransactionOrigin::External, transaction)
        .await
        .unwrap();
    assert!(pool.contains(&hash));

    let chain = |block| {
        Arc::new(Chain::new(
            vec![RecoveredBlock::new_unhashed(block, vec![])],
            Default::default(),
            Default::default(),
        ))
    };
    let mut old = block.clone();
    old.header.inner.extra_data = Bytes::from_static(b"orphan");
    maintain_tempo_pool_with_events(
        pool.clone(),
        futures::stream::iter([CanonStateNotification::Reorg {
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
    tokio::time::timeout(Duration::from_secs(2), async {
        while !pool.contains(&hash) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("native transaction should be revalidated and restored");
    service.abort();
}
