use super::*;
use crate::tempo_transaction::helpers::{create_expiring_nonce_tx, sign_fee_payer};
use alloy::{
    consensus::{BlockHeader, SignableTransaction, TxEip1559, TxLegacy},
    sol_types::{SolError, SolEvent},
};
use alloy_eips::{BlockNumberOrTag, eip7702::Authorization};
use eyre::OptionExt;
use futures::{FutureExt, StreamExt};
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use reth_e2e_test_utils::{node::Finality, wait::WAIT_TIMEOUT};
use reth_ethereum::pool::{TransactionEvent, TransactionPool};
use reth_node_builder::BuiltPayload;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_primitives::transaction::{
    KeyAuthorization, KeychainSignature, PrimitiveSignature, SignedKeyAuthorization,
    TempoSignedAuthorization,
};
use tokio::time::timeout;

/// What a pending transaction needs from the root key of an account that migrates.
#[derive(Clone, Copy, Debug)]
enum RootRole {
    LegacySender,
    Eip1559Sender,
    ProtocolLaneSender,
    TwoDimensionalLaneSender,
    ExpiringNonceSender,
    FeePayer,
    AccessKey,
    GrantSigner,
}

impl RootRole {
    const ALL: [Self; 8] = [
        Self::LegacySender,
        Self::Eip1559Sender,
        Self::ProtocolLaneSender,
        Self::TwoDimensionalLaneSender,
        Self::ExpiringNonceSender,
        Self::FeePayer,
        Self::AccessKey,
        Self::GrantSigner,
    ];

    /// A transaction that is valid until the migration of `account`, whose root key is `root`,
    /// commits and depends on that key in this role. `other` is a second key: the key of a
    /// bystander account for the fee payer and access key roles, and a fresh access key of
    /// `account` for the grant signer role.
    fn pending_transaction(
        self,
        chain_id: u64,
        root: &PrivateKeySigner,
        account: &ConfigurableAccount,
        other: &PrivateKeySigner,
        valid_before: u64,
    ) -> eyre::Result<TempoTxEnvelope> {
        let target = noop().to;
        // The migration takes the account's next nonce, so a protocol lane sender uses the one
        // after it.
        let queued = account.nonce + 1;
        Ok(match self {
            Self::LegacySender => legacy_signed(chain_id, queued, root)?,
            Self::Eip1559Sender => {
                let tx = TxEip1559 {
                    chain_id,
                    nonce: queued,
                    gas_limit: 200_000,
                    max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
                    max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
                    to: target,
                    ..Default::default()
                };
                let signature = root.sign_hash_sync(&tx.signature_hash())?;
                TempoTxEnvelope::Eip1559(tx.into_signed(signature))
            }
            Self::ProtocolLaneSender => root_signed(
                create_basic_aa_tx(chain_id, queued, vec![noop()], GAS_LIMIT),
                root,
            )?,
            Self::TwoDimensionalLaneSender => {
                let mut tx = create_basic_aa_tx(chain_id, 0, vec![noop()], GAS_LIMIT);
                tx.nonce_key = U256::ONE;
                root_signed(tx, root)?
            }
            Self::ExpiringNonceSender => root_signed(
                create_expiring_nonce_tx(chain_id, valid_before, Address::repeat_byte(0x73)),
                root,
            )?,
            // A bystander sends and `root` sponsors, so only the fee payer depends on it.
            Self::FeePayer => {
                let mut tx = create_basic_aa_tx(chain_id, 0, vec![noop()], GAS_LIMIT);
                sign_fee_payer(&mut tx, other.address(), root)?;
                root_signed(tx, other)?
            }
            // A bystander account grants `root` as its access key, and `root` signs for it.
            Self::AccessKey => {
                let mut tx = create_basic_aa_tx(chain_id, 0, vec![noop()], GAS_LIMIT);
                tx.key_authorization = Some(grant_signed(chain_id, root.address(), other)?);
                key_signed(tx, other.address(), root)?
            }
            // The account signs a grant of its fresh access key `other`, which sends the
            // transaction, so only the grant depends on `root`.
            Self::GrantSigner => {
                let mut tx = create_basic_aa_tx(chain_id, 0, vec![noop()], GAS_LIMIT);
                tx.nonce_key = U256::ONE;
                tx.key_authorization = Some(grant_signed(chain_id, other.address(), root)?);
                key_signed(tx, account.address, other)?
            }
        })
    }
}

/// Signs `tx` as the sender with the primitive root key of its account.
fn root_signed(tx: TempoTransaction, root: &PrivateKeySigner) -> eyre::Result<TempoTxEnvelope> {
    let signature = TempoSignature::from(root.sign_hash_sync(&tx.signature_hash())?);
    Ok(tx.into_signed(signature).into())
}

/// Signs `tx` for `account` with its access key `key`.
fn key_signed(
    tx: TempoTransaction,
    account: Address,
    key: &PrivateKeySigner,
) -> eyre::Result<TempoTxEnvelope> {
    let digest = KeychainSignature::signing_hash(tx.signature_hash(), account);
    let signature = PrimitiveSignature::Secp256k1(key.sign_hash_sync(&digest)?);
    let signature = TempoSignature::Keychain(KeychainSignature::new(account, signature));
    Ok(tx.into_signed(signature).into())
}

/// An unrestricted grant of `key` that the primitive key `signer` signs for its own account.
fn grant_signed(
    chain_id: u64,
    key: Address,
    signer: &PrivateKeySigner,
) -> eyre::Result<SignedKeyAuthorization> {
    let grant = KeyAuthorization::unrestricted(chain_id, SignatureType::Secp256k1, key);
    let signature = PrimitiveSignature::Secp256k1(signer.sign_hash_sync(&grant.signature_hash())?);
    Ok(grant.into_signed(signature))
}

/// A legacy transaction with `nonce` to the no-op target, signed by `signer`.
fn legacy_signed(
    chain_id: u64,
    nonce: u64,
    signer: &PrivateKeySigner,
) -> eyre::Result<TempoTxEnvelope> {
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 200_000,
        to: noop().to,
        value: U256::ZERO,
        input: Bytes::new(),
    };
    let signature = signer.sign_hash_sync(&tx.signature_hash())?;
    Ok(TempoTxEnvelope::Legacy(tx.into_signed(signature)))
}

/// The migration of `account` (nonce `account.nonce`), signed by its root key. It pays a higher
/// tip than the default, so the builder runs it before the other transactions.
fn migration(
    env: &Localnet,
    account: &ConfigurableAccount,
    root: &PrivateKeySigner,
) -> eyre::Result<TempoTxEnvelope> {
    let mut tx = account.transaction(env, vec![account.upgrade_call()]);
    tx.max_priority_fee_per_gas *= 2;
    tx.max_fee_per_gas *= 2;
    root_signed(tx, root)
}

/// Sends `txs` to the pool and returns their hashes, each checked to be pooled.
async fn pend(env: &Localnet, txs: &[&TempoTxEnvelope]) -> eyre::Result<Vec<B256>> {
    let provider = tempo_provider(env);
    let mut hashes = Vec::new();
    for tx in txs {
        let hash = *provider
            .send_raw_transaction(&tx.encoded_2718())
            .await?
            .tx_hash();
        assert!(
            env.setup.node.inner.pool.contains(&hash),
            "{hash} not pooled"
        );
        hashes.push(hash);
    }
    Ok(hashes)
}

/// Builds the next block and checks that it holds the successful migration `hash` of `account`.
async fn mine_migration(
    env: &mut Localnet,
    account: &ConfigurableAccount,
    hash: B256,
) -> eyre::Result<()> {
    env.setup.node.advance_block().await?;
    let receipt = tempo_provider(env)
        .get_transaction_receipt(hash)
        .await?
        .ok_or_eyre("migration not included")?;
    assert!(receipt.status(), "{receipt:?}");
    assert_eq!(
        commitment(env, account.address).await?,
        account.config.commitment().unwrap()
    );
    Ok(())
}

/// The hash of the latest block, the fork point of a later reorg.
async fn latest_block_hash(env: &Localnet) -> eyre::Result<B256> {
    Ok(env
        .provider()
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .ok_or_eyre("latest block missing")?
        .hash())
}

/// Pending transactions that depend on a root key leave the pool when their account's migration
/// commits, whether the key sends them or is their fee payer, access key or grant signer
/// (TIP-1112). Each variant migrates a fresh account. The builder skips the dependent
/// transaction, so only the pool's revalidation of the changed commitment removes it.
#[tokio::test(flavor = "multi_thread")]
async fn retired_root_pending_transactions_evicted() -> eyre::Result<()> {
    let mut env = environment().await?;
    let chain_id = env.chain_id();
    let provider = tempo_provider(&env);
    for (index, role) in RootRole::ALL.into_iter().enumerate() {
        let seed = 0x20 + 0x10 * index as u8;
        let root = signer(seed);
        let other = signer(seed + 4);
        let account = ConfigurableAccount::migrated(root.address(), seed + 1, 3);
        env.fund_account(account.address).await?;
        env.fund_account(other.address()).await?;
        let latest = provider
            .get_block_by_number(Default::default())
            .await?
            .ok_or_eyre("latest block missing")?;
        let valid_before =
            latest.header.timestamp() + env.setup.hardfork.expiring_nonce_max_expiry_secs();

        let pending = role.pending_transaction(chain_id, &root, &account, &other, valid_before)?;
        let migrate = migration(&env, &account, &root)?;
        let hashes = pend(&env, &[&pending, &migrate]).await?;
        mine_migration(&mut env, &account, hashes[1]).await?;

        assert!(
            provider.get_transaction_receipt(hashes[0]).await?.is_none(),
            "{role:?}: the transaction of the retired root key was included"
        );
        env.setup
            .node
            .wait_for_pool_removal([hashes[0]])
            .await
            .map_err(|error| eyre!("{role:?}: {error}"))?;
    }
    Ok(())
}

/// What stays valid after a migration commits: a bystander's transaction, a transaction that an
/// uncommitted access key of the migrated account signs (the migration leaves its grant valid),
/// and a transaction that carries an authorization list entry of the migrated account, which the
/// block skips (TIP-1112). All of them follow the migration in its block and succeed.
#[tokio::test(flavor = "multi_thread")]
async fn retired_root_leaves_unrelated_pending_transactions_valid() -> eyre::Result<()> {
    let mut env = environment().await?;
    let chain_id = env.chain_id();
    let provider = tempo_provider(&env);
    let root = signer(0x30);
    let key = signer(0x34);
    let bystanders = [0x40, 0x50].map(signer);
    let mut account = ConfigurableAccount::migrated(root.address(), 0x31, 3);
    for address in [
        account.address,
        bystanders[0].address(),
        bystanders[1].address(),
    ] {
        env.fund_account(address).await?;
    }

    // Before the migration the account grants `key`, which is not committed.
    let mut tx = account.transaction(&env, vec![noop()]);
    tx.key_authorization = Some(grant_signed(chain_id, key.address(), &root)?);
    let signature = TempoSignature::from(root.sign_hash_sync(&tx.signature_hash())?);
    account.submit(&mut env, tx, signature, true).await?;

    let migrate = migration(&env, &account, &root)?;
    // The entry has the nonce that the account has after the migration, so the block would
    // install the delegation if it did not skip the entry.
    let delegation = Authorization {
        chain_id: U256::from(chain_id),
        address: Address::repeat_byte(0x7d),
        nonce: account.nonce + 1,
    };
    let signature = root.sign_hash_sync(&delegation.signature_hash())?;
    let entry = TempoSignedAuthorization::new_unchecked(delegation, signature.into());
    let mut with_entry = create_basic_aa_tx(chain_id, 0, vec![noop()], GAS_LIMIT);
    with_entry.tempo_authorization_list = vec![entry];
    let with_entry = root_signed(with_entry, &bystanders[0])?;
    let bystander = root_signed(
        create_basic_aa_tx(chain_id, 0, vec![noop()], GAS_LIMIT),
        &bystanders[1],
    )?;
    let mut by_key = create_basic_aa_tx(chain_id, 0, vec![noop()], GAS_LIMIT);
    by_key.nonce_key = U256::ONE;
    let by_key = key_signed(by_key, account.address, &key)?;
    let hashes = pend(&env, &[&with_entry, &bystander, &by_key, &migrate]).await?;
    mine_migration(&mut env, &account, hashes[3]).await?;

    for (hash, what) in [
        (
            hashes[0],
            "transaction with the migrated account's authorization entry",
        ),
        (hashes[1], "bystander's transaction"),
        (hashes[2], "uncommitted access key's transaction"),
    ] {
        let receipt = provider
            .get_transaction_receipt(hash)
            .await?
            .ok_or_else(|| eyre!("{what} not included"))?;
        assert!(receipt.status(), "{what}: {receipt:?}");
    }
    // The entry was skipped: no delegation, only the migration's marker, and the nonce is the
    // migration's alone.
    assert_eq!(
        provider.get_code_at(account.address).await?,
        Bytes::from_static(&[0xef])
    );
    assert_eq!(
        provider.get_transaction_count(account.address).await?,
        account.nonce + 1
    );
    Ok(())
}

/// A migration that arrives with a reorg evicts the pending transactions of its account's root
/// key, as one that arrives with a canonical commit does, and a reorg that commits nothing evicts
/// nothing (TIP-1112). The reorg's changes are those of the new chain since the fork point.
/// Neither reorg removes, not even to revalidate it, a pending transaction that the migration
/// leaves valid.
#[tokio::test(flavor = "multi_thread")]
async fn retired_root_reorg_evicts_pending_transactions() -> eyre::Result<()> {
    let mut env = environment().await?;
    // Keep genesis finalized, so the blocks below can be reorged.
    env.setup.node.set_finality(Finality::Keep);
    let chain_id = env.chain_id();
    let root = signer(0x30);
    let key = signer(0x34);
    let bystander = signer(0x40);
    let sponsor = signer(0x41);
    let grantor = signer(0x42);
    let grantee = signer(0x43);
    let mut account = ConfigurableAccount::migrated(root.address(), 0x31, 3);
    for address in [
        account.address,
        bystander.address(),
        sponsor.address(),
        grantor.address(),
    ] {
        env.fund_account(address).await?;
    }
    // Before the migration the account grants `key`, and the migration leaves that grant valid.
    let mut tx = account.transaction(&env, vec![noop()]);
    tx.key_authorization = Some(grant_signed(chain_id, key.address(), &root)?);
    let signature = TempoSignature::from(root.sign_hash_sync(&tx.signature_hash())?);
    account.submit(&mut env, tx, signature, true).await?;
    let fork_point = latest_block_hash(&env).await?;

    // All transactions wait for a nonce that nothing has mined: the root key's and the access
    // key's behind the migration, the others behind a nonce that their sender never sends. The
    // migration leaves the others valid. The bystander's has a fee payer and carries an
    // authorization entry of the account, which a block skips for a retired account (TIP-1112).
    // The sponsor sends a legacy one, and the grantor's carries the grant of the access key that
    // signs it.
    let old_chain = env.setup.node.advance_block().await?;
    env.setup
        .node
        .wait_for_pool_head(old_chain.block().hash())
        .await?;
    let root_tx = root_signed(
        create_basic_aa_tx(chain_id, account.nonce + 1, vec![noop()], GAS_LIMIT),
        &root,
    )?;
    let delegation = Authorization {
        chain_id: U256::from(chain_id),
        address: Address::repeat_byte(0x7d),
        nonce: account.nonce + 1,
    };
    let signature = root.sign_hash_sync(&delegation.signature_hash())?;
    let mut bystander_tx = create_basic_aa_tx(chain_id, 1, vec![noop()], GAS_LIMIT);
    bystander_tx.tempo_authorization_list = vec![TempoSignedAuthorization::new_unchecked(
        delegation,
        signature.into(),
    )];
    sign_fee_payer(&mut bystander_tx, bystander.address(), &sponsor)?;
    let bystander_tx = root_signed(bystander_tx, &bystander)?;
    let legacy_tx = legacy_signed(chain_id, 1, &sponsor)?;
    let mut grantee_tx = create_basic_aa_tx(chain_id, 1, vec![noop()], GAS_LIMIT);
    grantee_tx.key_authorization = Some(grant_signed(chain_id, grantee.address(), &grantor)?);
    let grantee_tx = key_signed(grantee_tx, grantor.address(), &grantee)?;
    let key_tx = key_signed(
        create_basic_aa_tx(chain_id, account.nonce + 2, vec![noop()], GAS_LIMIT),
        account.address,
        &key,
    )?;
    let hashes = pend(
        &env,
        &[&root_tx, &bystander_tx, &legacy_tx, &grantee_tx, &key_tx],
    )
    .await?;
    // The pool reports every removal of these transactions to their listeners, also one that the
    // revalidation adds back.
    let bystanders = [
        (hashes[1], "the bystander's transaction"),
        (hashes[2], "the sponsor's legacy transaction"),
        (hashes[3], "the grantor's transaction"),
        (hashes[4], "the access key's transaction"),
    ];
    let pool = &env.setup.node.inner.pool;
    let listeners = bystanders
        .iter()
        .map(|(hash, what)| {
            pool.transaction_event_listener(*hash)
                .ok_or_else(|| eyre!("{what} is not pooled"))
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    // A reorg onto a block that commits nothing leaves all of them pooled.
    let node = &mut env.setup.node;
    let empty = node.advance_block_on(fork_point).await?;
    node.wait_for_pool_head(empty.block().hash()).await?;
    for hash in &hashes {
        assert!(
            node.inner.pool.contains(hash),
            "{hash} left the pool in a reorg that commits nothing"
        );
    }

    // A reorg onto a block that holds the migration retires the root key.
    let migrate = migration(&env, &account, &root)?;
    let migrate_hash = pend(&env, &[&migrate]).await?[0];
    let mut root_events = env
        .setup
        .node
        .inner
        .pool
        .transaction_event_listener(hashes[0])
        .ok_or_eyre("the root key's transaction is not pooled")?;
    let node = &mut env.setup.node;
    let new_chain = node.advance_block_on(fork_point).await?;
    node.wait_for_pool_head(new_chain.block().hash()).await?;
    assert_eq!(
        commitment(&env, account.address).await?,
        account.config.commitment().unwrap()
    );
    let provider = tempo_provider(&env);
    let receipt = provider
        .get_transaction_receipt(migrate_hash)
        .await?
        .ok_or_eyre("migration not included")?;
    assert_eq!(receipt.block_hash, Some(new_chain.block().hash()));
    assert!(receipt.status(), "{receipt:?}");
    assert!(provider.get_transaction_receipt(hashes[0]).await?.is_none());
    env.setup.node.wait_for_pool_removal([hashes[0]]).await?;
    // The pool reports the eviction and every other removal of its batch while it holds the lock
    // of its listeners, which subscribing takes. So once the eviction is reported, a check that
    // subscribes sees every removal of a bystander's transaction.
    let evicted = timeout(WAIT_TIMEOUT, async {
        while let Some(event) = root_events.next().await {
            if event.is_final() {
                return Some(event);
            }
        }
        None
    })
    .await?;
    assert_eq!(evicted, Some(TransactionEvent::Discarded));
    let pool = &env.setup.node.inner.pool;
    for ((hash, what), mut events) in bystanders.into_iter().zip(listeners) {
        assert!(
            pool.transaction_event_listener(hash).is_some(),
            "{what} left the pool"
        );
        while let Some(Some(event)) = events.next().now_or_never() {
            assert!(!event.is_final(), "{what} left the pool: {event:?}");
        }
    }
    Ok(())
}

/// Reads the revert data of a failed `eth_call` and requires it to be exactly `expected`.
fn assert_call_reverts(result: Result<Bytes, TransportError>, expected: Vec<u8>) {
    let error = result.expect_err("call must revert");
    let data = error
        .as_error_resp()
        .and_then(|payload| payload.as_revert_data());
    assert_eq!(data, Some(Bytes::from(expected)), "{error:?}");
}

/// An EOA migrates through the RPC, for a root of each signature type: simulations of the upgrade
/// write nothing and a contract cannot be upgraded, the root signs the upgrade, the retired root
/// can no longer send but the witness can, calls and estimates from the retired address stay
/// allowed, and the witness rotates the configuration (TIP-1112).
#[tokio::test(flavor = "multi_thread")]
async fn eoa_migration_rpc_lifecycle() -> eyre::Result<()> {
    let mut env = environment().await?;
    for (index, kind) in [
        SignatureType::Secp256k1,
        SignatureType::P256,
        SignatureType::WebAuthn,
    ]
    .into_iter()
    .enumerate()
    {
        let seed = 0x30 + 0x10 * index as u8;
        let root = OwnerKey::new(seed, kind);
        let mut account = ConfigurableAccount::migrated(root.address(), seed + 1, 3);
        env.fund_account(account.address).await?;
        assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
        let expected = account.config.commitment().unwrap();
        let call = account.upgrade_call();
        let request = call_request(account.address, call.input.clone());

        // A simulation returns the commitment and the gas, and writes nothing.
        assert_eq!(
            env.provider().call(request.clone()).latest().await?,
            Bytes::from(IConfigurableAccount::upgradeAccountCall::abi_encode_returns(&expected))
        );
        assert!(
            env.provider()
                .estimate_gas(request.clone())
                .latest()
                .await?
                > 0
        );
        assert_eq!(commitment(&env, account.address).await?, B256::ZERO);

        // A contract cannot be upgraded, even by simulation.
        let from_contract = TransactionRequest {
            from: Some(OBSERVER),
            ..request.clone()
        };
        assert_call_reverts(
            env.provider().call(from_contract).latest().await,
            IConfigurableAccount::AccountHasCode {}.abi_encode(),
        );

        // The root signs the sole call.
        let tx = account.transaction(&env, vec![call]);
        let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
        let receipt = account.submit(&mut env, tx, signature, true).await?;
        assert_eq!(commitment(&env, account.address).await?, expected);
        let upgraded = receipt
            .logs()
            .iter()
            .filter(|log| log.address() == CONFIGURABLE_ACCOUNT_ADDRESS)
            .map(|log| IConfigurableAccount::AccountUpgraded::decode_log(&log.inner))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(upgraded.len(), 1);
        assert_eq!(
            upgraded[0].data,
            IConfigurableAccount::AccountUpgraded {
                account: account.address,
                commitment: expected,
                salt: account.config.salt,
                threshold: account.config.threshold,
                owners: abi_owners(&account.config),
            }
        );

        // The root key cannot send any more, whatever the transaction does.
        let tx = account.transaction(&env, vec![noop()]);
        let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
        reject_with(
            &env,
            tx,
            signature,
            TempoInvalidTransaction::RootKeyRetired {
                account: account.address,
                role: RootKeyRole::Sender,
            },
        )
        .await?;

        // A quorum whose last approval signs the wrong digest fails sender recovery, so the pool
        // rejects it and the transaction uses no nonce.
        let tx = account.transaction(&env, vec![noop()]);
        let signature =
            TempoSignature::ConfigurableAccount(account.quorum(tx.signature_hash(), true)?);
        let error = rejection(&env, tx, signature).await;
        assert_rpc_error(&error, INVALID_PARAMS_CODE, "invalid transaction signature")?;
        assert_eq!(commitment(&env, account.address).await?, expected);

        // The witness still can, and the rejected transaction used no nonce.
        let tx = account.transaction(&env, vec![noop()]);
        let signature = account.sign(&tx)?;
        account.submit(&mut env, tx, signature, true).await?;

        // The account is configured now, so a second upgrade reverts when simulated.
        assert_call_reverts(
            env.provider().call(request).latest().await,
            IConfigurableAccount::AccountAlreadyConfigurable {}.abi_encode(),
        );

        // Calls and gas estimates from the retired address are simulations, which stay allowed.
        let request = call_request(
            account.address,
            IConfigurableAccount::getConfigCommitmentCall {
                account: account.address,
            }
            .abi_encode()
            .into(),
        );
        assert_eq!(
            env.provider().call(request.clone()).latest().await?,
            Bytes::from(
                IConfigurableAccount::getConfigCommitmentCall::abi_encode_returns(
                    &account.config.commitment().unwrap()
                )
            )
        );
        assert!(env.provider().estimate_gas(request).latest().await? > 0);

        // The version-one witness signs the next transaction, which rotates to version two.
        let replacement = ConfigurableAccount::new(seed + 8, 2);
        let (next, rotate) = account.rotate_to(&replacement);
        let tx = account.transaction(&env, vec![rotate]);
        let signature = account.sign(&tx)?;
        account.submit(&mut env, tx, signature, true).await?;
        assert_eq!(
            commitment(&env, account.address).await?,
            next.commitment().unwrap()
        );
    }
    Ok(())
}
