use super::*;
use crate::tempo_transaction::helpers::{
    create_expiring_nonce_tx, create_transfer_call, parse_filled_tx, sign_fee_payer,
};
use alloy::{
    consensus::{BlockHeader, SignableTransaction, TxEip1559, TxLegacy},
    primitives::Signature,
    rpc::types::{
        simulate::{SimBlock, SimulatePayload, SimulatedBlock},
        state::StateOverridesBuilder,
    },
    sol_types::{SolError, SolEvent},
    transports::TransportError,
};
use alloy_eips::{BlockId, BlockNumberOrTag, Decodable2718, eip7702::Authorization};
use evm2::registry::HandlerError;
use eyre::OptionExt;
use futures::{FutureExt, StreamExt};
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use reth_e2e_test_utils::{node::Finality, wait::WAIT_TIMEOUT};
use reth_ethereum::{
    pool::{
        TransactionEvent, TransactionOrigin, TransactionPool,
        error::{PoolError, PoolErrorKind},
    },
    primitives::SignerRecoverable,
};
use reth_node_builder::BuiltPayload;
use reth_rpc_eth_types::RpcInvalidTransactionError;
use serde_json::{from_value, json};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, IAccountKeychain, configurable_account::IConfigurableAccountShim,
};
use tempo_evm::transaction_error::ConfigurableAccountError;
use tempo_primitives::{
    account::encode_config_commitment,
    transaction::{
        KeyAuthorization, SignedKeyAuthorization, TempoSignedAuthorization, TokenLimit,
        calc_gas_balance_spending,
    },
};
use tempo_transaction_pool::transaction::TempoPoolTransactionError;
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

#[tokio::test(flavor = "multi_thread")]
async fn configurable_account_rpc_delegate_rotation_preserves_grant_and_spending()
-> eyre::Result<()> {
    let mut env = environment().await?;
    let mut parent = ConfigurableAccount::new(0x31, 2);
    let mut delegate = ConfigurableAccount::new(0x41, 2);
    env.fund_account(parent.address).await?;
    env.fund_account(delegate.address).await?;
    let limit = U256::from(100_000_000_000u64);
    let grant = KeyAuthorization::unrestricted(
        env.chain_id(),
        SignatureType::ConfigurableAccount,
        delegate.address,
    )
    .with_account(parent.address)
    .with_limits(vec![TokenLimit {
        token: DEFAULT_FEE_TOKEN,
        limit,
        period: 0,
    }]);
    let grant_signature = parent.quorum(grant.signature_hash(), false)?;
    let transfer = create_transfer_call(
        DEFAULT_FEE_TOKEN,
        Address::repeat_byte(0x74),
        U256::from(100),
    );
    let mut tx = parent.transaction(&env, vec![transfer.clone()]);
    tx.key_authorization = Some(grant.into_signed(grant_signature));
    let signature = delegate.as_delegate(&tx, parent.address, false)?;
    parent.submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        commitment(&env, parent.address).await?,
        parent.config.commitment().unwrap()
    );
    assert_eq!(
        commitment(&env, delegate.address).await?,
        delegate.config.commitment().unwrap()
    );
    let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, env.provider().clone());
    let (account, key) = (parent.address, delegate.address);
    let remaining = async || {
        eyre::Ok(
            keychain
                .getRemainingLimitWithPeriod(account, key, DEFAULT_FEE_TOKEN)
                .call()
                .await?
                .remaining,
        )
    };
    let before_rotation = remaining().await?;
    assert!(before_rotation < limit);
    let key_before = keychain.getKey(account, key).call().await?;

    let replacement = ConfigurableAccount::new(0x51, 2);
    let (next, rotate) = delegate.rotate_to(&replacement);
    let tx = delegate.transaction(&env, vec![rotate]);
    let signature = delegate.sign(&tx)?;
    delegate.submit(&mut env, tx, signature, true).await?;
    assert_eq!(remaining().await?, before_rotation);
    assert_eq!(keychain.getKey(account, key).call().await?, key_before);

    let tx = parent.transaction(&env, vec![transfer]);
    reject_with(
        &env,
        tx.clone(),
        delegate.as_delegate(&tx, parent.address, false)?,
        TempoInvalidTransaction::ConfigurableAccount(
            ConfigurableAccountError::ConfigurationCommitmentMismatch {
                expected: next.commitment().unwrap(),
                actual: delegate.config.commitment().unwrap(),
            },
        ),
    )
    .await?;
    delegate.adopt(next, replacement);
    let signature = delegate.as_delegate(&tx, parent.address, false)?;
    parent.submit(&mut env, tx, signature, true).await?;
    assert!(remaining().await? < before_rotation);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn configurable_account_rpc_registration_revert_retry_and_rotation() -> eyre::Result<()> {
    let mut env = environment().await?;
    let mut account = ConfigurableAccount::new(0x11, 2);
    env.fund_account(account.address).await?;
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    let request = account.simulation_request();
    let provider = tempo_provider(&env);
    assert_eq!(
        provider.call(request.clone()).latest().await?,
        Bytes::from(account.config.commitment().unwrap())
    );
    let estimate = provider.estimate_gas(request).latest().await?;
    assert!(estimate > 0);
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    let before = fee_balance(&env, account.address).await?;

    let tx = account.transaction(
        &env,
        vec![Call {
            to: CONFIGURABLE_ACCOUNT_ADDRESS.into(),
            value: U256::ZERO,
            input: Bytes::from_static(&[0xff, 0xff, 0xff, 0xff]),
        }],
    );
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, false).await?;
    assert_eq!(
        commitment(&env, account.address).await?,
        account.config.commitment().unwrap()
    );
    let account_info: Value = env
        .provider()
        .raw_request("eth_getAccount".into(), (account.address, "latest"))
        .await?;
    assert_eq!(
        account_info["extension"],
        json!(encode_config_commitment(
            account.config.commitment().unwrap()
        ))
    );
    // Registration installs the one-byte marker, which answers ERC-1271 and ERC-721 receipts.
    assert_eq!(
        env.provider().get_code_at(account.address).await?,
        Bytes::from_static(&[0xef])
    );
    assert_eq!(account_info["codeHash"], json!(keccak256([0xef])));
    let hash = B256::repeat_byte(0x5a);
    let is_valid_signature = IConfigurableAccountShim::isValidSignatureCall {
        hash,
        signature: TempoSignature::ConfigurableAccount(account.quorum(hash, false)?).to_bytes(),
    };
    let address = account.address;
    let shim_call = move |input: Vec<u8>| {
        let mut request = call_request(Address::ZERO, input.into());
        request.to = Some(address.into());
        request
    };
    // A returned bytes4 is left-aligned in its word.
    let magic = |value: [u8; 4]| {
        let mut word = [0; 32];
        word[..4].copy_from_slice(&value);
        Bytes::from(word)
    };
    assert_eq!(
        env.provider()
            .call(shim_call(is_valid_signature.abi_encode()))
            .await?,
        magic(IConfigurableAccountShim::isValidSignatureCall::SELECTOR)
    );
    assert_eq!(
        env.provider()
            .call(shim_call(
                IConfigurableAccountShim::onERC721ReceivedCall {
                    operator: Address::ZERO,
                    from: Address::ZERO,
                    tokenId: U256::ONE,
                    data: Bytes::new(),
                }
                .abi_encode()
            ))
            .await?,
        magic(IConfigurableAccountShim::onERC721ReceivedCall::SELECTOR)
    );
    // Other selectors revert without data.
    let error = env
        .provider()
        .call(shim_call(vec![0xff; 4]))
        .await
        .expect_err("unknown selectors revert");
    let payload = error.as_error_resp().expect("revert response");
    assert_eq!(payload.message, "execution reverted");
    assert_eq!(payload.as_revert_data(), None);
    let registered_estimate = provider
        .estimate_gas(account.simulation_request())
        .latest()
        .await?;
    assert!(
        registered_estimate < estimate,
        "registered version zero avoids initial registration gas"
    );
    assert_eq!(
        env.provider()
            .get_transaction_count(account.address)
            .await?,
        1
    );
    assert!(fee_balance(&env, account.address).await? < before);

    let tx = account.transaction(
        &env,
        vec![Call {
            to: OBSERVER.into(),
            ..noop()
        }],
    );
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
    let initial = account.config.commitment().unwrap();
    assert_eq!(commitment(&env, account.address).await?, initial);
    assert_eq!(
        env.provider().get_storage_at(OBSERVER, U256::ZERO).await?,
        U256::from_be_bytes(initial.0)
    );

    let replacement = ConfigurableAccount::new(0x21, 2);
    let (next, rotate) = account.rotate_to(&replacement);
    // The current config signs transactions that wait in the pool behind the rotation: as the
    // sender, as the grant signer of its access key and as the access key of another account.
    let mut stale = account.transaction(&env, vec![noop()]);
    stale.nonce += 1;
    let signature = account.sign(&stale)?;
    let stale: TempoTxEnvelope = stale.into_signed(signature).into();
    let chain_id = env.chain_id();
    let key = signer(0x34);
    let parent = signer(0x40);
    env.fund_account(parent.address()).await?;
    let grant = KeyAuthorization::unrestricted(chain_id, SignatureType::Secp256k1, key.address())
        .with_account(account.address);
    let grant_signature = account.quorum(grant.signature_hash(), false)?;
    let mut key_tx = account.transaction(&env, vec![noop()]);
    key_tx.nonce += 2;
    key_tx.key_authorization = Some(grant.into_signed(grant_signature));
    let key_tx = key_signed(key_tx, account.address, &key)?;
    let delegation = KeyAuthorization::unrestricted(
        chain_id,
        SignatureType::ConfigurableAccount,
        account.address,
    );
    let signature =
        PrimitiveSignature::Secp256k1(parent.sign_hash_sync(&delegation.signature_hash())?);
    // Nothing sends the parent's first nonce, so no block includes this transaction.
    let mut delegate_tx = create_basic_aa_tx(chain_id, 1, vec![noop()], GAS_LIMIT);
    delegate_tx.key_authorization = Some(delegation.into_signed(signature));
    let signature = account.as_delegate(&delegate_tx, parent.address(), false)?;
    let delegate_tx: TempoTxEnvelope = delegate_tx.into_signed(signature).into();
    let stale = pend(&env, &[&stale, &key_tx, &delegate_tx]).await?;
    let tx = account.transaction(&env, vec![rotate]);
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        commitment(&env, account.address).await?,
        next.commitment().unwrap()
    );
    // The rotation changes the commitment, so the pool revalidates the transactions and evicts
    // them (TIP-1112).
    env.setup.node.wait_for_pool_removal(stale).await?;
    // The rotated-out witness no longer verifies through the account.
    assert_eq!(
        env.provider()
            .call(shim_call(is_valid_signature.abi_encode()))
            .await?,
        magic([0xff; 4])
    );
    let tx = account.transaction(&env, vec![noop()]);
    reject_with(
        &env,
        tx.clone(),
        account.sign(&tx)?,
        TempoInvalidTransaction::ConfigurableAccount(
            ConfigurableAccountError::ConfigurationCommitmentMismatch {
                expected: next.commitment().unwrap(),
                actual: account.config.commitment().unwrap(),
            },
        ),
    )
    .await?;
    account.adopt(next, replacement);
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;

    // A simulated block checks each call against the state the calls before it leave: once its
    // first call rotates the configuration, the old one is stale and the new one signs. The
    // rotation stays in the simulation's state (TIP-1114).
    let stale = account.simulation_request();
    let current = account.config.commitment().unwrap();
    let replacement = ConfigurableAccount::new(0x22, 2);
    let (next, rotate) = account.rotate_to(&replacement);
    let mut rotation = stale.clone();
    rotation.inner.input = rotate.input.into();
    account.adopt(next, replacement);
    let simulate = |call: TempoTransactionRequest| SimulatePayload {
        block_state_calls: vec![SimBlock {
            block_overrides: None,
            state_overrides: None,
            calls: vec![rotation.clone(), call],
        }],
        trace_transfers: false,
        validation: false,
        return_full_transactions: false,
    };
    let blocks: Vec<SimulatedBlock<Value>> = provider
        .raw_request(
            "eth_simulateV1".into(),
            (simulate(account.simulation_request()),),
        )
        .await?;
    let [rotated, read] = blocks[0].calls.as_slice() else {
        panic!("{blocks:?}");
    };
    assert!(rotated.status, "{blocks:?}");
    assert!(read.status, "{blocks:?}");
    assert_eq!(
        read.return_data,
        Bytes::from(account.config.commitment().unwrap())
    );
    assert_rpc_error(
        &provider
            .raw_request::<_, Vec<SimulatedBlock<Value>>>(
                "eth_simulateV1".into(),
                (simulate(stale),),
            )
            .await
            .expect_err("a configuration rotated by an earlier call must be stale"),
        EthRpcErrorCode::TransactionRejected.code(),
        &TempoInvalidTransaction::ConfigurableAccount(
            ConfigurableAccountError::ConfigurationCommitmentMismatch {
                expected: account.config.commitment().unwrap(),
                actual: current,
            },
        )
        .to_string(),
    )?;
    assert_eq!(commitment(&env, account.address).await?, current);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn configurable_account_rpc_historical_state_and_account_overrides() -> eyre::Result<()> {
    let mut env = environment().await?;
    let mut account = ConfigurableAccount::new(0x18, 2);
    env.fund_account(account.address).await?;
    let tx = account.transaction(&env, vec![noop()]);
    let signature = account.sign(&tx)?;
    let receipt = account.submit(&mut env, tx, signature, true).await?;
    let historical_block = BlockId::number(receipt.block_number().unwrap());
    let provider = tempo_provider(&env);
    let initial = account.config.commitment().unwrap();
    let old_request = account.simulation_request();

    let replacement = ConfigurableAccount::new(0x28, 2);
    let (next, rotate) = account.rotate_to(&replacement);
    let tx = account.transaction(&env, vec![rotate]);
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
    let current = next.commitment().unwrap();
    assert_eq!(
        provider
            .call(old_request.clone())
            .block(historical_block)
            .await?,
        Bytes::from(initial)
    );
    assert_rpc_error(
        &provider
            .call(old_request.clone())
            .latest()
            .await
            .unwrap_err(),
        EthRpcErrorCode::TransactionRejected.code(),
        &TempoInvalidTransaction::ConfigurableAccount(
            ConfigurableAccountError::ConfigurationCommitmentMismatch {
                expected: current,
                actual: initial,
            },
        )
        .to_string(),
    )?;
    assert!(
        provider
            .estimate_gas(old_request)
            .block(historical_block)
            .await?
            > 0
    );

    account.adopt(next, replacement);
    let request = account.simulation_request();
    // Ordinary account overrides must merge with, rather than erase, the stored extension.
    assert_eq!(
        provider
            .call(request.clone())
            .latest()
            .overrides(
                StateOverridesBuilder::default()
                    .with_balance(account.address, U256::ONE)
                    .with_nonce(account.address, 9)
                    .with_state_diff(account.address, [(B256::ZERO, B256::repeat_byte(0x42))])
                    .build()
            )
            .await?,
        Bytes::from(current)
    );
    assert_rpc_error(
        &provider
            .call(request)
            .latest()
            .overrides(
                StateOverridesBuilder::default()
                    .with_code(account.address, Bytes::from_static(&[0x00]))
                    .build(),
            )
            .await
            .unwrap_err(),
        EthRpcErrorCode::TransactionRejected.code(),
        &TempoInvalidTransaction::ConfigurableAccount(ConfigurableAccountError::InvalidAccount {
            account: account.address,
        })
        .to_string(),
    )?;
    assert_eq!(commitment(&env, account.address).await?, current);
    assert_eq!(
        env.provider()
            .get_storage_at(account.address, U256::ZERO)
            .await?,
        U256::ZERO
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn configurable_account_rpc_fill_and_access_list_preserve_authority() -> eyre::Result<()> {
    let mut env = environment().await?;
    let mut account = ConfigurableAccount::new(0x19, 3);
    env.fund_account(account.address).await?;
    let provider = tempo_provider(&env);
    let mut request = account.simulation_request();
    // Model the same algorithms and WebAuthn length that will be submitted.
    request
        .configurable_account_simulation
        .as_mut()
        .expect("simulation request carries a quorum")
        .approvals = account
        .owners
        .iter()
        .map(|owner| {
            let (key_type, key_data) = match owner.sign(B256::ZERO)? {
                PrimitiveSignature::Secp256k1(_) => (PrimitiveSignatureType::Secp256k1, None),
                PrimitiveSignature::P256(_) => (PrimitiveSignatureType::P256, None),
                PrimitiveSignature::WebAuthn(signature) => (
                    PrimitiveSignatureType::WebAuthn,
                    Some(Bytes::from(
                        u16::try_from(signature.webauthn_data.len())?.to_be_bytes(),
                    )),
                ),
            };
            Ok(ConfigurableAccountSimulationApproval {
                owner: owner.address(),
                key_type: Some(key_type),
                key_data,
            })
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    request.to = Some(OBSERVER.into());
    request.input = Bytes::new().into();
    let access = provider.create_access_list(&request).latest().await?;
    assert!(access.is_ok(), "{access:?}");
    assert!(
        access
            .access_list
            .iter()
            .any(|item| { item.address == OBSERVER && item.storage_keys.contains(&B256::ZERO) }),
        "{access:?}"
    );
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    assert_eq!(
        env.provider().get_storage_at(OBSERVER, U256::ZERO).await?,
        U256::ZERO
    );

    let delegate = PrivateKeySigner::random();
    let grant = KeyAuthorization::unrestricted(
        env.chain_id(),
        SignatureType::Secp256k1,
        delegate.address(),
    )
    .with_account(account.address);
    let signature = account.quorum(grant.signature_hash(), false)?;
    let grant = grant.into_signed(signature);
    request.set_key_authorization(grant.clone());
    let estimate = provider.estimate_gas(request.clone()).latest().await?;
    let filled: Value = env
        .provider()
        .raw_request("eth_fillTransaction".into(), (request.clone(),))
        .await?;
    let mut tx = parse_filled_tx(&filled)?;
    assert_eq!(tx.key_authorization.as_ref(), Some(&grant));
    assert_eq!(tx.nonce, 0);
    assert_eq!(tx.chain_id, env.chain_id());
    assert_eq!(tx.calls[0].to, OBSERVER.into());
    let TempoTxEnvelope::AA(unsigned) =
        TempoTxEnvelope::decode_2718(&mut from_value::<Bytes>(filled["raw"].clone())?.as_ref())?
    else {
        panic!("configurable fill must retain the AA transaction type");
    };
    assert_eq!(unsigned.tx().key_authorization.as_ref(), Some(&grant));
    for field in [
        "configurableAccountSimulation",
        "keyAuthorizationSimulation",
    ] {
        assert!(filled["tx"].get(field).is_none(), "{filled}");
    }
    // A simulated grant quorum replaces the attached grant's signature with mock approvals.
    request.key_authorization_simulation = request.configurable_account_simulation.clone();
    let filled = provider.fill_transaction(request).await?;
    let simulated = filled
        .tx
        .as_aa()
        .ok_or_eyre("configurable fill must retain the AA transaction type")?
        .tx()
        .key_authorization
        .as_ref()
        .ok_or_eyre("the fill keeps the grant")?;
    assert_eq!(simulated.authorization, grant.authorization);
    assert_ne!(
        simulated, &grant,
        "the mock approvals replace the signed ones"
    );
    let quorum = simulated
        .signature
        .as_configurable_account()
        .ok_or_eyre("the grant carries the mock quorum")?;
    assert_eq!(quorum.account(), account.address);
    assert_eq!(quorum.config(), &account.config);
    assert_eq!(quorum.signatures().len(), account.owners.len());
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    tx.gas_limit = estimate;
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        commitment(&env, account.address).await?,
        account.config.commitment().unwrap()
    );
    Ok(())
}

/// `keyAuthorizationSimulation` lets a wallet estimate a transaction that grants a delegate and
/// uses it before the parent's owners sign the grant; the estimate covers the signed transaction.
#[tokio::test(flavor = "multi_thread")]
async fn configurable_account_rpc_simulated_grant_estimate_covers_the_signed_grant()
-> eyre::Result<()> {
    let mut env = environment().await?;
    let mut parent = ConfigurableAccount::new(0x1a, 2);
    let delegate = ConfigurableAccount::new(0x2a, 2);
    env.fund_account(parent.address).await?;
    let grant = KeyAuthorization::unrestricted(
        env.chain_id(),
        SignatureType::ConfigurableAccount,
        delegate.address,
    )
    .with_account(parent.address);
    let mut tx = parent.transaction(&env, vec![noop()]);
    let mut request = TempoTransactionRequest::from(tx.clone());
    request.inner.from = Some(parent.address);
    request.key_id = Some(delegate.address);
    request.configurable_account_simulation = delegate
        .simulation_request()
        .configurable_account_simulation;
    // No owner has signed the grant yet: the simulated quorum replaces this placeholder.
    request.set_key_authorization(grant.clone().into_signed(Signature::test_signature()));
    request.key_authorization_simulation =
        parent.simulation_request().configurable_account_simulation;
    let provider = tempo_provider(&env);
    // A simulated block names the delegate as `eth_call` does, without recovering its mock
    // approvals. `eth_simulateV1` turns a request without `to` into a create, so the call moves
    // there.
    let mut call = request.clone();
    call.calls.clear();
    call.inner.to = Some(noop().to);
    let blocks: Vec<SimulatedBlock<Value>> = provider
        .raw_request(
            "eth_simulateV1".into(),
            (SimulatePayload {
                block_state_calls: vec![SimBlock {
                    block_overrides: None,
                    state_overrides: None,
                    calls: vec![call],
                }],
                trace_transfers: false,
                validation: false,
                return_full_transactions: false,
            },),
        )
        .await?;
    assert!(blocks[0].calls[0].status, "{blocks:?}");
    tx.gas_limit = provider.estimate_gas(request).latest().await?;

    let grant_signature = parent.quorum(grant.signature_hash(), false)?;
    tx.key_authorization = Some(grant.into_signed(grant_signature));
    let signature = delegate.as_delegate(&tx, parent.address, false)?;
    parent.submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        commitment(&env, parent.address).await?,
        parent.config.commitment().unwrap()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn configurable_account_rpc_maximum_mixed_quorums_and_validation_cost_order()
-> eyre::Result<()> {
    let mut env = environment().await?;
    let mut parent = ConfigurableAccount::new(0x61, 8);
    let delegate = ConfigurableAccount::new(0x81, 8);
    let grant = KeyAuthorization::unrestricted(
        env.chain_id(),
        SignatureType::ConfigurableAccount,
        delegate.address,
    )
    .with_account(parent.address);
    let mut tx = parent.transaction(&env, vec![noop()]);
    tx.key_authorization = Some(
        grant
            .clone()
            .into_signed(parent.quorum(grant.signature_hash(), false)?),
    );

    // The pool and the RPC check intrinsic gas, then the fee balance, of a transaction whose
    // delegate and grant quorums both recovered.
    let mut low_gas = tx.clone();
    low_gas.gas_limit = 21_000;
    let signature = delegate.as_delegate(&low_gas, parent.address, false)?;
    let low_gas: TempoTxEnvelope = low_gas.into_signed(signature).into();
    let PoolError {
        kind: PoolErrorKind::InvalidTransaction(error),
        ..
    } = env
        .setup
        .node
        .inner
        .pool
        .add_consensus_transaction(low_gas.try_into_recovered()?, TransactionOrigin::External)
        .await
        .unwrap_err()
    else {
        panic!("the pool must reject the transaction as invalid");
    };
    assert!(
        matches!(
            error.downcast_other_ref::<TempoPoolTransactionError>(),
            Some(TempoPoolTransactionError::Evm(
                HandlerError::IntrinsicGasTooLow { .. }
            ))
        ),
        "{error:?}"
    );
    let unfunded = RpcInvalidTransactionError::InsufficientFunds {
        cost: calc_gas_balance_spending(tx.gas_limit, tx.max_fee_per_gas),
        balance: U256::ZERO,
    };
    assert_rpc_error(
        &rejection(
            &env,
            tx.clone(),
            delegate.as_delegate(&tx, parent.address, false)?,
        )
        .await,
        unfunded.error_code(),
        &unfunded.to_string(),
    )?;

    // Only the last approval of the grant signs the wrong digest. Recovery rejects the
    // transaction before any state is read, so it never reaches the unfunded check above.
    let mut invalid_grant = tx.clone();
    let invalid_quorum = parent.quorum(grant.signature_hash(), true)?;
    invalid_grant.key_authorization = Some(grant.into_signed(invalid_quorum));
    let signature = delegate.as_delegate(&invalid_grant, parent.address, false)?;
    TempoTxEnvelope::from(invalid_grant.clone().into_signed(signature.clone()))
        .recover_signer()
        .expect_err("recovery verifies the grant quorum");
    // Simulation skips recovery, so the RPC checks the grant quorum itself.
    let mut request = TempoTransactionRequest::from(invalid_grant.clone());
    request.inner.from = Some(parent.address);
    request.key_id = Some(delegate.address);
    request.configurable_account_simulation = delegate
        .simulation_request()
        .configurable_account_simulation;
    let provider = tempo_provider(&env);
    for error in [
        provider
            .estimate_gas(request.clone())
            .latest()
            .await
            .unwrap_err(),
        provider.call(request).latest().await.unwrap_err(),
    ] {
        assert_rpc_error(
            &error,
            INVALID_PARAMS_CODE,
            "invalid configurable account owner signature",
        )?;
    }
    assert_rpc_error(
        &rejection(&env, invalid_grant, signature).await,
        INVALID_PARAMS_CODE,
        "invalid transaction signature",
    )?;
    env.fund_account(parent.address).await?;
    assert_eq!(commitment(&env, parent.address).await?, B256::ZERO);
    assert_eq!(commitment(&env, delegate.address).await?, B256::ZERO);

    // Two independent eight-owner witnesses include secp256k1, P256 and WebAuthn. Sponsorship
    // adds exactly one ordinary secp256k1 signature without giving the sponsor authority.
    sign_fee_payer(&mut tx, parent.address, &env.funder_signer)?;
    let before = fee_balance(&env, parent.address).await?;
    let signature = delegate.as_delegate(&tx, parent.address, false)?;
    parent.submit(&mut env, tx, signature, true).await?;
    assert_eq!(fee_balance(&env, parent.address).await?, before);
    assert_eq!(
        commitment(&env, parent.address).await?,
        parent.config.commitment().unwrap()
    );
    assert_eq!(
        commitment(&env, delegate.address).await?,
        delegate.config.commitment().unwrap()
    );
    Ok(())
}
