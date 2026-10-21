use super::*;
use crate::tempo_transaction::helpers::{
    create_expiring_nonce_tx, create_transfer_call, parse_filled_tx, sign_fee_payer,
};
use alloy::{
    consensus::{BlockHeader, SignableTransaction, TxEip1559, TxLegacy},
    rpc::types::state::StateOverridesBuilder,
    sol_types::{SolError, SolEvent},
    transports::TransportError,
};
use alloy_eips::{BlockId, BlockNumberOrTag, Decodable2718, eip7702::Authorization};
use eyre::OptionExt;
use futures::{FutureExt, StreamExt};
use jsonrpsee::types::ErrorObject;
use reth_e2e_test_utils::{node::Finality, wait::WAIT_TIMEOUT};
use reth_ethereum::pool::{TransactionEvent, TransactionPool};
use reth_node_builder::BuiltPayload;
use reth_rpc_eth_types::{EthApiError, RpcInvalidTransactionError};
use serde_json::{from_value, json};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{ACCOUNT_KEYCHAIN_ADDRESS, IAccountKeychain, ITIP20};
use tempo_evm::transaction_error::ConfigurableAccountError;
use tempo_primitives::{
    account::encode_config_commitment,
    transaction::{
        ConfigurableAccountQuorumError, ConfigurableAccountStateError, KeyAuthorization,
        SignedKeyAuthorization, TempoSignedAuthorization, TokenLimit, calc_gas_balance_spending,
    },
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

#[tokio::test(flavor = "multi_thread")]
async fn configurable_account_rpc_registration_revert_retry_and_rotation() -> eyre::Result<()> {
    let mut env = environment().await?;
    let mut account = ConfigurableAccount::new(0x11, 2);
    env.fund_account(account.address).await?;
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    let request = account.simulation_request();
    let provider = tempo_provider(&env);
    let simulated = provider.call(request.clone()).latest().await?;
    assert_eq!(simulated, Bytes::from(account.config.commitment().unwrap()));
    let estimate = provider.estimate_gas(request).latest().await?;
    assert!(estimate > 0);
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    let before = ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
        .balanceOf(account.address)
        .call()
        .await?;

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
    let extension = account_info["extension"]
        .as_str()
        .expect("registered account extension missing");
    assert_eq!(extension.len(), 2 + 66);
    assert_eq!(
        account_info["extension"],
        json!(encode_config_commitment(
            account.config.commitment().unwrap()
        ))
    );
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
    assert!(
        ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
            .balanceOf(account.address)
            .call()
            .await?
            < before
    );

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
    let initial_word: U256 = initial.into();
    assert_eq!(
        env.provider().get_storage_at(OBSERVER, U256::ZERO).await?,
        initial_word
    );

    let replacement = ConfigurableAccount::new(0x21, 2);
    let (next, rotate) = account.rotate_to(&replacement);
    // The current config signs a transaction that waits in the pool behind the rotation.
    let mut stale = account.transaction(&env, vec![noop()]);
    stale.nonce += 1;
    let signature = account.sign(&stale)?;
    let stale: TempoTxEnvelope = stale.into_signed(signature).into();
    let stale = pend(&env, &[&stale]).await?[0];
    let tx = account.transaction(&env, vec![rotate]);
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        commitment(&env, account.address).await?,
        next.commitment().unwrap()
    );
    // The rotation changes the commitment, so the pool revalidates the transaction and evicts
    // it (TIP-1112).
    env.setup.node.wait_for_pool_removal([stale]).await?;
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
    account.config = next;
    account.owners = replacement.owners;
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
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
    let historical = provider
        .call(old_request.clone())
        .block(historical_block)
        .await?;
    assert_eq!(historical, Bytes::from(initial));
    let stale = provider
        .call(old_request.clone())
        .latest()
        .await
        .unwrap_err();
    let mismatch = ConfigurableAccountStateError::CommitmentMismatch {
        expected: current,
        actual: initial,
    };
    let invalid = EthApiError::InvalidParams(format!(
        "{mismatch} for {} at the requested state",
        account.address
    ));
    let invalid = ErrorObject::from(invalid);
    assert_rpc_error(&stale, invalid.code(), invalid.message())?;
    let historical_gas = provider
        .estimate_gas(old_request)
        .block(historical_block)
        .await?;
    assert!(historical_gas > 0);

    account.config = next;
    account.owners = replacement.owners;
    let request = account.simulation_request();
    // Ordinary account overrides must merge with, rather than erase, the stored extension.
    let overrides = StateOverridesBuilder::default()
        .with_balance(account.address, U256::ONE)
        .with_nonce(account.address, 9)
        .with_state_diff(account.address, [(B256::ZERO, B256::repeat_byte(0x42))])
        .build();
    let overridden = provider
        .call(request.clone())
        .latest()
        .overrides(overrides)
        .await?;
    assert_eq!(overridden, Bytes::from(current));
    let code_override = StateOverridesBuilder::default()
        .with_code(account.address, Bytes::from_static(&[0x00]))
        .build();
    let error = provider
        .call(request)
        .latest()
        .overrides(code_override)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("code"), "{error}");
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
            let signature = owner.sign(B256::ZERO)?;
            let key_data = match &signature {
                PrimitiveSignature::WebAuthn(signature) => Some(Bytes::from(
                    u16::try_from(signature.webauthn_data.len())?.to_be_bytes(),
                )),
                _ => None,
            };
            Ok(ConfigurableAccountSimulationApproval {
                owner: owner.address(),
                key_type: Some(signature.signature_type()),
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
    let raw: Bytes = from_value(filled["raw"].clone())?;
    let TempoTxEnvelope::AA(unsigned) = TempoTxEnvelope::decode_2718(&mut raw.as_ref())? else {
        panic!("configurable fill must retain the AA transaction type");
    };
    assert_eq!(unsigned.tx().key_authorization.as_ref(), Some(&grant));
    assert_eq!(unsigned.signature(), &TempoSignature::default());
    for field in [
        "configurableAccountSimulation",
        "keyAuthorizationSimulation",
        "configurableAccountSimulationSignature",
    ] {
        assert!(filled["tx"].get(field).is_none(), "{filled}");
    }
    request.key_authorization_simulation = request.configurable_account_simulation.clone();
    let error = provider
        .fill_transaction(request)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("real signed grant"), "{error}");
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
    let mut tx = parent.transaction(
        &env,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            Address::repeat_byte(0x74),
            U256::from(100),
        )],
    );
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
    let before_rotation = keychain
        .getRemainingLimitWithPeriod(parent.address, delegate.address, DEFAULT_FEE_TOKEN)
        .call()
        .await?
        .remaining;
    assert!(before_rotation < limit);
    let key_before = keychain
        .getKey(parent.address, delegate.address)
        .call()
        .await?;

    let replacement = ConfigurableAccount::new(0x51, 2);
    let (next, rotate) = delegate.rotate_to(&replacement);
    let tx = delegate.transaction(&env, vec![rotate]);
    let signature = delegate.sign(&tx)?;
    delegate.submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        keychain
            .getRemainingLimitWithPeriod(parent.address, delegate.address, DEFAULT_FEE_TOKEN)
            .call()
            .await?
            .remaining,
        before_rotation
    );
    assert_eq!(
        keychain
            .getKey(parent.address, delegate.address)
            .call()
            .await?,
        key_before
    );

    let tx = parent.transaction(
        &env,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            Address::repeat_byte(0x74),
            U256::from(100),
        )],
    );
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
    delegate.config = next;
    delegate.owners = replacement.owners;
    let signature = delegate.as_delegate(&tx, parent.address, false)?;
    parent.submit(&mut env, tx, signature, true).await?;
    assert!(
        keychain
            .getRemainingLimitWithPeriod(parent.address, delegate.address, DEFAULT_FEE_TOKEN)
            .call()
            .await?
            .remaining
            < before_rotation
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
    let grant_signature = parent.quorum(grant.signature_hash(), false)?;
    let mut tx = parent.transaction(&env, vec![noop()]);
    tx.key_authorization = Some(
        grant
            .clone()
            .into_signed(parent.quorum(grant.signature_hash(), true)?),
    );

    // The outer delegate quorum is verified first, then the grant's quorum. Only the last
    // approval of the grant signs the wrong digest, so the funded rejection reaches check 16.
    let mut low_gas = tx.clone();
    low_gas.gas_limit = 21_000;
    let error = reject(
        &env,
        low_gas.clone(),
        delegate.as_delegate(&low_gas, parent.address, false)?,
    )
    .await?;
    assert!(
        error.contains("intrinsic") || error.contains("gas limit"),
        "{error}"
    );
    let error = rejection(
        &env,
        tx.clone(),
        delegate.as_delegate(&tx, parent.address, false)?,
    )
    .await;
    let unfunded = RpcInvalidTransactionError::InsufficientFunds {
        cost: calc_gas_balance_spending(tx.gas_limit, tx.max_fee_per_gas),
        balance: U256::ZERO,
    };
    assert_rpc_error(&error, unfunded.error_code(), &unfunded.to_string())?;
    env.fund_account(parent.address).await?;
    let expected = match parent.owners.last().unwrap() {
        OwnerKey::Secp(_) => {
            ConfigurableAccountError::Quorum(ConfigurableAccountQuorumError::SignerNotOwner)
        }
        OwnerKey::P256 { .. } => {
            ConfigurableAccountError::OwnerSignatureRecoveryFailed { approval_index: 7 }
        }
    };
    reject_with(
        &env,
        tx.clone(),
        delegate.as_delegate(&tx, parent.address, false)?,
        TempoInvalidTransaction::ConfigurableAccount(expected),
    )
    .await?;
    assert_eq!(commitment(&env, parent.address).await?, B256::ZERO);
    assert_eq!(commitment(&env, delegate.address).await?, B256::ZERO);

    // Two independent eight-owner witnesses include secp256k1, P256 and WebAuthn. Sponsorship
    // adds exactly one ordinary secp256k1 signature without giving the sponsor authority.
    let sponsor = env.funder_signer.clone();
    tx.key_authorization = Some(grant.into_signed(grant_signature));
    sign_fee_payer(&mut tx, parent.address, &sponsor)?;
    let before = ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
        .balanceOf(parent.address)
        .call()
        .await?;
    let signature = delegate.as_delegate(&tx, parent.address, false)?;
    parent.submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
            .balanceOf(parent.address)
            .call()
            .await?,
        before
    );
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

/// Reads the revert data of a failed `eth_call` and requires it to be exactly `expected`.
fn assert_call_reverts(result: Result<Bytes, TransportError>, expected: Vec<u8>) {
    let error = result.expect_err("call must revert");
    let data = error
        .as_error_resp()
        .and_then(|payload| payload.as_revert_data());
    assert_eq!(data, Some(Bytes::from(expected)), "{error:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn eoa_migration_rpc_estimate_send_and_rotate() -> eyre::Result<()> {
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
        let request = TransactionRequest {
            from: Some(account.address),
            to: Some(CONFIGURABLE_ACCOUNT_ADDRESS.into()),
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            max_fee_per_blob_gas: None,
            gas: Some(GAS_LIMIT),
            value: None,
            input: call.input.clone().into(),
            nonce: None,
            chain_id: None,
            access_list: None,
            transaction_type: None,
            blob_versioned_hashes: None,
            sidecar: None,
            authorization_list: None,
        };

        // A simulation returns the commitment and the gas, and writes nothing.
        let simulated = env.provider().call(request.clone()).latest().await?;
        assert_eq!(
            simulated,
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
        let event = &upgraded[0].data;
        assert_eq!(
            *event,
            IConfigurableAccount::AccountUpgraded {
                account: account.address,
                commitment: expected,
                salt: account.config.salt,
                threshold: account.config.threshold,
                owners: abi_owners(&account.config),
            }
        );

        // The account is configured now, so a second upgrade reverts when simulated.
        assert_call_reverts(
            env.provider().call(request).latest().await,
            IConfigurableAccount::AccountAlreadyConfigurable {}.abi_encode(),
        );

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
async fn retired_root_rpc_rejects_send_and_allows_calls() -> eyre::Result<()> {
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

        // Before the migration the root key is the account's authority.
        let tx = account.transaction(&env, vec![noop()]);
        let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
        account.submit(&mut env, tx, signature, true).await?;

        let call = account.upgrade_call();
        let tx = account.transaction(&env, vec![call]);
        let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
        account.submit(&mut env, tx, signature, true).await?;
        assert_eq!(
            commitment(&env, account.address).await?,
            account.config.commitment().unwrap()
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

        // The witness still can, and the rejected transaction used no nonce.
        let tx = account.transaction(&env, vec![noop()]);
        let signature = account.sign(&tx)?;
        account.submit(&mut env, tx, signature, true).await?;

        // Calls and gas estimates from the retired address are simulations, which stay allowed.
        let request = TransactionRequest {
            from: Some(account.address),
            to: Some(CONFIGURABLE_ACCOUNT_ADDRESS.into()),
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            max_fee_per_blob_gas: None,
            gas: Some(GAS_LIMIT),
            value: None,
            input: IConfigurableAccount::getConfigCommitmentCall {
                account: account.address,
            }
            .abi_encode()
            .into(),
            nonce: None,
            chain_id: None,
            access_list: None,
            transaction_type: None,
            blob_versioned_hashes: None,
            sidecar: None,
            authorization_list: None,
        };
        let output = env.provider().call(request.clone()).latest().await?;
        assert_eq!(
            output,
            Bytes::from(
                IConfigurableAccount::getConfigCommitmentCall::abi_encode_returns(
                    &account.config.commitment().unwrap()
                )
            )
        );
        assert!(env.provider().estimate_gas(request).latest().await? > 0);
    }
    Ok(())
}

/// A root-signed transaction queued behind its account's migration stays out of the chain and
/// leaves the pool once the migration commits, and the root key cannot send it again (TIP-1112).
#[tokio::test(flavor = "multi_thread")]
async fn root_transaction_queued_behind_migration_is_not_included() -> eyre::Result<()> {
    let mut env = environment().await?;
    let root = OwnerKey::new(0x30, SignatureType::Secp256k1);
    let mut account = ConfigurableAccount::migrated(root.address(), 0x31, 3);
    env.fund_account(account.address).await?;

    // The migration (nonce n) and a root-signed transaction (nonce n + 1) are pending together.
    let migrate = account.transaction(&env, vec![account.upgrade_call()]);
    let queued = create_basic_aa_tx(env.chain_id(), account.nonce + 1, vec![noop()], GAS_LIMIT);
    let provider = tempo_provider(&env);
    let mut hashes = Vec::new();
    for tx in [migrate, queued.clone()] {
        let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
        hashes.push(
            *provider
                .send_raw_transaction(&envelope.encoded_2718())
                .await?
                .tx_hash(),
        );
    }
    assert!(env.setup.node.inner.pool.contains(&hashes[1]));
    env.setup.node.advance_block().await?;

    let migrated = provider
        .get_transaction_receipt(hashes[0])
        .await?
        .ok_or_eyre("migration not included")?;
    assert!(migrated.status(), "{migrated:?}");
    assert_eq!(
        commitment(&env, account.address).await?,
        account.config.commitment().unwrap()
    );
    account.nonce += 1;

    // The builder skips the queued transaction in the migration's block and in the next one, and
    // the pool drops it once the migration commits.
    env.setup.node.advance_block().await?;
    assert!(
        provider.get_transaction_receipt(hashes[1]).await?.is_none(),
        "root-signed transaction queued behind the migration was included"
    );
    env.setup.node.wait_for_pool_removal([hashes[1]]).await?;
    assert_eq!(
        provider.get_transaction_count(account.address).await?,
        account.nonce
    );

    // The evicted transaction, sent again by the root key at a higher fee, is rejected.
    let mut resent = queued;
    resent.max_priority_fee_per_gas *= 2;
    resent.max_fee_per_gas *= 2;
    let signature = TempoSignature::Primitive(root.sign(resent.signature_hash())?);
    reject_with(
        &env,
        resent,
        signature,
        TempoInvalidTransaction::RootKeyRetired {
            account: account.address,
            role: RootKeyRole::Sender,
        },
    )
    .await?;
    Ok(())
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
        let root = PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).unwrap();
        let other = PrivateKeySigner::from_bytes(&B256::repeat_byte(seed + 4)).unwrap();
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
/// uncommitted access key of the migrated account signs (its grant outlives the commitment, R17),
/// and a transaction that carries an authorization list entry of the migrated account, which the
/// block skips (TIP-1112). All of them follow the migration in its block and succeed.
#[tokio::test(flavor = "multi_thread")]
async fn retired_root_leaves_unrelated_pending_transactions_valid() -> eyre::Result<()> {
    let mut env = environment().await?;
    let chain_id = env.chain_id();
    let provider = tempo_provider(&env);
    let root = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x30)).unwrap();
    let key = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x34)).unwrap();
    let bystanders =
        [0x40, 0x50].map(|seed| PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).unwrap());
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
    // The entry was skipped: no delegation, and the nonce is the migration's alone.
    assert!(provider.get_code_at(account.address).await?.is_empty());
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
    let root = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x30)).unwrap();
    let key = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x34)).unwrap();
    let bystander = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x40)).unwrap();
    let sponsor = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x41)).unwrap();
    let grantor = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x42)).unwrap();
    let grantee = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x43)).unwrap();
    let mut account = ConfigurableAccount::migrated(root.address(), 0x31, 3);
    for address in [
        account.address,
        bystander.address(),
        sponsor.address(),
        grantor.address(),
    ] {
        env.fund_account(address).await?;
    }
    // Before the migration the account grants `key`, whose grant outlives the commitment (R17).
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

/// A reorg onto a chain without an account's migration evicts the pending transactions that its
/// configurable account config signs: as the sender, as the grant signer of its access key and as
/// the access key of another account (TIP-1112). The new chain changes no commitment, so only the
/// reorg marks them for revalidation.
#[tokio::test(flavor = "multi_thread")]
async fn reorg_without_migration_evicts_configurable_account_transactions() -> eyre::Result<()> {
    let mut env = environment().await?;
    // Keep genesis finalized, so the blocks below can be reorged.
    env.setup.node.set_finality(Finality::Keep);
    let chain_id = env.chain_id();
    let root = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x30)).unwrap();
    let key = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x34)).unwrap();
    let parent = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x40)).unwrap();
    let mut account = ConfigurableAccount::migrated(root.address(), 0x31, 3);
    for address in [account.address, parent.address()] {
        env.fund_account(address).await?;
    }
    let fork_point = latest_block_hash(&env).await?;
    let migrate = migration(&env, &account, &root)?;
    pend(&env, &[&migrate]).await?;
    let migrated = env.setup.node.advance_block().await?;
    env.setup
        .node
        .wait_for_pool_head(migrated.block().hash())
        .await?;
    assert_eq!(
        commitment(&env, account.address).await?,
        account.config.commitment().unwrap()
    );
    account.nonce += 1;

    // Each transaction waits for a nonce that nothing sends, so no block includes it.
    let mut own_tx = account.transaction(&env, vec![noop()]);
    own_tx.nonce += 1;
    let signature = account.sign(&own_tx)?;
    let own_tx: TempoTxEnvelope = own_tx.into_signed(signature).into();
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
    let mut delegate_tx = create_basic_aa_tx(chain_id, 1, vec![noop()], GAS_LIMIT);
    delegate_tx.key_authorization = Some(delegation.into_signed(signature));
    let signature = account.as_delegate(&delegate_tx, parent.address(), false)?;
    let delegate_tx: TempoTxEnvelope = delegate_tx.into_signed(signature).into();
    let hashes = pend(&env, &[&own_tx, &key_tx, &delegate_tx]).await?;

    // A reorg onto a block that does not hold the migration clears the commitment.
    let node = &mut env.setup.node;
    let new_chain = node.advance_block_on(fork_point).await?;
    node.wait_for_pool_head(new_chain.block().hash()).await?;
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    env.setup.node.wait_for_pool_removal(hashes).await?;
    Ok(())
}

/// From T14 the parallel builder does not replay payments recorded on the parent state, so a
/// payment whose sender or fee payer is a root key that a same-block migration retires runs after
/// the migration and is rejected.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_builder_skips_root_payment_after_same_block_migration() -> eyre::Result<()> {
    let mut env = environment_with(TestNodeBuilder::new().with_parallel_builder()).await?;
    // Three root-signed payments on a 2D nonce lane: one from an account that migrates in this
    // block, one that account's root key sponsors, and one from a bystander. The migration pays a
    // higher tip, so the builder executes it first.
    let migrating = OwnerKey::new(0x30, SignatureType::Secp256k1);
    let OwnerKey::Secp(root) = &migrating else {
        unreachable!("the migrating owner is a secp256k1 key")
    };
    let account = ConfigurableAccount::migrated(migrating.address(), 0x31, 3);
    let sponsored = OwnerKey::new(0x50, SignatureType::Secp256k1);
    let bystander = OwnerKey::new(0x40, SignatureType::Secp256k1);
    for address in [account.address, sponsored.address(), bystander.address()] {
        env.fund_account(address).await?;
    }
    let [retired_recipient, sponsored_recipient, live_recipient] =
        [0x7a, 0x7b, 0x7c].map(Address::repeat_byte);

    let provider = tempo_provider(&env);
    let mut migrate = account.transaction(&env, vec![account.upgrade_call()]);
    migrate.max_priority_fee_per_gas *= 2;
    migrate.max_fee_per_gas *= 2;
    let chain_id = env.chain_id();
    let payment = |owner: &OwnerKey, fee_payer: Option<&PrivateKeySigner>, recipient: Address| {
        let mut tx = create_basic_aa_tx(
            chain_id,
            0,
            vec![create_transfer_call(
                DEFAULT_FEE_TOKEN,
                recipient,
                U256::ONE,
            )],
            GAS_LIMIT,
        );
        tx.nonce_key = U256::ONE;
        if let Some(fee_payer) = fee_payer {
            sign_fee_payer(&mut tx, owner.address(), fee_payer)?;
        }
        let signature = TempoSignature::Primitive(owner.sign(tx.signature_hash())?);
        eyre::Ok(TempoTxEnvelope::from(tx.into_signed(signature)))
    };
    let migrate_signature = TempoSignature::Primitive(migrating.sign(migrate.signature_hash())?);
    let migrate: TempoTxEnvelope = migrate.into_signed(migrate_signature).into();
    let retired_payment = payment(&migrating, None, retired_recipient)?;
    let sponsored_payment = payment(&sponsored, Some(root), sponsored_recipient)?;
    // The bystander's payment pays the same tip as the retired ones and stays valid.
    let live_payment = payment(&bystander, None, live_recipient)?;
    let mut hashes = Vec::new();
    for tx in [
        &migrate,
        &retired_payment,
        &sponsored_payment,
        &live_payment,
    ] {
        hashes.push(
            *provider
                .send_raw_transaction(&tx.encoded_2718())
                .await?
                .tx_hash(),
        );
    }
    env.setup.node.advance_block().await?;

    let migrated = provider
        .get_transaction_receipt(hashes[0])
        .await?
        .ok_or_eyre("migration not included")?;
    assert!(migrated.status(), "{migrated:?}");
    assert_eq!(
        commitment(&env, account.address).await?,
        account.config.commitment().unwrap()
    );
    let live = provider
        .get_transaction_receipt(hashes[3])
        .await?
        .ok_or_eyre("unmigrated account's payment not included")?;
    assert_eq!(live.block_number, migrated.block_number);
    assert!(live.status(), "{live:?}");
    let token = ITIP20::new(DEFAULT_FEE_TOKEN, env.provider());
    assert_eq!(token.balanceOf(live_recipient).call().await?, U256::ONE);
    for (hash, (recipient, role)) in hashes[1..].iter().zip([
        (retired_recipient, "sender"),
        (sponsored_recipient, "fee payer"),
    ]) {
        assert!(
            provider.get_transaction_receipt(*hash).await?.is_none(),
            "payment with a migrated account's root key as its {role} was included"
        );
        assert_eq!(token.balanceOf(recipient).call().await?, U256::ZERO);
    }
    Ok(())
}
