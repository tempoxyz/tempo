//! TIP-1113 through signed RPC admission, block execution, receipts, and subsequent signing.
use super::*;
use crate::tempo_transaction::helpers::{create_transfer_call, sign_fee_payer};
use alloy::{eips::BlockNumberOrTag, primitives::keccak256, sol_types::SolEvent};
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, DEFAULT_FEE_TOKEN, IAccountKeychain, ITIP20,
};
use tempo_primitives::transaction::{KeyAuthorization, TEMPO_EXPIRING_NONCE_KEY, TokenLimit};

fn upgrade(config: &MultisigConfig) -> Call {
    Call {
        to: NATIVE_MULTISIG_ADDRESS.into(),
        value: U256::ZERO,
        input: INativeMultisig::upgradeAccountCall {
            threshold: config.threshold,
            owners: abi_owners(config),
        }
        .abi_encode()
        .into(),
    }
}

fn migration_config(account: &mut NativeAccount, root: Address) {
    account.address = root;
    account.config.version = 1;
    account.config.salt =
        keccak256([b"tempo:multisig:upgrade".as_slice(), root.as_slice()].concat());
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_rpc_all_root_types_quorum_rotation_and_retirement() -> eyre::Result<()> {
    let mut env = environment_with_migration(true).await?;
    for (seed, kind) in [
        (0x51, SignatureType::Secp256k1),
        (0x52, SignatureType::P256),
        (0x53, SignatureType::WebAuthn),
    ] {
        let root = OwnerKey::new(seed, kind);
        let mut account = NativeAccount::new(0x21, 3);
        migration_config(&mut account, root.address());
        env.fund_account(root.address()).await?;
        let tx = account.transaction(&env, vec![upgrade(&account.config)]);
        let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
        let receipt = account
            .submit(&mut env, tx.clone(), signature.clone(), true)
            .await?;
        assert_eq!(
            commitment(&env, root.address()).await?,
            account.config.commitment().unwrap()
        );
        let upgrade_logs = receipt["logs"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|log| {
                log["address"] == serde_json::json!(NATIVE_MULTISIG_ADDRESS)
                    && log["topics"][0]
                        == serde_json::json!(INativeMultisig::AccountUpgraded::SIGNATURE_HASH)
            })
            .collect::<Vec<_>>();
        assert_eq!(upgrade_logs.len(), 1);
        let log = upgrade_logs[0];
        let topics: Vec<B256> = serde_json::from_value(log["topics"].clone())?;
        let data: Bytes = serde_json::from_value(log["data"].clone())?;
        let event = INativeMultisig::AccountUpgraded::decode_raw_log(topics, &data)?;
        assert_eq!(event.account, root.address());
        assert_eq!(event.commitment, account.config.commitment().unwrap());
        assert_eq!(event.salt, account.config.salt);
        assert_eq!(event.threshold, account.config.threshold);
        assert_eq!(event.owners, abi_owners(&account.config));

        // Both a fresh root-signed transaction and the exact old envelope are rejected.
        let root_tx = account.transaction(&env, vec![noop()]);
        let error = reject(
            &env,
            root_tx.clone(),
            TempoSignature::Primitive(root.sign(root_tx.signature_hash())?),
        )
        .await?;
        insta::assert_snapshot!(error.replace(&root.address().to_string(), "ACCOUNT"), @"server returned an error response: error code -32003: invalid transaction: primitive root key retired for account ACCOUNT");
        assert!(reject(&env, tx, signature).await.is_ok());

        let tx = account.transaction(&env, vec![noop()]);
        let signature = account.sign(&tx)?;
        account.submit(&mut env, tx, signature, true).await?;
        let replacement = NativeAccount::new(0x31, 2);
        let (next, call) = account.rotate_to(&replacement);
        let tx = account.transaction(&env, vec![call]);
        let signature = account.sign(&tx)?;
        account.submit(&mut env, tx, signature, true).await?;
        account.config = next;
        account.owners = replacement.owners;
        let tx = account.transaction(&env, vec![noop()]);
        let signature = account.sign(&tx)?;
        account.submit(&mut env, tx, signature, true).await?;
        assert_eq!(
            env.provider().get_code_at(root.address()).await?,
            Bytes::new()
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_rpc_retired_root_can_be_explicit_owner_but_cannot_migrate_again()
-> eyre::Result<()> {
    let mut env = environment_with_migration(true).await?;
    let root = OwnerKey::new(0x61, SignatureType::Secp256k1);
    let mut account = NativeAccount::new(0x61, 1);
    migration_config(&mut account, root.address());
    env.fund_account(account.address).await?;
    let tx = account.transaction(&env, vec![upgrade(&account.config)]);
    let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
    account.submit(&mut env, tx, signature, true).await?;
    let tx = account.transaction(&env, vec![noop()]);
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
    let original = commitment(&env, account.address).await?;
    let tx = account.transaction(&env, vec![upgrade(&account.config)]);
    let signature = account.sign(&tx)?;
    let receipt = account.submit(&mut env, tx, signature, false).await?;
    assert_eq!(commitment(&env, account.address).await?, original);
    assert!(
        receipt["logs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|log| log["topics"][0]
                != serde_json::json!(INativeMultisig::AccountUpgraded::SIGNATURE_HASH))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_rpc_explicit_gate_and_invalid_config_preserve_root() -> eyre::Result<()> {
    for enabled in [false, true] {
        let mut env = environment_with_migration(enabled).await?;
        let root = OwnerKey::new(0x65, SignatureType::Secp256k1);
        let mut account = NativeAccount::new(0x21, 1);
        migration_config(&mut account, root.address());
        env.fund_account(account.address).await?;
        let mut invalid = account.config.clone();
        if enabled {
            invalid.threshold = 0;
        }
        let tx = account.transaction(&env, vec![upgrade(&invalid)]);
        let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
        let receipt = account.submit(&mut env, tx, signature, false).await?;
        assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
        assert!(
            receipt["logs"]
                .as_array()
                .unwrap()
                .iter()
                .all(|log| log["topics"][0]
                    != serde_json::json!(INativeMultisig::AccountUpgraded::SIGNATURE_HASH))
        );
        let tx = account.transaction(&env, vec![noop()]);
        let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
        account.submit(&mut env, tx, signature, true).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_rpc_rejects_extra_calls_and_inline_grants_before_side_effects()
-> eyre::Result<()> {
    let mut env = environment_with_migration(true).await?;
    let root = OwnerKey::new(0x66, SignatureType::Secp256k1);
    let mut account = NativeAccount::new(0x21, 1);
    migration_config(&mut account, root.address());
    env.fund_account(account.address).await?;
    let recipient = Address::repeat_byte(0x76);
    let before = ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
        .balanceOf(account.address)
        .call()
        .await?;
    for after in [false, true] {
        let transfer = create_transfer_call(DEFAULT_FEE_TOKEN, recipient, U256::from(1));
        let mut calls = vec![upgrade(&account.config)];
        if after {
            calls.push(transfer);
        } else {
            calls.insert(0, transfer);
        }
        let tx = account.transaction(&env, calls);
        let error = reject(
            &env,
            tx.clone(),
            TempoSignature::Primitive(root.sign(tx.signature_hash())?),
        )
        .await?;
        insta::assert_snapshot!(error, @"server returned an error response: error code -32003: invalid transaction: migration must be the sole call without authorizations");
    }
    let mut tx = account.transaction(&env, vec![upgrade(&account.config)]);
    let grant = KeyAuthorization::unrestricted(env.chain_id(), SignatureType::Secp256k1, recipient);
    tx.key_authorization = Some(
        grant
            .clone()
            .into_signed(root.sign(grant.signature_hash())?),
    );
    let error = reject(
        &env,
        tx.clone(),
        TempoSignature::Primitive(root.sign(tx.signature_hash())?),
    )
    .await?;
    insta::assert_snapshot!(error, @"server returned an error response: error code -32003: invalid transaction: migration must be the sole call without authorizations");
    let mut tx = account.transaction(&env, vec![upgrade(&account.config)]);
    let authorization = alloy::eips::eip7702::Authorization {
        chain_id: U256::from(env.chain_id()),
        address: recipient,
        nonce: 0,
    };
    let signature = TempoSignature::Primitive(root.sign(authorization.signature_hash())?);
    tx.tempo_authorization_list = vec![
        tempo_primitives::transaction::TempoSignedAuthorization::new_unchecked(
            authorization,
            signature,
        ),
    ];
    let error = reject(
        &env,
        tx.clone(),
        TempoSignature::Primitive(root.sign(tx.signature_hash())?),
    )
    .await?;
    insta::assert_snapshot!(error, @"server returned an error response: error code -32003: invalid transaction: migration must be the sole call without authorizations");
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    assert_eq!(
        env.provider()
            .get_transaction_count(account.address)
            .await?,
        0
    );
    assert_eq!(
        ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
            .balanceOf(account.address)
            .call()
            .await?,
        before
    );
    assert_eq!(
        ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
            .balanceOf(recipient)
            .call()
            .await?,
        U256::ZERO
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_rpc_sponsored_protocol_2d_and_expiring_nonces() -> eyre::Result<()> {
    let mut env = environment_with_migration(true).await?;
    for (seed, nonce_key) in [
        (0x67, U256::ZERO),
        (0x68, U256::from(7)),
        (0x69, TEMPO_EXPIRING_NONCE_KEY),
    ] {
        let root = OwnerKey::new(seed, SignatureType::Secp256k1);
        let mut account = NativeAccount::new(0x21, 1);
        migration_config(&mut account, root.address());
        let mut tx = account.transaction(&env, vec![upgrade(&account.config)]);
        tx.nonce_key = nonce_key;
        if nonce_key == TEMPO_EXPIRING_NONCE_KEY {
            tx.valid_before = std::num::NonZeroU64::new(
                env.provider()
                    .get_block_by_number(BlockNumberOrTag::Latest)
                    .await?
                    .unwrap()
                    .header
                    .timestamp
                    + 25,
            );
        }
        sign_fee_payer(&mut tx, root.address(), &env.funder_signer)?;
        let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
        let receipt = submit(&mut env, tx, signature, true).await?;
        assert_eq!(
            commitment(&env, root.address()).await?,
            account.config.commitment().unwrap()
        );
        assert_eq!(
            env.provider().get_transaction_count(root.address()).await?,
            u64::from(nonce_key.is_zero())
        );
        assert_eq!(
            ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
                .balanceOf(root.address())
                .call()
                .await?,
            U256::ZERO
        );
        assert_ne!(receipt["gasUsed"], serde_json::json!("0x0"));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_rpc_simulation_estimates_without_persisting_authority() -> eyre::Result<()> {
    let mut env = environment_with_migration(true).await?;
    let root = OwnerKey::new(0x6a, SignatureType::Secp256k1);
    let mut account = NativeAccount::new(0x21, 1);
    migration_config(&mut account, root.address());
    env.fund_account(account.address).await?;
    let call = upgrade(&account.config);
    let request = serde_json::json!({
        "type": "0x76", "from": account.address, "gas": "0x4c4b40",
        "feeToken": DEFAULT_FEE_TOKEN,
        "calls": [{"to": NATIVE_MULTISIG_ADDRESS, "data": call.input, "value": "0x0"}]
    });
    let estimated: U256 = env
        .provider()
        .raw_request("eth_estimateGas".into(), (request.clone(), "latest"))
        .await?;
    let returned: Bytes = env
        .provider()
        .raw_request("eth_call".into(), (request, "latest"))
        .await?;
    assert_eq!(
        INativeMultisig::upgradeAccountCall::abi_decode_returns(&returned)?,
        account.config.commitment().unwrap()
    );
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    assert_eq!(
        env.provider()
            .get_transaction_count(account.address)
            .await?,
        0
    );
    let mut tx = account.transaction(&env, vec![call]);
    tx.gas_limit = estimated.to();
    let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
    account.submit(&mut env, tx, signature, true).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_rpc_preserves_outgoing_grants_and_spent_limits() -> eyre::Result<()> {
    let mut env = environment_with_migration(true).await?;
    let root = OwnerKey::new(0x6b, SignatureType::Secp256k1);
    let delegate = OwnerKey::new(0x6c, SignatureType::Secp256k1);
    let mut account = NativeAccount::new(0x21, 1);
    migration_config(&mut account, root.address());
    env.fund_account(account.address).await?;
    let limit = U256::from(100_000_000_000u64);
    let grant = KeyAuthorization::unrestricted(
        env.chain_id(),
        SignatureType::Secp256k1,
        delegate.address(),
    )
    .with_limits(vec![TokenLimit {
        token: DEFAULT_FEE_TOKEN,
        limit,
        period: 0,
    }]);
    let mut tx = account.transaction(&env, vec![noop()]);
    tx.key_authorization = Some(
        grant
            .clone()
            .into_signed(root.sign(grant.signature_hash())?),
    );
    let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
    account.submit(&mut env, tx, signature, true).await?;
    let delegate_signature = |tx: &TempoTransaction| -> eyre::Result<TempoSignature> {
        Ok(TempoSignature::Keychain(KeychainSignature::new(
            account.address,
            delegate.sign(KeychainSignature::signing_hash(
                tx.signature_hash(),
                account.address,
            ))?,
        )))
    };
    // Build this separately to avoid retaining an immutable account borrow across submission.
    let tx = account.transaction(
        &env,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            Address::repeat_byte(0x77),
            U256::from(100),
        )],
    );
    let signature = delegate_signature(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
    let tx = account.transaction(&env, vec![upgrade(&account.config)]);
    let signature = delegate_signature(&tx)?;
    account.submit(&mut env, tx, signature, false).await?;
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, env.provider().clone());
    let before = keychain
        .getKey(account.address, delegate.address())
        .call()
        .await?;
    let remaining = keychain
        .getRemainingLimitWithPeriod(account.address, delegate.address(), DEFAULT_FEE_TOKEN)
        .call()
        .await?
        .remaining;
    assert!(remaining < limit);
    let request = serde_json::json!({
        "type": "0x76", "from": account.address, "keyId": delegate.address(),
        "gas": "0x4c4b40", "feeToken": DEFAULT_FEE_TOKEN,
        "calls": [{"to": Address::repeat_byte(0x79), "data": "0x", "value": "0x0"}]
    });
    for migrated in [false, true] {
        if migrated {
            let tx = account.transaction(&env, vec![upgrade(&account.config)]);
            let signature = TempoSignature::Primitive(root.sign(tx.signature_hash())?);
            account.submit(&mut env, tx, signature, true).await?;
        }
        let _: U256 = env
            .provider()
            .raw_request("eth_estimateGas".into(), (request.clone(), "latest"))
            .await?;
        let _: Bytes = env
            .provider()
            .raw_request("eth_call".into(), (request.clone(), "latest"))
            .await?;
        assert_eq!(
            keychain
                .getRemainingLimitWithPeriod(account.address, delegate.address(), DEFAULT_FEE_TOKEN)
                .call()
                .await?
                .remaining,
            remaining
        );
    }
    assert_eq!(
        keychain
            .getKey(account.address, delegate.address())
            .call()
            .await?,
        before
    );
    assert_eq!(
        keychain
            .getRemainingLimitWithPeriod(account.address, delegate.address(), DEFAULT_FEE_TOKEN)
            .call()
            .await?
            .remaining,
        remaining
    );
    let tx = account.transaction(
        &env,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            Address::repeat_byte(0x77),
            U256::from(100),
        )],
    );
    let signature = TempoSignature::Keychain(KeychainSignature::new(
        account.address,
        delegate.sign(KeychainSignature::signing_hash(
            tx.signature_hash(),
            account.address,
        ))?,
    ));
    account.submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        keychain
            .getKey(account.address, delegate.address())
            .call()
            .await?,
        before
    );
    assert!(
        keychain
            .getRemainingLimitWithPeriod(account.address, delegate.address(), DEFAULT_FEE_TOKEN)
            .call()
            .await?
            .remaining
            < remaining
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_rpc_incoming_grants_preserve_limits_scopes_and_revocation() -> eyre::Result<()> {
    let mut env = environment_with_migration(true).await?;
    for (seed, kind) in [
        (0x81, SignatureType::Secp256k1),
        (0x82, SignatureType::P256),
        (0x83, SignatureType::WebAuthn),
    ] {
        let parent_root = OwnerKey::new(seed + 3, SignatureType::Secp256k1);
        let delegate_root = OwnerKey::new(seed, kind);
        let mut parent = NativeAccount::new(0x21, 1);
        migration_config(&mut parent, parent_root.address());
        let mut delegate = NativeAccount::new(0x31, 2);
        migration_config(&mut delegate, delegate_root.address());
        env.fund_account(parent.address).await?;
        env.fund_account(delegate.address).await?;
        let recipient = Address::repeat_byte(0x91);
        let grant = KeyAuthorization::unrestricted(env.chain_id(), kind, delegate.address)
            .with_limits(vec![TokenLimit {
                token: DEFAULT_FEE_TOKEN,
                limit: U256::from(1_000),
                period: 0,
            }])
            .with_allowed_calls(vec![tempo_primitives::transaction::CallScope {
                target: DEFAULT_FEE_TOKEN,
                selector_rules: vec![tempo_primitives::transaction::SelectorRule {
                    selector: ITIP20::transferCall::SELECTOR,
                    recipients: vec![recipient],
                }],
            }]);
        let mut tx = parent.transaction(&env, vec![noop()]);
        tx.key_authorization = Some(
            grant
                .clone()
                .into_signed(parent_root.sign(grant.signature_hash())?),
        );
        let signature = TempoSignature::Primitive(parent_root.sign(tx.signature_hash())?);
        parent.submit(&mut env, tx, signature, true).await?;
        let mut tx = parent.transaction(
            &env,
            vec![create_transfer_call(
                DEFAULT_FEE_TOKEN,
                recipient,
                U256::from(100),
            )],
        );
        sign_fee_payer(&mut tx, parent.address, &env.funder_signer)?;
        let signature = TempoSignature::Keychain(KeychainSignature::new(
            parent.address,
            delegate_root.sign(KeychainSignature::signing_hash(
                tx.signature_hash(),
                parent.address,
            ))?,
        ));
        parent.submit(&mut env, tx, signature, true).await?;
        let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, env.provider().clone());
        let before = keychain
            .getKey(parent.address, delegate.address)
            .call()
            .await?;
        let scopes = keychain
            .getAllowedCalls(parent.address, delegate.address)
            .call()
            .await?;
        assert_eq!(
            keychain
                .getRemainingLimit(parent.address, delegate.address, DEFAULT_FEE_TOKEN)
                .call()
                .await?,
            U256::from(900)
        );
        let tx = delegate.transaction(&env, vec![upgrade(&delegate.config)]);
        let signature = TempoSignature::Primitive(delegate_root.sign(tx.signature_hash())?);
        delegate.submit(&mut env, tx, signature, true).await?;
        assert_eq!(
            keychain
                .getKey(parent.address, delegate.address)
                .call()
                .await?,
            before
        );
        assert_eq!(
            keychain
                .getAllowedCalls(parent.address, delegate.address)
                .call()
                .await?,
            scopes
        );
        assert_eq!(
            keychain
                .getRemainingLimit(parent.address, delegate.address, DEFAULT_FEE_TOKEN)
                .call()
                .await?,
            U256::from(900)
        );
        let mut tx = parent.transaction(
            &env,
            vec![create_transfer_call(
                DEFAULT_FEE_TOKEN,
                recipient,
                U256::from(100),
            )],
        );
        sign_fee_payer(&mut tx, parent.address, &env.funder_signer)?;
        let old_signature = TempoSignature::Keychain(KeychainSignature::new(
            parent.address,
            delegate_root.sign(KeychainSignature::signing_hash(
                tx.signature_hash(),
                parent.address,
            ))?,
        ));
        let error = reject(&env, tx.clone(), old_signature).await?;
        insta::assert_snapshot!(error.replace(&delegate.address.to_string(), "ACCOUNT"), @"server returned an error response: error code -32003: invalid transaction: primitive root key retired for account ACCOUNT");
        let signature = delegate.as_delegate(&tx, parent.address, false)?;
        parent.submit(&mut env, tx, signature, true).await?;
        assert_eq!(
            keychain
                .getRemainingLimit(parent.address, delegate.address, DEFAULT_FEE_TOKEN)
                .call()
                .await?,
            U256::from(800)
        );
        let mut tx = parent.transaction(
            &env,
            vec![create_transfer_call(
                DEFAULT_FEE_TOKEN,
                Address::repeat_byte(0x92),
                U256::from(1),
            )],
        );
        sign_fee_payer(&mut tx, parent.address, &env.funder_signer)?;
        let signature = delegate.as_delegate(&tx, parent.address, false)?;
        parent.submit(&mut env, tx, signature, false).await?;
        assert_eq!(
            keychain
                .getRemainingLimit(parent.address, delegate.address, DEFAULT_FEE_TOKEN)
                .call()
                .await?,
            U256::from(800)
        );
        assert_eq!(
            ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
                .balanceOf(Address::repeat_byte(0x92))
                .call()
                .await?,
            U256::ZERO
        );
        let revoke = Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: IAccountKeychain::revokeKeyCall {
                keyId: delegate.address,
            }
            .abi_encode()
            .into(),
        };
        let tx = parent.transaction(&env, vec![revoke]);
        let signature = TempoSignature::Primitive(parent_root.sign(tx.signature_hash())?);
        parent.submit(&mut env, tx, signature, true).await?;
        let mut tx = parent.transaction(
            &env,
            vec![create_transfer_call(
                DEFAULT_FEE_TOKEN,
                recipient,
                U256::from(1),
            )],
        );
        sign_fee_payer(&mut tx, parent.address, &env.funder_signer)?;
        let signature = delegate.as_delegate(&tx, parent.address, false)?;
        let error = reject(&env, tx, signature).await?;
        insta::assert_snapshot!("migration_revoked_incoming_grant", error);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_rpc_incoming_admin_grant_authorizes_native_sidecars() -> eyre::Result<()> {
    let mut env = environment_with_migration(true).await?;
    let parent_root = OwnerKey::new(0x94, SignatureType::Secp256k1);
    let delegate_root = OwnerKey::new(0x95, SignatureType::Secp256k1);
    let mut parent = NativeAccount::new(0x21, 1);
    migration_config(&mut parent, parent_root.address());
    let mut delegate = NativeAccount::new(0x31, 2);
    migration_config(&mut delegate, delegate_root.address());
    env.fund_account(parent.address).await?;
    env.fund_account(delegate.address).await?;
    let grant =
        KeyAuthorization::unrestricted(env.chain_id(), SignatureType::Secp256k1, delegate.address)
            .into_admin(parent.address);
    let mut tx = parent.transaction(&env, vec![noop()]);
    tx.key_authorization = Some(
        grant
            .clone()
            .into_signed(parent_root.sign(grant.signature_hash())?),
    );
    let signature = TempoSignature::Primitive(parent_root.sign(tx.signature_hash())?);
    parent.submit(&mut env, tx, signature, true).await?;
    let tx = delegate.transaction(&env, vec![upgrade(&delegate.config)]);
    let signature = TempoSignature::Primitive(delegate_root.sign(tx.signature_hash())?);
    delegate.submit(&mut env, tx, signature, true).await?;
    let child = OwnerKey::new(0x96, SignatureType::Secp256k1);
    let grant =
        KeyAuthorization::unrestricted(env.chain_id(), SignatureType::Secp256k1, child.address())
            .with_account(parent.address);
    let mut tx = parent.transaction(&env, vec![noop()]);
    tx.key_authorization = Some(
        grant
            .clone()
            .into_signed(delegate.quorum(grant.signature_hash(), false)?),
    );
    let signature = delegate.as_delegate(&tx, parent.address, false)?;
    parent.submit(&mut env, tx, signature, true).await?;
    let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, env.provider().clone());
    assert_eq!(
        keychain
            .getKey(parent.address, child.address())
            .call()
            .await?
            .keyId,
        child.address()
    );
    let mut tx = parent.transaction(&env, vec![noop()]);
    let grant = KeyAuthorization::unrestricted(
        env.chain_id(),
        SignatureType::Secp256k1,
        Address::repeat_byte(0x97),
    )
    .with_account(parent.address);
    tx.key_authorization = Some(
        grant
            .clone()
            .into_signed(delegate_root.sign(grant.signature_hash())?),
    );
    let signature = delegate.as_delegate(&tx, parent.address, false)?;
    assert!(reject(&env, tx, signature).await.is_ok());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_rpc_retired_root_cannot_delegate_code_or_sponsor() -> eyre::Result<()> {
    let mut env = environment_with_migration(true).await?;
    let root = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x98))?;
    let mut account = NativeAccount::new(0x21, 1);
    migration_config(&mut account, root.address());
    env.fund_account(account.address).await?;
    let tx = account.transaction(&env, vec![upgrade(&account.config)]);
    let signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        root.sign_hash_sync(&tx.signature_hash())?,
    ));
    account.submit(&mut env, tx, signature, true).await?;
    let authorization = alloy::eips::eip7702::Authorization {
        chain_id: U256::from(env.chain_id()),
        address: OBSERVER,
        nonce: account.nonce,
    };
    let signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        root.sign_hash_sync(&authorization.signature_hash())?,
    ));
    let nonce = env
        .provider()
        .get_transaction_count(env.funder_addr)
        .await?;
    let mut tx = create_basic_aa_tx(env.chain_id(), nonce, vec![noop()], GAS_LIMIT);
    tx.tempo_authorization_list = vec![
        tempo_primitives::transaction::TempoSignedAuthorization::new_unchecked(
            authorization,
            signature,
        ),
    ];
    let signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        env.funder_signer.sign_hash_sync(&tx.signature_hash())?,
    ));
    submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        env.provider().get_code_at(account.address).await?,
        Bytes::new()
    );
    assert_eq!(
        env.provider()
            .get_transaction_count(account.address)
            .await?,
        account.nonce
    );
    assert_eq!(
        commitment(&env, account.address).await?,
        account.config.commitment().unwrap()
    );
    let nonce = env
        .provider()
        .get_transaction_count(env.funder_addr)
        .await?;
    let mut tx = create_basic_aa_tx(env.chain_id(), nonce, vec![noop()], GAS_LIMIT);
    sign_fee_payer(&mut tx, env.funder_addr, &root)?;
    let signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        env.funder_signer.sign_hash_sync(&tx.signature_hash())?,
    ));
    let error = reject(&env, tx, signature).await?;
    insta::assert_snapshot!(error.replace(&account.address.to_string(), "ACCOUNT"), @"server returned an error response: error code -32003: invalid transaction: primitive root key retired for account ACCOUNT");
    Ok(())
}
