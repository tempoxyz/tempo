use super::*;
use crate::tempo_transaction::helpers::{create_transfer_call, sign_fee_payer};
use alloy_eips::Decodable2718;
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, DEFAULT_FEE_TOKEN, IAccountKeychain, ITIP20,
};
use tempo_primitives::{
    SignatureType,
    transaction::{KeyAuthorization, TokenLimit},
};

#[tokio::test(flavor = "multi_thread")]
async fn native_rpc_registration_revert_retry_and_rotation() -> eyre::Result<()> {
    let mut env = environment().await?;
    let mut account = NativeAccount::new(0x11, 2);
    env.fund_account(account.address).await?;
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    let request = account.simulation_request();
    let simulated: Bytes = env
        .provider()
        .raw_request("eth_call".into(), (request.clone(), "latest"))
        .await?;
    assert_eq!(
        simulated.as_ref(),
        account.config.commitment().unwrap().as_slice()
    );
    let estimate: U256 = env
        .provider()
        .raw_request("eth_estimateGas".into(), (request, "latest"))
        .await?;
    assert!(estimate > U256::ZERO);
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    let before = ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
        .balanceOf(account.address)
        .call()
        .await?;

    let tx = account.transaction(
        &env,
        vec![Call {
            to: NATIVE_MULTISIG_ADDRESS.into(),
            value: U256::ZERO,
            input: Bytes::from_static(&[0xff, 0xff, 0xff, 0xff]),
        }],
    );
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, false).await?;
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
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
            value: U256::ZERO,
            input: Bytes::new(),
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

    let replacement = NativeAccount::new(0x21, 2);
    let (next, rotate) = account.rotate_to(&replacement);
    let tx = account.transaction(&env, vec![rotate]);
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        commitment(&env, account.address).await?,
        next.commitment().unwrap()
    );
    let tx = account.transaction(&env, vec![noop()]);
    assert!(
        reject(&env, tx.clone(), account.sign(&tx)?)
            .await?
            .contains("commitment mismatch")
    );
    account.config = next;
    account.owners = replacement.owners;
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn native_rpc_historical_state_and_account_overrides() -> eyre::Result<()> {
    let mut env = environment().await?;
    let mut account = NativeAccount::new(0x18, 2);
    env.fund_account(account.address).await?;
    let tx = account.transaction(&env, vec![noop()]);
    let signature = account.sign(&tx)?;
    let receipt = account.submit(&mut env, tx, signature, true).await?;
    let historical_block = receipt["blockNumber"].as_str().unwrap().to_owned();
    let initial = account.config.commitment().unwrap();
    let old_request = account.simulation_request();

    let replacement = NativeAccount::new(0x28, 2);
    let (next, rotate) = account.rotate_to(&replacement);
    let tx = account.transaction(&env, vec![rotate]);
    let signature = account.sign(&tx)?;
    account.submit(&mut env, tx, signature, true).await?;
    let current = next.commitment().unwrap();
    let historical: Bytes = env
        .provider()
        .raw_request(
            "eth_call".into(),
            (old_request.clone(), historical_block.clone()),
        )
        .await?;
    assert_eq!(historical.as_ref(), initial.as_slice());
    let stale = env
        .provider()
        .raw_request::<_, Bytes>("eth_call".into(), (old_request.clone(), "latest"))
        .await
        .unwrap_err()
        .to_string();
    assert!(stale.contains("commitment mismatch"), "{stale}");
    assert!(stale.contains(&initial.to_string()), "{stale}");
    assert!(stale.contains(&current.to_string()), "{stale}");
    let historical_gas: U256 = env
        .provider()
        .raw_request("eth_estimateGas".into(), (old_request, historical_block))
        .await?;
    assert!(historical_gas > U256::ZERO);

    account.config = next;
    account.owners = replacement.owners;
    let request = account.simulation_request();
    // Ordinary account overrides must merge with, rather than erase, the stored extension.
    let overrides = serde_json::json!({
        account.address.to_string(): {
            "balance": "0x1", "nonce": "0x9",
            "stateDiff": {B256::ZERO.to_string(): B256::repeat_byte(0x42)}
        }
    });
    let overridden: Bytes = env
        .provider()
        .raw_request("eth_call".into(), (request.clone(), "latest", overrides))
        .await?;
    assert_eq!(overridden.as_ref(), current.as_slice());
    let code_override = serde_json::json!({account.address.to_string(): {"code": "0x00"}});
    let error = env
        .provider()
        .raw_request::<_, Bytes>("eth_call".into(), (request, "latest", code_override))
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
async fn native_rpc_fill_and_access_list_preserve_authority() -> eyre::Result<()> {
    let mut env = environment().await?;
    let account = NativeAccount::new(0x19, 2);
    env.fund_account(account.address).await?;
    let mut request = account.simulation_request();
    request["to"] = serde_json::json!(OBSERVER);
    request["data"] = serde_json::json!("0x");
    let access: serde_json::Value = env
        .provider()
        .raw_request("eth_createAccessList".into(), (request.clone(), "latest"))
        .await?;
    assert!(
        access.get("error").is_none_or(serde_json::Value::is_null),
        "{access}"
    );
    let entries = access["accessList"].as_array().unwrap();
    assert!(
        entries.iter().any(|entry| {
            entry["address"] == serde_json::json!(OBSERVER)
                && entry["storageKeys"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!(B256::ZERO))
        }),
        "{access}"
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
    let grant = grant.into_signed(TempoSignature::Multisig(signature));
    request["keyAuthorization"] = serde_json::to_value(&grant)?;
    let filled: serde_json::Value = env
        .provider()
        .raw_request("eth_fillTransaction".into(), (request.clone(),))
        .await?;
    let tx = crate::tempo_transaction::helpers::parse_filled_tx(&filled)?;
    assert_eq!(tx.key_authorization.as_ref(), Some(&grant));
    assert_eq!(tx.nonce, 0);
    assert_eq!(tx.chain_id, env.chain_id());
    assert_eq!(tx.calls[0].to, OBSERVER.into());
    let raw: Bytes = serde_json::from_value(filled["raw"].clone())?;
    let TempoTxEnvelope::AA(unsigned) = TempoTxEnvelope::decode_2718(&mut raw.as_ref())? else {
        panic!("configurable fill must retain the AA transaction type");
    };
    assert_eq!(unsigned.tx().key_authorization.as_ref(), Some(&grant));
    assert_eq!(unsigned.signature(), &TempoSignature::default());
    for field in [
        "multisigSimulation",
        "keyAuthorizationSimulation",
        "multisigSimulationSignature",
    ] {
        assert!(filled["tx"].get(field).is_none(), "{filled}");
    }
    request["keyAuthorizationSimulation"] = request["multisigSimulation"].clone();
    let error = env
        .provider()
        .raw_request::<_, serde_json::Value>("eth_fillTransaction".into(), (request,))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("real signed grant"), "{error}");
    assert_eq!(commitment(&env, account.address).await?, B256::ZERO);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn native_rpc_delegate_rotation_preserves_grant_and_spending() -> eyre::Result<()> {
    let mut env = environment().await?;
    let mut parent = NativeAccount::new(0x31, 2);
    let mut delegate = NativeAccount::new(0x41, 2);
    env.fund_account(parent.address).await?;
    env.fund_account(delegate.address).await?;
    let limit = U256::from(100_000_000_000u64);
    let grant =
        KeyAuthorization::unrestricted(env.chain_id(), SignatureType::Multisig, delegate.address)
            .with_account(parent.address)
            .with_limits(vec![TokenLimit {
                token: DEFAULT_FEE_TOKEN,
                limit,
                period: 0,
            }]);
    let grant_signature = TempoSignature::Multisig(parent.quorum(grant.signature_hash(), false)?);
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

    let replacement = NativeAccount::new(0x51, 2);
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
    assert!(
        reject(
            &env,
            tx.clone(),
            delegate.as_delegate(&tx, parent.address, false)?
        )
        .await?
        .contains("commitment mismatch")
    );
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
async fn native_rpc_maximum_mixed_quorums_and_validation_cost_order() -> eyre::Result<()> {
    let mut env = environment().await?;
    let mut parent = NativeAccount::new(0x61, 8);
    let delegate = NativeAccount::new(0x81, 8);
    let grant =
        KeyAuthorization::unrestricted(env.chain_id(), SignatureType::Multisig, delegate.address)
            .with_account(parent.address);
    let grant_signature = TempoSignature::Multisig(parent.quorum(grant.signature_hash(), false)?);
    let mut tx = parent.transaction(&env, vec![noop()]);
    tx.key_authorization = Some(grant.clone().into_signed(TempoSignature::Multisig(
        parent.quorum(grant.signature_hash(), true)?,
    )));

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
    let error = reject(
        &env,
        tx.clone(),
        delegate.as_delegate(&tx, parent.address, false)?,
    )
    .await?;
    assert!(
        error.contains("fund") || error.contains("balance"),
        "{error}"
    );
    env.fund_account(parent.address).await?;
    let error = reject(
        &env,
        tx.clone(),
        delegate.as_delegate(&tx, parent.address, false)?,
    )
    .await?;
    let expected = match parent.owners.last().unwrap() {
        OwnerKey::Secp(_) => tempo_revm::native_multisig::NativeMultisigError::Quorum(
            tempo_primitives::transaction::MultisigQuorumError::SignerNotOwner,
        ),
        OwnerKey::P256 { .. } => {
            tempo_revm::native_multisig::NativeMultisigError::OwnerSignatureRecoveryFailed {
                approval_index: 7,
            }
        }
    }
    .to_string();
    assert!(
        error.contains(&expected),
        "expected signature16 failure {expected}, got {error}"
    );
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
