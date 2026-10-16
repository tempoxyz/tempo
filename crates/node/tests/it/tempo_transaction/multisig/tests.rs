use super::*;
use crate::tempo_transaction::helpers::{create_transfer_call, parse_filled_tx, sign_fee_payer};
use alloy::rpc::types::state::StateOverridesBuilder;
use alloy_eips::{BlockId, Decodable2718};
use serde_json::{from_value, json};
use tempo_contracts::precompiles::{ACCOUNT_KEYCHAIN_ADDRESS, IAccountKeychain, ITIP20};
use tempo_primitives::{
    account::encode_config_commitment,
    transaction::{KeyAuthorization, MultisigQuorumError, TokenLimit},
};
use tempo_revm::native_multisig::NativeMultisigError;

#[tokio::test(flavor = "multi_thread")]
async fn native_rpc_registration_revert_retry_and_rotation() -> eyre::Result<()> {
    let mut env = environment().await?;
    let mut account = NativeAccount::new(0x11, 2);
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
            to: NATIVE_MULTISIG_ADDRESS.into(),
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
    let historical_block = BlockId::number(receipt.block_number().unwrap());
    let provider = tempo_provider(&env);
    let initial = account.config.commitment().unwrap();
    let old_request = account.simulation_request();

    let replacement = NativeAccount::new(0x28, 2);
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
        .unwrap_err()
        .to_string();
    assert!(stale.contains("commitment mismatch"), "{stale}");
    assert!(stale.contains(&initial.to_string()), "{stale}");
    assert!(stale.contains(&current.to_string()), "{stale}");
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
async fn native_rpc_fill_and_access_list_preserve_authority() -> eyre::Result<()> {
    let mut env = environment().await?;
    let mut account = NativeAccount::new(0x19, 3);
    env.fund_account(account.address).await?;
    let provider = tempo_provider(&env);
    let mut request = account.simulation_request();
    // Model the same algorithms and WebAuthn length that will be submitted.
    request
        .multisig_simulation
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
            Ok(MultisigSimulationApproval {
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
        "multisigSimulation",
        "keyAuthorizationSimulation",
        "multisigSimulationSignature",
    ] {
        assert!(filled["tx"].get(field).is_none(), "{filled}");
    }
    request.key_authorization_simulation = request.multisig_simulation.clone();
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
        OwnerKey::Secp(_) => NativeMultisigError::Quorum(MultisigQuorumError::SignerNotOwner),
        OwnerKey::P256 { .. } => {
            NativeMultisigError::OwnerSignatureRecoveryFailed { approval_index: 7 }
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
