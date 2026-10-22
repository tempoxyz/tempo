//! Zones reject configurable accounts until they sync configurations from Tempo (TIP-1114 Zones).

use alloy::{
    genesis::GenesisAccount,
    primitives::{Address, B256, Bytes, Signature, TxKind, U256, hex},
    rpc::types::TransactionRequest,
};
use alloy_eips::{eip2718::Encodable2718, eip2930::AccessList};
use alloy_provider::Provider;
use alloy_signer::SignerSync;
use alloy_sol_types::{SolCall, SolError};
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, CONFIGURABLE_ACCOUNT_ADDRESS, IAccountKeychain, IConfigurableAccount,
};
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        Call, ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        KeyAuthorization, KeychainSignature, PrimitiveSignature, SignatureType,
        SignedKeyAuthorization, TempoSignature, TempoTransaction,
    },
};

use crate::utils::{
    DEFAULT_TIMEOUT, l1_dev_signer, local_dev_zone_account,
    start_local_zone_with_fixture_and_withdrawal_batch_interval,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_configurable_accounts_are_rejected() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Zones cannot deploy contracts, so genesis carries one that forwards its calldata to the
    // configurable account precompile and bubbles up the outcome.
    let forwarder = Address::repeat_byte(0xfd);
    let forwarder_code = [
        &hex!("365f5f375f5f365f5f73")[..],
        CONFIGURABLE_ACCOUNT_ADDRESS.as_slice(),
        &hex!("5af13d5f5f3e602a573d5ffd5b3d5ff3"),
    ]
    .concat();
    let mut genesis = zone_node::genesis::genesis_template()?;
    genesis.alloc.insert(
        forwarder,
        GenesisAccount::default().with_code(Some(forwarder_code.into())),
    );
    let (zone, mut fixture) =
        start_local_zone_with_fixture_and_withdrawal_batch_interval(1114, 10, 8, genesis).await?;
    let (provider, dev_address) = local_dev_zone_account(&zone)?;
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev_address, dev_address, 1_000_000);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev_address,
        U256::from(1_000_000u128),
        DEFAULT_TIMEOUT,
    )
    .await?;

    let root = l1_dev_signer();
    let chain_id = provider.get_chain_id().await?;
    let next_nonce = provider.get_transaction_count(dev_address).await?;
    let delegate = Address::repeat_byte(0x66);
    // Zones reject before the owner quorum is checked, so the approval only needs a valid shape.
    let configurable = ConfigurableAccountSignature::try_new(
        delegate,
        ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![ConfigurableAccountOwner {
                owner: dev_address,
                weight: 1,
            }],
        },
        vec![PrimitiveSignature::Secp256k1(Signature::new(
            U256::ONE,
            U256::from(2),
            false,
        ))],
    )
    .expect("the witness has a valid shape");
    let delegate_grant =
        KeyAuthorization::unrestricted(chain_id, SignatureType::ConfigurableAccount, delegate);
    let delegate_grant_signature = root.sign_hash_sync(&delegate_grant.signature_hash())?;
    let configurable_grant = KeyAuthorization::unrestricted(
        chain_id,
        SignatureType::Secp256k1,
        Address::repeat_byte(0x77),
    )
    .into_signed(configurable.clone());

    let noop = vec![Call {
        to: TxKind::Call(dev_address),
        value: U256::ZERO,
        input: Bytes::new(),
    }];
    let owners = vec![IConfigurableAccount::ConfigurableAccountOwner {
        owner: delegate,
        weight: 1,
    }];
    let upgrade_account_input = Bytes::from(
        IConfigurableAccount::upgradeAccountCall {
            threshold: 1,
            owners: owners.clone(),
        }
        .abi_encode(),
    );
    let upgrade_account = vec![Call {
        to: TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS),
        value: U256::ZERO,
        input: upgrade_account_input.clone(),
    }];
    // Each case takes its own nonce so a case the pool accepts cannot shadow the next one.
    let transaction =
        |nonce, calls, key_authorization: Option<SignedKeyAuthorization>| TempoTransaction {
            chain_id,
            fee_token: Some(PATH_USD_ADDRESS),
            max_priority_fee_per_gas: u128::from(TEMPO_T0_BASE_FEE),
            max_fee_per_gas: u128::from(TEMPO_T0_BASE_FEE),
            gas_limit: 1_000_000,
            calls,
            access_list: AccessList(vec![]),
            nonce_key: U256::ZERO,
            nonce,
            fee_payer_signature: None,
            valid_before: None,
            valid_after: None,
            key_authorization,
            tempo_authorization_list: vec![],
        };
    let root_signed = |transaction: TempoTransaction| -> eyre::Result<TempoTxEnvelope> {
        let signature = root.sign_hash_sync(&transaction.signature_hash())?;
        Ok(transaction.into_signed(signature.into()).into())
    };

    let cases: [(&str, TempoTxEnvelope); 5] = [
        (
            "configurable account key authorization",
            root_signed(transaction(
                next_nonce,
                noop.clone(),
                Some(delegate_grant.into_signed(delegate_grant_signature)),
            ))?,
        ),
        (
            "key authorization signed by a configurable account",
            root_signed(transaction(
                next_nonce + 1,
                noop.clone(),
                Some(configurable_grant),
            ))?,
        ),
        (
            "upgradeAccount",
            root_signed(transaction(next_nonce + 2, upgrade_account, None))?,
        ),
        (
            "configurable account signature",
            transaction(next_nonce + 3, noop.clone(), None)
                .into_signed(TempoSignature::ConfigurableAccount(configurable.clone()))
                .into(),
        ),
        (
            "keychain-wrapped configurable account signature",
            transaction(next_nonce + 4, noop, None)
                .into_signed(TempoSignature::Keychain(KeychainSignature::new(
                    dev_address,
                    configurable,
                )))
                .into(),
        ),
    ];
    let mut mismatches = Vec::new();
    for (case, envelope) in cases {
        let outcome = match provider
            .send_raw_transaction(&envelope.encoded_2718())
            .await
        {
            Ok(_) => "accepted".to_string(),
            Err(err) => format!("{err:#}"),
        };
        if !outcome.contains("configurable account is unavailable in this execution context") {
            mismatches.push(format!("{case}: {outcome}"));
        }
    }

    // Granting a configurable delegate through the keychain reverts, as does a contract's nested
    // update or migration, while views stay available.
    let restrictions = IAccountKeychain::KeyRestrictions {
        expiry: u64::MAX,
        enforceLimits: false,
        limits: vec![],
        allowAnyCalls: true,
        allowedCalls: vec![],
    };
    let authorize_key_input = IAccountKeychain::authorizeKey_1Call {
        keyId: delegate,
        signatureType: IAccountKeychain::SignatureType::ConfigurableAccount,
        config: restrictions.clone(),
    }
    .abi_encode();
    let authorize_key_with_witness_input = IAccountKeychain::authorizeKey_2Call {
        keyId: delegate,
        signatureType: IAccountKeychain::SignatureType::ConfigurableAccount,
        config: restrictions,
        witness: B256::ZERO,
    }
    .abi_encode();
    let authorize_admin_key_input = IAccountKeychain::authorizeAdminKeyCall {
        keyId: delegate,
        signatureType: IAccountKeychain::SignatureType::ConfigurableAccount,
        witness: B256::ZERO,
    }
    .abi_encode();
    let update_config_input = IConfigurableAccount::updateConfigCall {
        current: IConfigurableAccount::ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        },
        threshold: 1,
        owners,
    }
    .abi_encode();
    let invalid_signature_type =
        Bytes::from(IAccountKeychain::InvalidSignatureType {}.abi_encode());
    let unauthorized =
        Bytes::from(IConfigurableAccount::UnauthorizedConfigurableAccountCaller {}.abi_encode());
    for (case, to, input, revert) in [
        (
            "authorizeKey",
            ACCOUNT_KEYCHAIN_ADDRESS,
            authorize_key_input,
            &invalid_signature_type,
        ),
        (
            "authorizeKey with witness",
            ACCOUNT_KEYCHAIN_ADDRESS,
            authorize_key_with_witness_input,
            &invalid_signature_type,
        ),
        (
            "authorizeAdminKey",
            ACCOUNT_KEYCHAIN_ADDRESS,
            authorize_admin_key_input,
            &invalid_signature_type,
        ),
        (
            "nested upgradeAccount",
            forwarder,
            upgrade_account_input.to_vec(),
            &unauthorized,
        ),
        (
            "nested updateConfig",
            forwarder,
            update_config_input,
            &unauthorized,
        ),
    ] {
        let outcome = provider
            .call(
                TransactionRequest::default()
                    .from(dev_address)
                    .to(to)
                    .input(Bytes::from(input).into()),
            )
            .await;
        if !outcome.as_ref().is_err_and(|err| {
            err.as_error_resp()
                .and_then(|payload| payload.as_revert_data())
                .as_ref()
                == Some(revert)
        }) {
            mismatches.push(format!("{case}: {outcome:?}"));
        }
    }
    let commitment = IConfigurableAccount::new(CONFIGURABLE_ACCOUNT_ADDRESS, &provider)
        .getConfigCommitment(dev_address)
        .call()
        .await;
    if !commitment
        .as_ref()
        .is_ok_and(|commitment| commitment.is_zero())
    {
        mismatches.push(format!("getConfigCommitment: {commitment:?}"));
    }

    assert!(mismatches.is_empty(), "not rejected: {mismatches:#?}");
    Ok(())
}
