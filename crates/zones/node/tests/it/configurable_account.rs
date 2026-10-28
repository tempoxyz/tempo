//! Zones reject configurable accounts until they sync configurations from Tempo (TIP-1114 Zones).

use alloy::primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use alloy_eips::{eip2718::Encodable2718, eip2930::AccessList};
use alloy_provider::Provider;
use alloy_signer::SignerSync;
use alloy_sol_types::SolCall;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount};
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        Call, ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        PrimitiveSignature, TempoSignature, TempoTransaction,
    },
};

use crate::utils::{
    DEFAULT_TIMEOUT, l1_dev_signer, local_dev_zone_account,
    start_local_zone_with_fixture_and_withdrawal_batch_interval,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_configurable_accounts_are_rejected() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let genesis = zone_node::genesis::genesis_template()?;
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
    let update_config_input = Bytes::from(
        IConfigurableAccount::updateConfigCall {
            current: IConfigurableAccount::ConfigurableAccountConfig {
                salt: B256::ZERO,
                version: 0,
                threshold: 1,
                owners: owners.clone(),
            },
            threshold: 1,
            owners,
        }
        .abi_encode(),
    );
    let call = |to, input| {
        vec![Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input,
        }]
    };

    // A case without its own signature is signed by the root key. Each case takes its own nonce
    // so a case the pool accepts cannot shadow the next one.
    let cases = [
        (
            "configurable account signature",
            call(dev_address, Bytes::new()),
            Some(TempoSignature::ConfigurableAccount(configurable)),
        ),
        (
            "upgradeAccount transaction",
            call(CONFIGURABLE_ACCOUNT_ADDRESS, upgrade_account_input),
            None,
        ),
        (
            "updateConfig transaction",
            call(CONFIGURABLE_ACCOUNT_ADDRESS, update_config_input),
            None,
        ),
    ];
    let mut mismatches = Vec::new();
    for (nonce, (case, calls, signature)) in (next_nonce..).zip(cases) {
        let transaction = TempoTransaction {
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
            key_authorization: None,
            tempo_authorization_list: vec![],
        };
        let signature = match signature {
            Some(signature) => signature,
            None => root.sign_hash_sync(&transaction.signature_hash())?.into(),
        };
        let envelope: TempoTxEnvelope = transaction.into_signed(signature).into();
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

    assert!(mismatches.is_empty(), "not rejected: {mismatches:#?}");
    Ok(())
}
