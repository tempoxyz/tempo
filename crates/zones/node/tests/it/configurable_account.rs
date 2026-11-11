//! Zones read configurable accounts from Tempo and never update them (TIP-1154).

use alloy::{
    network::ReceiptResponse as _,
    primitives::{Address, B256, Bytes, TxKind, U256},
};
use alloy_eips::eip2718::Encodable2718;
use alloy_provider::{DynProvider, PendingTransactionBuilder, Provider};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    TempoTxEnvelope,
    account::CONFIGURABLE_ACCOUNT_CODE,
    transaction::{
        Call, ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        PrimitiveSignature, TempoSignature, TempoTransaction, configurable_account_digest,
    },
};

use crate::utils::{
    DEFAULT_TIMEOUT, L1Fixture, ZoneTestNode, l1_dev_signer, local_dev_tempo_zone_account,
    start_local_zone_with_fixture_and_withdrawal_batch_interval,
};
use zone_primitives::constants::ZONE_OUTBOX_ADDRESS;

/// A zone whose dev account holds pathUSD, with its provider and address.
async fn funded_zone() -> eyre::Result<(ZoneTestNode, L1Fixture, DynProvider<TempoNetwork>, Address)>
{
    reth_tracing::init_test_tracing();
    let genesis = zone_node::genesis::genesis_template()?;
    let (zone, mut fixture) =
        start_local_zone_with_fixture_and_withdrawal_batch_interval(1114, 10, 8, genesis).await?;
    let (provider, dev_address) = local_dev_tempo_zone_account(&zone)?;
    fund(&zone, &mut fixture, dev_address).await?;
    Ok((zone, fixture, provider, dev_address))
}

async fn fund(zone: &ZoneTestNode, fixture: &mut L1Fixture, account: Address) -> eyre::Result<()> {
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, account, account, 1_000_000);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        account,
        U256::from(1_000_000u128),
        DEFAULT_TIMEOUT,
    )
    .await?;
    Ok(())
}

fn transaction(chain_id: u64, nonce: u64, to: Address, input: Bytes) -> TempoTransaction {
    TempoTransaction {
        chain_id,
        fee_token: Some(PATH_USD_ADDRESS),
        max_priority_fee_per_gas: u128::from(TEMPO_T0_BASE_FEE),
        max_fee_per_gas: u128::from(TEMPO_T0_BASE_FEE),
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input,
        }],
        nonce,
        ..Default::default()
    }
}

async fn send(
    provider: &DynProvider<TempoNetwork>,
    transaction: TempoTransaction,
    signature: TempoSignature,
) -> eyre::Result<PendingTransactionBuilder<TempoNetwork>> {
    let envelope: TempoTxEnvelope = transaction.into_signed(signature).into();
    Ok(provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?)
}

/// An account unregistered on Tempo sends from the zone with its version-zero owner quorum.
#[tokio::test(flavor = "multi_thread")]
async fn test_derived_account_sends_with_its_owner_quorum() -> eyre::Result<()> {
    let (zone, mut fixture, provider, _) = funded_zone().await?;
    let owner = PrivateKeySigner::random();
    let config = ConfigurableAccountConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: owner.address(),
            weight: 1,
        }],
    };
    let account = config
        .derive_account()
        .expect("the configuration derives an account");
    // The fixture deposit also seeds the account's zero commitment on Tempo.
    fund(&zone, &mut fixture, account).await?;

    let chain_id = provider.get_chain_id().await?;
    let approve = ITIP20::approveCall {
        spender: ZONE_OUTBOX_ADDRESS,
        amount: U256::ONE,
    };
    let tx = transaction(chain_id, 0, PATH_USD_ADDRESS, approve.abi_encode().into());
    let digest = configurable_account_digest(tx.signature_hash(), account, 0);
    let approval = PrimitiveSignature::Secp256k1(owner.sign_hash_sync(&digest)?);
    let signature = TempoSignature::ConfigurableAccount(
        ConfigurableAccountSignature::try_new(account, config, vec![approval])
            .expect("the witness has a valid shape"),
    );
    let pending = send(&provider, tx, signature).await?;
    fixture.inject_empty_block(zone.deposit_queue());
    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "{receipt:?}");
    assert_eq!(receipt.from(), account);
    Ok(())
}

/// Once Tempo migrates an EOA, the zone reports the account marker code and rejects its original key.
#[tokio::test(flavor = "multi_thread")]
async fn test_migrated_account_rejects_its_original_key() -> eyre::Result<()> {
    let (zone, _fixture, provider, dev_address) = funded_zone().await?;
    let anchor = zone.tempo_block_number().await?;
    zone.l1_state_cache()
        .lock()
        .set_commitment(dev_address, anchor, B256::repeat_byte(0x11));
    // The operator RPC returns the account marker code that zone execution sees.
    assert_eq!(
        provider.get_code_at(dev_address).await?,
        CONFIGURABLE_ACCOUNT_CODE
    );

    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(dev_address).await?;
    let tx = transaction(chain_id, nonce, PATH_USD_ADDRESS, Bytes::new());
    let signature = l1_dev_signer().sign_hash_sync(&tx.signature_hash())?.into();
    let err = send(&provider, tx, signature)
        .await
        .expect_err("the retired root key must not send");
    assert!(
        format!("{err:#}").contains(&format!("root key of {dev_address} is retired")),
        "{err:#}"
    );
    Ok(())
}
