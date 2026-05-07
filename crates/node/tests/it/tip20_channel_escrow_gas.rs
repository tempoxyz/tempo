use std::collections::BTreeMap;

use alloy::{
    primitives::{Address, B256, Bytes, U256, aliases::U96},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolEvent,
};
use tempo_contracts::precompiles::{ITIP20, ITIP20ChannelEscrow};
use tempo_precompiles::{PATH_USD_ADDRESS, TIP20_CHANNEL_ESCROW_ADDRESS};

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};

const DEPOSIT: u64 = 1_000_000;
const FUNDING: u64 = 20_000_000;

fn fixed_signer(last_byte: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::with_last_byte(last_byte))
        .expect("fixed test private key must be valid")
}

struct OpenedChannel {
    id: B256,
    descriptor: ITIP20ChannelEscrow::ChannelDescriptor,
    gas_used: u64,
}

async fn fund_and_approve<P: Provider + Clone>(
    funder_provider: P,
    user_provider: P,
    user: Address,
) -> eyre::Result<()> {
    let token = ITIP20::new(PATH_USD_ADDRESS, funder_provider);
    let transfer_receipt = token
        .transfer(user, U256::from(FUNDING))
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(transfer_receipt.status(), "funding transfer failed");

    let user_token = ITIP20::new(PATH_USD_ADDRESS, user_provider);
    let approve_receipt = user_token
        .approve(TIP20_CHANNEL_ESCROW_ADDRESS, U256::MAX)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(approve_receipt.status(), "escrow approval failed");

    Ok(())
}

async fn open_channel<P: Provider + Clone>(
    channel: &ITIP20ChannelEscrow::ITIP20ChannelEscrowInstance<P>,
    payee: Address,
    operator: Address,
    salt: B256,
) -> eyre::Result<OpenedChannel> {
    let receipt = channel
        .open(
            payee,
            operator,
            PATH_USD_ADDRESS,
            U96::from(DEPOSIT),
            salt,
            Address::ZERO,
        )
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "open failed");

    let opened = receipt
        .logs()
        .iter()
        .find_map(|log| ITIP20ChannelEscrow::ChannelOpened::decode_log(&log.inner).ok())
        .ok_or_else(|| eyre::eyre!("ChannelOpened event not found"))?;

    Ok(OpenedChannel {
        id: opened.channelId,
        descriptor: ITIP20ChannelEscrow::ChannelDescriptor {
            payer: opened.payer,
            payee: opened.payee,
            operator: opened.operator,
            token: opened.token,
            salt: opened.salt,
            authorizedSigner: opened.authorizedSigner,
            expiringNonceHash: opened.expiringNonceHash,
        },
        gas_used: receipt.gas_used,
    })
}

async fn voucher_signature<P: Provider + Clone>(
    channel: &ITIP20ChannelEscrow::ITIP20ChannelEscrowInstance<P>,
    payer: &PrivateKeySigner,
    channel_id: B256,
    amount: u64,
) -> eyre::Result<Bytes> {
    let digest = channel
        .getVoucherDigest(channel_id, U96::from(amount))
        .call()
        .await?;
    Ok(Bytes::copy_from_slice(
        &payer.sign_hash_sync(&digest)?.as_bytes(),
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_channel_escrow_gas_snapshots() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let funder = alloy::signers::local::MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let funder_provider = ProviderBuilder::new()
        .wallet(funder.clone())
        .connect_http(http_url.clone());

    let payer = fixed_signer(0x11);
    let payee = fixed_signer(0x12);
    let operator = fixed_signer(0x13);
    let payer_provider = ProviderBuilder::new()
        .wallet(payer.clone())
        .connect_http(http_url.clone());
    let payee_provider = ProviderBuilder::new()
        .wallet(payee.clone())
        .connect_http(http_url.clone());
    let operator_provider = ProviderBuilder::new()
        .wallet(operator.clone())
        .connect_http(http_url);

    fund_and_approve(
        funder_provider.clone(),
        payer_provider.clone(),
        payer.address(),
    )
    .await?;
    fund_and_approve(
        funder_provider.clone(),
        payee_provider.clone(),
        payee.address(),
    )
    .await?;
    fund_and_approve(
        funder_provider,
        operator_provider.clone(),
        operator.address(),
    )
    .await?;

    let payer_channel =
        ITIP20ChannelEscrow::new(TIP20_CHANNEL_ESCROW_ADDRESS, payer_provider.clone());
    let payee_channel =
        ITIP20ChannelEscrow::new(TIP20_CHANNEL_ESCROW_ADDRESS, payee_provider.clone());
    let operator_channel =
        ITIP20ChannelEscrow::new(TIP20_CHANNEL_ESCROW_ADDRESS, operator_provider);

    let mut gas = BTreeMap::new();

    let first = open_channel(
        &payer_channel,
        payee.address(),
        Address::ZERO,
        B256::with_last_byte(1),
    )
    .await?;
    gas.insert("open_new_channel_first_escrow_balance", first.gas_used);

    let second = open_channel(
        &payer_channel,
        payee.address(),
        Address::ZERO,
        B256::with_last_byte(2),
    )
    .await?;
    gas.insert("open_new_channel_existing_escrow_balance", second.gas_used);

    let top_up_receipt = payer_channel
        .topUp(second.descriptor.clone(), U96::from(250_000))
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(top_up_receipt.status(), "topUp failed");
    gas.insert("top_up_existing_channel", top_up_receipt.gas_used);

    let settle_sig = voucher_signature(&payer_channel, &payer, second.id, 400_000).await?;
    let settle_receipt = payee_channel
        .settle(second.descriptor.clone(), U96::from(400_000), settle_sig)
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(settle_receipt.status(), "settle failed");
    gas.insert(
        "settle_existing_channel_existing_payee_balance",
        settle_receipt.gas_used,
    );

    let operator_payee = fixed_signer(0x14);
    let operator_settle = open_channel(
        &payer_channel,
        operator_payee.address(),
        operator.address(),
        B256::with_last_byte(3),
    )
    .await?;
    let operator_settle_sig =
        voucher_signature(&payer_channel, &payer, operator_settle.id, 300_000).await?;
    let operator_settle_receipt = operator_channel
        .settle(
            operator_settle.descriptor.clone(),
            U96::from(300_000),
            operator_settle_sig,
        )
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(
        operator_settle_receipt.status(),
        "operator settle to new payee balance failed"
    );
    gas.insert(
        "settle_existing_channel_new_payee_balance",
        operator_settle_receipt.gas_used,
    );

    let close_only = open_channel(
        &payer_channel,
        payee.address(),
        Address::ZERO,
        B256::with_last_byte(4),
    )
    .await?;
    let close_only_sig = voucher_signature(&payer_channel, &payer, close_only.id, 700_000).await?;
    let close_only_receipt = payee_channel
        .close(
            close_only.descriptor.clone(),
            U96::from(700_000),
            U96::from(700_000),
            close_only_sig,
        )
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(close_only_receipt.status(), "close failed");
    gas.insert(
        "close_existing_channel_no_prior_settlement",
        close_only_receipt.gas_used,
    );

    let close_after_settle = open_channel(
        &payer_channel,
        payee.address(),
        Address::ZERO,
        B256::with_last_byte(5),
    )
    .await?;
    let pre_close_settle_sig =
        voucher_signature(&payer_channel, &payer, close_after_settle.id, 250_000).await?;
    let pre_close_settle_receipt = payee_channel
        .settle(
            close_after_settle.descriptor.clone(),
            U96::from(250_000),
            pre_close_settle_sig,
        )
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(pre_close_settle_receipt.status(), "pre-close settle failed");

    let close_after_settle_sig =
        voucher_signature(&payer_channel, &payer, close_after_settle.id, 650_000).await?;
    let close_after_settle_receipt = payee_channel
        .close(
            close_after_settle.descriptor.clone(),
            U96::from(650_000),
            U96::from(650_000),
            close_after_settle_sig,
        )
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(
        close_after_settle_receipt.status(),
        "close after settle failed"
    );
    gas.insert(
        "close_existing_channel_after_settlement",
        close_after_settle_receipt.gas_used,
    );

    let request_close = open_channel(
        &payer_channel,
        payee.address(),
        Address::ZERO,
        B256::with_last_byte(6),
    )
    .await?;
    let request_close_receipt = payer_channel
        .requestClose(request_close.descriptor.clone())
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(request_close_receipt.status(), "requestClose failed");
    gas.insert(
        "request_close_existing_channel",
        request_close_receipt.gas_used,
    );

    let cancel_close_receipt = payer_channel
        .topUp(request_close.descriptor, U96::from(100_000))
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(
        cancel_close_receipt.status(),
        "topUp canceling close request failed"
    );
    gas.insert(
        "top_up_existing_channel_cancel_close_request",
        cancel_close_receipt.gas_used,
    );

    eprintln!("\nTIP20ChannelEscrow gas snapshot:");
    for (name, gas_used) in &gas {
        eprintln!("{name}: {gas_used}");
    }

    insta::assert_yaml_snapshot!(gas);

    Ok(())
}
