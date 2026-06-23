use std::collections::BTreeMap;

use alloy::{
    primitives::{Address, B256, Bytes, U256, aliases::U96},
    providers::Provider,
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolEvent,
};
use alloy_network::ReceiptResponse;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{IStorageCredits, ITIP20ChannelReserve};
use tempo_precompiles::{PATH_USD_ADDRESS, STORAGE_CREDITS_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS};
use test_case::test_case;

use super::helpers::{Receipt, TempoTxSender, fixed_signer, test_signer};
use crate::utils::{TestNodeBuilder, make_genesis_at};

const DEPOSIT: u64 = 1_000_000;
const FUNDING: u64 = 20_000_000;

#[derive(Debug, serde::Serialize)]
struct ChannelGasRow {
    gas: u64,
    storage_credits: String,
    pooled_storage_credits: String,
}

struct ChannelEnv<P> {
    contract: ITIP20ChannelReserve::ITIP20ChannelReserveInstance<P>,
    id: B256,
    descriptor: ITIP20ChannelReserve::ChannelDescriptor,
    open_gas_used: u64,
}

impl<P: Provider + Clone> ChannelEnv<P> {
    async fn open(sender: &mut TempoTxSender<P>, payee: Address, salt: u8) -> eyre::Result<Self> {
        Self::open_with_operator(sender, payee, Address::ZERO, salt).await
    }

    async fn open_with_operator(
        sender: &mut TempoTxSender<P>,
        payee: Address,
        operator: Address,
        salt: u8,
    ) -> eyre::Result<Self> {
        let sent = sender
            .send_call(
                TIP20_CHANNEL_RESERVE_ADDRESS,
                ITIP20ChannelReserve::openCall {
                    payee,
                    operator,
                    token: PATH_USD_ADDRESS,
                    deposit: U96::from(DEPOSIT),
                    salt: B256::with_last_byte(salt),
                    authorizedSigner: Address::ZERO,
                },
            )
            .await?;
        Self::from_open_receipt(sender, sent).await
    }

    fn gas_used(&self) -> u64 {
        self.open_gas_used
    }

    async fn top_up(&self, sender: &mut TempoTxSender<P>, amount: u64) -> eyre::Result<Receipt> {
        sender
            .send_call(
                TIP20_CHANNEL_RESERVE_ADDRESS,
                ITIP20ChannelReserve::topUpCall {
                    descriptor: self.descriptor.clone(),
                    additionalDeposit: U96::from(amount),
                },
            )
            .await
    }

    async fn settle(
        &self,
        submitter: &mut TempoTxSender<P>,
        payer: &PrivateKeySigner,
        amount: u64,
    ) -> eyre::Result<Receipt> {
        let signature = self.voucher_signature(payer, amount).await?;
        submitter
            .send_call(
                TIP20_CHANNEL_RESERVE_ADDRESS,
                ITIP20ChannelReserve::settleCall {
                    descriptor: self.descriptor.clone(),
                    cumulativeAmount: U96::from(amount),
                    signature,
                },
            )
            .await
    }

    async fn close(
        &self,
        submitter: &mut TempoTxSender<P>,
        payer: &PrivateKeySigner,
        amount: u64,
    ) -> eyre::Result<Receipt> {
        let signature = self.voucher_signature(payer, amount).await?;
        submitter
            .send_call(
                TIP20_CHANNEL_RESERVE_ADDRESS,
                ITIP20ChannelReserve::closeCall {
                    descriptor: self.descriptor.clone(),
                    cumulativeAmount: U96::from(amount),
                    captureAmount: U96::from(amount),
                    signature,
                },
            )
            .await
    }

    async fn request_close(&self, sender: &mut TempoTxSender<P>) -> eyre::Result<Receipt> {
        sender
            .send_call(
                TIP20_CHANNEL_RESERVE_ADDRESS,
                ITIP20ChannelReserve::requestCloseCall {
                    descriptor: self.descriptor.clone(),
                },
            )
            .await
    }

    async fn from_open_receipt(sender: &TempoTxSender<P>, sent: Receipt) -> eyre::Result<Self> {
        let receipt = sender
            .provider
            .raw_request::<_, Option<TempoTransactionReceipt>>(
                "eth_getTransactionReceipt".into(),
                (sent.tx_hash,),
            )
            .await?
            .ok_or_else(|| eyre::eyre!("open receipt not found"))?;
        assert!(receipt.status(), "open failed");

        let opened = receipt
            .logs()
            .iter()
            .find_map(|log| ITIP20ChannelReserve::ChannelOpened::decode_log(&log.inner).ok())
            .ok_or_else(|| eyre::eyre!("ChannelOpened event not found"))?;

        Ok(Self {
            contract: ITIP20ChannelReserve::new(
                TIP20_CHANNEL_RESERVE_ADDRESS,
                sender.provider.clone(),
            ),
            id: opened.channelId,
            descriptor: ITIP20ChannelReserve::ChannelDescriptor {
                payer: opened.payer,
                payee: opened.payee,
                operator: opened.operator,
                token: opened.token,
                salt: opened.salt,
                authorizedSigner: opened.authorizedSigner,
                expiringNonceHash: opened.expiringNonceHash,
            },
            open_gas_used: sent.gas_used,
        })
    }

    async fn voucher_signature(
        &self,
        payer: &PrivateKeySigner,
        amount: u64,
    ) -> eyre::Result<Bytes> {
        let digest = self
            .contract
            .getVoucherDigest(self.id, U96::from(amount))
            .call()
            .await?;
        Ok(Bytes::copy_from_slice(
            &payer.sign_hash_sync(&digest)?.as_bytes(),
        ))
    }
}

async fn channel_credits<P: Provider + Clone>(
    provider: P,
    hardfork: TempoHardfork,
    payer: Address,
) -> eyre::Result<u64> {
    if hardfork.is_t7() {
        Ok(
            ITIP20ChannelReserve::new(TIP20_CHANNEL_RESERVE_ADDRESS, provider)
                .storageCredits(payer)
                .call()
                .await?,
        )
    } else {
        Ok(0)
    }
}

async fn pooled_credits<P: Provider + Clone>(
    provider: P,
    hardfork: TempoHardfork,
) -> eyre::Result<u64> {
    if hardfork.is_t7() {
        Ok(IStorageCredits::new(STORAGE_CREDITS_ADDRESS, provider)
            .balanceOf(TIP20_CHANNEL_RESERVE_ADDRESS)
            .call()
            .await?)
    } else {
        Ok(0)
    }
}

#[test_case(TempoHardfork::T6 ; "t6_without_tip1060")]
#[test_case(TempoHardfork::T7 ; "t7_with_tip1060_tip1066")]
#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_channel_reserve_gas_snapshots(hardfork: TempoHardfork) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .with_genesis(make_genesis_at(hardfork))
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let mut funder = TempoTxSender::connect(http_url.clone(), test_signer(0)?).await?;
    let mut payer =
        TempoTxSender::connect_with_zero_nonce(http_url.clone(), fixed_signer(0x11)).await?;
    let mut other_payer =
        TempoTxSender::connect_with_zero_nonce(http_url.clone(), fixed_signer(0x12)).await?;
    let mut payee =
        TempoTxSender::connect_with_zero_nonce(http_url.clone(), fixed_signer(0x13)).await?;
    let mut operator =
        TempoTxSender::connect_with_zero_nonce(http_url.clone(), fixed_signer(0x14)).await?;
    let operator_payee = fixed_signer(0x15);

    funder
        .fund_tip20(
            PATH_USD_ADDRESS,
            [
                payer.address(),
                other_payer.address(),
                payee.address(),
                operator.address(),
                operator_payee.address(),
            ],
            U256::from(FUNDING),
        )
        .await?;

    let mut gas = BTreeMap::new();
    let credit_provider = payer.provider.clone();

    macro_rules! record_tx {
        ($name:literal, $payer:expr, $call:expr) => {{
            let before = channel_credits(credit_provider.clone(), hardfork, $payer).await?;
            let pooled_before = pooled_credits(credit_provider.clone(), hardfork).await?;
            let receipt = $call.await?;
            let after = channel_credits(credit_provider.clone(), hardfork, $payer).await?;
            let pooled_after = pooled_credits(credit_provider.clone(), hardfork).await?;
            gas.insert(
                $name,
                ChannelGasRow {
                    gas: receipt.gas_used,
                    storage_credits: format!("{before} -> {after}"),
                    pooled_storage_credits: format!(
                        "Reserve TIP-1060: {pooled_before} -> {pooled_after}"
                    ),
                },
            );
            receipt
        }};
    }

    macro_rules! record_open {
        ($name:literal, $payer:expr, $call:expr) => {{
            let before = channel_credits(credit_provider.clone(), hardfork, $payer).await?;
            let pooled_before = pooled_credits(credit_provider.clone(), hardfork).await?;
            let channel = $call.await?;
            let after = channel_credits(credit_provider.clone(), hardfork, $payer).await?;
            let pooled_after = pooled_credits(credit_provider.clone(), hardfork).await?;
            gas.insert(
                $name,
                ChannelGasRow {
                    gas: channel.gas_used(),
                    storage_credits: format!("{before} -> {after}"),
                    pooled_storage_credits: format!(
                        "Reserve TIP-1060: {pooled_before} -> {pooled_after}"
                    ),
                },
            );
            channel
        }};
    }

    macro_rules! record_cross_open {
        ($name:literal, $credit_payer:expr, $other:expr, $call:expr) => {{
            let before = channel_credits(credit_provider.clone(), hardfork, $credit_payer).await?;
            let other_before = channel_credits(credit_provider.clone(), hardfork, $other).await?;
            let pooled_before = pooled_credits(credit_provider.clone(), hardfork).await?;
            let channel = $call.await?;
            let after = channel_credits(credit_provider.clone(), hardfork, $credit_payer).await?;
            let other_after = channel_credits(credit_provider.clone(), hardfork, $other).await?;
            let pooled_after = pooled_credits(credit_provider.clone(), hardfork).await?;
            gas.insert(
                $name,
                ChannelGasRow {
                    gas: channel.gas_used(),
                    storage_credits: format!(
                        "payer: {before} -> {after}; other: {other_before} -> {other_after}"
                    ),
                    pooled_storage_credits: format!(
                        "Reserve TIP-1060: {pooled_before} -> {pooled_after}"
                    ),
                },
            );
            channel
        }};
    }

    let payer_address = payer.address();
    let other_payer_address = other_payer.address();

    let _first = record_open!(
        "open_first_channel_from_wallet",
        payer_address,
        ChannelEnv::open(&mut payer, payee.address(), 1)
    );

    let active = record_open!(
        "open_channel_existing_reserve_balance",
        payer_address,
        ChannelEnv::open(&mut payer, payee.address(), 2)
    );

    record_tx!(
        "top_up_existing_channel",
        payer_address,
        active.top_up(&mut payer, 250_000)
    );

    record_tx!(
        "settle_existing_channel_existing_payee_balance",
        payer_address,
        active.settle(&mut payee, &payer.signer, 400_000)
    );

    let request_close_channel = ChannelEnv::open(&mut payer, payee.address(), 3).await?;
    record_tx!(
        "request_close_existing_channel",
        payer_address,
        request_close_channel.request_close(&mut payer)
    );

    record_tx!(
        "top_up_existing_channel_cancel_close_request",
        payer_address,
        request_close_channel.top_up(&mut payer, 100_000)
    );

    let operator_channel =
        ChannelEnv::open_with_operator(&mut payer, operator_payee.address(), operator.address(), 4)
            .await?;
    record_tx!(
        "settle_existing_channel_new_payee_balance",
        payer_address,
        operator_channel.settle(&mut operator, &payer.signer, 300_000)
    );

    record_tx!(
        "close_after_settlement_earn_credit",
        payer_address,
        active.close(&mut payee, &payer.signer, 700_000)
    );

    let _reused = record_open!(
        "open_same_payer_reuse_close_credit",
        payer_address,
        ChannelEnv::open(&mut payer, payee.address(), 5)
    );

    let close_only = ChannelEnv::open(&mut payer, payee.address(), 6).await?;
    record_tx!(
        "close_without_prior_settlement_earn_credit",
        payer_address,
        close_only.close(&mut payee, &payer.signer, 700_000)
    );

    let _other_open = record_cross_open!(
        "open_different_payer_after_credit",
        payer_address,
        other_payer_address,
        ChannelEnv::open(&mut other_payer, payee.address(), 7)
    );

    record_cross_open!(
        "open_original_payer_after_cross_user",
        payer_address,
        other_payer_address,
        ChannelEnv::open(&mut payer, payee.address(), 8)
    );

    eprintln!(
        "\nTIP20ChannelReserve {} lifecycle gas snapshot:",
        hardfork.name()
    );
    for (name, row) in &gas {
        eprintln!(
            "{name}: {} ({}, {})",
            row.gas, row.storage_credits, row.pooled_storage_credits
        );
    }

    let snapshot_name = format!(
        "tip20_channel_reserve_lifecycle_gas_snapshot_{}",
        hardfork.name().to_lowercase()
    );
    insta::assert_yaml_snapshot!(snapshot_name, gas);

    Ok(())
}
