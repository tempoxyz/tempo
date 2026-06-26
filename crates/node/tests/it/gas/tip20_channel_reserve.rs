use alloy::{
    primitives::{Address, B256, Bytes, U256, aliases::U96},
    providers::Provider,
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolEvent,
};
use alloy_network::ReceiptResponse;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::ITIP20ChannelReserve;
use tempo_precompiles::{PATH_USD_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS};
use test_case::test_case;

use super::helpers::{
    GasSnapshot, Receipt, TempoTxSender, fixed_signer, print_gas_snapshot, test_signer,
};
use crate::utils::{TestNodeBuilder, make_genesis_at};

const DEPOSIT: u64 = 1_000_000;
const FUNDING: u64 = 20_000_000;

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

    async fn top_up(
        &self,
        gas: &mut GasSnapshot,
        name: impl Into<String>,
        sender: &mut TempoTxSender<P>,
        amount: u64,
    ) -> eyre::Result<Receipt> {
        gas.call(
            name,
            sender,
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
        gas: &mut GasSnapshot,
        name: impl Into<String>,
        submitter: &mut TempoTxSender<P>,
        payer: &PrivateKeySigner,
        amount: u64,
    ) -> eyre::Result<Receipt> {
        let signature = self.voucher_signature(payer, amount).await?;
        gas.call(
            name,
            submitter,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            ITIP20ChannelReserve::settleCall {
                descriptor: self.descriptor.clone(),
                cumulativeAmount: U96::from(amount),
                signature,
            },
        )
        .await
    }

    async fn settle_unrecorded(
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
        gas: &mut GasSnapshot,
        name: impl Into<String>,
        submitter: &mut TempoTxSender<P>,
        payer: &PrivateKeySigner,
        amount: u64,
    ) -> eyre::Result<Receipt> {
        let signature = self.voucher_signature(payer, amount).await?;
        gas.call(
            name,
            submitter,
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

    async fn close_unrecorded(
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

    async fn request_close(
        &self,
        gas: &mut GasSnapshot,
        name: impl Into<String>,
        sender: &mut TempoTxSender<P>,
    ) -> eyre::Result<Receipt> {
        gas.call(
            name,
            sender,
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

#[test_case(TempoHardfork::T6 ; "t6_without_tip1060")]
#[test_case(TempoHardfork::T7 ; "t7_without_tip1060")]
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
    let mut payee =
        TempoTxSender::connect_with_zero_nonce(http_url.clone(), fixed_signer(0x12)).await?;
    let mut operator = TempoTxSender::connect_with_zero_nonce(http_url, fixed_signer(0x13)).await?;

    funder
        .fund_tip20(
            PATH_USD_ADDRESS,
            [payer.address(), payee.address(), operator.address()],
            U256::from(FUNDING),
        )
        .await?;

    let mut gas = GasSnapshot::new();

    let first = ChannelEnv::open(&mut payer, payee.address(), 1).await?;
    gas.record("open_new_channel_first_reserve_balance", first.gas_used());

    let second = ChannelEnv::open(&mut payer, payee.address(), 2).await?;
    gas.record(
        "open_new_channel_existing_reserve_balance",
        second.gas_used(),
    );

    second
        .top_up(&mut gas, "top_up_existing_channel", &mut payer, 250_000)
        .await?;

    second
        .settle(
            &mut gas,
            "settle_existing_channel_existing_payee_balance",
            &mut payee,
            &payer.signer,
            400_000,
        )
        .await?;

    let operator_payee = fixed_signer(0x14);
    let operator_settle =
        ChannelEnv::open_with_operator(&mut payer, operator_payee.address(), operator.address(), 3)
            .await?;
    operator_settle
        .settle(
            &mut gas,
            "settle_existing_channel_new_payee_balance",
            &mut operator,
            &payer.signer,
            300_000,
        )
        .await?;

    let close_only = ChannelEnv::open(&mut payer, payee.address(), 4).await?;
    close_only
        .close(
            &mut gas,
            "close_existing_channel_no_prior_settlement",
            &mut payee,
            &payer.signer,
            700_000,
        )
        .await?;

    let close_after_settle = ChannelEnv::open(&mut payer, payee.address(), 5).await?;
    close_after_settle
        .settle_unrecorded(&mut payee, &payer.signer, 250_000)
        .await?;
    close_after_settle
        .close(
            &mut gas,
            "close_existing_channel_after_settlement",
            &mut payee,
            &payer.signer,
            650_000,
        )
        .await?;

    let request_close_channel = ChannelEnv::open(&mut payer, payee.address(), 6).await?;
    request_close_channel
        .request_close(&mut gas, "request_close_existing_channel", &mut payer)
        .await?;

    request_close_channel
        .top_up(
            &mut gas,
            "top_up_existing_channel_cancel_close_request",
            &mut payer,
            100_000,
        )
        .await?;

    let credit_seed = ChannelEnv::open(&mut payer, payee.address(), 7).await?;
    credit_seed
        .close_unrecorded(&mut payee, &payer.signer, 500_000)
        .await?;

    let credited_reopen = ChannelEnv::open(&mut payer, payee.address(), 8).await?;
    gas.record(
        "open_new_channel_with_storage_credit",
        credited_reopen.gas_used(),
    );

    let snapshot_name = format!(
        "tip20_channel_reserve_gas_snapshot_{}",
        hardfork.name().to_lowercase()
    );
    print_gas_snapshot(
        &format!("TIP20ChannelReserve gas snapshot ({})", hardfork.name()),
        &gas,
    );

    insta::assert_yaml_snapshot!(snapshot_name, gas);

    Ok(())
}
