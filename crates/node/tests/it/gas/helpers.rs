use std::{collections::BTreeMap, ops::Deref};

use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    network::EthereumWallet,
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
    sol_types::SolCall,
    transports::http::reqwest::Url,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSignerSync;
use reth_primitives_traits::transaction::TxHashRef;
use tempo_chainspec::{constants::gas::TEMPO_T1_TX_GAS_LIMIT_CAP, spec::TEMPO_T1_BASE_FEE};
use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, ITIP20};
use tempo_primitives::{TempoTransaction, TempoTxEnvelope, transaction::Call};

use crate::utils::TEST_MNEMONIC;

pub(crate) const GAS_LIMIT: u64 = TEMPO_T1_TX_GAS_LIMIT_CAP;

#[derive(Debug, Default, serde::Serialize)]
#[serde(transparent)]
pub(crate) struct GasSnapshot {
    values: BTreeMap<String, u64>,
}

impl GasSnapshot {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record(&mut self, name: impl Into<String>, gas_used: u64) {
        self.values.insert(name.into(), gas_used);
    }

    pub(crate) async fn call<P: Provider, C: SolCall>(
        &mut self,
        name: impl Into<String>,
        sender: &mut TempoTxSender<P>,
        to: Address,
        call: C,
    ) -> eyre::Result<Receipt> {
        let receipt = sender.send_call(to, call).await?;
        self.record(name, receipt.gas_used);
        Ok(receipt)
    }

    pub(crate) fn print(&self, title: &str) {
        eprintln!("\n{title}:");
        for (name, gas_used) in &self.values {
            eprintln!("{name}: {gas_used}");
        }
    }
}

impl Deref for GasSnapshot {
    type Target = BTreeMap<String, u64>;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

pub(crate) fn test_signer(index: u32) -> eyre::Result<PrivateKeySigner> {
    Ok(MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(index)?
        .build()?)
}

pub(crate) fn fixed_signer(last_byte: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::with_last_byte(last_byte))
        .expect("fixed test private key must be valid")
}

/// Builds and encodes a signed EIP-1559 CALL transaction.
pub(crate) fn build_call_tx(
    signer: &PrivateKeySigner,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    to: Address,
    input: Bytes,
) -> Bytes {
    let mut tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        to: to.into(),
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        input,
        ..Default::default()
    };
    let signature = signer.sign_transaction_sync(&mut tx).unwrap();
    TxEnvelope::Eip1559(tx.into_signed(signature))
        .encoded_2718()
        .into()
}

pub(crate) struct TempoTxSender<P> {
    pub(crate) provider: P,
    pub(crate) chain_id: u64,
    pub(crate) signer: PrivateKeySigner,
    pub(crate) nonce: u64,
}

impl TempoTxSender<()> {
    pub(crate) async fn connect(
        http_url: Url,
        signer: PrivateKeySigner,
    ) -> eyre::Result<TempoTxSender<impl Provider + Clone>> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(http_url);
        let chain_id = provider.get_chain_id().await?;
        let nonce = provider.get_transaction_count(signer.address()).await?;
        Ok(TempoTxSender::new(provider, chain_id, signer, nonce))
    }

    pub(crate) async fn connect_with_zero_nonce(
        http_url: Url,
        signer: PrivateKeySigner,
    ) -> eyre::Result<TempoTxSender<impl Provider + Clone>> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(http_url);
        let chain_id = provider.get_chain_id().await?;
        Ok(TempoTxSender::new(provider, chain_id, signer, 0))
    }
}

impl<P: Provider> TempoTxSender<P> {
    pub(crate) fn new(provider: P, chain_id: u64, signer: PrivateKeySigner, nonce: u64) -> Self {
        Self {
            provider,
            chain_id,
            signer,
            nonce,
        }
    }

    pub(crate) fn with_zero_nonce(provider: P, chain_id: u64, signer: PrivateKeySigner) -> Self {
        Self::new(provider, chain_id, signer, 0)
    }

    pub(crate) fn address(&self) -> Address {
        self.signer.address()
    }

    pub(crate) async fn sync_nonce(&mut self) -> eyre::Result<()> {
        self.nonce = self.provider.get_transaction_count(self.address()).await?;
        Ok(())
    }

    pub(crate) async fn send_call<C: SolCall>(
        &mut self,
        to: Address,
        call: C,
    ) -> eyre::Result<Receipt> {
        TempoCalls::new()
            .push(to, call)
            .send_with_receipt(self)
            .await
    }

    pub(crate) async fn fund_tip20(
        &mut self,
        token: Address,
        accounts: impl IntoIterator<Item = Address>,
        amount: U256,
    ) -> eyre::Result<Receipt> {
        TempoCalls::new()
            .extend(accounts, |to| (token, ITIP20::mintCall { to, amount }))
            .send(self)
            .await
    }
}

pub(crate) struct TempoCalls {
    calls: Vec<Call>,
    gas_limit: u64,
    fee_token: Option<Address>,
    nonce_key: U256,
    expect_existing_nonce: bool,
}

pub(crate) struct Receipt {
    pub(crate) tx_hash: B256,
    pub(crate) gas_used: u64,
}

impl TempoCalls {
    pub(crate) fn new() -> Self {
        Self {
            calls: Vec::new(),
            gas_limit: GAS_LIMIT,
            fee_token: Some(DEFAULT_FEE_TOKEN),
            nonce_key: U256::ZERO,
            expect_existing_nonce: false,
        }
    }

    pub(crate) fn push<C: SolCall>(mut self, to: Address, call: C) -> Self {
        self.calls.push(Call {
            to: to.into(),
            value: U256::ZERO,
            input: call.abi_encode().into(),
        });
        self
    }

    pub(crate) fn extend<I, C, F>(mut self, values: I, mut f: F) -> Self
    where
        I: IntoIterator,
        C: SolCall,
        F: FnMut(I::Item) -> (Address, C),
    {
        self.calls.extend(values.into_iter().map(|value| {
            let (to, call) = f(value);
            Call {
                to: to.into(),
                value: U256::ZERO,
                input: call.abi_encode().into(),
            }
        }));
        self
    }

    #[allow(dead_code)]
    pub(crate) fn fee_token(mut self, fee_token: Option<Address>) -> Self {
        self.fee_token = fee_token;
        self
    }

    #[allow(dead_code)]
    pub(crate) fn nonce_key(mut self, nonce_key: U256) -> Self {
        self.nonce_key = nonce_key;
        self
    }

    #[allow(dead_code)]
    pub(crate) fn expect_existing_nonce(mut self) -> Self {
        self.expect_existing_nonce = true;
        self
    }

    pub(crate) async fn send<P: Provider>(
        self,
        sender: &mut TempoTxSender<P>,
    ) -> eyre::Result<Receipt> {
        self.send_with_receipt(sender).await
    }

    pub(crate) async fn send_with_receipt<P: Provider>(
        self,
        sender: &mut TempoTxSender<P>,
    ) -> eyre::Result<Receipt> {
        let call_count = self.calls.len();
        eyre::ensure!(call_count > 0, "cannot send TempoCalls with zero calls");
        if self.expect_existing_nonce {
            eyre::ensure!(sender.nonce > 0, "expected existing Tempo nonce");
        }

        let tx = TempoTransaction {
            chain_id: sender.chain_id,
            max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
            max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
            gas_limit: self.gas_limit,
            calls: self.calls,
            nonce_key: self.nonce_key,
            nonce: sender.nonce,
            fee_token: self.fee_token,
            ..Default::default()
        };
        let signature = sender.signer.sign_hash_sync(&tx.signature_hash())?;
        let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
        let tx_hash = *envelope.tx_hash();
        let _ = sender
            .provider
            .send_raw_transaction(&envelope.encoded_2718())
            .await?;

        for _ in 0..120 {
            let receipt: Option<serde_json::Value> = sender
                .provider
                .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                .await?;
            if let Some(receipt) = receipt {
                let status = receipt["status"]
                    .as_str()
                    .ok_or_else(|| eyre::eyre!("tempo calls receipt missing status field"))?;
                eyre::ensure!(status == "0x1", "tempo calls reverted: {receipt}");
                let gas_used = hex_u64_field(&receipt, "gasUsed")?;
                sender.nonce += 1;
                return Ok(Receipt { tx_hash, gas_used });
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        eyre::bail!("timed out waiting for tempo calls receipt {tx_hash}")
    }
}

fn hex_u64_field(receipt: &serde_json::Value, field: &str) -> eyre::Result<u64> {
    let value = receipt[field]
        .as_str()
        .ok_or_else(|| eyre::eyre!("tempo calls receipt missing {field} field"))?;
    Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
}

pub(crate) fn print_gas_snapshot(title: &str, gas: &GasSnapshot) {
    gas.print(title);
}
