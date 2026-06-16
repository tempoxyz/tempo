use std::{collections::BTreeMap, fmt::Display, ops::Deref};

use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    network::EthereumWallet,
    primitives::{Address, B256, Bytes, U256, keccak256},
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
use serde_json::{Map, Value, json};
use tempo_chainspec::{
    constants::gas::TEMPO_T1_TX_GAS_LIMIT_CAP, hardfork::TempoHardfork, spec::TEMPO_T1_BASE_FEE,
};
use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, ITIP20};
use tempo_primitives::{TempoTransaction, TempoTxEnvelope, transaction::Call};

use crate::utils::{TEST_MNEMONIC, make_genesis_at};

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
    pub(crate) fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
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

pub(crate) fn mainnet_prestate_genesis_value(
    hardfork: TempoHardfork,
    chain_id: u64,
    timestamp: u64,
    prestate_json: &str,
) -> eyre::Result<Value> {
    let mut genesis: Value = serde_json::from_str(&make_genesis_at(hardfork))?;
    genesis["config"]["chainId"] = Value::from(chain_id);
    genesis["timestamp"] = Value::String(format!("0x{timestamp:x}"));

    let prestate: Value = serde_json::from_str(prestate_json)?;
    let alloc = genesis["alloc"]
        .as_object_mut()
        .ok_or_else(|| eyre::eyre!("test genesis missing alloc"))?;
    for (address, account) in prestate
        .as_object()
        .ok_or_else(|| eyre::eyre!("prestate fixture must be a JSON object"))?
    {
        alloc.insert(address.clone(), genesis_account(account)?);
    }

    Ok(genesis)
}

pub(crate) fn upsert_storage(
    alloc: &mut Map<String, Value>,
    address: Address,
    slot: B256,
    value: U256,
) -> eyre::Result<()> {
    let account = alloc
        .entry(address_key(address))
        .or_insert_with(|| json!({ "balance": "0x0", "storage": {} }));
    let account = account
        .as_object_mut()
        .ok_or_else(|| eyre::eyre!("alloc account must be object"))?;
    let storage = account
        .entry("storage")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| eyre::eyre!("alloc account storage must be object"))?;
    storage.insert(slot_key(slot), word_value(value));
    Ok(())
}

pub(crate) fn upsert_balance(
    alloc: &mut Map<String, Value>,
    address: Address,
    balance: &str,
) -> eyre::Result<()> {
    let account = alloc
        .entry(address_key(address))
        .or_insert_with(|| json!({ "balance": "0x0" }));
    let account = account
        .as_object_mut()
        .ok_or_else(|| eyre::eyre!("alloc account must be object"))?;
    account.insert("balance".to_string(), Value::String(balance.to_string()));
    Ok(())
}

pub(crate) fn tip20_balance_slot(owner: Address) -> B256 {
    mapping_slot_address(owner, B256::from(U256::from(9)))
}

pub(crate) fn tip20_allowance_slot(owner: Address, spender: Address) -> B256 {
    mapping_slot_address(
        spender,
        mapping_slot_address(owner, B256::from(U256::from(10))),
    )
}

pub(crate) fn mapping_slot_bytes32(key: B256, slot: B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(key.as_slice());
    buf[32..].copy_from_slice(slot.as_slice());
    keccak256(buf)
}

pub(crate) fn mapping_slot_address(key: Address, slot: B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(key.as_slice());
    buf[32..].copy_from_slice(slot.as_slice());
    keccak256(buf)
}

pub(crate) fn b256_from_hex(value: &str) -> eyre::Result<B256> {
    let bytes = alloy::hex::decode(value.trim_start_matches("0x"))?;
    eyre::ensure!(bytes.len() == 32, "expected 32-byte hex value");
    Ok(B256::from_slice(&bytes))
}

pub(crate) fn address_key(address: Address) -> String {
    address.to_string().to_ascii_lowercase()
}

pub(crate) fn slot_key(slot: B256) -> String {
    format!("0x{}", alloy::hex::encode(slot.as_slice()))
}

pub(crate) fn word_value(value: U256) -> Value {
    Value::String(format!(
        "0x{}",
        alloy::hex::encode(value.to_be_bytes::<32>())
    ))
}

fn genesis_account(account: &Value) -> eyre::Result<Value> {
    let mut out = Map::new();
    let balance = account
        .get("balance")
        .and_then(Value::as_str)
        .unwrap_or("0x0");
    out.insert("balance".to_string(), Value::String(balance.to_string()));
    if let Some(nonce) = account.get("nonce") {
        if !nonce.is_null() {
            out.insert("nonce".to_string(), Value::String(hex_quantity(nonce)?));
        }
    }
    if let Some(code) = account.get("code").and_then(Value::as_str) {
        if code != "0x" {
            out.insert("code".to_string(), Value::String(code.to_string()));
        }
    }
    if let Some(storage) = account.get("storage").and_then(Value::as_object) {
        if !storage.is_empty() {
            out.insert("storage".to_string(), Value::Object(storage.clone()));
        }
    }
    Ok(Value::Object(out))
}

fn hex_quantity(value: &Value) -> eyre::Result<String> {
    if let Some(value) = value.as_u64() {
        return Ok(format!("0x{value:x}"));
    }
    if let Some(value) = value.as_str() {
        return Ok(value.to_string());
    }
    Err(eyre::eyre!("expected hex quantity or u64, got {value}"))
}

pub(crate) fn successful_raw_receipt_gas_used(
    receipt: &Value,
    expected_hash: B256,
) -> eyre::Result<u64> {
    let transaction_hash = receipt
        .get("transactionHash")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre::eyre!("receipt missing transactionHash"))?;
    let expected_hash = expected_hash.to_string();
    eyre::ensure!(
        transaction_hash.eq_ignore_ascii_case(&expected_hash),
        "unexpected receipt transactionHash: got {transaction_hash}, expected {expected_hash}"
    );

    let status = receipt
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre::eyre!("receipt missing status"))?;
    eyre::ensure!(status == "0x1", "transaction failed: {receipt}");

    hex_u64(
        receipt
            .get("gasUsed")
            .ok_or_else(|| eyre::eyre!("receipt missing gasUsed"))?,
    )
}

pub(crate) fn find_call_gas_used(
    trace: &Value,
    to: impl Display,
    selector: &str,
) -> eyre::Result<u64> {
    let to = to.to_string();
    find_call(trace, &to, selector)
        .and_then(|call| call.get("gasUsed"))
        .ok_or_else(|| eyre::eyre!("trace call not found: to={to} selector={selector}"))
        .and_then(hex_u64)
}

pub(crate) fn ensure_call_trace_succeeded(trace: &Value) -> eyre::Result<()> {
    if let Some(summary) = failed_call_summary(trace) {
        eyre::bail!("call trace contains failed call: {summary}");
    }
    Ok(())
}

fn failed_call_summary(trace: &Value) -> Option<String> {
    let error = trace.get("error").and_then(Value::as_str);
    let revert_reason = trace.get("revertReason").and_then(Value::as_str);
    if error.is_some() || revert_reason.is_some() {
        let to = trace
            .get("to")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        let selector = trace
            .get("input")
            .and_then(Value::as_str)
            .and_then(|input| input.get(..10))
            .unwrap_or("<missing>");
        let gas_used = trace
            .get("gasUsed")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        return Some(format!(
            "to={to} selector={selector} gasUsed={gas_used} error={} revertReason={}",
            error.unwrap_or("<none>"),
            revert_reason.unwrap_or("<none>")
        ));
    }

    trace
        .get("calls")
        .and_then(Value::as_array)?
        .iter()
        .find_map(failed_call_summary)
}

fn find_call<'a>(trace: &'a Value, to: &str, selector: &str) -> Option<&'a Value> {
    let matches = trace
        .get("to")
        .and_then(Value::as_str)
        .is_some_and(|address| address.eq_ignore_ascii_case(to))
        && trace
            .get("input")
            .and_then(Value::as_str)
            .is_some_and(|input| selector_matches(input, selector));
    if matches {
        return Some(trace);
    }
    trace
        .get("calls")
        .and_then(Value::as_array)?
        .iter()
        .find_map(|call| find_call(call, to, selector))
}

fn selector_matches(input: &str, selector: &str) -> bool {
    input
        .get(..selector.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(selector))
}

pub(crate) fn hex_u64(value: &Value) -> eyre::Result<u64> {
    let value = value
        .as_str()
        .ok_or_else(|| eyre::eyre!("expected hex u64 string, got {value}"))?;
    hex_u64_str(value)
}

pub(crate) fn hex_u64_str(value: &str) -> eyre::Result<u64> {
    Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
}
