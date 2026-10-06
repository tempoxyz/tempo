//! Fee-payer signing with explicit chain, fee-token, and gas-limit policy.

use crate::{Next, Request, RpcError};
use alloy_consensus::transaction::SignerRecoverable;
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, Bytes, Signature, U256};
use alloy_rlp::{Decodable, Encodable, Header};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::Arc;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_primitives::{AASigned, TempoTransaction, transaction::FEE_PAYER_SIGNATURE_MARKER};

/// Custody boundary for local, hardware, or remote fee-payer signers.
#[async_trait]
pub trait FeePayer: Send + Sync {
    /// Address whose funds pay the fees.
    fn address(&self) -> Address;
    /// Signs exactly the supplied Tempo fee-payer hash.
    async fn sign_hash(&self, hash: B256) -> Result<Signature, RpcError>;
}

/// Optional per-transaction sponsorship approval.
#[async_trait]
pub trait Policy: Send + Sync {
    /// `None` approves; a named refusal or an empty string rejects.
    async fn validate(&self, transaction: &Value) -> Result<Option<String>, RpcError>;
}

/// Facts recorded after signing and before returning or broadcasting.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SponsoredEvent {
    /// Target chain.
    pub chain_id: u64,
    /// Selected fee token.
    pub fee_token: Address,
    /// RPC method that requested sponsorship.
    pub method: String,
    /// Sender account.
    pub sender: Address,
    /// Stable fee-payer signing payload.
    pub sign_payload: B256,
    /// Serialized sponsored transaction or unsigned fill intent.
    pub transaction: Bytes,
    /// Actual hash for sender-signed transactions; absent for fill intents.
    pub transaction_hash: Option<B256>,
}

/// Durable recording callback. Errors refuse the broadcast.
#[async_trait]
pub trait Observer: Send + Sync {
    /// Records a commitment exactly once for this signing invocation.
    async fn on_sponsored(&self, event: SponsoredEvent) -> Result<(), RpcError>;
}

#[async_trait]
impl FeePayer for PrivateKeySigner {
    fn address(&self) -> Address {
        Signer::address(self)
    }

    async fn sign_hash(&self, hash: B256) -> Result<Signature, RpcError> {
        Signer::sign_hash(self, &hash)
            .await
            .map_err(|_| RpcError::new(-32603, "Fee payer signing failed"))
    }
}

/// An opt-in fee payer with a fixed chain and fee token.
pub struct Sponsor {
    signer: Arc<dyn FeePayer>,
    chain_id: u64,
    fee_token: Address,
    max_gas: u64,
    max_fee_per_gas: u128,
    policy: Option<Arc<dyn Policy>>,
    observer: Option<Arc<dyn Observer>>,
    name: Option<String>,
    url: Option<String>,
}

impl Sponsor {
    /// Configures sponsorship limits. This does not authorize production usage.
    pub fn new(
        signer: Arc<dyn FeePayer>,
        chain_id: u64,
        fee_token: Address,
        max_gas: u64,
        max_fee_per_gas: u128,
    ) -> Result<Self, RpcError> {
        if chain_id == 0 || fee_token.is_zero() || max_gas == 0 || max_fee_per_gas == 0 {
            return Err(RpcError::invalid(
                "Sponsor chain, token and fee limits must be nonzero",
            ));
        }
        Ok(Self {
            signer,
            chain_id,
            fee_token,
            max_gas,
            max_fee_per_gas,
            policy: None,
            observer: None,
            name: None,
            url: None,
        })
    }

    /// Installs an asynchronous per-transaction approval callback.
    pub fn with_policy(mut self, policy: Arc<dyn Policy>) -> Self {
        self.policy = Some(policy);
        self
    }
    /// Installs a recording callback awaited before any sponsored broadcast.
    pub fn with_observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observer = Some(observer);
        self
    }
    /// Adds optional display metadata to fill capabilities.
    pub fn with_metadata(mut self, name: Option<String>, url: Option<String>) -> Self {
        self.name = name;
        self.url = url;
        self
    }

    pub(crate) async fn approve_fill(
        &self,
        original: &Request,
        filled: &Value,
    ) -> Result<bool, RpcError> {
        if original.transaction()?.get("feePayer") == Some(&json!(false)) {
            return Ok(true);
        }
        let Some(policy) = &self.policy else {
            return Ok(true);
        };
        let mut transaction = filled["tx"].clone();
        transaction["from"] = original.params[0]["from"].clone();
        Ok(policy.validate(&transaction).await?.is_none())
    }

    pub(crate) fn prepare_fill(&self, request: &mut Request) -> Result<(), RpcError> {
        let transaction = request.transaction_mut()?;
        match transaction.get("feePayer") {
            Some(Value::Bool(false)) => return Ok(()),
            None | Some(Value::Bool(true)) => {}
            _ => {
                return Err(RpcError::invalid(
                    "External fee payer URLs are not supported",
                ));
            }
        }
        if transaction
            .get("feePayerSignature")
            .is_some_and(|value| !value.is_null())
        {
            return Err(RpcError::invalid(
                "Fill sponsorship cannot replace an existing fee payer signature",
            ));
        }
        transaction.insert("feePayer".into(), json!(true));
        if let Some(value) = transaction.get("chainId") {
            let chain = value.as_u64().or_else(|| {
                value.as_str().and_then(|value| {
                    value
                        .strip_prefix("0x")
                        .and_then(|value| u64::from_str_radix(value, 16).ok())
                })
            });
            if chain != Some(self.chain_id) {
                return Err(RpcError::invalid("Conflicting chain IDs"));
            }
        }
        transaction.insert("chainId".into(), json!(format!("{:#x}", self.chain_id)));
        transaction.remove("feeToken");
        Ok(())
    }

    pub(crate) fn finalize_fill(
        &self,
        original: &Request,
        filled: &mut Value,
    ) -> Result<(), RpcError> {
        if original.transaction()?.get("feePayer") == Some(&json!(false)) {
            return Ok(());
        }
        let transaction = filled
            .get_mut("tx")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| RpcError::new(-32603, "Missing filled transaction"))?;
        let prepared = original.transaction()?.contains_key("gas")
            && original.transaction()?.contains_key("nonce")
            && (original.transaction()?.contains_key("maxFeePerGas")
                || original.transaction()?.contains_key("gasPrice"));
        if (!prepared || original.transaction()?.get("feePayer") != Some(&json!(true)))
            && transaction
                .get("feePayerSignature")
                .is_none_or(Value::is_null)
            && let Some(gas) = transaction.get("gas").and_then(Value::as_str)
        {
            let gas: U256 = gas
                .parse()
                .map_err(|_| RpcError::invalid("Invalid fill gas"))?;
            transaction.insert(
                "gas".into(),
                json!(format!(
                    "{:#x}",
                    gas.checked_add(U256::from(20_000))
                        .ok_or_else(|| RpcError::invalid("Fill gas overflow"))?
                )),
            );
        }
        transaction.insert("feeToken".into(), json!(self.fee_token));
        transaction.remove("signature");
        let mut sponsor = json!({"address": self.signer.address()});
        if let Some(name) = &self.name {
            sponsor["name"] = json!(name);
        }
        if let Some(url) = &self.url {
            sponsor["url"] = json!(url);
        }
        let capabilities = filled
            .as_object_mut()
            .expect("validated response")
            .entry("capabilities")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| RpcError::new(-32603, "Invalid fill capabilities"))?;
        if capabilities.contains_key("sponsor") || capabilities.contains_key("sponsored") {
            return Err(RpcError::invalid("Conflicting sponsor capability"));
        }
        capabilities.insert("sponsor".into(), sponsor.clone());
        capabilities.insert("sponsored".into(), json!(true));
        filled["sponsor"] = sponsor;
        Ok(())
    }

    pub(crate) async fn sign_fill(
        &self,
        original: &Request,
        filled: &mut Value,
    ) -> Result<(), RpcError> {
        if original.transaction()?.get("feePayer") == Some(&json!(false)) {
            return Ok(());
        }
        if original
            .transaction()?
            .get("multisigSimulation")
            .is_some_and(Value::is_object)
        {
            filled["tx"]["feePayerSignature"] = Value::Null;
            return Ok(());
        }
        let sender: Address = serde_json::from_value(
            original
                .transaction()?
                .get("from")
                .cloned()
                .ok_or_else(|| RpcError::invalid("Sponsorship requires from"))?,
        )
        .map_err(|_| RpcError::invalid("Invalid sender address"))?;
        let transaction = filled
            .get_mut("tx")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| RpcError::new(-32603, "Missing filled transaction"))?;
        if transaction
            .get("from")
            .is_some_and(|value| value != &json!(sender))
        {
            let address: Address = serde_json::from_value(transaction["from"].clone())
                .map_err(|_| RpcError::invalid("Invalid filled sender"))?;
            if address != sender {
                return Err(RpcError::invalid("Filled sender differs from request"));
            }
        }
        let request: TempoTransactionRequest =
            serde_json::from_value(Value::Object(transaction.clone()))
                .map_err(|error| RpcError::invalid(error.to_string()))?;
        if request.inner.chain_id.is_none() {
            return Err(RpcError::invalid("Filled transaction is missing chainId"));
        }
        let mut unsigned = request
            .build_aa()
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        unsigned.fee_payer_signature = Some(FEE_PAYER_SIGNATURE_MARKER);
        unsigned.validate().map_err(RpcError::invalid)?;
        let signature = self.sign(&unsigned, sender).await?;
        transaction.insert("feePayerSignature".into(), json!(signature));
        transaction.insert("from".into(), json!(sender));
        unsigned.fee_payer_signature = Some(signature);
        if let Some(observer) = &self.observer {
            let intent = unsigned
                .clone()
                .into_signed(
                    alloy_primitives::Signature::new(U256::from(1), U256::from(1), false).into(),
                )
                .encoded_2718();
            // Strip the dummy outer signature so recording contains an unsigned intent.
            let mut fields = crate::wire::Rlp::decode(&intent[1..])?.list()?.to_vec();
            fields.pop();
            observer
                .on_sponsored(SponsoredEvent {
                    chain_id: unsigned.chain_id,
                    fee_token: self.fee_token,
                    method: original.method.clone(),
                    sender,
                    sign_payload: unsigned.fee_payer_signature_hash(sender),
                    transaction: Bytes::from(
                        [&[0x76][..], &crate::wire::Rlp::List(fields).encode()].concat(),
                    ),
                    transaction_hash: None,
                })
                .await?;
        }
        if let Some(raw) = filled.get("raw") {
            let bytes: Bytes = serde_json::from_value(raw.clone())
                .map_err(|_| RpcError::new(-32603, "Invalid downstream fill raw bytes"))?;
            let mut remaining = bytes.as_ref();
            let envelope = AASigned::decode_2718(&mut remaining)
                .map_err(|_| RpcError::new(-32603, "Invalid downstream fill raw envelope"))?;
            if !remaining.is_empty() {
                return Err(RpcError::new(-32603, "Trailing downstream fill raw data"));
            }
            filled["raw"] = json!(Bytes::from(
                unsigned
                    .into_signed(envelope.signature().clone())
                    .encoded_2718()
            ));
        }
        Ok(())
    }

    pub(crate) async fn handle_raw(
        &self,
        mut request: Request,
        next: Next<'_>,
    ) -> Result<Value, RpcError> {
        let raw: Bytes =
            serde_json::from_value(request.params.first().cloned().unwrap_or(Value::Null))
                .map_err(|_| RpcError::invalid("Expected a serialized transaction"))?;
        if !matches!(raw.first(), Some(0x76 | 0x78)) {
            if request.method == "eth_signRawTransaction" {
                return Err(RpcError::invalid(
                    "Only Tempo (0x76/0x78) transactions can be sponsored",
                ));
            }
            return next.run(request).await;
        }
        if let Ok(envelope) = crate::wire::Envelope::decode(&raw, true) {
            if matches!(envelope.fields[11], crate::wire::Rlp::List(_)) {
                return if request.method == "eth_signRawTransaction" {
                    Ok(json!(raw))
                } else {
                    next.run(request).await
                };
            }
            if envelope.fields[11] == crate::wire::Rlp::Bytes(Vec::new()) {
                return if request.method == "eth_signRawTransaction" {
                    Err(RpcError::invalid(
                        "Transaction must request fee-payer sponsorship",
                    ))
                } else {
                    next.run(request).await
                };
            }
            let signed = self.sign_multisig(envelope, &request.method).await?;
            request.params[0] = json!(signed);
            return if request.method == "eth_signRawTransaction" {
                Ok(request.params[0].clone())
            } else {
                next.run(request).await
            };
        }
        let (canonical, expected_sender) = normalize_service_encoding(&raw)?;
        let mut remaining = canonical.as_slice();
        let signed = AASigned::decode_2718(&mut remaining)
            .map_err(|_| RpcError::invalid("Invalid or unsupported Tempo transaction signature"))?;
        if !remaining.is_empty() {
            return Err(RpcError::invalid("Trailing transaction data"));
        }
        if signed.tx().has_fee_payer_signature_marker() {
            let sender = signed
                .recover_signer()
                .map_err(|_| RpcError::invalid("Invalid sender signature"))?;
            if expected_sender.is_some_and(|expected| sender != expected) {
                return Err(RpcError::invalid(
                    "Fee-payer service sender differs from recovered signer",
                ));
            }
            let (mut transaction, signature, _) = signed.into_parts();
            transaction.validate().map_err(RpcError::invalid)?;
            transaction.fee_token = Some(self.fee_token);
            let mut prepared = json!(TempoTransactionRequest::from(transaction.clone()));
            prepared["from"] = json!(sender);
            prepared["feePayerSignature"] = Value::Null;
            self.approve_raw(&prepared).await?;
            transaction.fee_payer_signature = Some(self.sign(&transaction, sender).await?);
            let hash = transaction.fee_payer_signature_hash(sender);
            let bytes = Bytes::from(transaction.into_signed(signature).encoded_2718());
            self.record(&request.method, sender, hash, &bytes).await?;
            request.params[0] = json!(bytes);
        } else if request.method == "eth_signRawTransaction" {
            return Err(RpcError::invalid(
                "Transaction must request fee-payer sponsorship",
            ));
        }
        if request.method == "eth_signRawTransaction" {
            Ok(request.params[0].clone())
        } else {
            next.run(request).await
        }
    }

    async fn sign(
        &self,
        transaction: &TempoTransaction,
        sender: Address,
    ) -> Result<Signature, RpcError> {
        if transaction.chain_id != self.chain_id {
            return Err(RpcError::invalid("Sponsor chain ID mismatch"));
        }
        if transaction.gas_limit > self.max_gas
            || transaction.max_fee_per_gas > self.max_fee_per_gas
        {
            return Err(RpcError::invalid("Transaction exceeds sponsor fee limits"));
        }
        let hash = transaction.fee_payer_signature_hash(sender);
        if transaction.fee_token != Some(self.fee_token) {
            return Err(RpcError::invalid("Sponsor fee token mismatch"));
        }
        let signature = self.signer.sign_hash(hash).await?;
        if signature.recover_address_from_prehash(&hash).ok() != Some(self.signer.address()) {
            return Err(RpcError::new(
                -32603,
                "Fee payer returned an invalid signature",
            ));
        }
        Ok(signature)
    }

    async fn approve_raw(&self, transaction: &Value) -> Result<(), RpcError> {
        if let Some(policy) = &self.policy
            && let Some(reason) = policy.validate(transaction).await?
        {
            let message = match reason.as_str() {
                "billing_past_due" => "Billing past due.",
                "billing_required" => "Billing required.",
                "fee_token_unsupported" => "Fee token unsupported.",
                "spend_limit_exceeded" => "Spend limit exceeded.",
                "tx_fee_limit_exceeded" => "Transaction fee limit exceeded.",
                _ => "Sponsorship rejected.",
            };
            let mut error = RpcError::invalid(message);
            if !reason.is_empty() {
                error.data = Some(json!({"code": reason}));
            }
            return Err(error);
        }
        Ok(())
    }

    async fn record(
        &self,
        method: &str,
        sender: Address,
        hash: B256,
        bytes: &Bytes,
    ) -> Result<(), RpcError> {
        if let Some(observer) = &self.observer {
            observer
                .on_sponsored(SponsoredEvent {
                    chain_id: self.chain_id,
                    fee_token: self.fee_token,
                    method: method.into(),
                    sender,
                    sign_payload: hash,
                    transaction: bytes.clone(),
                    transaction_hash: Some(alloy_primitives::keccak256(bytes)),
                })
                .await?;
        }
        Ok(())
    }

    /// Signs a complete native multisig envelope without needing a consensus codec.
    pub async fn sign_multisig(
        &self,
        mut envelope: crate::wire::Envelope,
        method: &str,
    ) -> Result<Bytes, RpcError> {
        let digest = envelope.witness.digest(envelope.payload_hash());
        if envelope
            .witness
            .select(digest, &envelope.witness.approvals)?
            .weight
            < envelope.witness.config.threshold
        {
            return Err(RpcError::invalid(
                "Multisig quorum is required before sponsorship",
            ));
        }
        let quantity = |index: usize| -> Result<U256, RpcError> {
            U256::try_from_be_slice(envelope.fields[index].bytes()?)
                .ok_or_else(|| RpcError::invalid("Invalid transaction quantity"))
        };
        if envelope.chain_id()? != self.chain_id
            || quantity(3)? > U256::from(self.max_gas)
            || quantity(2)? > U256::from(self.max_fee_per_gas)
        {
            return Err(RpcError::invalid(
                "Transaction exceeds sponsor chain or fee limits",
            ));
        }
        envelope.fields[10] = crate::wire::Rlp::Bytes(self.fee_token.to_vec());
        self.approve_raw(&envelope.rpc_transaction()?).await?;
        let mut payload = envelope.fields.clone();
        payload[11] = crate::wire::Rlp::Bytes(envelope.witness.account.to_vec());
        let hash = alloy_primitives::keccak256(
            [&[0x78][..], &crate::wire::Rlp::List(payload).encode()].concat(),
        );
        let signature = self.signer.sign_hash(hash).await?;
        if signature.recover_address_from_prehash(&hash).ok() != Some(self.signer.address()) {
            return Err(RpcError::new(
                -32603,
                "Fee payer returned an invalid signature",
            ));
        }
        let integer = |value: U256| {
            let bytes = value.to_be_bytes::<32>();
            crate::wire::Rlp::Bytes(
                bytes[bytes.iter().position(|v| *v != 0).unwrap_or(32)..].to_vec(),
            )
        };
        envelope.fields[11] = crate::wire::Rlp::List(vec![
            crate::wire::Rlp::number(u64::from(signature.v())),
            integer(signature.r()),
            integer(signature.s()),
        ]);
        envelope.prefix = Some(0x76);
        let bytes = envelope.serialize(Some(&envelope.witness));
        self.record(method, envelope.witness.account, hash, &bytes)
            .await?;
        Ok(bytes)
    }
}

fn normalize_service_encoding(raw: &[u8]) -> Result<(Vec<u8>, Option<Address>), RpcError> {
    let invalid = || RpcError::invalid("Invalid Tempo fee-payer service encoding");
    let mut payload = &raw[1..];
    let header = Header::decode(&mut payload).map_err(|_| invalid())?;
    if !header.list || header.payload_length != payload.len() {
        return Err(invalid());
    }
    let mut fields = Vec::new();
    while !payload.is_empty() {
        let original = payload;
        let field = Header::decode(&mut payload).map_err(|_| invalid())?;
        if field.payload_length > payload.len() {
            return Err(invalid());
        }
        payload = &payload[field.payload_length..];
        fields.push(&original[..original.len() - payload.len()]);
    }
    if fields.len() < 14 {
        return Err(invalid());
    }
    let expected_sender = if fields[11].len() == 21 {
        let mut sender = fields[11];
        let address = Address::decode(&mut sender).map_err(|_| invalid())?;
        if !sender.is_empty() {
            return Err(invalid());
        }
        Some(address)
    } else {
        None
    };
    if fields[11] != [0x00] && expected_sender.is_none() {
        if raw[0] == 0x78 {
            return Err(invalid());
        }
        return Ok((raw.to_vec(), None));
    }
    let mut marker = Vec::new();
    let mut signature = Vec::new();
    false.encode(&mut signature);
    U256::ZERO.encode(&mut signature);
    U256::ZERO.encode(&mut signature);
    Header {
        list: true,
        payload_length: signature.len(),
    }
    .encode(&mut marker);
    marker.extend_from_slice(&signature);
    fields[11] = &marker;
    let mut encoded = vec![0x76];
    Header {
        list: true,
        payload_length: fields.iter().map(|field| field.len()).sum(),
    }
    .encode(&mut encoded);
    for field in fields {
        encoded.extend_from_slice(field);
    }
    Ok((encoded, expected_sender))
}
