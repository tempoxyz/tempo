//! Native multisig approval coordination, fenced submission and durable recovery.

use crate::{
    Backend, Next, Plugin, Request, RpcError,
    store::{Store, now},
    wire::{self, Envelope, Rlp, Witness},
};
use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_sol_types::{SolCall, sol};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tempo_alloy::provider::relay::{RelayMultisigConfig, RelayMultisigOwner};
use tempo_primitives::transaction::PrimitiveSignature;

sol! {
    struct NativeOwner { address owner; uint8 weight; }
    struct NativeConfig { bytes32 salt; uint64 version; uint8 threshold; NativeOwner[] owners; }
    function updateConfig(NativeConfig current, uint8 threshold, NativeOwner[] owners);
}

const PENDING_TTL: u64 = 30 * 24 * 60 * 60 * 1000;
const LEASE_TTL: u64 = 30_000;

/// Configurable multisig coordination plugin. The downstream must implement native multisig.
pub struct Multisig {
    store: Arc<dyn Store>,
    backend: Arc<dyn Backend>,
    chain_id: u64,
    sponsor: Option<Arc<crate::sponsor::Sponsor>>,
}

impl Multisig {
    /// Binds a shared atomic store to one chain and its downstream.
    pub fn new(store: Arc<dyn Store>, backend: Arc<dyn Backend>, chain_id: u64) -> Self {
        Self {
            store,
            backend,
            chain_id,
            sponsor: None,
        }
    }
    /// Installs the relay's sole signer for deferred sponsorship after owner quorum.
    pub fn with_sponsor(mut self, sponsor: Arc<crate::sponsor::Sponsor>) -> Self {
        self.sponsor = Some(sponsor);
        self
    }

    fn key(&self, kind: &str, suffix: impl std::fmt::Display) -> String {
        format!("multisig:{}:{kind}:{suffix}", self.chain_id)
    }

    async fn commitment(&self, account: Address) -> Result<B256, RpcError> {
        let block = self
            .backend
            .request(Request::new("eth_blockNumber", vec![]))
            .await?;
        let selector = &keccak256("getConfigCommitment(address)")[..4];
        let mut data = selector.to_vec();
        data.extend([0; 12]);
        data.extend(account);
        let result = self.backend.request(Request::new("eth_call", vec![json!({"to": "0xAACC000000000000000000000000000000000000", "data": Bytes::from(data)}), block])).await?;
        serde_json::from_value(result)
            .map_err(|_| RpcError::new(-32603, "Invalid native multisig commitment response"))
    }

    async fn validate(&self, witness: &Witness) -> Result<B256, RpcError> {
        wire::validate_config(&witness.config)?;
        if witness.config.version == 0 && wire::account(&witness.config)? != witness.account {
            return Err(RpcError::invalid(
                "Initial multisig config does not match the multisig account",
            ));
        }
        let commitment = self.commitment(witness.account).await?;
        if !(commitment.is_zero() && witness.config.version == 0)
            && commitment != wire::commitment(&witness.config)
        {
            return Err(RpcError::invalid("Multisig config does not match account"));
        }
        Ok(commitment)
    }

    async fn cache_config(&self, witness: &Witness, commitment: B256) -> Result<(), RpcError> {
        let serialized = serde_json::to_string(&witness.config).map_err(internal)?;
        for commitment in [commitment, wire::commitment(&witness.config)] {
            let key = self.key("config", format!("{}:{commitment}", witness.account));
            let previous = self.store.get(&key).await?;
            self.store
                .compare_and_set(&key, previous.as_deref(), Some(&serialized), None)
                .await?;
        }
        Ok(())
    }

    async fn read(&self, hash: B256) -> Result<Option<Record>, RpcError> {
        self.store
            .get(&self.key("operation", hash))
            .await?
            .map(|value| Record::decode(&value, hash))
            .transpose()
    }

    async fn update(
        &self,
        hash: B256,
        update: impl Fn(Option<Record>) -> Result<Record, RpcError>,
    ) -> Result<Record, RpcError> {
        let key = self.key("operation", hash);
        for _ in 0..32 {
            let previous = self.store.get(&key).await?;
            let current = previous
                .as_deref()
                .map(|value| Record::decode(value, hash))
                .transpose()?;
            let next = update(current)?;
            let serialized = serde_json::to_string(&next).map_err(internal)?;
            if serialized.len() > 1_048_576 {
                return Err(RpcError::invalid(
                    "Multisig operation exceeds storage limit",
                ));
            }
            let expiration = (next.status != "success").then(|| now().saturating_add(PENDING_TTL));
            if self
                .store
                .compare_and_set(&key, previous.as_deref(), Some(&serialized), expiration)
                .await?
            {
                return Ok(next);
            }
        }
        Err(RpcError::new(-32603, "Multisig store conflict"))
    }

    async fn collect(&self, envelope: &Envelope) -> Result<Record, RpcError> {
        let chain = envelope.chain_id()?;
        if chain != self.chain_id && !(envelope.prefix.is_none() && chain == 0) {
            return Err(RpcError::invalid("Conflicting chain ids"));
        }
        if envelope.witness.approvals.is_empty() {
            return Err(RpcError::invalid(
                "A multisig approval envelope must include a signature",
            ));
        }
        let commitment = self.validate(&envelope.witness).await?;
        let hash = envelope.witness.digest(envelope.payload_hash());
        // Verify even when the record is already submitted; malformed new approvals are not trusted.
        envelope.witness.select(hash, &envelope.witness.approvals)?;
        let operation = self
            .update(hash, |existing| {
                let mut record = existing.unwrap_or_else(|| Record::new(envelope, hash));
                if record.kind
                    != if envelope.prefix.is_some() {
                        "transaction"
                    } else {
                        "keyAuthorization"
                    }
                    || record.account != envelope.witness.account
                    || record.config != envelope.witness.config
                {
                    return Err(internal("Inconsistent multisig operation"));
                }
                if record.status == "success" || record.status == "submitting" {
                    return Ok(record);
                }
                let approvals = [
                    record.approvals.as_slice(),
                    envelope.witness.approvals.as_slice(),
                ]
                .concat();
                let selected = envelope.witness.select(hash, &approvals)?;
                record.approvals = selected.retained;
                record.weight = selected.weight;
                record.signature_count = selected.selected.len() as u8;
                record.updated_at = now();
                if envelope.prefix.is_none() && record.weight >= record.threshold {
                    let witness = Witness {
                        approvals: selected.selected,
                        ..envelope.witness.clone()
                    };
                    record.key_authorization = Some(envelope.serialize(Some(&witness)));
                    record.status = "success".into();
                } else if envelope.prefix.is_some() {
                    // Upgrade an unsigned fee-payer marker to a concrete sponsor signature without
                    // changing the sender's signing hash or discarding an existing sponsorship.
                    let incoming_signed = matches!(envelope.fields[11], Rlp::List(_));
                    let existing_envelope = record.envelope()?;
                    if incoming_signed || existing_envelope.fields[11] == Rlp::Bytes(Vec::new()) {
                        record.transaction = Some(envelope.unsigned());
                    }
                }
                Ok(record)
            })
            .await?;
        self.cache_config(&envelope.witness, commitment).await?;
        self.cache_next_configs(envelope).await?;
        Ok(operation)
    }

    async fn cache_next_configs(&self, envelope: &Envelope) -> Result<(), RpcError> {
        if envelope.prefix.is_none() {
            return Ok(());
        }
        let mut current = envelope.witness.config.clone();
        for call in envelope.fields[4].list()? {
            let fields = call.list()?;
            if fields.len() != 3
                || fields[0].bytes()?
                    != alloy_primitives::address!("aacc000000000000000000000000000000000000")
                        .as_slice()
            {
                continue;
            }
            let Ok(decoded) = updateConfigCall::abi_decode(fields[2].bytes()?) else {
                continue;
            };
            let supplied = RelayMultisigConfig {
                salt: decoded.current.salt,
                version: decoded.current.version,
                threshold: decoded.current.threshold,
                owners: decoded
                    .current
                    .owners
                    .into_iter()
                    .map(|owner| RelayMultisigOwner {
                        owner: owner.owner,
                        weight: owner.weight,
                    })
                    .collect(),
            };
            if wire::validate_config(&supplied).is_err()
                || wire::commitment(&supplied) != wire::commitment(&current)
            {
                continue;
            }
            let Some(version) = supplied.version.checked_add(1) else {
                continue;
            };
            let next = RelayMultisigConfig {
                salt: supplied.salt,
                version,
                threshold: decoded.threshold,
                owners: decoded
                    .owners
                    .into_iter()
                    .map(|owner| RelayMultisigOwner {
                        owner: owner.owner,
                        weight: owner.weight,
                    })
                    .collect(),
            };
            if wire::validate_config(&next).is_err() {
                continue;
            }
            self.cache_config(
                &Witness {
                    account: envelope.witness.account,
                    config: next.clone(),
                    approvals: Vec::new(),
                },
                wire::commitment(&next),
            )
            .await?;
            current = next;
        }
        Ok(())
    }

    async fn reconcile(&self, record: Record) -> Result<Record, RpcError> {
        if record.status != "submitting" {
            return Ok(record);
        }
        let Some(hash) = record.candidate_hash else {
            return Err(internal("Missing persisted submission hash"));
        };
        // Exact persisted bytes/hash survive changes to the config and mutable relay callbacks.
        let transaction = self
            .backend
            .request(Request::new("eth_getTransactionByHash", vec![json!(hash)]))
            .await?;
        if !transaction.is_null() {
            return self.finish(&record, hash).await;
        }
        if record
            .expires_at
            .is_some_and(|expiration| expiration <= now())
        {
            return self
                .update(record.hash, |current| {
                    let mut current = current.ok_or_else(|| internal("Missing operation"))?;
                    if current.status == "submitting"
                        && current.submission_id == record.submission_id
                        && current
                            .expires_at
                            .is_some_and(|expiration| expiration <= now())
                    {
                        current.status = "pending".into();
                        current.expires_at = None;
                        current.submission_id = None;
                        current.candidate_hash = None;
                        current.final_transaction = None;
                        current.updated_at = now();
                    }
                    Ok(current)
                })
                .await;
        }
        Ok(record)
    }

    async fn finish(&self, submitted: &Record, hash: B256) -> Result<Record, RpcError> {
        self.update(submitted.hash, |current| {
            let mut current = current.ok_or_else(|| internal("Missing operation"))?;
            if current.status == "success" {
                if current.transaction_hash != Some(hash) {
                    return Err(internal("Conflicting submitted transaction hash"));
                }
                return Ok(current);
            }
            if current.status != "submitting" || current.submission_id != submitted.submission_id {
                return Err(internal("Lost multisig submission lease"));
            }
            current.status = "success".into();
            current.transaction_hash = Some(hash);
            current.expires_at = None;
            current.submission_id = None;
            current.final_transaction = None;
            current.candidate_hash = None;
            current.updated_at = now();
            Ok(current)
        })
        .await
    }

    async fn submit(&self, request: Request, envelope: Envelope) -> Result<Value, RpcError> {
        let mut operation = self.collect(&envelope).await?;
        if operation.status == "submitting" {
            operation = self.reconcile(operation).await?;
        }
        let synchronous = request.method.ends_with("Sync");
        let timeout = request
            .params
            .get(1)
            .and_then(Value::as_u64)
            .unwrap_or(LEASE_TTL);
        let deadline = now().saturating_add(timeout);
        while operation.status == "submitting" && synchronous && now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
            operation = self
                .reconcile(
                    self.read(operation.hash)
                        .await?
                        .ok_or_else(|| internal("Missing operation"))?,
                )
                .await?;
        }
        if operation.status != "pending" || operation.weight < operation.threshold {
            return self.result(&request, operation).await;
        }
        self.validate(&operation.envelope()?.witness).await?;
        let submission_id = B256::random();
        let lease_ttl = if synchronous {
            timeout.saturating_add(LEASE_TTL)
        } else {
            LEASE_TTL
        };
        operation = self
            .update(operation.hash, |current| {
                let mut current = current.ok_or_else(|| internal("Missing operation"))?;
                if current.status != "pending" || current.weight < current.threshold {
                    return Ok(current);
                }
                let mut final_envelope = current.envelope()?;
                let selected = final_envelope
                    .witness
                    .select(current.hash, &current.approvals)?;
                final_envelope.witness.approvals = selected.selected;
                let final_bytes = final_envelope.serialize(Some(&final_envelope.witness));
                current.status = "submitting".into();
                current.submission_id = Some(submission_id);
                current.expires_at = Some(now().saturating_add(lease_ttl));
                current.candidate_hash = Some(keccak256(&final_bytes));
                current.final_transaction = Some(final_bytes);
                current.updated_at = now();
                Ok(current)
            })
            .await?;
        if operation.submission_id != Some(submission_id) {
            return self.result(&request, operation).await;
        }
        if let Some(sponsor) = &self.sponsor {
            let final_bytes = operation
                .final_transaction
                .as_ref()
                .expect("persisted claim");
            let envelope = Envelope::decode(final_bytes, true)?;
            if !matches!(envelope.fields[11], Rlp::List(_))
                && envelope.fields[11] != Rlp::Bytes(Vec::new())
            {
                let signing = sponsor.sign_multisig(envelope, &request.method);
                tokio::pin!(signing);
                let signed = loop {
                    tokio::select! {
                        signed = &mut signing => match signed {
                            Ok(signed) => break signed,
                            Err(error) => {
                                self.update(operation.hash, |current| {
                                    let mut current = current.ok_or_else(|| internal("Missing operation"))?;
                                    if current.status == "submitting" && current.submission_id == Some(submission_id) {
                                        current.status = "pending".into(); current.expires_at = None; current.submission_id = None;
                                        current.final_transaction = None; current.candidate_hash = None; current.updated_at = now();
                                    }
                                    Ok(current)
                                }).await?;
                                return Err(error);
                            }
                        },
                        _ = tokio::time::sleep(Duration::from_millis(LEASE_TTL / 2)) => {
                            operation = self.renew(&operation, lease_ttl).await?;
                        }
                    }
                };
                operation = self
                    .update(operation.hash, |current| {
                        let mut current = current.ok_or_else(|| internal("Missing operation"))?;
                        if current.status != "submitting"
                            || current.submission_id != Some(submission_id)
                        {
                            return Err(internal("Lost multisig submission lease"));
                        }
                        current.candidate_hash = Some(keccak256(&signed));
                        current.final_transaction = Some(signed.clone());
                        current.updated_at = now();
                        Ok(current)
                    })
                    .await?;
            }
        }
        let mut parameters = request.params.clone();
        parameters[0] = json!(operation.final_transaction);
        let broadcast = self.backend.request(Request::new(
            if synchronous {
                "eth_sendRawTransactionSync"
            } else {
                "eth_sendRawTransaction"
            },
            parameters,
        ));
        tokio::pin!(broadcast);
        let result = loop {
            tokio::select! {
                result = &mut broadcast => break result,
                _ = tokio::time::sleep(Duration::from_millis(LEASE_TTL / 2)) => {
                    operation = self.update(operation.hash, |current| {
                        let mut current = current.ok_or_else(|| internal("Missing operation"))?;
                        if current.status != "submitting" || current.submission_id != Some(submission_id) { return Err(internal("Lost multisig submission lease")); }
                        current.expires_at = Some(now().saturating_add(lease_ttl)); current.updated_at = now(); Ok(current)
                    }).await?;
                }
            }
        };
        match result {
            Ok(response) => {
                let hash: B256 = serde_json::from_value(if response.is_string() {
                    response.clone()
                } else {
                    response["transactionHash"].clone()
                })
                .map_err(|_| internal("Invalid downstream submission result"))?;
                if Some(hash) != operation.candidate_hash {
                    return Err(internal(
                        "Downstream transaction hash does not match durable submission",
                    ));
                }
                let success = self.finish(&operation, hash).await?;
                if request.method == "eth_sendRawTransactionSync" && response.is_object() {
                    let mut response = response;
                    response["multisig"] = success.rpc();
                    return Ok(response);
                }
                self.result(&request, success).await
            }
            Err(error) => {
                // Never clear durable bytes solely because transport failed: cancellation or a
                // timeout may have happened after the node accepted the transaction.
                if let Ok(recovered) = self.reconcile(operation).await
                    && recovered.status == "success"
                {
                    return self.result(&request, recovered).await;
                }
                Err(error)
            }
        }
    }

    async fn result(&self, request: &Request, record: Record) -> Result<Value, RpcError> {
        if !request.method.ends_with("Sync") {
            return Ok(json!(record.hash));
        }
        if request.method == "multisig_approveRawTransactionSync" {
            return Ok(record.rpc());
        }
        if record.status == "success" {
            let deadline = tokio::time::Instant::now()
                + Duration::from_millis(
                    request
                        .params
                        .get(1)
                        .and_then(Value::as_u64)
                        .unwrap_or(LEASE_TTL),
                );
            loop {
                let receipt = self
                    .backend
                    .request(Request::new(
                        "eth_getTransactionReceipt",
                        vec![json!(record.transaction_hash)],
                    ))
                    .await?;
                if receipt.is_object() {
                    let mut receipt = receipt;
                    receipt["multisig"] = record.rpc();
                    return Ok(receipt);
                }
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        Ok(
            json!({"blockHash": null, "blockNumber": null, "contractAddress": null, "cumulativeGasUsed": null, "effectiveGasPrice": null, "from": record.account, "gasUsed": null, "logs": [], "logsBloom": null, "multisig": record.rpc(), "status": "pending", "to": null, "transactionHash": record.hash, "transactionIndex": null, "type": "0x76"}),
        )
    }

    async fn renew(&self, record: &Record, lease_ttl: u64) -> Result<Record, RpcError> {
        self.update(record.hash, |current| {
            let mut current = current.ok_or_else(|| internal("Missing operation"))?;
            if current.status != "submitting" || current.submission_id != record.submission_id {
                return Err(internal("Lost multisig submission lease"));
            }
            current.expires_at = Some(now().saturating_add(lease_ttl));
            current.updated_at = now();
            Ok(current)
        })
        .await
    }

    async fn authorization(&self, value: &Value) -> Result<Value, RpcError> {
        if let Some(serialized) = value.get("keyAuthorization") {
            let envelope = if serialized.is_object() {
                Envelope::from_rpc_authorization(serialized)?
            } else {
                let bytes: Bytes = serde_json::from_value(serialized.clone())
                    .map_err(|_| RpcError::invalid("Invalid key authorization"))?;
                Envelope::decode(&bytes, false)?
            };
            return Ok(self.collect(&envelope).await?.rpc());
        }
        let hash: B256 = serde_json::from_value(value["hash"].clone())
            .map_err(|_| RpcError::invalid("Expected a multisig operation hash"))?;
        let record = self
            .read(hash)
            .await?
            .filter(|record| record.kind == "keyAuthorization")
            .ok_or_else(|| {
                RpcError::invalid("Multisig key authorization operation was not found")
            })?;
        if record.status == "success" {
            return Ok(record.rpc());
        }
        let signature: Bytes = if value["signature"].is_string() {
            serde_json::from_value(value["signature"].clone())
                .map_err(|_| RpcError::invalid("Invalid multisig owner signature"))?
        } else {
            serde_json::from_value::<PrimitiveSignature>(value["signature"].clone())
                .map_err(|_| RpcError::invalid("Invalid multisig owner signature"))?
                .to_bytes()
        };
        let mut envelope = record.envelope()?;
        envelope.witness.approvals = vec![signature];
        Ok(self.collect(&envelope).await?.rpc())
    }
}

#[async_trait]
impl Plugin for Multisig {
    async fn handle(&self, request: Request, next: Next<'_>) -> Result<Value, RpcError> {
        match request.method.as_str() {
            "multisig_getConfig" => {
                let address: Address = serde_json::from_value(
                    request
                        .params
                        .first()
                        .and_then(|v| v.get("address"))
                        .cloned()
                        .unwrap_or(Value::Null),
                )
                .map_err(|_| RpcError::invalid("Expected a multisig account address"))?;
                if address.is_zero() {
                    return Err(RpcError::invalid("Expected a multisig account address"));
                }
                let commitment = self.commitment(address).await?;
                let key = self.key("config", format!("{address}:{commitment}"));
                let Some(value) = self.store.get(&key).await? else {
                    return Ok(Value::Null);
                };
                let config: RelayMultisigConfig = serde_json::from_str(&value).map_err(internal)?;
                wire::validate_config(&config)?;
                if config.version == 0 && wire::account(&config)? != address
                    || commitment.is_zero() && config.version != 0
                    || !commitment.is_zero() && wire::commitment(&config) != commitment
                {
                    return Err(internal("Invalid stored configuration"));
                }
                Ok(json!(config))
            }
            "multisig_getOperation" => {
                let hash = parse_hash(request.params.first())?;
                Ok(self
                    .read(hash)
                    .await?
                    .map(|record| record.rpc())
                    .unwrap_or(Value::Null))
            }
            "multisig_approveKeyAuthorization" => {
                self.authorization(request.params.first().unwrap_or(&Value::Null))
                    .await
            }
            "eth_sendRawTransaction"
            | "eth_sendRawTransactionSync"
            | "multisig_approveRawTransaction"
            | "multisig_approveRawTransactionSync" => {
                let bytes = request
                    .params
                    .first()
                    .cloned()
                    .and_then(|value| serde_json::from_value::<Bytes>(value).ok());
                if let Some(bytes) = bytes
                    && let Ok(envelope) = Envelope::decode(&bytes, true)
                {
                    return self.submit(request, envelope).await;
                }
                if request.method.starts_with("multisig_") {
                    return Err(RpcError::invalid(
                        "Expected a serialized Tempo multisig transaction",
                    ));
                }
                next.run(request).await
            }
            "eth_getTransactionByHash" | "eth_getTransactionReceipt" => {
                let Ok(hash) = parse_hash(request.params.first()) else {
                    return next.run(request).await;
                };
                let Some(record) = self.read(hash).await? else {
                    return next.run(request).await;
                };
                if record.kind != "transaction" {
                    return next.run(request).await;
                }
                let record = self.reconcile(record).await?;
                let transaction_hash = record.transaction_hash.or(record.candidate_hash);
                if let Some(transaction_hash) = transaction_hash {
                    let mut parameters = request.params.clone();
                    parameters[0] = json!(transaction_hash);
                    let mut result = self
                        .backend
                        .request(Request::new(&request.method, parameters))
                        .await?;
                    if result.is_object() {
                        result["multisig"] = record.rpc();
                        return Ok(result);
                    }
                }
                if request.method == "eth_getTransactionReceipt" {
                    return Ok(Value::Null);
                }
                let envelope = record.envelope()?;
                self.validate(&envelope.witness).await?;
                let mut result = envelope.rpc_transaction()?;
                result["multisig"] = record.rpc();
                result["hash"] = json!(record.hash);
                result["from"] = json!(record.account);
                Ok(result)
            }
            _ => next.run(request).await,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    #[serde(rename = "type")]
    kind: String,
    account: Address,
    approvals: Vec<Bytes>,
    config: RelayMultisigConfig,
    created_at: u64,
    hash: B256,
    signature_count: u8,
    status: String,
    threshold: u8,
    updated_at: u64,
    weight: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_authorization: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    submission_id: Option<B256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction_hash: Option<B256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    final_transaction: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate_hash: Option<B256>,
}

impl Record {
    fn new(envelope: &Envelope, hash: B256) -> Self {
        Self {
            kind: if envelope.prefix.is_some() {
                "transaction"
            } else {
                "keyAuthorization"
            }
            .into(),
            account: envelope.witness.account,
            approvals: Vec::new(),
            config: envelope.witness.config.clone(),
            created_at: now(),
            hash,
            signature_count: 0,
            status: "pending".into(),
            threshold: envelope.witness.config.threshold,
            updated_at: now(),
            weight: 0,
            transaction: envelope.prefix.map(|_| envelope.unsigned()),
            key_authorization: envelope.prefix.is_none().then(|| envelope.unsigned()),
            expires_at: None,
            submission_id: None,
            transaction_hash: None,
            final_transaction: None,
            candidate_hash: None,
        }
    }

    fn envelope(&self) -> Result<Envelope, RpcError> {
        let transaction = self.kind == "transaction";
        let bytes = if transaction {
            self.transaction.as_ref()
        } else {
            self.key_authorization.as_ref()
        }
        .ok_or_else(|| internal("Missing stored operation payload"))?;
        let (prefix, payload) = if transaction {
            let (prefix, payload) = bytes
                .split_first()
                .ok_or_else(|| internal("Empty stored envelope"))?;
            (Some(*prefix), payload)
        } else {
            (None, bytes.as_ref())
        };
        let mut fields = Rlp::decode(payload)?.list()?.to_vec();
        if !transaction && fields.len() == 2 {
            fields.pop();
        }
        if transaction && !(13..=14).contains(&fields.len()) || !transaction && fields.len() != 1 {
            return Err(internal("Invalid stored envelope fields"));
        }
        if transaction {
            wire::validate_transaction_fields(prefix, &fields)?;
        }
        Ok(Envelope {
            prefix,
            fields,
            witness: Witness {
                account: self.account,
                config: self.config.clone(),
                approvals: self.approvals.clone(),
            },
        })
    }

    fn decode(value: &str, hash: B256) -> Result<Self, RpcError> {
        if value.len() > 1_048_576 {
            return Err(internal("Stored multisig operation exceeds limit"));
        }
        let record: Self = serde_json::from_str(value).map_err(internal)?;
        let envelope = record.envelope()?;
        wire::validate_config(&record.config)?;
        if record.hash != hash
            || envelope.witness.digest(envelope.payload_hash()) != hash
            || !matches!(record.status.as_str(), "pending" | "submitting" | "success")
            || !matches!(record.kind.as_str(), "transaction" | "keyAuthorization")
            || record.threshold != record.config.threshold
            || record.approvals.len() > 48
            || record.account.is_zero()
            || record.config.version == 0 && wire::account(&record.config)? != record.account
            || record.kind == "transaction" && !matches!(envelope.prefix, Some(0x76 | 0x78))
            || record.kind == "keyAuthorization" && record.status == "submitting"
            || record.status != "submitting"
                && (record.submission_id.is_some()
                    || record.expires_at.is_some()
                    || record.final_transaction.is_some()
                    || record.candidate_hash.is_some())
        {
            return Err(internal("Invalid stored operation"));
        }
        let selection = envelope.witness.select(hash, &record.approvals)?;
        if selection.weight != record.weight
            || selection.selected.len() != usize::from(record.signature_count)
        {
            return Err(internal("Invalid stored quorum"));
        }
        if record.status == "success" {
            if record.weight < record.threshold
                || record.kind == "transaction" && record.transaction_hash.is_none()
            {
                return Err(internal("Invalid completed operation"));
            }
            if record.kind == "keyAuthorization" {
                let signed = Envelope::decode(
                    record
                        .key_authorization
                        .as_ref()
                        .ok_or_else(|| internal("Missing completed authorization"))?,
                    false,
                )?;
                if signed.witness.digest(signed.payload_hash()) != hash
                    || signed.witness.account != record.account
                    || signed.witness.config != record.config
                    || signed
                        .witness
                        .select(hash, &signed.witness.approvals)?
                        .weight
                        < record.threshold
                {
                    return Err(internal("Invalid completed authorization"));
                }
            }
        }
        if record.status == "submitting" {
            let final_bytes = record
                .final_transaction
                .as_ref()
                .ok_or_else(|| internal("Missing durable submission bytes"))?;
            let final_envelope = Envelope::decode(final_bytes, true)?;
            if record.submission_id.is_none()
                || record.expires_at.is_none()
                || record.candidate_hash != Some(keccak256(final_bytes))
                || final_envelope.witness.digest(final_envelope.payload_hash()) != hash
                || final_envelope.witness.config != record.config
                || final_envelope.witness.account != record.account
                || final_envelope
                    .witness
                    .select(hash, &final_envelope.witness.approvals)?
                    .weight
                    < record.threshold
            {
                return Err(internal("Invalid durable submission"));
            }
        }
        Ok(record)
    }

    fn rpc(&self) -> Value {
        let mut value = json!(self);
        let object = value.as_object_mut().expect("serialized record");
        object.remove("finalTransaction");
        object.remove("candidateHash");
        value
    }
}

fn parse_hash(value: Option<&Value>) -> Result<B256, RpcError> {
    serde_json::from_value(value.cloned().unwrap_or(Value::Null))
        .map_err(|_| RpcError::invalid("Expected a multisig operation hash"))
}
fn internal(error: impl std::fmt::Display) -> RpcError {
    RpcError::new(-32603, error.to_string())
}
