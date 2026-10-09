//! Native multisig relay codecs, independent of node consensus support.
//!
//! Mirrors ox 0.14.45 fixed-width domains and canonical RLP envelopes.

use crate::RpcError;
use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_rlp::{Decodable, Encodable, Header};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tempo_alloy::provider::relay::RelayMultisigConfig;
use tempo_primitives::transaction::{KeyAuthorization, PrimitiveSignature};

/// Bounded generic RLP representation used for unsupported consensus envelope types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rlp {
    /// Byte string.
    Bytes(Vec<u8>),
    /// RLP list.
    List(Vec<Self>),
}

impl Rlp {
    /// Decodes one canonical RLP item, rejecting trailing bytes and excessive nesting.
    pub fn decode(bytes: &[u8]) -> Result<Self, RpcError> {
        if bytes.len() > 1_048_576 {
            return Err(RpcError::invalid("RLP envelope exceeds limit"));
        }
        let mut remaining = bytes;
        let result = Self::read(&mut remaining, 0)?;
        if !remaining.is_empty() {
            return Err(RpcError::invalid("Trailing RLP bytes"));
        }
        if result.encode() != bytes {
            return Err(RpcError::invalid("Noncanonical RLP"));
        }
        Ok(result)
    }

    fn read(bytes: &mut &[u8], depth: usize) -> Result<Self, RpcError> {
        if depth > 24 {
            return Err(RpcError::invalid("RLP nesting exceeds limit"));
        }
        let header = Header::decode(bytes).map_err(|e| RpcError::invalid(e.to_string()))?;
        if bytes.len() < header.payload_length {
            return Err(RpcError::invalid("Truncated RLP"));
        }
        let (mut payload, rest) = bytes.split_at(header.payload_length);
        *bytes = rest;
        if !header.list {
            return Ok(Self::Bytes(payload.to_vec()));
        }
        let mut values = Vec::new();
        while !payload.is_empty() {
            if values.len() >= 1024 {
                return Err(RpcError::invalid("RLP list exceeds limit"));
            }
            values.push(Self::read(&mut payload, depth + 1)?);
        }
        Ok(Self::List(values))
    }

    /// Encodes canonically.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Bytes(bytes) => {
                let mut out = Vec::new();
                bytes.as_slice().encode(&mut out);
                out
            }
            Self::List(values) => {
                let payload = values.iter().flat_map(Self::encode).collect::<Vec<_>>();
                let mut out = Vec::new();
                Header {
                    list: true,
                    payload_length: payload.len(),
                }
                .encode(&mut out);
                out.extend(payload);
                out
            }
        }
    }

    /// Returns a byte string or an invalid-parameters error.
    pub fn bytes(&self) -> Result<&[u8], RpcError> {
        if let Self::Bytes(bytes) = self {
            Ok(bytes)
        } else {
            Err(RpcError::invalid("Expected RLP bytes"))
        }
    }
    /// Returns a list or an invalid-parameters error.
    pub fn list(&self) -> Result<&[Self], RpcError> {
        if let Self::List(values) = self {
            Ok(values)
        } else {
            Err(RpcError::invalid("Expected RLP list"))
        }
    }
    /// Decodes an unsigned 64-bit RLP integer.
    pub fn integer(&self) -> Result<u64, RpcError> {
        let input = self.encode();
        let mut bytes = input.as_slice();
        u64::decode(&mut bytes).map_err(|e| RpcError::invalid(e.to_string()))
    }
    /// Constructs a canonical RLP integer.
    pub fn number(value: u64) -> Self {
        let bytes = value.to_be_bytes();
        Self::Bytes(bytes[bytes.iter().position(|v| *v != 0).unwrap_or(8)..].to_vec())
    }
}

/// Configuration validation shared by decoding and digest construction.
pub fn validate_config(config: &RelayMultisigConfig) -> Result<(), RpcError> {
    if config.owners.is_empty() || config.owners.len() > 48 || !(1..=8).contains(&config.threshold)
    {
        return Err(RpcError::invalid("Invalid native multisig configuration"));
    }
    let mut previous = Address::ZERO;
    let mut total = 0_u16;
    for owner in &config.owners {
        if owner.owner <= previous || owner.weight == 0 {
            return Err(RpcError::invalid(
                "Owners must be nonzero, weighted and strictly ascending",
            ));
        }
        previous = owner.owner;
        total += u16::from(owner.weight);
    }
    let mut weights = config
        .owners
        .iter()
        .map(|owner| owner.weight)
        .collect::<Vec<_>>();
    weights.sort_unstable_by(|a, b| b.cmp(a));
    if total > 255
        || weights.into_iter().take(8).map(u16::from).sum::<u16>() < u16::from(config.threshold)
    {
        return Err(RpcError::invalid("Unreachable native multisig quorum"));
    }
    Ok(())
}

fn config_parts(config: &RelayMultisigConfig, version: bool, domain: &[u8]) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    bytes.extend(config.salt);
    if version {
        bytes.extend(config.version.to_be_bytes());
    }
    bytes.push(config.threshold);
    bytes.push(config.owners.len() as u8);
    for owner in &config.owners {
        bytes.extend(owner.owner);
        bytes.push(owner.weight);
    }
    bytes
}

/// Commitment used by the native multisig precompile.
pub fn commitment(config: &RelayMultisigConfig) -> B256 {
    keccak256(config_parts(config, true, b"tempo:multisig:config"))
}

/// Version-zero CREATE2 account derivation.
pub fn account(config: &RelayMultisigConfig) -> Result<Address, RpcError> {
    validate_config(config)?;
    if config.version != 0 {
        return Err(RpcError::invalid(
            "Account derivation requires version zero",
        ));
    }
    let salt = keccak256(config_parts(config, false, b"tempo:multisig:account"));
    let factory = Address::repeat_byte(0x71);
    let init =
        alloy_primitives::b256!("583cc63a2e37f645b43eac911b1a6d6de08b83abdc308c61364edda8cfc3bd37");
    let hash = keccak256(
        [
            &[0xff][..],
            factory.as_slice(),
            salt.as_slice(),
            init.as_slice(),
        ]
        .concat(),
    );
    let account = Address::from_slice(&hash[12..]);
    if account.is_zero() || config.owners.iter().any(|owner| owner.owner == account) {
        return Err(RpcError::invalid("Invalid derived multisig account"));
    }
    Ok(account)
}

/// Native multisig signature and complete configuration witness.
#[derive(Clone, Debug)]
pub struct Witness {
    /// Root account.
    pub account: Address,
    /// Current configuration witness.
    pub config: RelayMultisigConfig,
    /// Serialized primitive owner signatures.
    pub approvals: Vec<Bytes>,
}

impl Witness {
    /// Parses the type-0x05 owner envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, RpcError> {
        if bytes.first() != Some(&5) {
            return Err(RpcError::invalid("Expected native multisig signature"));
        }
        let parsed = Rlp::decode(&bytes[1..])?;
        let values = parsed.list()?;
        if values.len() != 3 {
            return Err(RpcError::invalid("Invalid multisig witness"));
        }
        let account = address(&values[0])?;
        let tuple = values[1].list()?;
        if tuple.len() != 4 || tuple[0].bytes()?.len() != 32 {
            return Err(RpcError::invalid("Invalid configuration tuple"));
        }
        let owners = tuple[3]
            .list()?
            .iter()
            .map(|owner| {
                let pair = owner.list()?;
                if pair.len() != 2 {
                    return Err(RpcError::invalid("Invalid owner tuple"));
                }
                Ok(tempo_alloy::provider::relay::RelayMultisigOwner {
                    owner: address(&pair[0])?,
                    weight: u8::try_from(pair[1].integer()?)
                        .map_err(|_| RpcError::invalid("Invalid owner weight"))?,
                })
            })
            .collect::<Result<Vec<_>, RpcError>>()?;
        let config = RelayMultisigConfig {
            salt: B256::from_slice(tuple[0].bytes()?),
            version: tuple[1].integer()?,
            threshold: u8::try_from(tuple[2].integer()?)
                .map_err(|_| RpcError::invalid("Invalid threshold"))?,
            owners,
        };
        validate_config(&config)?;
        let approvals = values[2]
            .list()?
            .iter()
            .map(|v| v.bytes().map(Bytes::copy_from_slice))
            .collect::<Result<Vec<_>, _>>()?;
        if account.is_zero()
            || approvals.is_empty()
            || approvals.len() > 8
            || approvals.iter().any(|a| a.len() > 2049)
        {
            return Err(RpcError::invalid("Invalid native multisig approvals"));
        }
        Ok(Self {
            account,
            config,
            approvals,
        })
    }

    /// Encodes an owner witness with canonical RLP.
    pub fn encode(&self) -> Bytes {
        let owners = self
            .config
            .owners
            .iter()
            .map(|owner| {
                Rlp::List(vec![
                    Rlp::Bytes(owner.owner.to_vec()),
                    Rlp::number(owner.weight.into()),
                ])
            })
            .collect();
        let config = Rlp::List(vec![
            Rlp::Bytes(self.config.salt.to_vec()),
            Rlp::number(self.config.version),
            Rlp::number(self.config.threshold.into()),
            Rlp::List(owners),
        ]);
        let tuple = Rlp::List(vec![
            Rlp::Bytes(self.account.to_vec()),
            config,
            Rlp::List(
                self.approvals
                    .iter()
                    .map(|a| Rlp::Bytes(a.to_vec()))
                    .collect(),
            ),
        ]);
        Bytes::from([&[5][..], &tuple.encode()].concat())
    }

    /// Digest approved by owners.
    pub fn digest(&self, payload: B256) -> B256 {
        keccak256(
            [
                b"tempo:multisig:signature".as_slice(),
                payload.as_slice(),
                self.account.as_slice(),
                &self.config.version.to_be_bytes(),
            ]
            .concat(),
        )
    }

    /// Validates primitive signatures, deduplicates by owner and selects the smallest weighted quorum.
    pub fn select(&self, digest: B256, approvals: &[Bytes]) -> Result<Selection, RpcError> {
        let mut retained = BTreeMap::<Address, Bytes>::new();
        for approval in approvals {
            if approval.len() > 2049 {
                return Err(RpcError::invalid("Owner signature exceeds limit"));
            }
            let signature = PrimitiveSignature::from_bytes(approval).map_err(RpcError::invalid)?;
            let owner = signature
                .recover_signer(&digest)
                .map_err(|e| RpcError::invalid(e.to_string()))?;
            if !self.config.owners.iter().any(|v| v.owner == owner) {
                return Err(RpcError::invalid("Signature from non-owner"));
            }
            let canonical = signature.to_bytes();
            retained
                .entry(owner)
                .and_modify(|value| {
                    if canonical < *value {
                        *value = canonical.clone();
                    }
                })
                .or_insert(canonical);
        }
        let mut ranked = retained
            .iter()
            .map(|(owner, signature)| {
                (
                    *owner,
                    signature.clone(),
                    self.config
                        .owners
                        .iter()
                        .find(|v| v.owner == *owner)
                        .expect("validated owner")
                        .weight,
                )
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
        let mut selected = Vec::new();
        let mut weight = 0_u16;
        for (owner, signature, w) in ranked.into_iter().take(8) {
            if weight >= u16::from(self.config.threshold) {
                break;
            }
            selected.push((owner, signature));
            weight += u16::from(w);
        }
        selected.sort_by_key(|v| v.0);
        Ok(Selection {
            retained: retained.into_values().collect(),
            selected: selected.into_iter().map(|v| v.1).collect(),
            weight: weight as u8,
        })
    }
}

/// Deterministic retained approvals and minimal selected quorum.
pub struct Selection {
    /// One canonical primitive approval per owner.
    pub retained: Vec<Bytes>,
    /// Selected approvals sorted by owner address.
    pub selected: Vec<Bytes>,
    /// Selected owner weight.
    pub weight: u8,
}

/// Transaction or key-authorization envelope, retaining fields the node cannot decode yet.
pub struct Envelope {
    /// Optional Tempo transaction prefix; absent for key authorizations.
    pub prefix: Option<u8>,
    /// Unsigned payload tuple.
    pub fields: Vec<Rlp>,
    /// Owner signature witness.
    pub witness: Witness,
}

impl Envelope {
    /// Converts viem's RPC key authorization, including a prefix-free native witness.
    pub fn from_rpc_authorization(value: &Value) -> Result<Self, RpcError> {
        let mut authorization = value.clone();
        let signature: Bytes = serde_json::from_value(authorization["signature"].clone())
            .map_err(|_| RpcError::invalid("Expected a multisig key authorization signature"))?;
        let witness = Witness::decode(&[&[5], signature.as_ref()].concat())?;
        let account: Address =
            serde_json::from_value(authorization["account"].clone()).map_err(|_| {
                RpcError::invalid("Multisig key authorization requires an account binding")
            })?;
        if account != witness.account {
            return Err(RpcError::invalid(
                "Multisig key authorization account does not match its signature",
            ));
        }
        let multisig = authorization["keyType"] == "multisig";
        if multisig {
            authorization["keyType"] = json!("secp256k1");
        }
        if authorization["chainId"] == "0x" {
            authorization["chainId"] = json!("0x0");
        }
        if authorization["expiry"] == "0x0" || authorization["expiry"] == "0x" {
            authorization["expiry"] = Value::Null;
        }
        let authorization: KeyAuthorization = serde_json::from_value(authorization)
            .map_err(|_| RpcError::invalid("Invalid multisig key authorization"))?;
        let mut encoded = Vec::new();
        authorization.encode(&mut encoded);
        let mut tuple = Rlp::decode(&encoded)?.list()?.to_vec();
        if multisig {
            tuple[1] = Rlp::number(3);
        }
        Ok(Self {
            prefix: None,
            fields: vec![Rlp::List(tuple)],
            witness,
        })
    }
    /// Decodes a signed multisig transaction or key authorization.
    pub fn decode(bytes: &[u8], transaction: bool) -> Result<Self, RpcError> {
        let (prefix, payload) = if transaction {
            let (first, payload) = bytes
                .split_first()
                .ok_or_else(|| RpcError::invalid("Empty envelope"))?;
            if !matches!(first, 0x76 | 0x78) {
                return Err(RpcError::invalid("Expected Tempo envelope"));
            }
            (Some(*first), payload)
        } else {
            (None, bytes)
        };
        let mut fields = Rlp::decode(payload)?.list()?.to_vec();
        if transaction && !(14..=15).contains(&fields.len()) || !transaction && fields.len() != 2 {
            return Err(RpcError::invalid("Invalid signed envelope fields"));
        }
        let signature = fields.pop().expect("validated field count");
        let witness = Witness::decode(signature.bytes()?)?;
        if transaction {
            validate_transaction_fields(prefix, &fields)?;
        }
        if !transaction {
            let tuple = fields[0].list()?;
            if tuple.len() != 9 || tuple[8].bytes()? != witness.account.as_slice() {
                return Err(RpcError::invalid(
                    "Multisig key authorization requires its signer account binding",
                ));
            }
            let mut checked = tuple.to_vec();
            if checked[1].integer()? == 3 {
                checked[1] = Rlp::number(0);
            }
            let encoded = Rlp::List(checked).encode();
            let mut remaining = encoded.as_slice();
            KeyAuthorization::decode(&mut remaining)
                .map_err(|_| RpcError::invalid("Invalid multisig key authorization"))?;
            if !remaining.is_empty() {
                return Err(RpcError::invalid("Trailing key authorization bytes"));
            }
        }
        if transaction
            && fields[11].bytes().is_ok_and(|b| b.len() == 20)
            && fields[11].bytes()? != witness.account.as_slice()
        {
            return Err(RpcError::invalid(
                "Fee payer sender does not match multisig account",
            ));
        }
        Ok(Self {
            prefix,
            fields,
            witness,
        })
    }

    /// Unsigned wire payload used in operation records.
    pub fn unsigned(&self) -> Bytes {
        self.serialize(None)
    }

    /// Serializes with or without a root signature.
    pub fn serialize(&self, witness: Option<&Witness>) -> Bytes {
        let mut fields = self.fields.clone();
        if let Some(witness) = witness {
            fields.push(Rlp::Bytes(witness.encode().to_vec()));
        }
        let payload = Rlp::List(fields).encode();
        Bytes::from(
            self.prefix
                .map(|prefix| [&[prefix][..], &payload].concat())
                .unwrap_or(payload),
        )
    }

    /// Sender signing hash, excluding mutable fee-payer signatures and fee tokens when sponsored.
    pub fn payload_hash(&self) -> B256 {
        if self.prefix.is_none() {
            return keccak256(self.fields[0].encode());
        }
        let mut fields = self.fields.clone();
        if fields[11] != Rlp::Bytes(Vec::new()) {
            fields[10] = Rlp::Bytes(Vec::new());
            fields[11] = Rlp::Bytes(vec![0]);
        }
        keccak256([&[0x76][..], &Rlp::List(fields).encode()].concat())
    }

    /// Chain identifier committed by this operation.
    pub fn chain_id(&self) -> Result<u64, RpcError> {
        if self.prefix.is_some() {
            self.fields[0].integer()
        } else {
            self.fields[0]
                .list()?
                .first()
                .ok_or_else(|| RpcError::invalid("Empty authorization"))?
                .integer()
        }
    }

    /// RPC representation for pending operation lookups, without requiring a node codec.
    pub fn rpc_transaction(&self) -> Result<Value, RpcError> {
        if self.prefix.is_none() {
            return Err(RpcError::invalid("Expected transaction"));
        }
        let quantity = |index: usize| -> Result<Value, RpcError> {
            let bytes = self.fields[index].bytes()?;
            let value = alloy_primitives::U256::try_from_be_slice(bytes)
                .ok_or_else(|| RpcError::invalid("Invalid transaction quantity"))?;
            Ok(json!(format!("{value:#x}")))
        };
        let calls = self.fields[4].list()?.iter().map(|call| {
            let fields = call.list()?;
            if fields.len() != 3 { return Err(RpcError::invalid("Invalid call tuple")); }
            let value = alloy_primitives::U256::try_from_be_slice(fields[1].bytes()?).ok_or_else(|| RpcError::invalid("Invalid call value"))?;
            let to = if fields[0].bytes()?.is_empty() { Value::Null } else { json!(address(&fields[0])?) };
            Ok(json!({"to": to, "value": format!("{value:#x}"), "data": Bytes::copy_from_slice(fields[2].bytes()?)}))
        }).collect::<Result<Vec<_>, RpcError>>()?;
        let selection = self.witness.select(
            self.witness.digest(self.payload_hash()),
            &self.witness.approvals,
        )?;
        let witness = Witness {
            approvals: selection.selected,
            ..self.witness.clone()
        };
        let mut result = json!({"type": "0x76", "chainId": quantity(0)?, "maxPriorityFeePerGas": quantity(1)?, "maxFeePerGas": quantity(2)?, "gas": quantity(3)?, "calls": calls, "nonceKey": quantity(6)?, "nonce": quantity(7)?, "validBefore": quantity(8)?, "validAfter": quantity(9)?, "blockHash": null, "blockNumber": null, "transactionIndex": null, "from": self.witness.account, "to": null, "value": "0x0", "input": "0x", "signature": Bytes::copy_from_slice(&witness.encode()[1..])});
        if !self.fields[10].bytes()?.is_empty() {
            result["feeToken"] = json!(address(&self.fields[10])?);
        }
        if let Rlp::List(signature) = &self.fields[11] {
            if signature.len() != 3 {
                return Err(RpcError::invalid("Invalid fee payer signature"));
            }
            let r = alloy_primitives::U256::try_from_be_slice(signature[1].bytes()?)
                .ok_or_else(|| RpcError::invalid("Invalid signature scalar"))?;
            let s = alloy_primitives::U256::try_from_be_slice(signature[2].bytes()?)
                .ok_or_else(|| RpcError::invalid("Invalid signature scalar"))?;
            let parity = signature[0].integer()?;
            result["feePayerSignature"] = json!({"r": format!("{r:#066x}"), "s": format!("{s:#066x}"), "yParity": format!("{parity:#x}"), "v": format!("{:#x}", parity + 27)});
        }
        result["accessList"] = Value::Array(
            self.fields[5]
                .list()?
                .iter()
                .map(|entry| {
                    let entry = entry.list()?;
                    if entry.len() != 2 {
                        return Err(RpcError::invalid("Invalid access list entry"));
                    }
                    let keys = entry[1]
                        .list()?
                        .iter()
                        .map(|key| key.bytes().map(Bytes::copy_from_slice))
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(json!({"address": address(&entry[0])?, "storageKeys": keys}))
                })
                .collect::<Result<Vec<_>, RpcError>>()?,
        );
        result["aaAuthorizationList"] = Value::Array(self.fields[12].list()?.iter().map(|entry| {
            let entry = entry.list()?;
            if entry.len() != 6 { return Err(RpcError::invalid("Invalid delegation authorization")); }
            let q = |i: usize| -> Result<String, RpcError> { Ok(format!("{:#x}", alloy_primitives::U256::try_from_be_slice(entry[i].bytes()?).ok_or_else(|| RpcError::invalid("Invalid authorization quantity"))?)) };
            Ok(json!({"chainId": q(0)?, "address": address(&entry[1])?, "nonce": q(2)?, "yParity": q(3)?, "r": q(4)?, "s": q(5)?}))
        }).collect::<Result<Vec<_>, RpcError>>()?);
        if let Some(authorization) = self.fields.get(13) {
            result["keyAuthorization"] = rpc_authorization(authorization)?;
        }
        Ok(result)
    }
}

pub(crate) fn rpc_authorization(value: &Rlp) -> Result<Value, RpcError> {
    let fields = value.list()?;
    if fields.len() != 2 {
        return Err(RpcError::invalid("Invalid attached key authorization"));
    }
    let mut authorization = fields[0].list()?.to_vec();
    if authorization.len() < 3 {
        return Err(RpcError::invalid("Invalid key authorization tuple"));
    }
    let native = authorization[1].integer()? == 3;
    if native {
        authorization[1] = Rlp::number(0);
    }
    let encoded = Rlp::List(authorization).encode();
    let mut remaining = encoded.as_slice();
    let authorization = KeyAuthorization::decode(&mut remaining)
        .map_err(|_| RpcError::invalid("Invalid attached key authorization"))?;
    if !remaining.is_empty() {
        return Err(RpcError::invalid("Trailing key authorization bytes"));
    }
    let mut rpc = json!(authorization);
    if native {
        rpc["keyType"] = json!("multisig");
    }
    let signature = fields[1].bytes()?;
    rpc["signature"] = if signature.first() == Some(&5) {
        let witness = Witness::decode(signature)?;
        json!(Bytes::copy_from_slice(&witness.encode()[1..]))
    } else {
        json!(PrimitiveSignature::from_bytes(signature).map_err(RpcError::invalid)?)
    };
    Ok(rpc)
}

pub(crate) fn validate_transaction_fields(
    prefix: Option<u8>,
    fields: &[Rlp],
) -> Result<(), RpcError> {
    if !(13..=14).contains(&fields.len()) || !matches!(prefix, Some(0x76 | 0x78)) {
        return Err(RpcError::invalid("Invalid Tempo envelope"));
    }
    let quantity = |value: &Rlp| -> Result<(), RpcError> {
        let bytes = value.bytes()?;
        if bytes.len() > 32 || bytes.first() == Some(&0) {
            return Err(RpcError::invalid("Noncanonical transaction quantity"));
        }
        Ok(())
    };
    for index in [0, 1, 2, 3, 6, 7, 8, 9] {
        quantity(&fields[index])?;
    }
    for index in [0, 3, 7, 8, 9] {
        fields[index].integer()?;
    }
    if fields[0].integer()? == 0 || fields[4].list()?.is_empty() {
        return Err(RpcError::invalid("Expected a chain and nonempty calls"));
    }
    for call in fields[4].list()? {
        let call = call.list()?;
        if call.len() != 3 || !matches!(call[0].bytes()?.len(), 0 | 20) {
            return Err(RpcError::invalid("Invalid call tuple"));
        }
        quantity(&call[1])?;
        call[2].bytes()?;
    }
    for entry in fields[5].list()? {
        let entry = entry.list()?;
        if entry.len() != 2 || entry[0].bytes()?.len() != 20 {
            return Err(RpcError::invalid("Invalid access list entry"));
        }
        for key in entry[1].list()? {
            if key.bytes()?.len() != 32 {
                return Err(RpcError::invalid("Invalid access list key"));
            }
        }
    }
    if !matches!(fields[10].bytes()?.len(), 0 | 20) {
        return Err(RpcError::invalid("Invalid fee token"));
    }
    match &fields[11] {
        Rlp::Bytes(bytes)
            if bytes.is_empty() || bytes == &[0] || prefix == Some(0x78) && bytes.len() == 20 => {}
        Rlp::List(signature) if signature.len() == 3 => {
            if signature[0].integer()? > 1 {
                return Err(RpcError::invalid("Invalid fee payer signature parity"));
            }
            quantity(&signature[1])?;
            quantity(&signature[2])?;
        }
        _ => return Err(RpcError::invalid("Invalid fee payer signature")),
    }
    for entry in fields[12].list()? {
        let entry = entry.list()?;
        if entry.len() != 6 || entry[1].bytes()?.len() != 20 {
            return Err(RpcError::invalid("Invalid delegation authorization"));
        }
        for index in [0, 2, 3, 4, 5] {
            quantity(&entry[index])?;
        }
        if entry[3].integer()? > 1 {
            return Err(RpcError::invalid("Invalid authorization parity"));
        }
    }
    if fields.len() == 14 {
        let authorization = fields[13].list()?;
        if authorization.len() != 2
            || authorization[0].list()?.len() < 3
            || authorization[1].bytes()?.is_empty()
        {
            return Err(RpcError::invalid("Invalid attached key authorization"));
        }
    }
    Ok(())
}

fn address(value: &Rlp) -> Result<Address, RpcError> {
    let bytes = value.bytes()?;
    if bytes.len() != 20 {
        return Err(RpcError::invalid("Invalid address width"));
    }
    Ok(Address::from_slice(bytes))
}
