//! Fee-token liquidity, virtual-address resolution, simulation and balance previews.

use crate::{
    Backend, Next, Plugin, Request, RpcError,
    store::{Store, now},
};
use alloy_primitives::{Address, B256, Bytes, FixedBytes, U256, keccak256};
use alloy_sol_types::SolValue;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{collections::BTreeSet, sync::Arc};

/// Immutable TIP-20 metadata used by fee and balance previews.
#[derive(Clone, Deserialize, Serialize)]
pub struct Metadata {
    /// Token precision.
    pub decimals: u8,
    /// Display name.
    pub name: String,
    /// Ticker symbol.
    pub symbol: String,
}

/// A deployless snapshot of funded fee routes and registered virtual masters.
pub struct Snapshot {
    /// Sender's configured fee token.
    pub preferred: Address,
    /// Preferred token's liquid balance.
    pub preferred_balance: U256,
    /// Candidate liquid balances, preserving configured order.
    pub balances: Vec<(Address, U256)>,
    /// Virtual-address resolutions when the registry was readable.
    pub virtual_addresses: Option<Value>,
}

/// Reads the same deployless bytecode and ABI as viem's RelayPreflight.
pub async fn preflight(
    backend: &dyn Backend,
    account: Address,
    tokens: &[Address],
    targets: &[Address],
) -> Result<Snapshot, RpcError> {
    if tokens.len() > 100 || targets.len() > 100 {
        return Err(RpcError::invalid(
            "Preflight candidates exceed the limit of 100",
        ));
    }
    let mut masters = Vec::<FixedBytes<4>>::new();
    for target in targets {
        let id = FixedBytes::from_slice(&target[..4]);
        if !masters.contains(&id) {
            masters.push(id);
        }
    }
    let manager = alloy_primitives::address!("feec000000000000000000000000000000000000");
    let registry = alloy_primitives::address!("fdc0000000000000000000000000000000000000");
    let parameters =
        (account, manager, tokens.to_vec(), registry, masters.clone()).abi_encode_params();
    let code: Bytes = include_str!("preflight.hex")
        .trim()
        .parse()
        .map_err(|_| RpcError::new(-32603, "Invalid embedded preflight bytecode"))?;
    let data = Bytes::from([code.as_ref(), &parameters].concat());
    let response = backend
        .request(Request::new(
            "eth_call",
            vec![json!({"data": data}), json!("latest")],
        ))
        .await?;
    let bytes: Bytes = serde_json::from_value(response)
        .map_err(|_| RpcError::new(-32603, "Invalid preflight result"))?;
    let (preferred, preferred_balance, balances, resolved, addresses) =
        <(Address, U256, Vec<U256>, bool, Vec<Address>)>::abi_decode_params(&bytes)
            .map_err(|e| RpcError::new(-32603, e.to_string()))?;
    if balances.len() != tokens.len() || addresses.len() != masters.len() {
        return Err(RpcError::new(-32603, "Invalid preflight result lengths"));
    }
    let virtual_addresses = (resolved && !targets.is_empty()).then(|| {
        let mut map = Map::new();
        for target in targets {
            let index = masters
                .iter()
                .position(|id| id.as_slice() == &target[..4])
                .expect("collected master ID");
            let master = addresses[index];
            map.insert(
                format!("{target:#x}"),
                if master.is_zero() {
                    Value::Null
                } else {
                    json!(master)
                },
            );
        }
        Value::Object(map)
    });
    Ok(Snapshot {
        preferred,
        preferred_balance,
        balances: tokens.iter().copied().zip(balances).collect(),
        virtual_addresses,
    })
}

/// Collects literal virtual call targets and TIP-20 transfer recipients.
pub fn virtual_targets(transaction: &Value) -> Result<Vec<Address>, RpcError> {
    let mut targets = BTreeSet::new();
    for call in transaction
        .get("calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let to = call
            .get("to")
            .cloned()
            .and_then(|v| serde_json::from_value::<Address>(v).ok());
        let data = call
            .get("data")
            .or_else(|| call.get("input"))
            .cloned()
            .and_then(|v| serde_json::from_value::<Bytes>(v).ok());
        let recipient = data.as_ref().and_then(|data| {
            let (offset, minimum) = match data.get(..4)? {
                [0xa9, 0x05, 0x9c, 0xbb] => (16, 68),
                [0x95, 0x77, 0x7d, 0x59] => (16, 100),
                [0x23, 0xb8, 0x72, 0xdd] => (48, 100),
                [0x92, 0x9c, 0x25, 0x39] => (48, 132),
                _ => return None,
            };
            if data.len() < minimum || data[offset - 12..offset].iter().any(|byte| *byte != 0) {
                return None;
            }
            let address = data.get(offset..offset + 20)?;
            Some(Address::from_slice(address))
        });
        for address in [to, recipient].into_iter().flatten() {
            if address[4..14] == [0xfd; 10] {
                targets.insert(address);
            }
        }
        if targets.len() > 100 {
            return Err(RpcError::invalid(
                "Virtual-address targets exceed the limit of 100 addresses",
            ));
        }
    }
    Ok(targets.into_iter().collect())
}

/// Fee-token selection using sender preferences, balances and validator-token AMM liquidity.
pub struct FeeTokens {
    backend: Arc<dyn Backend>,
    tokens: Vec<Address>,
}

impl FeeTokens {
    /// Configures the chain's ordered fee-token candidates.
    pub fn new(backend: Arc<dyn Backend>, tokens: Vec<Address>) -> Result<Self, RpcError> {
        let tokens = tokens
            .into_iter()
            .collect::<indexmap::IndexSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if tokens.len() > 100 {
            return Err(RpcError::invalid(
                "Fee-token candidates exceed the limit of 100 tokens",
            ));
        }
        Ok(Self { backend, tokens })
    }
}

#[async_trait]
impl Plugin for FeeTokens {
    async fn handle(&self, mut request: Request, next: Next<'_>) -> Result<Value, RpcError> {
        if request.method != "eth_fillTransaction" {
            return next.run(request).await;
        }
        let transaction = Value::Object(request.transaction()?.clone());
        let targets = virtual_targets(&transaction)?;
        let account = transaction
            .get("from")
            .cloned()
            .and_then(|v| serde_json::from_value::<Address>(v).ok());
        let sponsored = transaction["feePayer"] == true;
        let explicit = transaction
            .get("feeToken")
            .filter(|v| !v.is_null())
            .cloned();
        let mut candidates = self.tokens.clone();
        for call in transaction
            .get("calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(to) = call
                .get("to")
                .cloned()
                .and_then(|v| serde_json::from_value::<Address>(v).ok())
                && to[..2] == [0x20, 0xc0]
                && !candidates.contains(&to)
            {
                candidates.push(to);
            }
        }
        if candidates.len() > 100 {
            return Err(RpcError::invalid(
                "Fee-token candidates exceed the limit of 100 tokens",
            ));
        }
        let snapshot = if !sponsored
            && explicit.is_none()
            && let Some(account) = account
        {
            Some(preflight(&*self.backend, account, &candidates, &targets).await?)
        } else {
            None
        };
        let token = if let Some(explicit) = explicit {
            Some(explicit)
        } else if sponsored {
            self.tokens.first().map(|token| json!(token))
        } else if let Some(snapshot) = &snapshot {
            if snapshot.preferred_balance > U256::ZERO {
                Some(json!(snapshot.preferred))
            } else {
                snapshot
                    .balances
                    .iter()
                    .filter(|(_, balance)| *balance > U256::ZERO)
                    .fold(None, |best: Option<&(Address, U256)>, candidate| {
                        if best.is_none_or(|best| candidate.1 > best.1) {
                            Some(candidate)
                        } else {
                            best
                        }
                    })
                    .map(|(token, _)| json!(token))
            }
        } else {
            None
        };
        if let Some(token) = &token
            && !sponsored
        {
            request
                .transaction_mut()?
                .insert("feeToken".into(), token.clone());
        }
        let mut result = next.run(request).await?;
        if result.get("tx").is_some() {
            if result["tx"].get("feeToken").is_none_or(Value::is_null)
                && let Some(token) = token
            {
                result["tx"]["feeToken"] = token;
            }
            if let Some(addresses) = snapshot.and_then(|snapshot| snapshot.virtual_addresses) {
                let capabilities = result
                    .as_object_mut()
                    .ok_or_else(|| RpcError::invalid("Invalid fill response"))?
                    .entry("capabilities")
                    .or_insert_with(|| json!({}));
                capabilities["virtualAddresses"] = addresses;
            }
        }
        Ok(result)
    }
}

/// Post-fill balance-diff and fee capabilities, with bounded metadata lookups.
pub struct Simulate {
    store: Option<Arc<dyn Store>>,
    chain_id: u64,
}

impl Simulate {
    /// Configures immutable TIP-20 metadata caching scoped by chain.
    pub fn new(chain_id: u64, store: Option<Arc<dyn Store>>) -> Self {
        Self { store, chain_id }
    }

    /// Turns execution reverts into opt-in preview capabilities; never signs the stub.
    pub async fn error_fill(
        &self,
        request: &Request,
        error: &RpcError,
        backend: &dyn Backend,
    ) -> Value {
        let transaction = request.params.first().cloned().unwrap_or_else(|| json!({}));
        let decoded = crate::errors::decode(error);
        let mut result = json!({"tx": {"from": transaction["from"], "to": transaction.get("to").cloned().unwrap_or(Value::Null), "gas": "0x0", "nonce": "0x0", "value": "0x0", "maxFeePerGas": "0x0", "maxPriorityFeePerGas": "0x0"}, "capabilities": {"error": decoded.rpc, "sponsored": false}});
        if let Ok(targets) = virtual_targets(&transaction)
            && !targets.is_empty()
            && let Ok(snapshot) = preflight(backend, Address::ZERO, &[], &targets).await
            && let Some(addresses) = snapshot.virtual_addresses
        {
            result["capabilities"]["virtualAddresses"] = addresses;
        }
        if decoded.rpc["errorName"] == "InsufficientBalance"
            && let [
                alloy_dyn_abi::DynSolValue::Uint(available, _),
                alloy_dyn_abi::DynSolValue::Uint(required, _),
                alloy_dyn_abi::DynSolValue::Address(token),
            ] = decoded.arguments.as_slice()
        {
            if let Ok(metadata) = self.metadata(backend, *token, &Value::Null).await {
                let deficit = required.saturating_sub(*available);
                result["capabilities"]["insufficientFunds"] = json!({"amount": format!("{deficit:#x}"), "decimals": metadata.decimals, "formatted": format_units(deficit, metadata.decimals), "token": token, "symbol": metadata.symbol});
            }
            let optimistic = Request::new(
                "eth_fillTransaction",
                vec![{
                    let mut transaction = transaction.clone();
                    transaction["from"] = json!(Address::ZERO);
                    transaction
                }],
            );
            if let Ok(capabilities) = self
                .after_fill(&optimistic, &json!({"tx": transaction}), backend)
                .await
                && let Some(diffs) = capabilities.get("balanceDiffs")
                && let Some(sender) = transaction["from"].as_str()
            {
                let entries = diffs
                    .get(format!("{:#x}", Address::ZERO))
                    .cloned()
                    .unwrap_or_else(|| json!([]));
                result["capabilities"]["balanceDiffs"] = json!({sender: entries});
            }
        }
        result
    }

    async fn metadata(
        &self,
        backend: &dyn Backend,
        token: Address,
        hints: &Value,
    ) -> Result<Metadata, RpcError> {
        let hint = hints.as_object().and_then(|map| {
            map.iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(&format!("{token:#x}")))
                .map(|(_, v)| v)
        });
        if token[..2] == [0x20, 0xc0]
            && let Some(hint) = hint
            && let (Some(name), Some(symbol)) = (hint["name"].as_str(), hint["symbol"].as_str())
        {
            return Ok(Metadata {
                decimals: 6,
                name: name.into(),
                symbol: symbol.into(),
            });
        }
        let key = format!("tokenMetadata:{}:{token:#x}", self.chain_id);
        if let Some(store) = &self.store
            && let Some(value) = store.get(&key).await?
        {
            return serde_json::from_str(&value).map_err(|e| RpcError::new(-32603, e.to_string()));
        }
        let read = |signature: &'static str| async move {
            let data = Bytes::copy_from_slice(&keccak256(signature)[..4]);
            let value = backend
                .request(Request::new(
                    "eth_call",
                    vec![json!({"to": token, "data": data}), json!("latest")],
                ))
                .await?;
            serde_json::from_value::<Bytes>(value)
                .map_err(|_| RpcError::new(-32603, "Invalid token metadata response"))
        };
        let (name, symbol, decimals) =
            futures::try_join!(read("name()"), read("symbol()"), read("decimals()"))?;
        let metadata = Metadata {
            name: String::abi_decode(&name).map_err(|e| RpcError::new(-32603, e.to_string()))?,
            symbol: String::abi_decode(&symbol)
                .map_err(|e| RpcError::new(-32603, e.to_string()))?,
            decimals: u8::try_from(
                U256::abi_decode(&decimals).map_err(|e| RpcError::new(-32603, e.to_string()))?,
            )
            .map_err(|e| RpcError::new(-32603, e.to_string()))?,
        };
        if let Some(store) = &self.store {
            let value = serde_json::to_string(&metadata)
                .map_err(|e| RpcError::new(-32603, e.to_string()))?;
            store
                .compare_and_set(&key, None, Some(&value), Some(now() + 86_400_000))
                .await?;
        }
        Ok(metadata)
    }

    async fn fee(
        &self,
        backend: &dyn Backend,
        transaction: &Value,
        hints: &Value,
    ) -> Option<Value> {
        let token = serde_json::from_value::<Address>(transaction["feeToken"].clone()).ok()?;
        let gas = quantity(&transaction["gas"])?;
        let price = quantity(&transaction["maxFeePerGas"])?;
        if gas.is_zero() || price.is_zero() {
            return None;
        }
        let metadata = self.metadata(backend, token, hints).await.ok()?;
        let raw = gas.checked_mul(price)?;
        let scale =
            U256::from(10).checked_pow(U256::from(18_u8.saturating_sub(metadata.decimals)))?;
        let amount = raw.checked_add(scale - U256::from(1))? / scale;
        Some(
            json!({"amount": format!("{amount:#x}"), "decimals": metadata.decimals, "formatted": format_units(amount, metadata.decimals), "symbol": metadata.symbol}),
        )
    }

    async fn diffs(
        &self,
        backend: &dyn Backend,
        account: Address,
        logs: &[Value],
        hints: &Value,
    ) -> Option<Value> {
        let transfer = keccak256("Transfer(address,address,uint256)");
        let approval = keccak256("Approval(address,address,uint256)");
        let mut tokens = indexmap::IndexMap::<Address, Movement>::new();
        let mut approvals = indexmap::IndexMap::<(Address, Address), U256>::new();
        for log in logs {
            let token = serde_json::from_value::<Address>(log["address"].clone());
            let topics = log["topics"].as_array();
            if let (Ok(token), Some(topics)) = (token, topics)
                && topics.len() == 3
            {
                let event = serde_json::from_value::<B256>(topics[0].clone());
                let from = serde_json::from_value::<B256>(topics[1].clone());
                let to = serde_json::from_value::<B256>(topics[2].clone());
                let data = serde_json::from_value::<Bytes>(log["data"].clone());
                if let (Ok(event), Ok(from), Ok(to), Ok(data)) = (event, from, to, data)
                    && (event == transfer || event == approval)
                    && data.len() == 32
                {
                    let from = Address::from_slice(&from[12..]);
                    let to = Address::from_slice(&to[12..]);
                    let amount = U256::from_be_slice(&data);
                    if event == approval {
                        if from == account {
                            approvals.insert((token, to), amount);
                        }
                    } else {
                        let movement = tokens.entry(token).or_default();
                        if from == account {
                            movement.outgoing = movement.outgoing.checked_add(amount)?;
                            movement.recipients.insert(to);
                        }
                        if to == account {
                            movement.incoming = movement.incoming.checked_add(amount)?;
                        }
                    }
                }
            }
        }
        for ((token, recipient), amount) in approvals {
            if !amount.is_zero() {
                let movement = tokens.entry(token).or_default();
                movement.approved = movement.approved.checked_add(amount)?;
                movement.recipients.insert(recipient);
            }
        }
        tokens.retain(|_, movement| {
            movement.incoming != movement.outgoing || !movement.approved.is_zero()
        });
        if tokens.is_empty() {
            return Some(json!({}));
        }
        if tokens.len() > 100 {
            return None;
        }
        let entries =
            futures::stream::iter(tokens.into_iter().map(|(token, movement)| async move {
                self.metadata(backend, token, hints)
                    .await
                    .map(|metadata| (token, movement, metadata))
            }));
        let entries = futures::StreamExt::buffered(entries, 8);
        let entries = futures::StreamExt::collect::<Vec<_>>(entries).await;
        let mut diffs = Vec::new();
        for entry in entries {
            let (token, movement, metadata) = entry.ok()?;
            let incoming = movement.incoming.saturating_sub(movement.outgoing);
            let outgoing = movement
                .outgoing
                .saturating_sub(movement.incoming)
                .checked_add(movement.approved)?;
            for (direction, amount) in [("incoming", incoming), ("outgoing", outgoing)] {
                if amount.is_zero() {
                    continue;
                }
                let recipients = if direction == "incoming" {
                    Vec::new()
                } else {
                    movement.recipients.iter().copied().collect()
                };
                diffs.push(json!({"address": token, "decimals": metadata.decimals, "name": metadata.name, "symbol": metadata.symbol, "direction": direction, "formatted": format_units(amount, metadata.decimals), "recipients": recipients, "value": format!("{amount:#x}")}));
            }
        }
        Some(json!({format!("{account:#x}"): diffs}))
    }
}

#[async_trait]
impl Plugin for Simulate {
    async fn after_fill(
        &self,
        request: &Request,
        filled: &Value,
        backend: &dyn Backend,
    ) -> Result<Map<String, Value>, RpcError> {
        let transaction = &filled["tx"];
        let account = request
            .transaction()?
            .get("from")
            .cloned()
            .and_then(|value| serde_json::from_value::<Address>(value).ok());
        let mut capabilities = Map::new();
        let targets = virtual_targets(transaction)?;
        if filled.pointer("/capabilities/virtualAddresses").is_none()
            && !targets.is_empty()
            && let Ok(snapshot) =
                preflight(backend, account.unwrap_or_default(), &[], &targets).await
            && let Some(addresses) = snapshot.virtual_addresses
        {
            capabilities.insert("virtualAddresses".into(), addresses);
        }
        let mut hints = Value::Null;
        if request
            .transaction()?
            .get("capabilities")
            .and_then(|value| value.get("balanceDiffs"))
            != Some(&json!(false))
        {
            let mut calls = transaction["calls"].as_array().cloned().unwrap_or_default();
            let count = calls.len();
            if let Some(token) = transaction
                .get("feeToken")
                .cloned()
                .and_then(|value| serde_json::from_value::<Address>(value).ok())
                && !calls.iter().any(|call| {
                    call["to"]
                        .as_str()
                        .is_some_and(|to| to.eq_ignore_ascii_case(&format!("{token:#x}")))
                })
            {
                let mut data = keccak256("balanceOf(address)")[..4].to_vec();
                data.extend([0; 12]);
                data.extend(account.unwrap_or_default());
                calls.push(json!({"to": token, "data": Bytes::from(data)}));
            }
            for call in &mut calls {
                if let Some(account) = account
                    && !account.is_zero()
                {
                    call["from"] = json!(account);
                }
            }
            if let Ok(simulation) = backend
                .request(Request::new(
                    "tempo_simulateV1",
                    vec![
                        json!({"blockStateCalls": [{"calls": calls}], "traceTransfers": true}),
                        json!("latest"),
                    ],
                ))
                .await
            {
                hints = simulation
                    .get("tokenMetadata")
                    .cloned()
                    .unwrap_or(Value::Null);
                if let Some(results) = simulation
                    .pointer("/blocks/0/calls")
                    .or_else(|| simulation.pointer("/0/calls"))
                    .and_then(Value::as_array)
                {
                    let logs = results
                        .iter()
                        .take(count)
                        .flat_map(|result| result["logs"].as_array().into_iter().flatten().cloned())
                        .collect::<Vec<_>>();
                    let diffs = match account {
                        Some(account) => self.diffs(backend, account, &logs, &hints).await,
                        None => Some(json!({})),
                    };
                    if let Some(diffs) = diffs {
                        capabilities.insert("balanceDiffs".into(), diffs);
                    }
                }
            }
        }
        if let Some(fee) = self.fee(backend, transaction, &hints).await {
            capabilities.insert("fee".into(), fee);
        }
        Ok(capabilities)
    }
}

#[derive(Default)]
struct Movement {
    incoming: U256,
    outgoing: U256,
    approved: U256,
    recipients: indexmap::IndexSet<Address>,
}

fn quantity(value: &Value) -> Option<U256> {
    value.as_str()?.parse().ok()
}
/// Exact decimal formatting with no floating-point rounding.
pub fn format_units(value: U256, decimals: u8) -> String {
    let digits = value.to_string();
    let decimals = usize::from(decimals);
    if decimals == 0 {
        return digits;
    }
    let padded = format!("{:0>width$}", digits, width = decimals + 1);
    let split = padded.len() - decimals;
    let (integer, fraction) = padded.split_at(split);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        integer.into()
    } else {
        format!("{integer}.{fraction}")
    }
}
