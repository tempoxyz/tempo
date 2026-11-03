//! Per-target dictionaries aggregated from corpus indexes: the values real transactions sent to
//! one [`targets`] target, as whole records and per field, with counts.
//!
//! Calldata is decoded with the `sol!` ABIs of `tempo_contracts`; a selector they don't cover is
//! counted but not decoded. A numeric field is a set of exact values until it took more than
//! 64 distinct values, then a distribution over sign-folded log2 bins, as state
//! features are in foundry-rs/foundry#18018. Addresses, bytes and whole records keep their most
//! frequent values.

use crate::{
    index::{self, call_column, column},
    targets,
};
use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::{Function, JsonAbi, Param};
use alloy_primitives::{Address, I256, U256, hex};
use arrow_array::{Array, BinaryArray, FixedSizeBinaryArray, ListArray, UInt8Array, UInt64Array};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
};
use tempo_contracts::{precompiles::*, zones::ZonePortal};

/// Version of the dictionary layout, stored in every dictionary.
pub const VERSION: u32 = 1;
/// Distinct values a numeric field keeps exactly before it becomes a distribution.
const MAX_SET_VALUES: usize = 64;
/// Longest bytes or string value kept whole. Longer ones (proofs, encrypted payloads) keep only
/// their length.
const MAX_TOKEN_BYTES: usize = 32;
/// Values counted per address, bytes or record table before the rarest are pruned.
const TRACKED: usize = 1 << 14;

/// The dictionary of target `bit` over the index files `paths`, as JSON.
pub fn dict(paths: &[PathBuf], bit: u8) -> eyre::Result<Value> {
    let target = &targets::TARGETS[usize::from(bit)];
    let functions: HashMap<[u8; 4], Function> = abis(target.name)
        .iter()
        .flat_map(|abi| abi().functions().cloned().collect::<Vec<_>>())
        .map(|function| (function.selector().0, function))
        .collect();
    let tip20 = targets::bit("tip20").expect("registered target");
    let mut dict = Dict::default();
    let mut indexes = Vec::new();
    for path in paths {
        let (catalog, range, batches) = index::read(
            path,
            &[
                "tx_type",
                "calls",
                "status",
                "charged_gas",
                "gas_limit",
                "fee_token",
                "nonce_key",
            ],
        )?;
        let context = &catalog.context;
        indexes.push(json!({
            "range": range,
            "corpus": {
                "chain_id": context.chain_id,
                "start": context.start,
                "end": context.end,
                "tip": context.tip,
                "checkpoint": catalog.checkpoint,
            },
        }));
        for batch in batches {
            let batch = batch?;
            let tx_type = column::<UInt8Array>(&batch, "tx_type")?;
            let calls = column::<ListArray>(&batch, "calls")?;
            let status = column::<UInt8Array>(&batch, "status")?;
            let charged_gas = column::<UInt64Array>(&batch, "charged_gas")?;
            let gas_limit = column::<UInt64Array>(&batch, "gas_limit")?;
            let fee_token = column::<FixedSizeBinaryArray>(&batch, "fee_token")?;
            let nonce_key = column::<FixedSizeBinaryArray>(&batch, "nonce_key")?;
            let call_target = call_column::<UInt8Array>(calls, "target")?;
            let call_to = call_column::<FixedSizeBinaryArray>(calls, "to")?;
            let call_input = call_column::<BinaryArray>(calls, "input")?;
            let offsets = calls.value_offsets();
            for row in 0..batch.num_rows() {
                let row_calls = offsets[row] as usize..offsets[row + 1] as usize;
                let ours: Vec<_> = row_calls
                    .clone()
                    .filter(|&i| call_target.is_valid(i) && call_target.value(i) == bit)
                    .collect();
                if ours.is_empty() {
                    continue;
                }
                let tx = &mut dict.transactions;
                tx.count += 1;
                tx.failed += u64::from(status.value(row) != 0);
                tx.tx_type.add(U256::from(tx_type.value(row)));
                tx.calls.add(U256::from(row_calls.len()));
                tx.gas_limit.add(U256::from(gas_limit.value(row)));
                if charged_gas.value(row) > 0 {
                    tx.gas_limit_over_used_permille.add(U256::from(
                        u128::from(gas_limit.value(row)) * 1000
                            / u128::from(charged_gas.value(row)),
                    ));
                }
                if nonce_key.is_valid(row) {
                    tx.nonce_key.add(U256::from_be_slice(nonce_key.value(row)));
                }
                let fee = if fee_token.is_valid(row) {
                    Address::from_slice(fee_token.value(row)).to_string()
                } else {
                    "default".to_owned()
                };
                // The TIP-20 tokens the transaction calls are its user tokens.
                let users: Vec<_> = row_calls
                    .filter(|&i| call_target.is_valid(i) && call_target.value(i) == tip20)
                    .map(|i| Address::from_slice(call_to.value(i)).to_string())
                    .collect();
                if users.is_empty() {
                    tx.fee_pairs.add(json!([fee, null]).to_string());
                }
                for user in users {
                    tx.fee_pairs.add(json!([fee, user]).to_string());
                }
                for i in ours {
                    let input = call_input.value(i);
                    if target.name == "tip20" || target.name == "zone-portal" {
                        dict.addresses
                            .add(Address::from_slice(call_to.value(i)).to_string());
                    }
                    let Some(selector) = input.first_chunk::<4>() else {
                        dict.no_selector += 1;
                        continue;
                    };
                    let call = dict.calls.entry(*selector).or_default();
                    call.count += 1;
                    call.length.add(U256::from(input.len()));
                    let Some(function) = functions.get(selector) else {
                        continue;
                    };
                    let Ok(args) = function.abi_decode_input(&input[4..]) else {
                        call.undecoded += 1;
                        continue;
                    };
                    let record = Value::Array(args.iter().map(render).collect());
                    call.records.add(record.to_string());
                    for (param, arg) in function.inputs.iter().zip(&args) {
                        call.add(&param.name, param, arg);
                    }
                }
            }
        }
    }
    Ok(json!({
        "meta": {
            "dict_version": VERSION,
            "index_version": index::VERSION,
            "registry_version": targets::VERSION,
            "target": target.name,
            "indexes": indexes,
        },
        "transactions": dict.transactions.json(),
        "addresses": dict.addresses.json(),
        "calls_without_selector": dict.no_selector,
        "calls": dict
            .calls
            .iter()
            .map(|(selector, call)| {
                let function = functions.get(selector);
                json!({
                    "selector": hex::encode_prefixed(selector),
                    "signature": function.map(Function::signature),
                    "count": call.count,
                    "undecoded": call.undecoded,
                    "length": call.length.json(),
                    "records": call.records.json(),
                    "args": call
                        .args
                        .iter()
                        .map(|(path, field)| (path.clone(), field.json()))
                        .collect::<serde_json::Map<_, _>>(),
                })
            })
            .collect::<Vec<_>>(),
    }))
}

/// The ABIs decoding the calldata of the target named `name`.
fn abis(name: &str) -> &'static [fn() -> JsonAbi] {
    match name {
        "tip20" => &[ITIP20::abi::contract, IRolesAuth::abi::contract],
        "tip20-factory" => &[ITIP20Factory::abi::contract],
        "feeamm" => &[IFeeManager::abi::contract, ITIPFeeAMM::abi::contract],
        "dex" => &[IStablecoinDEX::abi::contract],
        "keychain" => &[IAccountKeychain::abi::contract],
        "nonce" => &[INonce::abi::contract],
        "tip403" => &[ITIP403Registry::abi::contract],
        "validator-config" => &[IValidatorConfig::abi::contract],
        "validator-config-v2" => &[IValidatorConfigV2::abi::contract],
        "signature-verifier" => &[ISignatureVerifier::abi::contract],
        "address-registry" => &[IAddressRegistry::abi::contract],
        "channel-reserve" => &[ITIP20ChannelReserve::abi::contract],
        "receive-policy-guard" => &[IReceivePolicyGuard::abi::contract],
        "storage-credits" => &[IStorageCredits::abi::contract],
        "current-committee" => &[ICurrentCommittee::abi::contract],
        "zone-factory" => &[IZoneFactory::abi::contract],
        "zone-verifier" => &[IZoneVerifier::abi::contract],
        "zone-portal" => &[ZonePortal::abi::contract],
        "configurable-account" => &[IConfigurableAccount::abi::contract],
        _ => &[],
    }
}

#[derive(Default)]
struct Dict {
    transactions: Transactions,
    /// Contract addresses of a prefix target (TIP-20 tokens, zone portals).
    addresses: Top,
    no_selector: u64,
    calls: BTreeMap<[u8; 4], Call>,
}

/// Fields of the transactions with a call to the target.
#[derive(Default)]
struct Transactions {
    count: u64,
    failed: u64,
    tx_type: Numbers,
    /// Calls in the transaction, the target's and others.
    calls: Numbers,
    gas_limit: Numbers,
    /// Gas limit over charged gas: the headroom senders leave.
    gas_limit_over_used_permille: Numbers,
    nonce_key: Numbers,
    /// (fee token, user token) pairs: the fee token, `default` when unset, and each TIP-20 the
    /// transaction calls, or null for none.
    fee_pairs: Top,
}

impl Transactions {
    fn json(&self) -> Value {
        json!({
            "count": self.count,
            "failed": self.failed,
            "tx_type": self.tx_type.json(),
            "calls": self.calls.json(),
            "gas_limit": self.gas_limit.json(),
            "gas_limit_over_used_permille": self.gas_limit_over_used_permille.json(),
            "nonce_key": self.nonce_key.json(),
            "fee_pairs": self.fee_pairs.json(),
        })
    }
}

/// One selector's calls: whole argument records and each argument field.
#[derive(Default)]
struct Call {
    count: u64,
    undecoded: u64,
    /// Calldata length.
    length: Numbers,
    records: Top,
    /// Fields by path: `name`, `name.field` in a tuple and `name[]` for array elements, whose
    /// lengths are `name.length`.
    args: BTreeMap<String, Field>,
}

impl Call {
    fn add(&mut self, path: &str, param: &Param, value: &DynSolValue) {
        let mut number = |path: String, value: U256, signed: bool| {
            let Field::Numbers(numbers) = self.args.entry(path).or_insert_with(|| {
                Field::Numbers(Numbers {
                    signed,
                    ..Default::default()
                })
            }) else {
                return;
            };
            numbers.add(value);
        };
        match value {
            DynSolValue::Bool(value) => number(path.to_owned(), U256::from(*value), false),
            DynSolValue::Uint(value, _) => number(path.to_owned(), *value, false),
            DynSolValue::Int(value, _) => number(path.to_owned(), value.into_raw(), true),
            DynSolValue::Array(values) | DynSolValue::FixedArray(values) => {
                number(format!("{path}.length"), U256::from(values.len()), false);
                let element = format!("{path}[]");
                for value in values {
                    self.add(&element, param, value);
                }
            }
            DynSolValue::Tuple(values) => {
                for (i, value) in values.iter().enumerate() {
                    match param.components.get(i) {
                        Some(component) => {
                            self.add(&format!("{path}.{}", component.name), component, value)
                        }
                        None => self.add(&format!("{path}.{i}"), param, value),
                    }
                }
            }
            DynSolValue::Bytes(bytes) => {
                number(format!("{path}.length"), U256::from(bytes.len()), false);
                if bytes.len() <= MAX_TOKEN_BYTES {
                    self.token(path, value);
                }
            }
            DynSolValue::String(text) => {
                number(format!("{path}.length"), U256::from(text.len()), false);
                if text.len() <= MAX_TOKEN_BYTES {
                    self.token(path, value);
                }
            }
            _ => self.token(path, value),
        }
    }

    fn token(&mut self, path: &str, value: &DynSolValue) {
        if let Field::Tokens(tokens) = self
            .args
            .entry(path.to_owned())
            .or_insert_with(|| Field::Tokens(Top::default()))
        {
            tokens.add(render(value).to_string());
        }
    }
}

enum Field {
    Numbers(Numbers),
    Tokens(Top),
}

impl Field {
    fn json(&self) -> Value {
        match self {
            Self::Numbers(numbers) => numbers.json(),
            Self::Tokens(tokens) => tokens.json(),
        }
    }
}

/// A numeric field: exact values until more than [`MAX_SET_VALUES`] distinct ones, then counts
/// per [`log2_bin`] with each bin's least and greatest value.
#[derive(Default)]
struct Numbers {
    signed: bool,
    values: HashMap<U256, u64>,
    bins: Option<BTreeMap<u16, (u64, U256, U256)>>,
}

impl Numbers {
    fn add(&mut self, value: U256) {
        let Some(bins) = &mut self.bins else {
            *self.values.entry(value).or_default() += 1;
            if self.values.len() > MAX_SET_VALUES {
                let mut bins = BTreeMap::new();
                for (value, count) in self.values.drain() {
                    bin(&mut bins, value, count);
                }
                self.bins = Some(bins);
            }
            return;
        };
        bin(bins, value, 1);
    }

    fn render(&self, value: U256) -> String {
        if self.signed {
            I256::from_raw(value).to_string()
        } else {
            value.to_string()
        }
    }

    fn json(&self) -> Value {
        match &self.bins {
            None => {
                let mut values: Vec<_> = self.values.iter().collect();
                values.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                json!({
                    "values": values
                        .into_iter()
                        .map(|(value, count)| json!([self.render(*value), count]))
                        .collect::<Vec<_>>(),
                })
            }
            Some(bins) => json!({
                "bins": bins
                    .iter()
                    .map(|(bin, (count, min, max))| {
                        json!([bin, count, self.render(*min), self.render(*max)])
                    })
                    .collect::<Vec<_>>(),
            }),
        }
    }
}

fn bin(bins: &mut BTreeMap<u16, (u64, U256, U256)>, value: U256, count: u64) {
    let entry = bins.entry(log2_bin(value)).or_insert((0, value, value));
    entry.0 += count;
    entry.1 = entry.1.min(value);
    entry.2 = entry.2.max(value);
}

/// Sign-folded bit length: small positive and small negative (two's complement) values land in
/// different, magnitude-ordered bins.
fn log2_bin(value: U256) -> u16 {
    if value.bit(255) {
        512 - (!value).bit_len() as u16
    } else {
        value.bit_len() as u16
    }
}

/// The most frequent values of a field. Past [`TRACKED`] distinct values it keeps those seen more
/// often than the [`TRACKED`]-th, so counts are then lower bounds.
#[derive(Default)]
struct Top {
    total: u64,
    counts: HashMap<String, u64>,
    pruned: bool,
}

impl Top {
    fn add(&mut self, value: String) {
        self.total += 1;
        *self.counts.entry(value).or_default() += 1;
        if self.counts.len() > 4 * TRACKED {
            let mut counts: Vec<_> = self.counts.values().copied().collect();
            let (_, floor, _) = counts.select_nth_unstable_by(TRACKED, |a, b| b.cmp(a));
            let floor = *floor;
            self.counts.retain(|_, count| *count > floor);
            self.pruned = true;
        }
    }

    fn json(&self) -> Value {
        let mut top: Vec<_> = self.counts.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        json!({
            "total": self.total,
            "distinct": (!self.pruned).then_some(self.counts.len()),
            "top": top
                .into_iter()
                .take(MAX_SET_VALUES)
                .map(|(value, count)| {
                    json!([serde_json::from_str::<Value>(value).unwrap_or_else(|_| value.clone().into()), count])
                })
                .collect::<Vec<_>>(),
        })
    }
}

/// `value` as JSON: numbers as decimal strings, bytes and addresses as hex, and bytes or strings
/// longer than [`MAX_TOKEN_BYTES`] as `{"length": n}`.
fn render(value: &DynSolValue) -> Value {
    match value {
        DynSolValue::Bool(value) => (*value).into(),
        DynSolValue::Int(value, _) => value.to_string().into(),
        DynSolValue::Uint(value, _) => value.to_string().into(),
        DynSolValue::Address(address) => address.to_string().into(),
        DynSolValue::FixedBytes(word, size) => hex::encode_prefixed(&word[..*size]).into(),
        DynSolValue::Bytes(bytes) if bytes.len() > MAX_TOKEN_BYTES => {
            json!({"length": bytes.len()})
        }
        DynSolValue::String(text) if text.len() > MAX_TOKEN_BYTES => json!({"length": text.len()}),
        DynSolValue::Bytes(bytes) => hex::encode_prefixed(bytes).into(),
        DynSolValue::String(text) => text.clone().into(),
        DynSolValue::Function(function) => hex::encode_prefixed(function).into(),
        // Arrays, tuples and (with alloy's eip712 feature) structs.
        _ => value
            .as_fixed_seq()
            .or_else(|| value.as_array())
            .map_or(Value::Null, |values| {
                Value::Array(values.iter().map(render).collect())
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{index, tests::corpus};
    use alloy_primitives::{Signature, TxKind};
    use alloy_sol_types::SolCall;
    use tempo_primitives::{TempoTransaction, TempoTxEnvelope, transaction::Call};

    #[test]
    fn every_target_has_an_abi() {
        for target in targets::TARGETS {
            assert!(!abis(target.name).is_empty(), "{}", target.name);
        }
    }

    #[test]
    fn numbers_turn_into_log2_bins_past_the_set_limit() {
        let mut numbers = Numbers::default();
        for value in 1..=MAX_SET_VALUES as u64 {
            numbers.add(U256::from(value));
        }
        assert!(numbers.bins.is_none());
        numbers.add(U256::from(1000));
        let bins = numbers.bins.as_ref().expect("binned");
        assert_eq!(bins[&1], (1, U256::from(1), U256::from(1)));
        assert_eq!(bins[&6], (32, U256::from(32), U256::from(63)));
        assert_eq!(bins[&10], (1, U256::from(1000), U256::from(1000)));
        // -1 and 1 land in different bins.
        assert_eq!((log2_bin(U256::MAX), log2_bin(U256::from(1))), (512, 1));
        let signed = Numbers {
            signed: true,
            ..Default::default()
        };
        assert_eq!(signed.render(U256::MAX), "-1");
    }

    #[test]
    fn decodes_calls_into_records_and_fields() -> eyre::Result<()> {
        let swap = |amount: u128| {
            let input = IStablecoinDEX::swapExactAmountInCall {
                tokenIn: PATH_USD_ADDRESS,
                tokenOut: Address::repeat_byte(0x20),
                amountIn: amount,
                minAmountOut: 0,
            }
            .abi_encode();
            TempoTxEnvelope::AA(
                TempoTransaction {
                    fee_token: Some(PATH_USD_ADDRESS),
                    gas_limit: 100_000,
                    calls: vec![Call {
                        to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                        value: U256::ZERO,
                        input: input.into(),
                    }],
                    ..Default::default()
                }
                .into_signed(Signature::test_signature().into()),
            )
        };
        let blocks = (0..70u128)
            .map(|amount| vec![(swap(amount % 66 + 1), STABLECOIN_DEX_ADDRESS)])
            .collect();
        let (store, catalog) = corpus(blocks)?;
        let dir = tempfile::tempdir()?;
        let out = dir.path().join("index.parquet");
        index(store, catalog, 1..71, &out, 2)?;
        let dict = dict(&[out], targets::bit("dex").expect("registered target"))?;
        let call = &dict["calls"][0];
        assert_eq!(
            call["signature"],
            "swapExactAmountIn(address,address,uint128,uint128)"
        );
        assert_eq!(call["count"], 70);
        // 66 distinct amounts: past the set limit.
        assert!(call["args"]["amountIn"]["bins"].is_array());
        assert_eq!(call["args"]["minAmountOut"]["values"], json!([["0", 70]]));
        assert_eq!(
            call["args"]["tokenIn"]["top"][0],
            json!([PATH_USD_ADDRESS.to_string(), 70])
        );
        assert_eq!(call["records"]["total"], 70);
        assert_eq!(call["records"]["distinct"], 66);
        assert_eq!(
            dict["transactions"]["fee_pairs"]["top"][0],
            json!([[PATH_USD_ADDRESS.to_string(), null], 70])
        );
        assert_eq!(
            dict["transactions"]["gas_limit"]["values"],
            json!([["100000", 70]])
        );
        Ok(())
    }
}
