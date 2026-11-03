//! Per-target dictionaries of real call values, for seeding a fuzzer's persistent tier.
//!
//! The index selects the transactions calling a target. Their blocks are read from the corpus,
//! and each call's calldata is decoded with the `sol!` ABIs of `tempo_contracts` (unknown
//! selectors and undecodable calldata are counted). Values are kept per field, either a call
//! argument of one selector or a transaction field, and as whole records: every decoded call with
//! all its arguments (as foundry-rs/foundry#18017 keeps whole structs), and the transaction
//! envelope combinations no single call holds. Every count is raw. Static spec constants are not included: tuner generates those
//! from code.
//!
//! A numeric field keeps exact values while it has at most 64 distinct ones, then sign-folded
//! log2 bins (as foundry-rs/foundry#18018 does for state), each with its most frequent exact
//! values. Categorical fields (addresses, hashes, short bytes) and records keep their most
//! frequent values and a tail count, and are never binned. A call record keeps small-domain
//! arguments (addresses, bools, enums, ticks) exact and wider integers as their bin, deduplicated on
//! that form, with the arguments of its first call as exemplar.

use crate::{
    index::{self, call_column, column},
    store::{self, Catalog, Store},
    targets,
};
use alloy_consensus::{BlockHeader, Transaction, Typed2718};
use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::{Function, JsonAbi, Param};
use alloy_primitives::{Address, I256, U256, hex};
use arrow_array::{Array, ListArray, UInt8Array, UInt32Array, UInt64Array};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
    path::PathBuf,
    sync::Arc,
};
use tempo_contracts::{precompiles::*, zones::ZonePortal};
use tempo_precompiles::{storage::StorageKey, tip_fee_manager};
use tempo_primitives::{Block, TempoTxEnvelope, transaction::TEMPO_EXPIRING_NONCE_KEY};

/// Version of the dictionary layout, stored in every dictionary.
pub const VERSION: u32 = 1;
/// Distinct values a numeric field keeps exactly before it is binned.
const EXACT_VALUES: usize = 64;
/// Most frequent values written per categorical field, record kind and selector.
const TOP: usize = 64;
/// Most frequent exact values written per bin.
const EXEMPLARS: usize = 4;
/// Distinct values counted per table before the rarest are pruned. Counts are then lower bounds.
const TRACKED: usize = 1 << 14;
/// Widest integer a call record keeps exact (enums, ticks). Wider ones are binned.
const EXACT_BITS: usize = 16;
/// Longest bytes or string value kept whole. Longer ones (proofs, encrypted payloads) keep only
/// their length.
const MAX_TOKEN_BYTES: usize = 32;

/// The dictionary of target `bit` over the transactions the index files `paths` list for
/// `catalog`'s corpus at `corpus` in `store`, read with `workers` parallel tasks.
pub fn dict(
    paths: &[PathBuf],
    bit: u8,
    store: Store,
    catalog: &Catalog,
    corpus: &str,
    workers: usize,
) -> eyre::Result<Value> {
    let target = &targets::TARGETS[usize::from(bit)];
    // Transactions of selected blocks: index and charged gas.
    let mut selected = BTreeMap::<u64, Vec<(usize, u64)>>::new();
    let mut ranges = Vec::new();
    for path in paths {
        let (indexed, range, batches) =
            index::read(path, &["block", "tx_index", "calls", "charged_gas"])?;
        eyre::ensure!(
            indexed.context == catalog.context && indexed.checkpoint == catalog.checkpoint,
            "{} indexes another corpus or checkpoint",
            path.display()
        );
        ranges.push(range);
        for batch in batches {
            let batch = batch?;
            let block = column::<UInt64Array>(&batch, "block")?;
            let tx_index = column::<UInt32Array>(&batch, "tx_index")?;
            let calls = column::<ListArray>(&batch, "calls")?;
            let charged_gas = column::<UInt64Array>(&batch, "charged_gas")?;
            let called = call_column::<UInt8Array>(calls, "target")?;
            let offsets = calls.value_offsets();
            for row in 0..batch.num_rows() {
                if (offsets[row] as usize..offsets[row + 1] as usize)
                    .any(|call| called.is_valid(call) && called.value(call) == bit)
                {
                    selected
                        .entry(block.value(row))
                        .or_default()
                        .push((tx_index.value(row) as usize, charged_gas.value(row)));
                }
            }
        }
    }
    let functions: Arc<HashMap<[u8; 4], Function>> = Arc::new(
        abis(target.name)
            .iter()
            .flat_map(|abi| abi().functions().cloned().collect::<Vec<_>>())
            .map(|function| (function.selector().0, function))
            .collect(),
    );
    let (first, last) = match (selected.keys().next(), selected.keys().next_back()) {
        (Some(first), Some(last)) => (*first, *last),
        _ => (catalog.context.start, catalog.context.start),
    };
    let wanted = selected.clone();
    let selected = Arc::new(selected);
    let visit = {
        let functions = functions.clone();
        move |window: &mut Vec<Sample>,
              record: &store::Record,
              block: &bytes::Bytes,
              _: &[bytes::Bytes]| {
            let Some(transactions) = selected.get(&record.number) else {
                return Ok(());
            };
            let input = store::decode(block, record)?;
            let decoded = alloy_rlp::decode_exact::<Block>(&input.block.rlp)?;
            let storage = |address: Address, slot: U256| {
                input
                    .storage
                    .get(&(address.into_array(), slot.to_be_bytes()))
                    .map(|value| Address::from_word((*value).into()))
            };
            for &(i, charged) in transactions {
                let transaction =
                    decoded.body.transactions.get(i).ok_or_else(|| {
                        eyre::eyre!("block {} has no transaction {i}", record.number)
                    })?;
                let sender = Address::from(input.block.senders[i]);
                window.push(sample(
                    bit,
                    &functions,
                    transaction,
                    Context {
                        sender,
                        charged,
                        timestamp: decoded.header.timestamp(),
                        beneficiary: decoded.header.beneficiary(),
                        storage: &storage,
                    },
                )?);
            }
            Ok(())
        }
    };
    let mut dict = Dict::default();
    index::scan(
        store,
        catalog,
        first..last + 1,
        workers,
        |window| wanted.range(window).next().is_some(),
        visit,
        |window: Vec<Sample>| {
            window.into_iter().for_each(|sample| dict.add(sample));
            Ok(())
        },
    )?;
    let context = &catalog.context;
    Ok(json!({
        "meta": {
            "dict_schema": VERSION,
            "index_schema": index::VERSION,
            "registry": targets::VERSION,
            "target": target.name,
            "chain_id": context.chain_id,
            "corpus": corpus,
            "checkpoint": catalog.checkpoint,
            "blocks": [context.start, context.end],
            "indexed": ranges,
        },
        "coverage": dict.coverage.json(),
        "fields": dict
            .fields
            .iter()
            .map(|(key, field)| {
                let mut entry = field.json()?;
                entry["key"] = key.json(&functions);
                Ok(entry)
            })
            .collect::<eyre::Result<Vec<_>>>()?,
        "calls": dict
            .calls
            .iter()
            .map(|(selector, records)| {
                let mut entry = records.json(|shape, exemplar| {
                    Ok(json!({"args": parse(shape)?, "exemplar": parse(exemplar)?}))
                })?;
                entry["selector"] = hex::encode_prefixed(selector).into();
                entry["signature"] = functions.get(selector).map(Function::signature).into();
                Ok(entry)
            })
            .collect::<eyre::Result<Vec<_>>>()?,
        "records": dict
            .records
            .iter()
            .map(|(kind, records)| Ok(((*kind).to_owned(), records.json(|record, _| parse(record))?)))
            .collect::<eyre::Result<serde_json::Map<_, _>>>()?,
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

/// What a sampled transaction's block tells about it.
struct Context<'a> {
    sender: Address,
    charged: u64,
    timestamp: u64,
    beneficiary: Address,
    /// The pre-block value of a slot the block read, as an address, if it is in the witness.
    storage: &'a dyn Fn(Address, U256) -> Option<Address>,
}

/// A dictionary field: one argument of one selector, or one transaction field.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum FieldKey {
    /// `arg` is the argument's index path (`2`, `3.1` in a tuple, `0[]` for array elements),
    /// `name` its name path.
    Arg {
        selector: [u8; 4],
        arg: String,
        name: String,
    },
    Tx(&'static str),
}

impl FieldKey {
    fn json(&self, functions: &HashMap<[u8; 4], Function>) -> Value {
        match self {
            Self::Arg {
                selector,
                arg,
                name,
            } => json!({"arg": {
                "selector": hex::encode_prefixed(selector),
                "signature": functions.get(selector).map(Function::signature),
                "arg": arg,
                "name": name,
            }}),
            Self::Tx(field) => json!({ "tx": field }),
        }
    }
}

enum Observed {
    Number { value: U256, signed: bool },
    Category(String),
}

/// What one transaction contributes to the dictionary.
#[derive(Default)]
struct Sample {
    fields: Vec<(FieldKey, Observed)>,
    /// Envelope records by kind, each as JSON text.
    records: Vec<(&'static str, String)>,
    /// Decoded calls: selector, arguments in record form and exactly, as JSON text.
    calls: Vec<([u8; 4], String, String)>,
    coverage: Coverage,
}

impl Sample {
    fn number(&mut self, key: FieldKey, value: impl Into<U256>) {
        self.fields.push((
            key,
            Observed::Number {
                value: value.into(),
                signed: false,
            },
        ));
    }

    fn category(&mut self, key: FieldKey, value: impl ToString) {
        self.fields
            .push((key, Observed::Category(value.to_string())));
    }

    fn record(&mut self, kind: &'static str, record: Value) {
        self.records.push((kind, record.to_string()));
    }

    /// Adds the fields of argument `value`, with `param` its ABI parameter.
    fn arg(
        &mut self,
        selector: [u8; 4],
        arg: &str,
        name: &str,
        param: &Param,
        value: &DynSolValue,
    ) {
        let key = |arg: String, name: String| FieldKey::Arg {
            selector,
            arg,
            name,
        };
        let length = |sample: &mut Self, len: usize| {
            sample.number(
                key(format!("{arg}.length"), format!("{name}.length")),
                U256::from(len),
            )
        };
        match value {
            DynSolValue::Bool(value) => {
                self.number(key(arg.into(), name.into()), U256::from(*value))
            }
            DynSolValue::Uint(value, _) => self.number(key(arg.into(), name.into()), *value),
            DynSolValue::Int(value, _) => self.fields.push((
                key(arg.into(), name.into()),
                Observed::Number {
                    value: value.into_raw(),
                    signed: true,
                },
            )),
            DynSolValue::Bytes(bytes) => {
                length(self, bytes.len());
                if bytes.len() <= MAX_TOKEN_BYTES {
                    self.category(key(arg.into(), name.into()), hex::encode_prefixed(bytes));
                }
            }
            DynSolValue::String(text) => {
                length(self, text.len());
                if text.len() <= MAX_TOKEN_BYTES {
                    self.category(key(arg.into(), name.into()), text);
                }
            }
            DynSolValue::Array(values) => {
                length(self, values.len());
                for value in values {
                    self.arg(
                        selector,
                        &format!("{arg}[]"),
                        &format!("{name}[]"),
                        param,
                        value,
                    );
                }
            }
            DynSolValue::Address(_) | DynSolValue::FixedBytes(..) | DynSolValue::Function(_) => {
                self.category(
                    key(arg.into(), name.into()),
                    render(value).as_str().unwrap_or_default(),
                )
            }
            // Tuples, fixed arrays and (with alloy's eip712 feature) structs.
            _ => {
                for (i, value) in value.as_fixed_seq().unwrap_or_default().iter().enumerate() {
                    let component = param.components.get(i).unwrap_or(param);
                    self.arg(
                        selector,
                        &format!("{arg}.{i}"),
                        &format!("{name}.{}", component.name),
                        component,
                        value,
                    );
                }
            }
        }
    }
}

/// The sample of a transaction calling target `bit`.
fn sample(
    bit: u8,
    functions: &HashMap<[u8; 4], Function>,
    transaction: &TempoTxEnvelope,
    context: Context<'_>,
) -> eyre::Result<Sample> {
    let mut sample = Sample::default();
    sample.coverage.transactions = 1;
    let aa = transaction.as_aa().map(|aa| aa.tx());
    let tx_type = transaction.ty();
    let calls: Vec<_> = transaction.calls().collect();
    let sponsored = aa.is_some_and(|aa| aa.fee_payer_signature.is_some());
    let max_fee = transaction.max_fee_per_gas();
    let priority_fee = transaction.max_priority_fee_per_gas();
    sample.category(
        FieldKey::Tx("fee_token"),
        transaction
            .fee_token()
            .map_or_else(|| "none".to_owned(), |token| token.to_string()),
    );
    sample.number(
        FieldKey::Tx("gas_limit"),
        U256::from(transaction.gas_limit()),
    );
    sample.number(FieldKey::Tx("max_fee"), U256::from(max_fee));
    if let Some(priority_fee) = priority_fee {
        sample.number(FieldKey::Tx("priority_fee"), U256::from(priority_fee));
    }
    sample.number(FieldKey::Tx("tx_type"), U256::from(tx_type));
    sample.number(FieldKey::Tx("batch_len"), U256::from(calls.len()));
    sample.number(FieldKey::Tx("sponsored"), U256::from(sponsored));
    let nonce_kind = match aa.map(|aa| aa.nonce_key) {
        None => "legacy",
        Some(key) if key.is_zero() => "protocol",
        Some(key) if key == TEMPO_EXPIRING_NONCE_KEY => "expiring",
        Some(_) => "2d",
    };
    // Seconds the transaction stays valid for: until valid_before, from valid_after or the block.
    let window = aa.and_then(|aa| {
        let before = aa.valid_before?.get();
        Some(
            before.saturating_sub(
                aa.valid_after
                    .map_or(context.timestamp, |after| after.get()),
            ),
        )
    });
    if let Some(aa) = aa {
        sample.number(FieldKey::Tx("nonce_key"), aa.nonce_key);
    }
    if let Some(window) = window {
        sample.number(FieldKey::Tx("valid_window"), U256::from(window));
    }
    sample.record("nonce", json!({"kind": nonce_kind, "window": window}));

    // The fee token approximates the protocol's resolution: the transaction's own, else the fee
    // payer's preference, else a TIP-20 it calls, else pathUSD.
    let fee_manager = TIP_FEE_MANAGER_ADDRESS;
    let preference = |slot| (context.storage)(fee_manager, slot).filter(|token| !token.is_zero());
    let fee_payer = transaction
        .fee_payer(context.sender)
        .unwrap_or(context.sender);
    let user_token = transaction
        .fee_token()
        .or_else(|| preference(fee_payer.mapping_slot(tip_fee_manager::slots::USER_TOKENS)))
        .or_else(|| {
            calls
                .iter()
                .filter_map(|(kind, _)| kind.to().copied())
                .find(|to| targets::classify(to) == targets::bit("tip20"))
        })
        .unwrap_or(DEFAULT_FEE_TOKEN);
    let validator_token = (context.storage)(
        fee_manager,
        context
            .beneficiary
            .mapping_slot(tip_fee_manager::slots::VALIDATOR_TOKENS),
    )
    .map(|token| {
        if token.is_zero() {
            DEFAULT_FEE_TOKEN
        } else {
            token
        }
    });
    sample.record(
        "fee_pair",
        json!({"user_token": user_token, "validator_token": validator_token}),
    );
    if let Some(authorization) = aa.and_then(|aa| aa.key_authorization.as_ref()) {
        sample.record(
            "key_auth",
            json!({
                "sig_type": format!("{:?}", authorization.key_type),
                "expiry": authorization
                    .expiry
                    .map(|expiry| bin_json(U256::from(expiry.get().saturating_sub(context.timestamp)))),
                "limits": authorization.limits.iter().flatten().map(|limit| {
                    json!({"token": limit.token, "limit": bin_json(limit.limit)})
                }).collect::<Vec<_>>(),
            }),
        );
    }

    if calls.len() > 1 {
        sample.record(
            "batch",
            calls
                .iter()
                .map(|(kind, input)| {
                    json!([
                        kind.to()
                            .and_then(targets::classify)
                            .map(|bit| targets::TARGETS[usize::from(bit)].name),
                        input.first_chunk::<4>().map(hex::encode_prefixed),
                    ])
                })
                .collect(),
        );
    }
    let mut gas_selector = None;
    for (kind, input) in &calls {
        let Some(to) = kind.to() else { continue };
        if targets::classify(to) != Some(bit) {
            continue;
        }
        sample.coverage.calls += 1;
        let selector = input.first_chunk::<4>().copied();
        gas_selector = gas_selector.or(selector);
        let Some(selector) = selector else {
            sample.coverage.no_selector += 1;
            continue;
        };
        let Some(function) = functions.get(&selector) else {
            sample.coverage.unknown_selector += 1;
            continue;
        };
        let Ok(args) = function.abi_decode_input(&input[4..]) else {
            sample.coverage.undecodable += 1;
            continue;
        };
        sample.coverage.decoded += 1;
        for (i, (param, value)) in function.inputs.iter().zip(&args).enumerate() {
            sample.arg(selector, &i.to_string(), &param.name, param, value);
        }
        sample.calls.push((
            selector,
            Value::Array(args.iter().map(shape).collect()).to_string(),
            Value::Array(args.iter().map(render).collect()).to_string(),
        ));
    }
    if context.charged > 0 {
        sample.record(
            "gas",
            json!({
                "selector": gas_selector.map(hex::encode_prefixed),
                "limit_over_used_permille": bin_json(U256::from(
                    u128::from(transaction.gas_limit()) * 1000 / u128::from(context.charged),
                )),
                "max_fee": bin_json(U256::from(max_fee)),
                "priority_fee": priority_fee.map(|fee| bin_json(U256::from(fee))),
            }),
        );
    }
    Ok(sample)
}

/// Share of the target's calls decoded.
#[derive(Default)]
struct Coverage {
    transactions: u64,
    calls: u64,
    decoded: u64,
    /// Calls whose selector no ABI of the target has.
    unknown_selector: u64,
    /// Calls with a known selector whose calldata doesn't decode.
    undecodable: u64,
    /// Calls with less than 4 bytes of calldata.
    no_selector: u64,
}

impl Coverage {
    fn json(&self) -> Value {
        json!({
            "transactions": self.transactions,
            "calls": self.calls,
            "decoded": self.decoded,
            "unknown_selector": self.unknown_selector,
            "undecodable": self.undecodable,
            "no_selector": self.no_selector,
        })
    }
}

#[derive(Default)]
struct Dict {
    coverage: Coverage,
    fields: BTreeMap<FieldKey, Field>,
    records: BTreeMap<&'static str, Top<String>>,
    /// Call records per selector, with the exact arguments of the first as exemplar.
    calls: BTreeMap<[u8; 4], Top<String, String>>,
}

impl Dict {
    fn add(&mut self, sample: Sample) {
        let (ours, theirs) = (&mut self.coverage, sample.coverage);
        ours.transactions += theirs.transactions;
        ours.calls += theirs.calls;
        ours.decoded += theirs.decoded;
        ours.unknown_selector += theirs.unknown_selector;
        ours.undecodable += theirs.undecodable;
        ours.no_selector += theirs.no_selector;
        for (key, observed) in sample.fields {
            match observed {
                Observed::Number { value, signed } => {
                    if let Field::Numbers(numbers) = self.fields.entry(key).or_insert_with(|| {
                        Field::Numbers(Numbers {
                            signed,
                            ..Default::default()
                        })
                    }) {
                        numbers.add(value);
                    }
                }
                Observed::Category(value) => {
                    if let Field::Categories(top) = self
                        .fields
                        .entry(key)
                        .or_insert_with(|| Field::Categories(Top::default()))
                    {
                        top.add(value);
                    }
                }
            }
        }
        for (kind, record) in sample.records {
            self.records.entry(kind).or_default().add(record);
        }
        for (selector, shape, exact) in sample.calls {
            self.calls
                .entry(selector)
                .or_default()
                .add_with(shape, 1, || exact);
        }
    }
}

enum Field {
    Numbers(Numbers),
    Categories(Top<String>),
}

impl Field {
    fn json(&self) -> eyre::Result<Value> {
        match self {
            Self::Numbers(numbers) => Ok(numbers.json()),
            Self::Categories(top) => top.json(|value, _| Ok(value.clone().into())),
        }
    }
}

/// A numeric field: exact values while it has at most [`EXACT_VALUES`] distinct ones, then
/// counts per sign-folded log2 bin, each with its most frequent exact values.
#[derive(Default)]
struct Numbers {
    signed: bool,
    count: u64,
    exact: HashMap<U256, u64>,
    bins: Option<BTreeMap<u16, Top<U256>>>,
}

impl Numbers {
    fn add(&mut self, value: U256) {
        self.add_count(value, 1);
    }

    fn add_count(&mut self, value: U256, count: u64) {
        self.count += count;
        let Some(bins) = &mut self.bins else {
            *self.exact.entry(value).or_default() += count;
            if self.exact.len() > EXACT_VALUES {
                let mut bins = BTreeMap::<u16, Top<U256>>::new();
                for (value, count) in self.exact.drain() {
                    bins.entry(bin(value)).or_default().add_count(value, count);
                }
                self.bins = Some(bins);
            }
            return;
        };
        bins.entry(bin(value)).or_default().add_count(value, count);
    }

    fn render(&self, value: U256) -> Value {
        if self.signed {
            I256::from_raw(value).to_string().into()
        } else {
            value.to_string().into()
        }
    }

    fn json(&self) -> Value {
        let Some(bins) = &self.bins else {
            let mut exact: Vec<_> = self.exact.iter().collect();
            exact.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            return json!({
                "count": self.count,
                "exact": exact
                    .into_iter()
                    .map(|(value, count)| json!([self.render(*value), count]))
                    .collect::<Vec<_>>(),
            });
        };
        json!({
            "count": self.count,
            "bins": bins
                .iter()
                .map(|(bin, top)| {
                    let (sign, log2) = sign_log2(*bin);
                    json!({
                        "sign": sign,
                        "log2": log2,
                        "count": top.total,
                        "exemplars": top
                            .top(EXEMPLARS)
                            .map(|(value, count, _)| json!([self.render(*value), count]))
                            .collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>(),
        })
    }
}

/// Sign-folded bit length: small positive and small negative (two's complement) values land in
/// different, magnitude-ordered bins.
fn bin(value: U256) -> u16 {
    if value.bit(255) {
        512 - (!value).bit_len() as u16
    } else {
        value.bit_len() as u16
    }
}

/// The sign and bit length of [`bin`] `bin`: `+` for values in [2^(log2-1), 2^log2), `-` for
/// two's complement negatives of that magnitude.
fn sign_log2(bin: u16) -> (&'static str, u16) {
    if bin > 256 {
        ("-", 512 - bin)
    } else {
        ("+", bin)
    }
}

fn bin_json(value: U256) -> Value {
    let (sign, log2) = sign_log2(bin(value));
    json!({"sign": sign, "log2": log2})
}

/// The most frequent values of a table, each with the payload of its first occurrence, and the
/// total count. Past [`TRACKED`] distinct values it keeps those seen more often than the
/// [`TRACKED`]-th, so counts are then lower bounds.
struct Top<K, E = ()> {
    total: u64,
    counts: HashMap<K, (u64, E)>,
}

impl<K, E> Default for Top<K, E> {
    fn default() -> Self {
        Self {
            total: 0,
            counts: HashMap::new(),
        }
    }
}

impl<K: Hash + Eq + Ord> Top<K> {
    fn add(&mut self, value: K) {
        self.add_with(value, 1, || ());
    }

    fn add_count(&mut self, value: K, count: u64) {
        self.add_with(value, count, || ());
    }
}

impl<K: Hash + Eq + Ord, E> Top<K, E> {
    fn add_with(&mut self, value: K, count: u64, payload: impl FnOnce() -> E) {
        self.total += count;
        self.counts.entry(value).or_insert_with(|| (0, payload())).0 += count;
        if self.counts.len() > 4 * TRACKED {
            let mut counts: Vec<_> = self.counts.values().map(|(count, _)| *count).collect();
            let (_, floor, _) = counts.select_nth_unstable_by(TRACKED, |a, b| b.cmp(a));
            let floor = *floor;
            self.counts.retain(|_, (count, _)| *count > floor);
        }
    }

    /// The `n` most frequent values, ties by value.
    fn top(&self, n: usize) -> impl Iterator<Item = (&K, u64, &E)> {
        let mut top: Vec<_> = self
            .counts
            .iter()
            .map(|(value, (count, payload))| (value, *count, payload))
            .collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        top.into_iter().take(n)
    }

    /// The [`TOP`] most frequent values, rendered by `render`, and the count of all others.
    fn json(&self, render: impl Fn(&K, &E) -> eyre::Result<Value>) -> eyre::Result<Value> {
        let top = self
            .top(TOP)
            .map(|(value, count, payload)| Ok((render(value, payload)?, count)))
            .collect::<eyre::Result<Vec<_>>>()?;
        let tail = self.total - top.iter().map(|(_, count)| count).sum::<u64>();
        Ok(json!({
            "count": self.total,
            "top": top.into_iter().map(|(value, count)| json!([value, count])).collect::<Vec<_>>(),
            "tail": tail,
        }))
    }
}

fn parse(record: &str) -> eyre::Result<Value> {
    Ok(serde_json::from_str(record)?)
}

/// `value` in call record form: as [~render~], but integers wider than [~EXACT_BITS~] as their
/// bin.
fn shape(value: &DynSolValue) -> Value {
    match value {
        DynSolValue::Uint(value, bits) if *bits > EXACT_BITS => json!({"bin": bin_json(*value)}),
        DynSolValue::Int(value, bits) if *bits > EXACT_BITS => {
            json!({"bin": bin_json(value.into_raw())})
        }
        DynSolValue::Array(values)
        | DynSolValue::FixedArray(values)
        | DynSolValue::Tuple(values) => Value::Array(values.iter().map(shape).collect()),
        _ => render(value),
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
    use tempo_primitives::{TempoTransaction, transaction::Call};

    #[test]
    fn every_target_has_an_abi() {
        for target in targets::TARGETS {
            assert!(!abis(target.name).is_empty(), "{}", target.name);
        }
    }

    #[test]
    fn numbers_bin_past_the_exact_limit_and_keep_exemplars() {
        let mut numbers = Numbers::default();
        for value in 1..=EXACT_VALUES as u64 {
            numbers.add(U256::from(value));
        }
        assert!(numbers.bins.is_none());
        for _ in 0..3 {
            numbers.add(U256::from(40));
        }
        numbers.add(U256::from(1000));
        let value = numbers.json();
        let bins = value["bins"].as_array().expect("binned");
        // 32..=63 is the bin of bit length 6, where 40 is the most frequent value.
        let six = bins.iter().find(|bin| bin["log2"] == 6).expect("bin 6");
        assert_eq!(six["count"], 35);
        assert_eq!(six["exemplars"][0], json!(["40", 4]));
        assert_eq!(six["exemplars"].as_array().map(Vec::len), Some(EXEMPLARS));
        assert_eq!(value["count"], 68);
        assert_eq!(
            (
                bin(U256::MAX),
                sign_log2(bin(U256::MAX)),
                bin(U256::from(1))
            ),
            (512, ("-", 0), 1)
        );
        let signed = Numbers {
            signed: true,
            ..Default::default()
        };
        assert_eq!(signed.render(U256::MAX), "-1");
    }

    #[test]
    fn decodes_selected_calls_from_the_corpus() -> eyre::Result<()> {
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
        index(store.clone(), catalog.clone(), 1..71, &out, 2)?;
        let bit = targets::bit("dex").expect("registered target");
        let dict = dict(&[out], bit, store, &catalog, "memory://", 2)?;
        assert_eq!(
            dict["coverage"],
            json!({"transactions": 70, "calls": 70, "decoded": 70, "unknown_selector": 0,
                "undecodable": 0, "no_selector": 0})
        );
        let field = |key: Value| {
            dict["fields"]
                .as_array()
                .and_then(|fields| fields.iter().find(|field| field["key"] == key))
                .cloned()
                .expect("field")
        };
        let arg = |arg: &str, name: &str| {
            json!({"arg": {
                "selector": hex::encode_prefixed(IStablecoinDEX::swapExactAmountInCall::SELECTOR),
                "signature": "swapExactAmountIn(address,address,uint128,uint128)",
                "arg": arg,
                "name": name,
            }})
        };
        // 66 distinct amounts: past the exact limit.
        assert!(field(arg("2", "amountIn"))["bins"].is_array());
        assert_eq!(field(arg("3", "minAmountOut"))["exact"], json!([["0", 70]]));
        assert_eq!(
            field(arg("0", "tokenIn"))["top"],
            json!([[PATH_USD_ADDRESS.to_string(), 70]])
        );
        assert_eq!(
            field(json!({"tx": "gas_limit"}))["exact"],
            json!([["100000", 70]])
        );
        assert_eq!(
            dict["records"]["fee_pair"]["top"],
            json!([[{"user_token": PATH_USD_ADDRESS, "validator_token": null}, 70]])
        );
        // Amounts 1..=66 fall in bins of bit length 1 to 7.
        let calls = &dict["calls"][0];
        assert_eq!((&calls["count"], &calls["tail"]), (&json!(70), &json!(0)));
        assert_eq!(calls["top"].as_array().map(Vec::len), Some(7));
        assert_eq!(
            calls["top"][0][0]["args"][2],
            json!({"bin": {"sign": "+", "log2": 6}})
        );
        Ok(())
    }
}
