//! A fake chain backend shared by the routing and decoration tests.

#![allow(dead_code, unreachable_pub)]

use alloy_primitives::B256;
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::BoxStream};
use jsonrpsee::core::RpcResult;
use serde_json::{Value, json, value::RawValue};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tempo_metabinary::routing::{Backend, BlockMetadata, RpcParams, invalid_params, unknown_block};

/// Forwarded calls answer with this closure's raw JSON.
pub type ForwardFn = dyn Fn(usize, &str, &Value) -> RpcResult<String> + Send + Sync;

/// A chain of blocks `0..=head` where block `n` has `timestamp(n)` and [`hash`]`(n)`.
pub struct FakeBackend {
    pub head: u64,
    pub timestamp: fn(u64) -> u64,
    /// Transaction hash to containing block.
    pub transactions: HashMap<B256, u64>,
    pub resolutions: AtomicUsize,
    pub forwarded: Mutex<Vec<(usize, String, Value)>>,
    pub forward: Box<ForwardFn>,
    pub subscribed: Mutex<Vec<(usize, Value)>>,
    /// Notifications each frozen era's subscription yields, keyed by era.
    pub notifications: HashMap<usize, Vec<Value>>,
    /// Ends upstream streams after their notifications, unlike native.
    pub end_streams: bool,
    pub open_streams: Arc<AtomicUsize>,
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self {
            head: 1000,
            timestamp: |number| number,
            transactions: HashMap::new(),
            resolutions: AtomicUsize::new(0),
            forwarded: Mutex::default(),
            forward: Box::new(|era, method, _| {
                Ok(json!({"era": era, "method": method}).to_string())
            }),
            subscribed: Mutex::default(),
            notifications: HashMap::new(),
            end_streams: false,
            open_streams: Arc::default(),
        }
    }
}

impl FakeBackend {
    pub fn resolutions(&self) -> usize {
        self.resolutions.load(Ordering::SeqCst)
    }

    pub fn forwarded(&self) -> Vec<(usize, String, Value)> {
        self.forwarded.lock().unwrap().clone()
    }

    fn metadata(&self, number: u64) -> RpcResult<BlockMetadata> {
        if number > self.head {
            return Err(unknown_block());
        }
        Ok(BlockMetadata {
            number,
            hash: hash(number),
            timestamp: (self.timestamp)(number),
        })
    }
}

pub fn hash(number: u64) -> B256 {
    B256::left_padding_from(&(number + 1).to_be_bytes())
}

pub fn hex(number: u64) -> Value {
    format!("{number:#x}").into()
}

pub fn raw(value: Value) -> Box<RawValue> {
    serde_json::value::to_raw_value(&value).unwrap()
}

fn number_of(selector: &Value) -> Option<u64> {
    match selector {
        Value::String(tag) if tag.len() == 66 => {
            let hash: B256 = tag.parse().ok()?;
            Some(u64::from_be_bytes(hash[24..].try_into().unwrap()) - 1)
        }
        Value::String(tag) => u64::from_str_radix(tag.strip_prefix("0x")?, 16).ok(),
        Value::Object(selector) => selector
            .get("blockHash")
            .or_else(|| selector.get("blockNumber"))
            .and_then(number_of),
        _ => None,
    }
}

impl Backend for FakeBackend {
    fn block<'a>(&'a self, selector: &'a Value) -> BoxFuture<'a, RpcResult<BlockMetadata>> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        let number = match selector.as_str() {
            Some("pending") => panic!("the router must not resolve pending"),
            Some("latest" | "safe" | "finalized") => Some(self.head),
            Some("earliest") => Some(0),
            _ => number_of(selector),
        };
        let result = number
            .ok_or_else(|| invalid_params("bad selector"))
            .and_then(|number| self.metadata(number));
        async move { result }.boxed()
    }

    fn transaction_timestamp<'a>(
        &'a self,
        hash: &'a Value,
    ) -> BoxFuture<'a, RpcResult<Option<u64>>> {
        let hash: B256 = serde_json::from_value(hash.clone()).unwrap();
        let timestamp = self.transactions.get(&hash).map(|n| (self.timestamp)(*n));
        async move { Ok(timestamp) }.boxed()
    }

    fn forward<'a>(
        &'a self,
        era: usize,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Box<RawValue>>> {
        self.forwarded
            .lock()
            .unwrap()
            .push((era, method.to_owned(), params.0.clone()));
        let result =
            (self.forward)(era, method, &params.0).map(|json| RawValue::from_string(json).unwrap());
        async move { result }.boxed()
    }

    fn subscribe<'a>(
        &'a self,
        era: usize,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<BoxStream<'static, Box<RawValue>>>> {
        self.subscribed.lock().unwrap().push((era, params.0));
        let items: Vec<_> = self
            .notifications
            .get(&era)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(raw)
            .collect();
        let guard = OpenStream::new(self.open_streams.clone());
        let tail = if self.end_streams {
            futures::stream::empty().boxed()
        } else {
            futures::stream::pending().boxed()
        };
        let stream = futures::stream::iter(items).chain(tail).map(move |item| {
            let _ = &guard;
            item
        });
        async move { Ok(stream.boxed()) }.boxed()
    }

    fn raw_block_timestamp(&self, params: &RpcParams) -> RpcResult<u64> {
        let number = params.0[0]
            .as_str()
            .and_then(|n| number_of(&n.into()))
            .unwrap();
        Ok((self.timestamp)(number))
    }

    fn merge_execution_outcomes(&self, parts: Vec<Box<RawValue>>) -> RpcResult<Box<RawValue>> {
        let parts: Vec<Value> = parts
            .iter()
            .map(|part| serde_json::from_str(part.get()).unwrap())
            .collect();
        Ok(raw(json!({ "merged": parts })))
    }
}

/// Counts open upstream streams.
struct OpenStream(Arc<AtomicUsize>);

impl OpenStream {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count)
    }
}

impl Drop for OpenStream {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
