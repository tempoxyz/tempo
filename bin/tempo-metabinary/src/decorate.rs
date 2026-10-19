//! Replaces execution callbacks of the native RPC transports in place, keeping their limits.

use crate::routing::{
    Merge, RelaySegment, Route, Router, RpcParams, internal, invalid_params, is_execution_method,
};
use alloy_primitives::U256;
use futures::{FutureExt as _, StreamExt as _, stream::BoxStream};
use jsonrpsee::{
    core::{
        RegisterMethodError, RpcResult,
        server::{
            ConnectionId, Extensions, MethodCallback, MethodResponse, MethodSink, Methods,
            ResponsePayload, RpcModule, SubscriptionMethod, SubscriptionPermit, SubscriptionState,
        },
        traits::{IdProvider, ToRpcParams as _},
    },
    types::{
        ErrorObjectOwned, Id, Params, SubscriptionId, SubscriptionPayload, SubscriptionResponse,
    },
};
use serde::{Deserialize, de::IgnoredAny};
use serde_json::{Value, value::RawValue};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;
use tracing::warn;

const DEBUG_SUBSCRIBE: &str = "debug_subscribe";
const DEBUG_UNSUBSCRIBE: &str = "debug_unsubscribe";
const DEBUG_SUBSCRIPTION: &str = "debug_subscription";

/// The API a set of methods is served on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcApi {
    /// Public HTTP, WS, and IPC transports.
    Eth,
    /// The authenticated engine transport, whose `eth_call` names its selector `block_id`.
    Engine,
}

/// Wraps execution callbacks with era routing. Other callbacks stay the identical `Arc`.
pub fn decorate(
    methods: Methods,
    router: Arc<Router>,
    api: RpcApi,
) -> Result<Methods, RegisterMethodError> {
    let mut module = RpcModule::new(());
    module.merge(methods)?;

    // Live relay segments subscribe in-process through the original callbacks.
    let mut natives = Methods::new();
    for name in [DEBUG_SUBSCRIBE, DEBUG_UNSUBSCRIBE] {
        if let Some(callback) = module.method(name) {
            natives.verify_and_insert(name, callback.clone())?;
        }
    }
    let decorator = Arc::new(Decorator {
        router,
        api,
        natives,
        relays: Mutex::default(),
    });

    let names: Vec<&'static str> = module.method_names().collect();
    for name in names {
        let Some(callback) = module.remove_method(name) else {
            continue;
        };
        let callback = match callback {
            MethodCallback::Sync(_) | MethodCallback::Async(_) if is_execution_method(name) => {
                decorator.clone().wrap_call(name, callback)
            }
            MethodCallback::Subscription(native) if name == DEBUG_SUBSCRIBE => {
                decorator.clone().wrap_subscribe(native)
            }
            MethodCallback::Unsubscription(native) if name == DEBUG_UNSUBSCRIBE => {
                let decorator = decorator.clone();
                MethodCallback::Unsubscription(Arc::new(move |id, params, conn_id, max, ext| {
                    decorator.unsubscribe(&*native, id, params, conn_id, max, ext)
                }))
            }
            callback => callback,
        };
        module.verify_and_insert(name, callback)?;
    }
    Ok(module.into())
}

/// Shared state of the wrapped callbacks of one transport.
struct Decorator {
    router: Arc<Router>,
    api: RpcApi,
    /// The original `debug_subscribe` and `debug_unsubscribe` callbacks.
    natives: Methods,
    /// Active relays, bounded by the subscription permit each one holds.
    relays: Mutex<HashMap<(ConnectionId, SubscriptionId<'static>), CancellationToken>>,
}

impl Decorator {
    fn wrap_call(self: Arc<Self>, method: &'static str, native: MethodCallback) -> MethodCallback {
        MethodCallback::Async(Arc::new(move |id, params, conn_id, max, ext| {
            let this = self.clone();
            let native = native.clone();
            async move {
                this.call(method, &native, id, params, conn_id, max, ext)
                    .await
            }
            .boxed()
        }))
    }

    #[expect(clippy::too_many_arguments)]
    async fn call(
        &self,
        method: &'static str,
        native: &MethodCallback,
        id: Id<'static>,
        params: Params<'static>,
        conn_id: ConnectionId,
        max: usize,
        ext: Extensions,
    ) -> MethodResponse {
        let result = match self.route(method, &params).await {
            Err(err) => Err(err),
            Ok(Route::Live) => return invoke(native, id, params, conn_id, max, ext).await,
            Ok(Route::Era(era, params)) => self.router.backend().forward(era, method, params).await,
            Ok(Route::Split { segments, merge }) => {
                self.split(method, native, segments, merge, conn_id, &ext)
                    .await
            }
            Ok(Route::Relay { .. }) => {
                Err(internal(format!("{method} cannot relay a subscription")))
            }
        };
        respond(id, result, max).with_extensions(ext)
    }

    /// Parses and routes params, translating the engine `eth_call` selector to the public name.
    async fn route(&self, method: &str, params: &Params<'_>) -> RpcResult<Route> {
        let mut parsed = RpcParams(match params.as_str() {
            None => Value::Null,
            Some(raw) => {
                serde_json::from_str(raw).map_err(|err| invalid_params(err.to_string()))?
            }
        });
        if self.api == RpcApi::Engine
            && method == "eth_call"
            && let Value::Object(named) = &mut parsed.0
        {
            named.remove("block_number");
            named.remove("blockNumber");
            for (engine, public) in [("block_id", "block_number"), ("blockId", "blockNumber")] {
                if let Some(selector) = named.remove(engine) {
                    named.insert(public.to_owned(), selector);
                }
            }
        }
        self.router.route(method, parsed).await
    }

    /// Runs split segments in block order and merges their results.
    async fn split(
        &self,
        method: &'static str,
        native: &MethodCallback,
        segments: Vec<(usize, RpcParams)>,
        merge: Merge,
        conn_id: ConnectionId,
        ext: &Extensions,
    ) -> RpcResult<Box<RawValue>> {
        let mut segments = segments.into_iter();
        let mut next = async || match segments.next() {
            Some((era, params)) => self
                .segment(era, method, native, params, conn_id, ext)
                .await
                .map(Some),
            None => Ok(None),
        };
        match merge {
            Merge::TraceFilter { after, count } => {
                let after = usize::try_from(after.unwrap_or_default()).unwrap_or(usize::MAX);
                let count = count.map_or(usize::MAX, |c| usize::try_from(c).unwrap_or(usize::MAX));
                // Later segments cannot change a full page.
                let needed = after.saturating_add(count);
                let mut traces = Vec::<Box<RawValue>>::new();
                while traces.len() < needed
                    && let Some(part) = next().await?
                {
                    let part: Vec<Box<RawValue>> =
                        serde_json::from_str(part.get()).map_err(|err| {
                            internal(format!("cannot merge traces across eras: {err}"))
                        })?;
                    traces.extend(part);
                }
                let page: Vec<_> = traces.into_iter().skip(after).take(count).collect();
                serde_json::value::to_raw_value(&page).map_err(|err| internal(err.to_string()))
            }
            Merge::ExecutionOutcome => {
                let mut parts = Vec::new();
                // Native also stops at the first absent block.
                while let Some(part) = next().await? {
                    if part.get() == "null" {
                        break;
                    }
                    parts.push(part);
                }
                if parts.is_empty() {
                    return Ok(RawValue::NULL.to_owned());
                }
                self.router.backend().merge_execution_outcomes(parts)
            }
        }
    }

    /// Runs one split segment, returning its raw `result`.
    async fn segment(
        &self,
        era: usize,
        method: &'static str,
        native: &MethodCallback,
        params: RpcParams,
        conn_id: ConnectionId,
        ext: &Extensions,
    ) -> RpcResult<Box<RawValue>> {
        if era != self.router.live_index() {
            return self.router.backend().forward(era, method, params).await;
        }
        let raw = params
            .to_rpc_params()
            .map_err(|err| internal(err.to_string()))?;
        let params = Params::new(raw.as_ref().map(|raw| raw.get())).into_owned();
        // The merged response is limited by the caller's size limit instead.
        let response = invoke(
            native,
            Id::Number(0),
            params,
            conn_id,
            u32::MAX as usize,
            ext.clone(),
        )
        .await;
        let envelope: Envelope = serde_json::from_str(response.as_json().get())
            .map_err(|err| internal(format!("invalid native response: {err}")))?;
        match envelope.error {
            Some(err) => Err(err),
            None => Ok(envelope.result.unwrap_or_else(|| RawValue::NULL.to_owned())),
        }
    }

    fn wrap_subscribe(self: Arc<Self>, native: SubscriptionMethod<'static>) -> MethodCallback {
        MethodCallback::Subscription(Arc::new(move |id, params, sink, state, ext| {
            // jsonrpsee lends the provider only for the synchronous part of the callback.
            let sub_id = state.id_provider.next_id();
            let this = self.clone();
            let native = native.clone();
            let (id, params) = (id.into_owned(), params.into_owned());
            let (conn_id, permit) = (state.conn_id, state.subscription_permit);
            async move {
                this.subscribe(native, id, params, sink, conn_id, permit, sub_id, ext)
                    .await
            }
            .boxed()
        }))
    }

    #[expect(clippy::too_many_arguments)]
    async fn subscribe(
        self: Arc<Self>,
        native: SubscriptionMethod<'static>,
        id: Id<'static>,
        params: Params<'static>,
        sink: MethodSink,
        conn_id: ConnectionId,
        permit: SubscriptionPermit,
        sub_id: SubscriptionId<'static>,
        ext: Extensions,
    ) -> MethodResponse {
        let segments = match self.route(DEBUG_SUBSCRIBE, &params).await {
            Ok(Route::Live) => {
                let state = SubscriptionState {
                    conn_id,
                    id_provider: &FixedId(sub_id),
                    subscription_permit: permit,
                };
                return native(id, params, sink, state, ext).await;
            }
            // The router splits relays into non-empty segment lists.
            Ok(Route::Relay { segments }) => segments,
            route => {
                let err = route
                    .err()
                    .unwrap_or_else(|| internal("traceChain must relay"));
                let response = MethodResponse::subscription_error(id, err);
                if sink.send(response.to_json()).await.is_err() {
                    warn!("client left before its subscription error was sent");
                }
                return response.with_extensions(ext);
            }
        };

        let response = MethodResponse::subscription_response(
            id,
            ResponsePayload::success_borrowed(&sub_id),
            sink.max_response_size() as usize,
        );
        if sink.send(response.to_json()).await.is_err() {
            return response.with_extensions(ext);
        }
        let cancel = CancellationToken::new();
        let key = (conn_id, sub_id.clone());
        self.relays
            .lock()
            .expect("relay registry lock poisoned")
            .insert(key.clone(), cancel.clone());
        tokio::spawn(self.relay(segments, sink, sub_id, permit, cancel, key));
        response.with_extensions(ext)
    }

    /// Chains one upstream subscription per segment into the client's stream.
    async fn relay(
        self: Arc<Self>,
        segments: Vec<RelaySegment>,
        sink: MethodSink,
        sub_id: SubscriptionId<'static>,
        _permit: SubscriptionPermit,
        cancel: CancellationToken,
        key: (ConnectionId, SubscriptionId<'static>),
    ) {
        'segments: for segment in segments {
            let upstream = tokio::select! {
                () = cancel.cancelled() => break,
                () = sink.closed() => break,
                upstream = self.open(&segment) => upstream,
            };
            let mut upstream = match upstream {
                Ok(upstream) => upstream,
                Err(err) => {
                    warn!(era = segment.era, %err, "failed to open traceChain segment");
                    break;
                }
            };
            loop {
                let next = tokio::select! {
                    () = cancel.cancelled() => break 'segments,
                    () = sink.closed() => break 'segments,
                    next = upstream.next() => next,
                };
                // The upstream stopped early on a missing block or a tracing error, where the
                // single native stream would have stopped too.
                let Some(result) = next else { break 'segments };
                let item = serde_json::from_str::<TraceChainItem>(result.get()).ok();
                let is_end = item
                    .as_ref()
                    .is_some_and(|item| item.block == U256::from(segment.last_block));
                // Native skips empty blocks except the final end block.
                let skip = is_end
                    && !segment.is_last
                    && item.as_ref().is_some_and(|item| item.traces.is_empty());
                if !skip && !self.notify(&sink, &sub_id, &result).await {
                    break 'segments;
                }
                if is_end {
                    continue 'segments;
                }
            }
        }
        // Like native, keep the finished subscription until the client unsubscribes or leaves.
        tokio::select! {
            () = cancel.cancelled() => {}
            () = sink.closed() => {}
        }
        self.relays
            .lock()
            .expect("relay registry lock poisoned")
            .remove(&key);
    }

    async fn open(&self, segment: &RelaySegment) -> RpcResult<BoxStream<'static, Box<RawValue>>> {
        if segment.era != self.router.live_index() {
            return self
                .router
                .backend()
                .subscribe(segment.era, segment.params.clone())
                .await;
        }
        let subscription = self
            .natives
            .subscribe_unbounded(DEBUG_SUBSCRIBE, segment.params.clone())
            .await
            .map_err(|err| internal(err.to_string()))?;
        Ok(
            futures::stream::unfold(subscription, async |mut subscription| {
                match subscription.next::<Box<RawValue>>().await? {
                    Ok((result, _)) => Some((result, subscription)),
                    Err(err) => {
                        warn!(%err, "invalid native traceChain notification");
                        None
                    }
                }
            })
            .boxed(),
        )
    }

    /// Sends one notification to the client. Returns `false` once the client is gone.
    async fn notify(
        &self,
        sink: &MethodSink,
        subscription: &SubscriptionId<'static>,
        result: &RawValue,
    ) -> bool {
        let payload = SubscriptionPayload {
            subscription: subscription.clone(),
            result,
        };
        let notification = SubscriptionResponse::new(DEBUG_SUBSCRIPTION.into(), payload);
        match serde_json::value::to_raw_value(&notification) {
            Ok(json) => sink.send(json).await.is_ok(),
            Err(err) => {
                warn!(%err, "failed to serialize traceChain notification");
                false
            }
        }
    }

    fn unsubscribe(
        &self,
        native: &UnsubscribeFn,
        id: Id<'_>,
        params: Params<'_>,
        conn_id: ConnectionId,
        max: usize,
        ext: Extensions,
    ) -> MethodResponse {
        if let Ok(sub_id) = params.one::<SubscriptionId<'_>>()
            && let Some(cancel) = self
                .relays
                .lock()
                .expect("relay registry lock poisoned")
                .remove(&(conn_id, sub_id.into_owned()))
        {
            cancel.cancel();
            return MethodResponse::response(id, ResponsePayload::success(true), max)
                .with_extensions(ext);
        }
        native(id, params, conn_id, max, ext)
    }
}

/// The callback type of [`MethodCallback::Unsubscription`].
type UnsubscribeFn =
    dyn Fn(Id<'_>, Params<'_>, ConnectionId, usize, Extensions) -> MethodResponse + Send + Sync;

/// Invokes an original call callback.
async fn invoke(
    native: &MethodCallback,
    id: Id<'static>,
    params: Params<'static>,
    conn_id: ConnectionId,
    max: usize,
    ext: Extensions,
) -> MethodResponse {
    match native {
        MethodCallback::Sync(native) => native(id, params, max, ext),
        MethodCallback::Async(native) => native(id, params, conn_id, max, ext).await,
        MethodCallback::Subscription(_) | MethodCallback::Unsubscription(_) => {
            MethodResponse::error(id, internal("subscriptions are not method calls"))
                .with_extensions(ext)
        }
    }
}

fn respond(id: Id<'_>, result: RpcResult<Box<RawValue>>, max: usize) -> MethodResponse {
    match result {
        Ok(result) => MethodResponse::response(id, ResponsePayload::success(result), max),
        Err(err) => MethodResponse::error(id, err),
    }
}

/// Provides a subscription ID allocated before the callback awaited.
#[derive(Debug)]
struct FixedId(SubscriptionId<'static>);

impl IdProvider for FixedId {
    fn next_id(&self) -> SubscriptionId<'static> {
        self.0.clone()
    }
}

/// A JSON-RPC response envelope.
#[derive(Deserialize)]
struct Envelope {
    result: Option<Box<RawValue>>,
    error: Option<ErrorObjectOwned>,
}

/// The fields of a `traceChain` notification the relay inspects.
#[derive(Deserialize)]
struct TraceChainItem {
    block: U256,
    traces: Vec<IgnoredAny>,
}
