//! Route historical execution while retaining the native transport registry and callbacks.

use std::sync::Arc;

use futures::FutureExt as _;
use jsonrpsee::{
    core::{
        RegisterMethodError,
        server::{IntoResponse as _, MethodCallback, MethodResponse, Methods, SubscriptionState},
        traits::IdProvider,
    },
    types::SubscriptionId,
};
use serde_json::Value;

use crate::routing::{Router, RpcParams, is_execution_method, unsupported};

/// The native callback consumes its provider synchronously. Allocate from that provider before
/// awaiting the guard, then give the generated callback the same subscription ID afterwards.
#[derive(Debug)]
struct AllocatedId(SubscriptionId<'static>);

impl IdProvider for AllocatedId {
    fn next_id(&self) -> SubscriptionId<'static> {
        self.0.clone()
    }
}

/// Decorate only execution methods already present in a native transport's registry.
///
/// Live execution invokes the original callback with its original parameters, connection,
/// extensions, and response limit. Stored-data methods and live subscriptions remain intact.
/// Chain tracing subscriptions are guarded because they can reexecute historical blocks.
/// A caller can apply this independently to HTTP, WebSocket, and IPC registries without changing
/// their namespace selection, authentication, transport settings, or batching behavior.
pub fn decorate(methods: Methods, router: Arc<Router>) -> Result<Methods, RegisterMethodError> {
    let live = router.live_index();
    let mut registry = jsonrpsee::RpcModule::new(());
    *registry = methods;
    let names: Vec<_> = registry
        .method_names()
        .filter(|name| *name == "debug_subscribe" || is_execution_method(name))
        .collect();
    for name in names {
        let native = registry.remove_method(name).expect("registered method");
        let callback = if name == "debug_subscribe"
            && let MethodCallback::Subscription(callback) = &native
        {
            let native = callback.clone();
            let router = router.clone();
            MethodCallback::Subscription(Arc::new(move |id, params, sink, state, extensions| {
                let native = native.clone();
                let router = router.clone();
                let id = id.into_owned();
                let params = params.into_owned();
                let provider = AllocatedId(state.id_provider.next_id());
                let connection = state.conn_id;
                let permit = state.subscription_permit;
                async move {
                    let target = match RpcParams::parse(&params) {
                        Ok(params) => router.route(name, params).await,
                        Err(error) => Err(error),
                    };
                    let error = match target {
                        Ok(target) if target.era == live => {
                            return native(
                                id,
                                params,
                                sink,
                                SubscriptionState {
                                    conn_id: connection,
                                    id_provider: &provider,
                                    subscription_permit: permit,
                                },
                                extensions,
                            )
                            .await;
                        }
                        Err(error) => error,
                        Ok(_) => {
                            unsupported("historical chain tracing subscriptions are unsupported")
                        }
                    };
                    let response = MethodResponse::subscription_response(
                        id,
                        Err::<Value, _>(error).into_response(),
                        sink.max_response_size() as usize,
                    )
                    .with_extensions(extensions);
                    // Subscription callbacks deliver their own response through the sink.
                    let _ = sink.send(response.to_json()).await;
                    response
                }
                .boxed()
            }))
        } else if is_execution_method(name)
            && matches!(native, MethodCallback::Sync(_) | MethodCallback::Async(_))
        {
            let router = router.clone();
            MethodCallback::Async(Arc::new(
                move |id, params, connection, max_response, extensions| {
                    let native = native.clone();
                    let router = router.clone();
                    async move {
                        let target = match RpcParams::parse(&params) {
                            Ok(params) => router.route(name, params).await,
                            Err(error) => Err(error),
                        };
                        let result = match target {
                            Ok(target) if target.era == live => {
                                return match native {
                                    MethodCallback::Sync(callback) => {
                                        callback(id, params, max_response, extensions)
                                    }
                                    MethodCallback::Async(callback) => {
                                        callback(id, params, connection, max_response, extensions)
                                            .await
                                    }
                                    _ => unreachable!("only ordinary callbacks are decorated"),
                                };
                            }
                            Ok(target) => {
                                router
                                    .backend
                                    .forward(target.era, name, target.params)
                                    .await
                            }
                            Err(error) => Err(error),
                        };
                        MethodResponse::response(id, result.into_response(), max_response)
                            .with_extensions(extensions)
                    }
                    .boxed()
                },
            ))
        } else {
            native
        };
        registry.verify_and_insert(name, callback)?;
    }
    Ok(registry.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{Backend, BlockMetadata};
    use futures::future::BoxFuture;
    use jsonrpsee::{
        Extensions, RpcModule,
        core::{
            RpcResult,
            server::{BoundedSubscriptions, ConnectionId, MethodSink},
        },
        types::{ErrorObjectOwned, Id, Params, error::OVERSIZED_RESPONSE_CODE},
    };
    use serde_json::{json, value::RawValue};
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicBool, Ordering},
    };

    struct FakeBackend {
        timestamp: RpcResult<u64>,
        response: Option<RpcResult<Box<RawValue>>>,
    }

    impl Backend for FakeBackend {
        fn block<'a>(&'a self, selector: &'a Value) -> BoxFuture<'a, RpcResult<BlockMetadata>> {
            async move {
                let number = if selector == "0x1" { 1 } else { 2 };
                Ok(BlockMetadata {
                    number,
                    hash: format!("0x{number:064x}").parse().unwrap(),
                    timestamp: self.timestamp.clone()?,
                })
            }
            .boxed()
        }

        fn transaction_timestamp<'a>(
            &'a self,
            _: &'a Value,
        ) -> BoxFuture<'a, RpcResult<Option<u64>>> {
            async { unreachable!("no transaction lookups in this fixture") }.boxed()
        }

        fn forward<'a>(
            &'a self,
            era: usize,
            method: &'a str,
            params: RpcParams,
        ) -> BoxFuture<'a, RpcResult<Box<RawValue>>> {
            async move {
                assert_eq!(era, 0);
                assert_eq!(method, "eth_call");
                assert_eq!(
                    params.0,
                    json!({"block":"latest", "block_number":{"blockHash":format!("0x{:064x}", 2)}})
                );
                self.response
                    .clone()
                    .expect("unexpected historical forwarding")
            }
            .boxed()
        }
    }

    fn router(
        timestamp: RpcResult<u64>,
        response: Option<RpcResult<Box<RawValue>>>,
    ) -> Arc<Router> {
        let schedule = serde_json::from_value(json!({
            "chain_id":"0x1", "genesis_hash":format!("0x{}", "00".repeat(32)),
            "eras":[
                {"name":"old", "start_timestamp":0, "binary":"/unused/frozen"},
                {"name":"live", "start_timestamp":100}
            ]
        }))
        .unwrap();
        let backend = Arc::new(FakeBackend {
            timestamp,
            response,
        });
        Arc::new(Router::new(schedule, backend).unwrap())
    }

    async fn invoke(methods: &Methods) -> MethodResponse {
        let mut extensions = Extensions::new();
        extensions.insert(42_u32);
        let params = Params::new(Some(r#"{"block":"latest"}"#));
        let MethodCallback::Async(callback) = methods.method("eth_call").unwrap() else {
            panic!("execution callback must be decorated");
        };
        callback(Id::Number(7), params, ConnectionId(11), 256, extensions).await
    }

    fn native_response(
        id: Id<'_>,
        params: Params<'_>,
        limit: usize,
        extensions: Extensions,
    ) -> MethodResponse {
        assert_eq!(id, Id::Number(7));
        assert_eq!(params.as_str(), Some(r#"{"block":"latest"}"#));
        assert_eq!(limit, 256);
        assert_eq!(extensions.get::<u32>(), Some(&42));
        MethodResponse::response(
            id,
            Ok::<_, ErrorObjectOwned>("native").into_response(),
            limit,
        )
        .with_extensions(extensions)
    }

    #[tokio::test]
    async fn preserves_registry_and_subscription_callbacks() {
        let mut module = RpcModule::new(());
        module
            .register_method("eth_blockNumber", |_, _, _| "0x1")
            .unwrap();
        module
            .register_subscription(
                "eth_subscribe",
                "eth_subscription",
                "eth_unsubscribe",
                |_, _, _, _| async { Ok(()) as jsonrpsee::core::SubscriptionResult },
            )
            .unwrap();
        let originals: Methods = module.into();
        let decorated = decorate(originals.clone(), router(Ok(50), None)).unwrap();
        assert_eq!(
            decorated.method_names().collect::<BTreeSet<_>>(),
            originals.method_names().collect()
        );
        match (
            originals.method("eth_subscribe"),
            decorated.method("eth_subscribe"),
        ) {
            (
                Some(MethodCallback::Subscription(original)),
                Some(MethodCallback::Subscription(callback)),
            ) => {
                assert!(Arc::ptr_eq(original, callback));
            }
            _ => panic!("subscription callback changed"),
        }
        assert_eq!(
            decorated
                .call::<_, String>("eth_blockNumber", RpcParams(json!([])))
                .await
                .unwrap(),
            "0x1"
        );
    }

    #[tokio::test]
    async fn execution_preserves_native_context_errors_and_response_limits() {
        let error = ErrorObjectOwned::owned(-32004, "cross-era request", Some(json!({"era":0})));
        let raw = RawValue::from_string(r#"{"n":1.00e+3,"escaped":"\u0061"}"#.into()).unwrap();
        for native in [
            MethodCallback::Sync(Arc::new(native_response)),
            MethodCallback::Async(Arc::new(|id, params, connection, limit, extensions| {
                assert_eq!(connection, ConnectionId(11));
                async move { native_response(id, params, limit, extensions) }.boxed()
            })),
        ] {
            for (timestamp, result, code) in [
                (Ok(110), None, None),
                (Ok(50), Some(Ok(raw.clone())), None),
                (
                    Ok(50),
                    Some(Ok(
                        serde_json::value::to_raw_value(&"x".repeat(1024)).unwrap()
                    )),
                    Some(OVERSIZED_RESPONSE_CODE),
                ),
                (Ok(50), Some(Err(error.clone())), Some(-32004)),
                (Err(error.clone()), None, Some(-32004)),
            ] {
                let historical = timestamp == Ok(50);
                let mut methods = Methods::new();
                methods
                    .verify_and_insert("eth_call", native.clone())
                    .unwrap();
                let decorated = decorate(methods, router(timestamp, result)).unwrap();
                let response = invoke(&decorated).await;
                assert_eq!(response.as_error_code(), code);
                let (value, _, extensions) = response.into_parts();
                if code.is_none() && historical {
                    assert!(
                        value.get().contains(raw.get()),
                        "historical result was reserialized"
                    );
                }
                let value: Value = serde_json::from_str(value.get()).unwrap();
                assert_eq!(value["id"], 7);
                assert_eq!(extensions.get::<u32>(), Some(&42));
                match code {
                    None if !historical => assert_eq!(value["result"], "native"),
                    Some(-32004) => {
                        assert_eq!(value["error"], serde_json::to_value(&error).unwrap())
                    }
                    _ => (),
                }
            }
        }
    }

    #[tokio::test]
    async fn chain_trace_subscriptions_delegate_live_and_reject_history() {
        for era in [0, 1] {
            let called = Arc::new(AtomicBool::new(false));
            let observed = called.clone();
            let mut methods = Methods::new();
            methods
                .verify_and_insert(
                    "debug_subscribe",
                    MethodCallback::Subscription(Arc::new(
                        move |id, params, sink, state, extensions| {
                            observed.store(true, Ordering::SeqCst);
                            assert_eq!(id, Id::Number(7));
                            assert_eq!(params.as_str(), Some(r#"["traceChain","0x1","latest"]"#));
                            assert_eq!(state.conn_id, ConnectionId(11));
                            assert_eq!(state.id_provider.next_id(), SubscriptionId::Num(99));
                            assert_eq!(extensions.get::<u32>(), Some(&42));
                            let id = id.into_owned();
                            async move {
                                let response = MethodResponse::subscription_response(
                                    id,
                                    Ok::<_, ErrorObjectOwned>(99_u64).into_response(),
                                    sink.max_response_size() as usize,
                                )
                                .with_extensions(extensions);
                                sink.send(response.to_json()).await.unwrap();
                                response
                            }
                            .boxed()
                        },
                    )),
                )
                .unwrap();
            let decorated =
                decorate(methods, router(Ok(if era == 0 { 50 } else { 110 }), None)).unwrap();
            let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
            let mut extensions = Extensions::new();
            extensions.insert(42_u32);
            let subscriptions = BoundedSubscriptions::new(1);
            let provider = AllocatedId(SubscriptionId::Num(99));
            let MethodCallback::Subscription(callback) =
                decorated.method("debug_subscribe").unwrap()
            else {
                panic!("subscription callback must remain a subscription");
            };
            let response = callback(
                Id::Number(7),
                Params::new(Some(r#"["traceChain","0x1","latest"]"#)),
                MethodSink::new_with_limit(sender, 256),
                SubscriptionState {
                    conn_id: ConnectionId(11),
                    id_provider: &provider,
                    subscription_permit: subscriptions.acquire().unwrap(),
                },
                extensions,
            )
            .await;
            assert_eq!(called.load(Ordering::SeqCst), era == 1);
            assert_eq!(response.as_error_code(), (era == 0).then_some(-32004));
            let delivered = receiver.recv().await.unwrap();
            assert_eq!(delivered.get(), response.as_ref());
            let value: Value = serde_json::from_str(delivered.get()).unwrap();
            assert_eq!(value["id"], 7);
            assert_eq!(response.into_parts().2.get::<u32>(), Some(&42));
            assert!(subscriptions.acquire().is_some());
        }
    }
}
