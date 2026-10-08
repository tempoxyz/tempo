//! Route historical execution while retaining the native transport registry and callbacks.

use std::sync::Arc;

use futures::{FutureExt as _, future::BoxFuture};
use jsonrpsee::{
    core::{
        RegisterMethodError, RpcResult,
        server::{IntoResponse as _, MethodCallback, MethodResponse, Methods, SubscriptionState},
        traits::IdProvider,
    },
    types::{ErrorObjectOwned, SubscriptionId},
};
use serde_json::Value;

use crate::routing::{Route, Router, RpcParams, is_execution_method};

type RouteCall =
    Arc<dyn Fn(&'static str, RpcParams) -> BoxFuture<'static, RpcResult<Route>> + Send + Sync>;
type ForwardCall = Arc<
    dyn Fn(usize, &'static str, RpcParams) -> BoxFuture<'static, RpcResult<Value>> + Send + Sync,
>;

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
    let route_router = router.clone();
    decorate_with(
        methods,
        live,
        Arc::new(move |method, params| {
            let router = route_router.clone();
            async move { router.route(method, params).await }.boxed()
        }),
        Arc::new(move |era, method, params| {
            let router = router.clone();
            async move { router.forward(era, method, params).await }.boxed()
        }),
    )
}

fn decorate_with(
    mut methods: Methods,
    live: usize,
    route: RouteCall,
    forward: ForwardCall,
) -> Result<Methods, RegisterMethodError> {
    let mut decorated = Methods::new();
    *decorated.extensions_mut() = methods.extensions().clone();
    for name in methods.method_names() {
        let native = methods.method(name).expect("registered method").clone();
        let callback = if name == "debug_subscribe"
            && let MethodCallback::Subscription(callback) = &native
        {
            let native = callback.clone();
            let route = route.clone();
            MethodCallback::Subscription(Arc::new(move |id, params, sink, state, extensions| {
                let native = native.clone();
                let route = route.clone();
                let id = id.into_owned();
                let params = params.into_owned();
                let provider = AllocatedId(state.id_provider.next_id());
                let connection = state.conn_id;
                let permit = state.subscription_permit;
                async move {
                    let target = match parse_params(&params) {
                        Ok(params) => route(name, params).await,
                        Err(error) => Err(error),
                    };
                    match target {
                        Ok(target) if target.era == live => {
                            native(
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
                            .await
                        }
                        target => {
                            let error = match target {
                                Err(error) => error,
                                Ok(_) => ErrorObjectOwned::owned(
                                    -32004,
                                    "historical chain tracing subscriptions are unsupported",
                                    None::<()>,
                                ),
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
                    }
                }
                .boxed()
            }))
        } else if is_execution_method(name)
            && matches!(native, MethodCallback::Sync(_) | MethodCallback::Async(_))
        {
            let route = route.clone();
            let forward = forward.clone();
            MethodCallback::Async(Arc::new(
                move |id, params, connection, max_response, extensions| {
                    let native = native.clone();
                    let route = route.clone();
                    let forward = forward.clone();
                    async move {
                        let target = match parse_params(&params) {
                            Ok(params) => route(name, params).await,
                            Err(error) => Err(error),
                        };
                        match target {
                            Ok(target) if target.era == live => match native {
                                MethodCallback::Sync(callback) => {
                                    callback(id, params, max_response, extensions)
                                }
                                MethodCallback::Async(callback) => {
                                    callback(id, params, connection, max_response, extensions).await
                                }
                                _ => unreachable!("only ordinary callbacks are decorated"),
                            },
                            target => {
                                let result = match target {
                                    Ok(target) => forward(target.era, name, target.params).await,
                                    Err(error) => Err(error),
                                };
                                MethodResponse::response(id, result.into_response(), max_response)
                                    .with_extensions(extensions)
                            }
                        }
                    }
                    .boxed()
                },
            ))
        } else {
            native
        };
        decorated.verify_and_insert(name, callback)?;
    }
    Ok(decorated)
}

fn parse_params(params: &jsonrpsee::types::Params<'_>) -> RpcResult<RpcParams> {
    params
        .as_str()
        .map(serde_json::from_str::<Value>)
        .transpose()
        .map(|value| RpcParams(value.unwrap_or(Value::Null)))
        .map_err(|error| ErrorObjectOwned::owned(-32602, error.to_string(), None::<()>))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::{
        Extensions, RpcModule,
        core::server::{BoundedSubscriptions, ConnectionId, MethodSink},
        types::{Id, Params, error::OVERSIZED_RESPONSE_CODE},
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn target(era: usize, params: Value) -> RouteCall {
        Arc::new(move |_, _| {
            let params = params.clone();
            async move {
                Ok(Route {
                    era,
                    params: RpcParams(params),
                })
            }
            .boxed()
        })
    }

    fn no_forward() -> ForwardCall {
        Arc::new(|_, _, _| async { panic!("unexpected historical forwarding") }.boxed())
    }

    async fn invoke(methods: &Methods, name: &str, limit: usize) -> MethodResponse {
        let mut extensions = Extensions::new();
        extensions.insert(42_u32);
        let params = Params::new(Some(r#"{"block":"latest"}"#));
        match methods.method(name).unwrap() {
            MethodCallback::Sync(callback) => callback(Id::Number(7), params, limit, extensions),
            MethodCallback::Async(callback) => {
                callback(Id::Number(7), params, ConnectionId(11), limit, extensions).await
            }
            _ => panic!("ordinary callback required"),
        }
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
        let decorated =
            decorate_with(originals.clone(), 1, target(0, json!([])), no_forward()).unwrap();
        let mut expected: Vec<_> = originals.method_names().collect();
        let mut actual: Vec<_> = decorated.method_names().collect();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
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
    async fn live_callbacks_keep_native_context_parameters_and_limits() {
        for synchronous in [true, false] {
            let native = if synchronous {
                MethodCallback::Sync(Arc::new(native_response))
            } else {
                MethodCallback::Async(Arc::new(
                    move |id, params, connection, limit, extensions| {
                        assert_eq!(connection, ConnectionId(11));
                        async move { native_response(id, params, limit, extensions) }.boxed()
                    },
                ))
            };
            let mut methods = Methods::new();
            methods.verify_and_insert("eth_call", native).unwrap();
            let decorated =
                decorate_with(methods, 1, target(1, json!(["pinned"])), no_forward()).unwrap();
            let response = invoke(&decorated, "eth_call", 256).await;
            assert_eq!(
                serde_json::from_str::<Value>(response.as_ref()).unwrap()["result"],
                "native"
            );
            assert_eq!(response.into_parts().2.get::<u32>(), Some(&42));
        }
    }

    #[tokio::test]
    async fn historical_forwarding_uses_pinned_params_and_public_response_limit() {
        let mut module = RpcModule::new(());
        module
            .register_method::<Value, _>("eth_call", |_, _, _| {
                panic!("native execution must not run")
            })
            .unwrap();
        let forward: ForwardCall = Arc::new(move |era, method, params| {
            assert_eq!(era, 0);
            assert_eq!(method, "eth_call");
            assert_eq!(params.0, json!(["pinned"]));
            async { Ok(json!("x".repeat(1024))) }.boxed()
        });
        let decorated =
            decorate_with(module.into(), 1, target(0, json!(["pinned"])), forward).unwrap();
        let response = invoke(&decorated, "eth_call", 256).await;
        assert_eq!(response.as_error_code(), Some(OVERSIZED_RESPONSE_CODE));
        let (value, _, extensions) = response.into_parts();
        assert_eq!(serde_json::from_str::<Value>(value.get()).unwrap()["id"], 7);
        assert_eq!(extensions.get::<u32>(), Some(&42));
    }

    #[tokio::test]
    async fn routing_errors_keep_error_data_and_request_context() {
        let mut module = RpcModule::new(());
        module
            .register_method::<Value, _>("eth_call", |_, _, _| {
                panic!("native execution must not run")
            })
            .unwrap();
        let route: RouteCall = Arc::new(|_, _| {
            async {
                Err(ErrorObjectOwned::owned(
                    -32004,
                    "cross-era request",
                    Some(json!({"era": 0})),
                ))
            }
            .boxed()
        });
        let decorated = decorate_with(module.into(), 1, route, no_forward()).unwrap();
        let response = invoke(&decorated, "eth_call", 256).await;
        let (value, _, extensions) = response.into_parts();
        let value: Value = serde_json::from_str(value.get()).unwrap();
        assert_eq!(value["id"], 7);
        assert_eq!(value["error"]["code"], -32004);
        assert_eq!(value["error"]["data"], json!({"era": 0}));
        assert_eq!(extensions.get::<u32>(), Some(&42));
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
                decorate_with(methods, 1, target(era, json!([])), no_forward()).unwrap();
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
            assert!(response.is_subscription());
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
