use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use jsonrpsee::{
    RpcModule,
    core::{
        SubscriptionResult,
        client::{Error as ClientError, SubscriptionClientT},
    },
    server::{ServerBuilder, ServerConfig, ServerHandle},
    ws_client::WsClient,
};
use serde_json::{Value, json};

use crate::{
    handshake::EXECUTION_INFO_METHOD,
    routing::{Router, RpcParams, upstream_error},
};

/// Limits are enforced by jsonrpsee for individual responses and batches alike.
#[derive(Debug, Clone, clap::Args)]
pub struct ServerOptions {
    #[arg(long, default_value_t = Self::default().listen)]
    pub listen: SocketAddr,
    /// Public namespaces; private methods outside this list are never registered.
    #[arg(long, value_delimiter = ',', default_values_t = Self::default().api)]
    pub api: Vec<String>,
    #[arg(long, default_value_t = Self::default().max_request_bytes)]
    pub max_request_bytes: u32,
    #[arg(long, default_value_t = Self::default().max_response_bytes)]
    pub max_response_bytes: u32,
    #[arg(long, default_value_t = Self::default().max_connections)]
    pub max_connections: u32,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8545".parse().unwrap(),
            api: vec![
                "eth".into(),
                "net".into(),
                "web3".into(),
                "tempo".into(),
                "token".into(),
                "consensus".into(),
                "rpc".into(),
            ],
            max_request_bytes: 10 * 1024 * 1024,
            max_response_bytes: 25 * 1024 * 1024,
            max_connections: 100,
        }
    }
}

pub fn rpc_module(
    router: Arc<Router>,
    api: &[String],
    ws: Option<Arc<WsClient>>,
    max_response_bytes: u32,
) -> eyre::Result<RpcModule<Router>> {
    let mut module = RpcModule::from_arc(router.clone());
    let mut namespaces = BTreeMap::<String, String>::new();
    let mut names: Vec<_> = router
        .live_methods()
        .iter()
        .filter(|name| {
            !matches!(
                name.as_str(),
                EXECUTION_INFO_METHOD
                    | "rpc_modules"
                    | "eth_subscribe"
                    | "eth_unsubscribe"
                    | "debug_subscribe"
                    | "debug_unsubscribe"
                    | "consensus_subscribe"
                    | "consensus_unsubscribe"
            ) && name
                .split_once('_')
                .is_some_and(|(namespace, _)| api.iter().any(|allowed| allowed == namespace))
        })
        .cloned()
        .collect();
    names.sort_unstable();
    for method in names {
        if let Some((namespace, _)) = method.split_once('_') {
            namespaces.insert(namespace.into(), "1.0".into());
        }
        // The registry requires static method names. This bounded startup catalogue is allocated
        // once per server, never from public requests.
        let method: &'static str = Box::leak(method.into_boxed_str());
        module.register_async_method(method, move |params, router, _| async move {
            router.call(method, RpcParams::parse(&params)?).await
        })?;
    }
    if api.iter().any(|a| a == "rpc") {
        namespaces.insert("rpc".into(), "1.0".into());
        module.register_method("rpc_modules", move |_, _, _| json!(namespaces))?;
    }
    if let Some(ws) = ws {
        for (namespace, subscribe, notification, unsubscribe) in [
            (
                "eth",
                "eth_subscribe",
                "eth_subscription",
                "eth_unsubscribe",
            ),
            (
                "consensus",
                "consensus_subscribe",
                "consensus_event",
                "consensus_unsubscribe",
            ),
        ] {
            if !api.iter().any(|a| a == namespace)
                || (namespace == "consensus"
                    && !router.live_methods().contains("consensus_getLatest"))
            {
                continue;
            }
            let ws = ws.clone();
            module.register_subscription(subscribe, notification, unsubscribe, move |params, pending, _, _| {
            let ws = ws.clone();
            async move {
                let result = async {
                    ws.subscribe::<Value, _>(subscribe, RpcParams::parse(&params)?, unsubscribe).await.map_err(upstream_error)
                }.await;
                let mut subscription = match result {
                    Ok(subscription) => subscription,
                    Err(error) => { pending.reject(error).await; return Ok(()) as SubscriptionResult; }
                };
                let sink = pending.accept().await?;
                loop {
                    tokio::select! {
                        _ = sink.closed() => break,
                        item = subscription.next() => match item {
                            Some(Ok(value)) => {
                                let envelope = json!({"jsonrpc":"2.0", "method":sink.method_name(), "params":{"subscription":sink.subscription_id(), "result":value}});
                                if serde_json::to_vec(&envelope)?.len() > max_response_bytes as usize {
                                    return Err(ClientError::Custom("subscription notification exceeds response limit".into()).into());
                                }
                                sink.send(serde_json::value::to_raw_value(&value)?).await?;
                            },
                            Some(Err(error)) => return Err(ClientError::Custom(error.to_string()).into()),
                            None => break,
                        }
                    }
                }
                // Dropping an upstream subscription unregisters it from the live node.
                Ok(())
            }
        })?;
        }
    }
    Ok(module)
}

pub async fn start(
    router: Arc<Router>,
    options: ServerOptions,
    ws: Option<Arc<WsClient>>,
) -> eyre::Result<(SocketAddr, ServerHandle)> {
    let module = rpc_module(router, &options.api, ws, options.max_response_bytes)?;
    let config = ServerConfig::builder()
        .max_request_body_size(options.max_request_bytes)
        .max_response_body_size(options.max_response_bytes)
        .max_connections(options.max_connections)
        .build();
    let server = ServerBuilder::with_config(config)
        .build(options.listen)
        .await?;
    let address = server.local_addr()?;
    Ok((address, server.start(module)))
}
