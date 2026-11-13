//! L1 RPC transports whose WebSocket handshakes and requests have deadlines.
//!
//! Alloy waits on a WebSocket handshake, and on each request, without a deadline. When an L1
//! connection is left half-open, a (re)connect can hang forever, and requests queued behind it
//! never return, so retry loops that run after an error never run.

use std::{
    str::FromStr,
    task::{Context, Poll},
    time::Duration,
};

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_pubsub::{ConnectionHandle, PubSubConnect};
use alloy_rpc_client::{BuiltInConnectionString, ConnectionConfig, WebSocketConfig, WsConnect};
use alloy_transport::{
    BoxTransport, Transport, TransportConnect, TransportError, TransportErrorKind, TransportFut,
    TransportResult,
};
use tower::Service;
use zone_primitives::constants::MAX_WS_FRAME_AND_MESSAGE_SIZE;

/// Deadline for one WebSocket connect attempt (TCP, TLS and the WebSocket handshake). A failed
/// attempt is retried by alloy's reconnect loop.
const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Interval between WebSocket keepalive pings. Alloy closes the connection when a ping goes
/// unanswered for one interval, but only pings after an interval with no request sent.
const WS_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Deadline for one L1 RPC request attempt.
///
/// It exceeds two keepalive intervals, so that a request retried after this deadline does not
/// keep resetting the keepalive timer before a half-open WebSocket is detected and reconnected.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const _: () = assert!(REQUEST_TIMEOUT.as_secs() > 2 * WS_KEEPALIVE_INTERVAL.as_secs());

/// Connection details for an L1 RPC endpoint, used with `connect_with` on an alloy
/// `ClientBuilder` or `ProviderBuilder`.
///
/// The transport is chosen from the URL scheme, like alloy's `connect_with_config`. Unlike it,
/// each WebSocket connect and reconnect attempt fails after [`WS_CONNECT_TIMEOUT`], and each
/// request fails with a transport error after [`REQUEST_TIMEOUT`] instead of waiting forever.
#[derive(Debug, Clone)]
pub struct L1Connect {
    url: String,
    config: ConnectionConfig,
}

impl L1Connect {
    /// Creates connection details for `url` with `config`.
    pub fn new(url: impl Into<String>, config: ConnectionConfig) -> Self {
        Self {
            url: url.into(),
            config,
        }
    }
}

impl TransportConnect for L1Connect {
    fn is_local(&self) -> bool {
        BuiltInConnectionString::from_str(&self.url).is_ok_and(|connect| connect.is_local())
    }

    async fn get_transport(&self) -> TransportResult<BoxTransport> {
        let transport = match BuiltInConnectionString::from_str(&self.url)? {
            BuiltInConnectionString::Ws(url, url_auth) => {
                let mut ws = WsConnect::new(url).with_keepalive_interval(WS_KEEPALIVE_INTERVAL);
                if let Some(auth) = self.config.auth.clone().or(url_auth) {
                    ws = ws.with_auth(auth);
                }
                if let Some(ws_config) = self.config.ws_config {
                    ws = ws.with_config(ws_config);
                }
                if let Some(max_retries) = self.config.max_retries {
                    ws = ws.with_max_retries(max_retries);
                }
                if let Some(retry_interval) = self.config.retry_interval {
                    ws = ws.with_retry_interval(retry_interval);
                }
                TimeoutConnect(ws).into_service().await?.boxed()
            }
            connect => connect.connect_boxed_with(self.config.clone()).await?,
        };
        Ok(RequestTimeout(transport).boxed())
    }
}

/// A [`PubSubConnect`] whose connect and reconnect attempts fail after [`WS_CONNECT_TIMEOUT`].
#[derive(Debug)]
struct TimeoutConnect<TConnect>(TConnect);

impl<TConnect: PubSubConnect> PubSubConnect for TimeoutConnect<TConnect> {
    fn is_local(&self) -> bool {
        self.0.is_local()
    }

    // Alloy's reconnect loop calls `try_reconnect`, which defaults to this.
    async fn connect(&self) -> TransportResult<ConnectionHandle> {
        tokio::time::timeout(WS_CONNECT_TIMEOUT, self.0.connect())
            .await
            .map_err(|_| {
                TransportErrorKind::custom_str(&format!(
                    "L1 WebSocket connect timed out after {WS_CONNECT_TIMEOUT:?}"
                ))
            })?
    }
}

/// A transport whose requests fail after [`REQUEST_TIMEOUT`].
#[derive(Debug, Clone)]
struct RequestTimeout(BoxTransport);

impl Service<RequestPacket> for RequestTimeout {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let response = self.0.call(request);
        Box::pin(async move {
            tokio::time::timeout(REQUEST_TIMEOUT, response)
                .await
                .map_err(|_| {
                    TransportErrorKind::custom_str(&format!(
                        "L1 RPC request timed out after {REQUEST_TIMEOUT:?}"
                    ))
                })?
        })
    }
}

pub(crate) fn rpc_connection_config(retry_connection_interval: Duration) -> ConnectionConfig {
    ConnectionConfig::new()
        .with_max_retries(u32::MAX)
        .with_retry_interval(retry_connection_interval)
        .with_ws_config(
            WebSocketConfig::default()
                .max_frame_size(Some(MAX_WS_FRAME_AND_MESSAGE_SIZE))
                .max_message_size(Some(MAX_WS_FRAME_AND_MESSAGE_SIZE)),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_provider::{Provider, ProviderBuilder};
    use tempo_alloy::TempoNetwork;
    use tokio::{io::AsyncReadExt, net::TcpListener};

    /// Accepts TCP connections and reads from them without ever answering, like a paused peer.
    async fn silent_endpoint() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while socket.read(&mut buf).await.is_ok_and(|read| read > 0) {}
                });
            }
        });
        addr
    }

    #[tokio::test(start_paused = true)]
    async fn ws_connect_times_out_on_unanswered_handshake() {
        let addr = silent_endpoint().await;
        let connect = L1Connect::new(
            format!("ws://{addr}"),
            rpc_connection_config(Duration::ZERO),
        );

        let start = tokio::time::Instant::now();
        let error = connect
            .get_transport()
            .await
            .expect_err("an unanswered handshake must fail");
        assert_eq!(start.elapsed(), WS_CONNECT_TIMEOUT);
        assert_eq!(
            error.to_string(),
            "L1 WebSocket connect timed out after 10s"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn request_times_out_on_unanswered_request() {
        let addr = silent_endpoint().await;
        let connect = L1Connect::new(
            format!("http://{addr}"),
            rpc_connection_config(Duration::ZERO),
        );
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_with(&connect)
            .await
            .expect("HTTP transport construction is lazy");

        let start = tokio::time::Instant::now();
        let error = provider
            .get_chain_id()
            .await
            .expect_err("an unanswered request must fail");
        assert_eq!(start.elapsed(), REQUEST_TIMEOUT);
        assert_eq!(error.to_string(), "L1 RPC request timed out after 30s");
    }
}
