//! Shared websocket subscription types for the redacted zone RPC.

use std::{future::Future, pin::Pin};

use futures::Stream;
use serde_json::value::RawValue;

use crate::types::JsonRpcError;

/// A boxed stream of serialized websocket subscription items.
pub type WsSubscriptionStream =
    Pin<Box<dyn Stream<Item = Result<Box<RawValue>, JsonRpcError>> + Send + 'static>>;

/// A boxed future that resolves to a websocket subscription stream.
pub type BoxWsSubscriptionFut<'a> =
    Pin<Box<dyn Future<Output = Result<WsSubscriptionStream, JsonRpcError>> + Send + 'a>>;
