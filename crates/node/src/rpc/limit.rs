//! RPC middleware that caps how many calls of chosen methods run at once.
//!
//! [`ConcurrencyLimitLayer`] sits in reth's RPC middleware stack, in front of every module of the
//! HTTP and WS servers. A limited method gets a fixed number of slots shared by every connection
//! of those servers. A call that finds them all taken fails at once with the server-busy error
//! (`-32009`), which clients can retry, before it reaches the handler. reth does not run the
//! middleware on the IPC server, which is local.
//!
//! [`CallLimits`] holds the limits Tempo configures and builds the layer from them.

#[cfg(test)]
mod tests;

use std::{collections::HashMap, future::Future, num::NonZeroUsize, sync::Arc};

use jsonrpsee::{
    MethodResponse,
    core::middleware::{Batch, BatchEntry, BatchEntryErr, Notification},
    server::middleware::rpc::RpcServiceT,
    types::{ErrorObject, ErrorObjectOwned, Params, Request, error::SERVER_IS_BUSY_CODE},
};
use reth_metrics::{Metrics, metrics::Counter};
use serde_json::value::RawValue;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::Layer;

use crate::rpc::consensus::Query;

/// Method name of `consensus_getFinalization`.
const CONSENSUS_GET_FINALIZATION: &str = "consensus_getFinalization";

/// Default cap on `consensus_getFinalization` height lookups in flight at once.
///
/// Each one is a request to the marshal, so this bounds how many of them the marshal has queued.
/// A follower filling a gap keeps 20 outstanding.
pub const DEFAULT_MAX_CONCURRENT_LOOKUPS: NonZeroUsize = NonZeroUsize::new(64).unwrap();

/// Calls in flight that Tempo allows per limited RPC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallLimits {
    /// `consensus_getFinalization` height lookups. `"latest"` queries are answered from memory
    /// and are not limited.
    pub consensus_get_finalization: NonZeroUsize,
}

impl Default for CallLimits {
    fn default() -> Self {
        Self {
            consensus_get_finalization: DEFAULT_MAX_CONCURRENT_LOOKUPS,
        }
    }
}

impl CallLimits {
    /// Builds the middleware that enforces these limits.
    pub fn layer(&self) -> ConcurrencyLimitLayer {
        ConcurrencyLimitLayer::default().limit_when(
            CONSENSUS_GET_FINALIZATION,
            self.consensus_get_finalization,
            is_height_query,
        )
    }
}

/// Whether `consensus_getFinalization` params ask for a height, which goes to the marshal.
///
/// Reads params the way the handler does: positional (`["latest"]`) or named
/// (`{"query": "latest"}`). Params that don't decode count as a height query, so the limit is
/// never skipped by accident.
fn is_height_query(params: Option<&RawValue>) -> bool {
    /// Named params of `consensus_getFinalization`.
    #[derive(serde::Deserialize)]
    struct Named {
        query: Query,
    }

    let raw = params.map(RawValue::get);
    let params = Params::new(raw);
    let query = if raw.is_some_and(|raw| raw.trim_start().starts_with('{')) {
        params.parse::<Named>().map(|named| named.query)
    } else {
        params.one::<Query>()
    };
    !matches!(query, Ok(Query::Latest))
}

/// Decides from a call's params whether the method's limit applies to it.
pub type AppliesTo = fn(Option<&RawValue>) -> bool;

/// Middleware layer that caps concurrent calls per method.
///
/// Clones share their slots: reth clones the layer into every connection, and into both servers
/// when HTTP and WS listen on different ports, so a limit covers all of them together.
#[derive(Debug, Clone, Default)]
pub struct ConcurrencyLimitLayer {
    limits: Arc<HashMap<&'static str, MethodLimit>>,
}

impl ConcurrencyLimitLayer {
    /// Allows at most `max` calls of `method` at once.
    #[cfg(test)]
    fn limit(self, method: &'static str, max: NonZeroUsize) -> Self {
        self.limit_when(method, max, |_| true)
    }

    /// Allows at most `max` calls of `method` at once, counting only calls whose params
    /// `applies_to` accepts. Others pass without taking a slot.
    pub fn limit_when(
        mut self,
        method: &'static str,
        max: NonZeroUsize,
        applies_to: AppliesTo,
    ) -> Self {
        Arc::make_mut(&mut self.limits).insert(method, MethodLimit::new(method, max, applies_to));
        self
    }

    /// Slots of `method` not taken right now, if it is limited.
    #[cfg(test)]
    fn available(&self, method: &str) -> Option<usize> {
        self.limits
            .get(method)
            .map(|limit| limit.slots.available_permits())
    }
}

impl<S> Layer<S> for ConcurrencyLimitLayer {
    type Service = ConcurrencyLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConcurrencyLimit {
            limits: self.limits.clone(),
            inner,
        }
    }
}

/// The slots of one limited method.
#[derive(Debug, Clone)]
struct MethodLimit {
    slots: Arc<Semaphore>,
    applies_to: AppliesTo,
    metrics: ConcurrencyLimitMetrics,
}

impl MethodLimit {
    fn new(method: &'static str, max: NonZeroUsize, applies_to: AppliesTo) -> Self {
        Self {
            // A semaphore panics when created with more permits than it can hold.
            slots: Arc::new(Semaphore::new(max.get().min(Semaphore::MAX_PERMITS))),
            applies_to,
            metrics: ConcurrencyLimitMetrics::new_with_labels(&[("method", method)]),
        }
    }

    fn try_acquire(&self) -> Result<OwnedSemaphorePermit, ErrorObjectOwned> {
        self.slots.clone().try_acquire_owned().map_err(|_| {
            ErrorObject::owned(
                SERVER_IS_BUSY_CODE,
                "too many concurrent calls of this method, try again later",
                None::<()>,
            )
        })
    }
}

/// Metrics of one limited method.
#[derive(Metrics, Clone)]
#[metrics(scope = "tempo_rpc_concurrency_limit")]
struct ConcurrencyLimitMetrics {
    /// Calls rejected because every slot of the method was taken.
    rejected: Counter,
}

/// The [`RpcServiceT`] of [`ConcurrencyLimitLayer`], one per connection.
#[derive(Debug, Clone)]
pub struct ConcurrencyLimit<S> {
    limits: Arc<HashMap<&'static str, MethodLimit>>,
    inner: S,
}

impl<S> ConcurrencyLimit<S> {
    /// The limit that applies to a call of `method` with `params`, if any.
    fn limit_for(
        &self,
        method: &str,
        params: Option<&RawValue>,
    ) -> Option<(&'static str, &MethodLimit)> {
        let (method, limit) = self.limits.get_key_value(method)?;
        (limit.applies_to)(params).then_some((*method, limit))
    }
}

impl<S> RpcServiceT for ConcurrencyLimit<S>
where
    S: RpcServiceT + Send + Sync + Clone + 'static,
{
    fn call<'a>(&self, request: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let admitted = match self.limit_for(request.method_name(), request.params.as_deref()) {
            None => Ok(None),
            Some((_, limit)) => limit.try_acquire().map(Some).inspect_err(|_| {
                limit.metrics.rejected.increment(1);
            }),
        };
        let call = match admitted {
            // The slot is held until the call ends, or until its future is dropped because the
            // caller went away.
            Ok(slot) => Ok((slot, self.inner.call(request))),
            Err(err) => Err((request.id, err)),
        };
        async move {
            match call {
                Ok((_slot, call)) => call.await,
                Err((id, err)) => MethodResponse::error(id, err),
            }
        }
    }

    /// The server runs a batch's calls itself, one after another, without passing them through
    /// [`Self::call`]. So a batch holds one slot per limited method it calls, for as long as the
    /// batch runs, and its calls of a method whose slots are all taken fail with the busy error.
    fn batch<'a>(&self, mut batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let mut slots: HashMap<&'static str, Result<OwnedSemaphorePermit, ErrorObjectOwned>> =
            HashMap::new();
        for entry in batch.iter_mut() {
            let rejected = {
                let Ok(BatchEntry::Call(request)) = &*entry else {
                    continue;
                };
                let Some((method, limit)) =
                    self.limit_for(request.method_name(), request.params.as_deref())
                else {
                    continue;
                };
                match slots.entry(method).or_insert_with(|| limit.try_acquire()) {
                    Ok(_) => None,
                    Err(err) => {
                        limit.metrics.rejected.increment(1);
                        Some((request.id.clone(), err.clone()))
                    }
                }
            };
            if let Some((id, err)) = rejected {
                *entry = Err(BatchEntryErr::new(id, err));
            }
        }
        let batch = self.inner.batch(batch);
        async move {
            let response = batch.await;
            drop(slots);
            response
        }
    }

    fn notification<'a>(
        &self,
        notification: Notification<'a>,
    ) -> impl Future<Output = MethodResponse> + Send + 'a {
        self.inner.notification(notification)
    }
}
