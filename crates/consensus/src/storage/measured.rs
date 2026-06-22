//! Tempo-side metrics wrappers for certificate stores passed to Commonware marshal.

use std::sync::Arc;

use commonware_consensus::{
    marshal::store::Certificates, simplex::types::Finalization, types::Height,
};
use commonware_runtime::{
    Clock, Metrics as RuntimeMetrics,
    telemetry::metrics::histogram::{self, Timed},
};
use commonware_storage::archive::Identifier;
use prometheus_client::metrics::histogram::Histogram;

/// Duration histograms for one marshal store.
struct OperationDurations<TContext>
where
    TContext: Clock,
{
    put: Timed<TContext>,
    sync: Timed<TContext>,
    prune: Timed<TContext>,
}

impl<TContext> OperationDurations<TContext>
where
    TContext: Clock + RuntimeMetrics,
{
    fn init(context: TContext, store: &str) -> Self
    where
        TContext: RuntimeMetrics,
    {
        let put = Histogram::new(histogram::Buckets::LOCAL);
        context.register(
            "put_duration",
            format!("Histogram of {store} put calls, in seconds"),
            put.clone(),
        );

        let sync = Histogram::new(histogram::Buckets::LOCAL);
        context.register(
            "sync_duration",
            format!("Histogram of {store} sync calls, in seconds"),
            sync.clone(),
        );

        let prune = Histogram::new(histogram::Buckets::LOCAL);
        context.register(
            "prune_duration",
            format!("Histogram of {store} prune calls, in seconds"),
            prune.clone(),
        );

        let clock = Arc::new(context);
        Self {
            put: Timed::new(put, Arc::clone(&clock)),
            sync: Timed::new(sync, Arc::clone(&clock)),
            prune: Timed::new(prune, clock),
        }
    }
}

/// Measured wrapper for marshal finalization certificate stores.
pub(crate) struct MeasuredCertificates<TContext, TStore>
where
    TContext: Clock,
{
    inner: TStore,
    durations: OperationDurations<TContext>,
}

impl<TContext, TStore> MeasuredCertificates<TContext, TStore>
where
    TContext: Clock,
{
    /// Wrap a certificate store and register per-operation duration histograms.
    pub(crate) fn new(inner: TStore, context: TContext, store: &str) -> Self
    where
        TContext: RuntimeMetrics,
    {
        Self {
            inner,
            durations: OperationDurations::init(context, store),
        }
    }
}

impl<TContext, TStore> Certificates for MeasuredCertificates<TContext, TStore>
where
    TContext: Clock + Send + Sync + 'static,
    TStore: Certificates,
{
    type BlockDigest = TStore::BlockDigest;
    type Commitment = TStore::Commitment;
    type Scheme = TStore::Scheme;
    type Error = TStore::Error;

    async fn put(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        finalization: Finalization<Self::Scheme, Self::Commitment>,
    ) -> Result<(), Self::Error> {
        let mut timer = self.durations.put.timer();
        let result = self.inner.put(height, digest, finalization).await;
        timer.observe();
        result
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        let mut timer = self.durations.sync.timer();
        let result = self.inner.sync().await;
        timer.observe();
        result
    }

    async fn get(
        &self,
        id: Identifier<'_, Self::BlockDigest>,
    ) -> Result<Option<Finalization<Self::Scheme, Self::Commitment>>, Self::Error> {
        self.inner.get(id).await
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        let mut timer = self.durations.prune.timer();
        let result = self.inner.prune(min).await;
        timer.observe();
        result
    }

    fn last_index(&self) -> Option<Height> {
        self.inner.last_index()
    }

    fn ranges_from(&self, from: Height) -> impl Iterator<Item = (Height, Height)> {
        self.inner.ranges_from(from)
    }
}
