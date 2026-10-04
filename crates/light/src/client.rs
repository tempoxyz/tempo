//! Checkpoint-backed, latest-only native TIP-20 client over untrusted HTTP upstreams.

use crate::{
    HeadTracker, Snapshot, VerifiedCache,
    checkpoint::{Checkpoint, Store, Transition},
    config::{Limits, Network},
    head, proof,
    token::{self, ReadRequest},
    transport::{self, Upstreams},
};
use alloy_consensus::BlockHeader as _;
use alloy_primitives::{B256, U256};
use serde::Serialize;
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, watch};
use url::Url;

#[derive(Clone)]
pub struct Client(Arc<Inner>);
struct Inner {
    network: Network,
    limits: Limits,
    upstreams: Upstreams,
    store: Arc<Store>,
    state: Mutex<State>,
    cache: Mutex<VerifiedCache>,
    refresh: Arc<Mutex<()>>,
    permits: Arc<Semaphore>,
    in_flight: Mutex<HashMap<QueryKey, watch::Receiver<Option<ReadOutcome>>>>,
    integrity_failures: AtomicU64,
}
struct State {
    tracker: HeadTracker,
    transition: Option<Transition>,
    failure: Option<FailureKind>,
    persistence_paused: bool,
}
type QueryKey = (B256, Vec<ReadRequest>);
type ReadOutcome = Result<Arc<VerifiedReads>, Arc<Error>>;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedBlock {
    pub hash: B256,
    pub height: u64,
    pub timestamp_millis: u64,
}
impl From<&Snapshot> for VerifiedBlock {
    fn from(snapshot: &Snapshot) -> Self {
        Self {
            hash: snapshot.evidence().digest,
            height: snapshot.header().number(),
            timestamp_millis: snapshot.header().timestamp_millis(),
        }
    }
}

/// Values are in request order, all at the single reported authenticated block.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedReads {
    block: VerifiedBlock,
    values: Vec<U256>,
}

impl VerifiedReads {
    /// Immutable authenticated block metadata for this operation.
    pub const fn block(&self) -> &VerifiedBlock {
        &self.block
    }

    /// Authenticated native token values in request order. Only the client can construct results.
    pub fn values(&self) -> &[U256] {
        &self.values
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FailureKind {
    Availability,
    Capability,
    Integrity,
    Persistence,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub head: Option<VerifiedBlock>,
    pub head_age_millis: Option<u64>,
    pub head_in_future: bool,
    pub last_failure: Option<FailureKind>,
    pub durable: bool,
    pub integrity_failures: u64,
    pub account_cache_entries: usize,
    pub slot_cache_entries: usize,
}

impl Client {
    /// Opening storage validates format, configured-network binding, retained transition evidence,
    /// and the retained head certificate. Corruption never silently changes the trust anchor.
    pub fn open(
        network: Network,
        urls: Vec<Url>,
        datadir: impl AsRef<Path>,
        limits: Limits,
    ) -> Result<Self, Error> {
        network.validate().map_err(Error::Configuration)?;
        limits.validate().map_err(Error::Configuration)?;
        let upstreams = Upstreams::new(urls, &limits)?;
        let store = Arc::new(Store::open(datadir)?);
        let (tracker, transition) = match store.load(&network)? {
            Some(checkpoint) => (checkpoint.restore()?, checkpoint.transition),
            None => (
                HeadTracker::new(network.anchor.clone(), network.epoch_length),
                None,
            ),
        };
        let cache = VerifiedCache::new(limits.account_cache, limits.slot_cache);
        let permits = Arc::new(Semaphore::new(limits.read_concurrency));
        Ok(Self(Arc::new(Inner {
            network,
            limits,
            upstreams,
            store,
            state: Mutex::new(State {
                tracker,
                transition,
                failure: None,
                persistence_paused: false,
            }),
            cache: Mutex::new(cache),
            refresh: Arc::new(Mutex::new(())),
            permits,
            in_flight: Mutex::new(HashMap::new()),
            integrity_failures: AtomicU64::new(0),
        })))
    }

    /// Discover and authenticate one selected head. No full blocks or contiguous header backfill.
    /// Key changes and head advancement are staged together, persisted, then atomically published.
    pub async fn refresh(&self) -> Result<(), Error> {
        let serial = self
            .0
            .refresh
            .clone()
            .try_lock_owned()
            .map_err(|_| Error::Busy)?;
        let client = self.clone();
        tokio::spawn(async move {
            let _serial = serial;
            client.refresh_owned().await
        })
        .await
        .map_err(|_| Error::Worker)?
    }

    // Runs in an owned task so cancelling a caller cannot release serialization while a critical
    // filesystem publication is still running. The task always records its persistence outcome.
    async fn refresh_owned(&self) -> Result<(), Error> {
        let result = async {
            let staged = tokio::time::timeout(self.0.limits.read_timeout, self.refresh_inner())
                .await
                .map_err(|_| Error::Deadline)??;
            if let Some((tracker, transition)) = staged {
                let snapshot = tracker.snapshot().ok_or(Error::Worker)?;
                let checkpoint = Checkpoint {
                    version: 1,
                    network: self.0.network.clone(),
                    identity: tracker.identity().clone(),
                    head: snapshot.evidence().clone(),
                    transition: transition.clone(),
                };
                let store = self.0.store.clone();
                // No timeout/cancellation of a critical rename+sync once publication starts.
                tokio::task::spawn_blocking(move || store.save(&checkpoint))
                    .await
                    .map_err(|_| Error::Worker)??;
                let mut state = self.0.state.lock().await;
                state.tracker = tracker;
                state.transition = transition;
                state.persistence_paused = false;
                state.failure = None;
            } else {
                let mut state = self.0.state.lock().await;
                if state.persistence_paused {
                    return Err(Error::PersistencePaused);
                }
                state.failure = None;
            }
            Ok(())
        }
        .await;
        if let Err(error) = &result {
            let mut state = self.0.state.lock().await;
            state.failure = Some(error.kind());
            if matches!(error, Error::Checkpoint(_)) {
                state.persistence_paused = true;
            }
        }
        result
    }

    async fn refresh_inner(&self) -> Result<Option<(HeadTracker, Option<Transition>)>, Error> {
        let mut last = Error::NoHead;
        let mut integrity = None;
        let mut retained_confirmed = false;
        for provider in 0..self.0.upstreams.count() {
            let evidence = match self.0.upstreams.finalized_header(provider, None).await {
                Ok(evidence) => evidence,
                Err(error) => {
                    last = error.into();
                    continue;
                }
            };
            let (mut tracker, mut transition) = {
                let state = self.0.state.lock().await;
                if let Some(head) = state.tracker.snapshot() {
                    if evidence.header.number() < head.header().number() {
                        continue;
                    }
                    if evidence == *head.evidence() && !state.persistence_paused {
                        // Still poll other providers: an old valid certificate is not global freshness.
                        retained_confirmed = true;
                        continue;
                    }
                }
                (state.tracker.clone(), state.transition.clone())
            };
            let mut rng: rand::rngs::StdRng = rand::make_rng();
            let mut accepted = tracker.accept(&mut rng, evidence.clone());
            let mut remaining = self.0.limits.max_transition_search;
            while matches!(&accepted, Err(head::Error::Verification(error)) if error.is_signature_mismatch())
                && remaining > 0
            {
                let mut epoch = evidence.epoch;
                let mut installed = false;
                while epoch > tracker.identity().from_epoch && remaining > 0 {
                    remaining -= 1;
                    epoch -= 1;
                    let Some(height) = epoch
                        .checked_add(1)
                        .and_then(|epoch| epoch.checked_mul(self.0.network.epoch_length.get()))
                        .and_then(|height| height.checked_sub(1))
                    else {
                        break;
                    };
                    let boundary = match self
                        .0
                        .upstreams
                        .finalized_header(provider, Some(height))
                        .await
                    {
                        Ok(boundary) => boundary,
                        Err(_) => continue,
                    };
                    let previous_identity = tracker.identity().clone();
                    if tracker.authenticate_transition(&mut rng, &boundary).is_ok() {
                        transition = Some(Transition {
                            previous_identity,
                            boundary,
                        });
                        installed = true;
                        break;
                    }
                }
                if !installed {
                    break;
                }
                accepted = tracker.accept(&mut rng, evidence.clone());
            }
            match accepted {
                Ok(_) => {}
                Err(error) => {
                    if matches!(&error, head::Error::Verification(error) if error.is_signature_mismatch())
                    {
                        last = Error::TransitionUnavailable;
                    } else {
                        self.0.integrity_failures.fetch_add(1, Ordering::Relaxed);
                        integrity = Some(Error::Head(error));
                    }
                    continue;
                }
            }
            return Ok(Some((tracker, transition)));
        }
        // With no advancement, retained progress remains valid but not necessarily fresh.
        if self.0.state.lock().await.tracker.snapshot().is_some()
            && integrity.is_none()
            && (retained_confirmed || matches!(last, Error::NoHead))
        {
            return Ok(None);
        }
        Err(integrity.unwrap_or(last))
    }

    /// Latest-only, snapshot-consistent batch. Identical in-flight queries share one bounded job.
    /// New jobs fail Busy instead of forming an unbounded queue. Stale valid heads remain labelled
    /// with their actual timestamp; provider proof lag never selects a different/older snapshot.
    pub async fn read(&self, requests: Vec<ReadRequest>) -> ReadOutcome {
        if requests.is_empty() || requests.len() > self.0.limits.max_reads {
            return Err(Arc::new(Error::RequestLimit));
        }
        let targets = token::targets(&requests).map_err(|error| Arc::new(Error::Token(error)))?;
        if targets.len() > self.0.limits.proofs.max_accounts {
            return Err(Arc::new(Error::RequestLimit));
        }
        let snapshot = {
            let state = self.0.state.lock().await;
            if state.persistence_paused {
                return Err(Arc::new(Error::PersistencePaused));
            }
            state
                .tracker
                .snapshot()
                .ok_or_else(|| Arc::new(Error::NoHead))?
        };
        if self
            .0
            .network
            .unsupported_layout_from
            .is_some_and(|timestamp| snapshot.header().timestamp() >= timestamp)
        {
            return Err(Arc::new(Error::UnsupportedLayout));
        }
        let key = (snapshot.evidence().digest, requests.clone());
        let mut in_flight = self.0.in_flight.lock().await;
        let mut rx = if let Some(rx) = in_flight.get(&key) {
            rx.clone()
        } else {
            let permit = Arc::new(
                self.0
                    .permits
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| Arc::new(Error::Busy))?,
            );
            let (tx, rx) = watch::channel(None);
            in_flight.insert(key.clone(), rx.clone());
            let client = self.clone();
            tokio::spawn(async move {
                let work = client.read_inner(snapshot, requests, permit.clone());
                let result = tokio::time::timeout(client.0.limits.read_timeout, work)
                    .await
                    .unwrap_or(Err(Error::Deadline));
                let result = result.map(Arc::new).map_err(Arc::new);
                tx.send_replace(Some(result));
                client.0.in_flight.lock().await.remove(&key);
            });
            rx
        };
        drop(in_flight);
        loop {
            if let Some(result) = rx.borrow().clone() {
                return result;
            }
            rx.changed().await.map_err(|_| Arc::new(Error::Worker))?;
        }
    }

    async fn read_inner(
        &self,
        snapshot: Snapshot,
        requests: Vec<ReadRequest>,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Result<VerifiedReads, Error> {
        let mut values = vec![None; requests.len()];
        let mut targets = proof::ProofTargets::new();
        {
            let mut cache = self.0.cache.lock().await;
            for (index, request) in requests.iter().enumerate() {
                let key = request.key()?;
                if let (Some(account), Some(word)) = (
                    cache.account(&snapshot, key.account),
                    cache.get(&snapshot, key),
                ) {
                    values[index] = Some(token::decode(key, account.as_ref(), word)?);
                } else {
                    targets.entry(key.account).or_default().insert(key.slot);
                }
            }
        }
        if !targets.is_empty() {
            let mut last = Error::NoHead;
            let mut integrity = None;
            let mut batch = None;
            for provider in 0..self.0.upstreams.count() {
                let responses = match self
                    .0
                    .upstreams
                    .proofs(provider, snapshot.evidence().digest, &targets)
                    .await
                {
                    Ok(responses) => responses,
                    Err(error) => {
                        last = error.into();
                        continue;
                    }
                };
                let selected = snapshot.clone();
                let selected_targets = targets.clone();
                let limits = self.0.limits.proofs;
                let cpu_permit = permit.clone();
                let verified = tokio::task::spawn_blocking(move || {
                    let _permit = cpu_permit;
                    selected.verify(&selected_targets, &responses, limits)
                })
                .await
                .map_err(|_| Error::Worker)?;
                match verified {
                    Ok(verified) => {
                        batch = Some(verified);
                        break;
                    }
                    Err(error) => {
                        self.0.integrity_failures.fetch_add(1, Ordering::Relaxed);
                        integrity = Some(Error::Proof(error));
                    }
                }
            }
            let batch = batch.ok_or_else(|| integrity.unwrap_or(last))?;
            // Decode the operation-owned batch, not a shared cache that another read may prune.
            // Captured cache hits were already authenticated at this immutable snapshot.
            for (index, request) in requests.iter().enumerate() {
                if values[index].is_some() {
                    continue;
                }
                let key = request.key()?;
                let account = batch.accounts().get(&key.account).ok_or(Error::Worker)?;
                let word = account.slots().get(&key.slot).ok_or(Error::Worker)?;
                values[index] = Some(token::decode(key, account.account(), *word)?);
            }
            self.0.cache.lock().await.commit(&snapshot, &batch)?;
        }
        Ok(VerifiedReads {
            block: (&snapshot).into(),
            values: values
                .into_iter()
                .map(|value| value.ok_or(Error::Worker))
                .collect::<Result<_, _>>()?,
        })
    }

    pub async fn status(&self) -> Status {
        let state = self.0.state.lock().await;
        let snapshot = state.tracker.snapshot();
        let head = snapshot.as_ref().map(VerifiedBlock::from);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_millis()).ok());
        let timestamp = head.as_ref().map(|head| head.timestamp_millis);
        let age = now
            .zip(timestamp)
            .and_then(|(now, timestamp)| now.checked_sub(timestamp));
        let head_in_future = now
            .zip(timestamp)
            .is_some_and(|(now, timestamp)| now < timestamp);
        let durable = head.is_some() && !state.persistence_paused;
        let last_failure = state.failure;
        drop(state);
        let (account_cache_entries, slot_cache_entries) = self.0.cache.lock().await.entry_counts();
        Status {
            head,
            head_age_millis: age,
            head_in_future,
            durable,
            last_failure,
            integrity_failures: self.0.integrity_failures.load(Ordering::Relaxed),
            account_cache_entries,
            slot_cache_entries,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid light-client configuration: {0}")]
    Configuration(&'static str),
    #[error(transparent)]
    Transport(#[from] transport::Error),
    #[error(transparent)]
    Checkpoint(#[from] crate::checkpoint::Error),
    #[error(transparent)]
    Head(#[from] head::Error),
    #[error(transparent)]
    Proof(#[from] proof::Error),
    #[error(transparent)]
    Cache(#[from] crate::cache::Error),
    #[error(transparent)]
    Token(#[from] token::Error),
    #[error("no authenticated finalized head is available")]
    NoHead,
    #[error(
        "authenticated signing-key transition evidence is unavailable within the configured bounds"
    )]
    TransitionUnavailable,
    #[error("light-client deadline expired")]
    Deadline,
    #[error("light-client concurrency limit reached")]
    Busy,
    #[error("empty or oversized light read batch")]
    RequestLimit,
    #[error("configured layout is unsupported at the selected finalized head")]
    UnsupportedLayout,
    #[error("reads paused after critical checkpoint persistence failure")]
    PersistencePaused,
    #[error("light-client verification worker stopped unexpectedly")]
    Worker,
}
impl Error {
    pub fn kind(&self) -> FailureKind {
        match self {
            Self::Checkpoint(_) | Self::PersistencePaused => FailureKind::Persistence,
            Self::Transport(transport::Error::Capability { .. }) | Self::UnsupportedLayout => {
                FailureKind::Capability
            }
            Self::Head(_)
            | Self::Proof(_)
            | Self::Cache(_)
            | Self::Transport(
                transport::Error::MalformedResponse(_) | transport::Error::ResponseSize(_),
            ) => FailureKind::Integrity,
            _ => FailureKind::Availability,
        }
    }
}
