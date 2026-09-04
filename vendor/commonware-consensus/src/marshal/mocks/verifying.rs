//! Mock verifying application for Marshaled wrapper tests.
//!
//! This module provides a generic mock application that implements the
//! `Application` trait, suitable for testing the `Marshaled` wrapper in
//! both standard and coding variants.

use crate::{marshal::ancestry::Ancestry, CertifiableBlock, Epochable};
use commonware_runtime::deterministic;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use std::{marker::PhantomData, sync::Arc};

/// A mock application that implements `Application` for testing.
///
/// This mock:
/// - Returns the configured block (if any) from `propose()`
/// - Returns a configurable result from `verify()`
#[derive(Clone)]
pub struct MockVerifyingApp<B, S> {
    /// The block returned by `propose`. If `None`, `propose` returns `None`.
    pub propose_result: Option<B>,
    /// The result returned by `verify`.
    pub verify_result: bool,
    _phantom: PhantomData<S>,
}

impl<B, S> MockVerifyingApp<B, S> {
    /// Create a new mock verifying application.
    pub fn new() -> Self {
        Self {
            propose_result: None,
            verify_result: true,
            _phantom: PhantomData,
        }
    }

    /// Create a new mock verifying application with a fixed verify result.
    pub fn with_verify_result(verify_result: bool) -> Self {
        Self {
            propose_result: None,
            verify_result,
            _phantom: PhantomData,
        }
    }

    /// Configure the block returned by `propose`.
    pub fn with_propose_result(mut self, block: B) -> Self {
        self.propose_result = Some(block);
        self
    }
}

impl<B, S> Default for MockVerifyingApp<B, S> {
    fn default() -> Self {
        Self {
            propose_result: None,
            verify_result: true,
            _phantom: PhantomData,
        }
    }
}

impl<B, S> crate::Application<deterministic::Context> for MockVerifyingApp<B, S>
where
    B: CertifiableBlock + Clone + Send + Sync + 'static,
    B::Context: Epochable + Clone + Send + Sync + 'static,
    S: commonware_cryptography::certificate::Scheme + Clone + Send + Sync + 'static,
{
    type Block = B;
    type Context = B::Context;
    type SigningScheme = S;

    async fn propose(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
    ) -> Option<Self::Block> {
        self.propose_result.clone()
    }

    async fn verify(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        self.verify_result
    }
}

/// A verifying mock application whose `verify()` signals `started` on entry and
/// blocks until `release` is received. Used to deterministically control when
/// the application verdict races with marshal shutdown.
#[derive(Clone)]
pub struct GatedVerifyingApp<B, S> {
    started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    _phantom: PhantomData<(B, S)>,
}

impl<B, S> GatedVerifyingApp<B, S> {
    /// Returns the gated app, a `started` receiver fired when `verify()` is entered,
    /// and a `release` sender that unblocks `verify()` once signaled.
    pub fn new() -> (Self, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        (
            Self {
                started: Arc::new(Mutex::new(Some(started_tx))),
                release: Arc::new(Mutex::new(Some(release_rx))),
                _phantom: PhantomData,
            },
            started_rx,
            release_tx,
        )
    }
}

impl<B, S> crate::Application<deterministic::Context> for GatedVerifyingApp<B, S>
where
    B: CertifiableBlock + Clone + Send + Sync + 'static,
    B::Context: Epochable + Clone + Send + Sync + 'static,
    S: commonware_cryptography::certificate::Scheme + Clone + Send + Sync + 'static,
{
    type Block = B;
    type Context = B::Context;
    type SigningScheme = S;

    async fn propose(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
    ) -> Option<Self::Block> {
        None
    }

    async fn verify(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        if let Some(started) = self.started.lock().take() {
            started.send_lossy(());
        }
        let release = self
            .release
            .lock()
            .take()
            .expect("release receiver missing");
        let _ = release.await;
        true
    }
}
