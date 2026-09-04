//! Mock provider for testing aggregation.
//!
//! This module provides a simple [`Provider`] implementation that can be
//! used in tests. It allows registering signing schemes for specific epochs
//! and retrieving them later.

use crate::types::Epoch;
use commonware_cryptography::certificate::{Provider as CertificateProvider, Scheme, Scoped};
use commonware_utils::sync::Mutex;
use std::{collections::HashMap, sync::Arc};

/// Provides signing schemes for different epochs.
#[derive(Clone)]
pub struct Provider<S: Scheme> {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<S>>>>,
}

impl<S: Scheme> Default for Provider<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Scheme> Provider<S> {
    pub fn new() -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S: Scheme> Provider<S> {
    /// Registers a new signing scheme for the given epoch.
    ///
    /// Returns `false` if a scheme was already registered for the epoch.
    pub fn register(&self, epoch: Epoch, scheme: S) -> bool {
        let mut schemes = self.schemes.lock();
        schemes.insert(epoch, Arc::new(scheme)).is_none()
    }
}

impl<S: Scheme> CertificateProvider for Provider<S> {
    type Scope = Epoch;
    type Scheme = S;

    fn scoped(&self, epoch: Epoch) -> Option<Scoped<S>> {
        let schemes = self.schemes.lock();
        schemes.get(&epoch).cloned().map(Scoped::scheme)
    }
}
