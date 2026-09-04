use crate::types::Epoch;
use commonware_cryptography::certificate::{Provider as CertificateProvider, Scheme, Scoped};
use commonware_utils::sync::Mutex;
use std::{collections::HashMap, sync::Arc};

/// A mock certificate provider that allows registering different schemes per epoch.
///
/// Unlike a constant certificate provider that returns the same scheme for all scopes,
/// this mock supports epoch-specific schemes for multi-epoch testing scenarios.
#[derive(Clone)]
pub struct Provider<S: Scheme> {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<S>>>>,
}

impl<S: Scheme> Provider<S> {
    pub fn new() -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Registers a new signing scheme for the given epoch.
    ///
    /// Returns `false` if a scheme was already registered for the epoch.
    pub fn register(&self, epoch: Epoch, scheme: S) -> bool {
        let mut schemes = self.schemes.lock();
        schemes.insert(epoch, Arc::new(scheme)).is_none()
    }
}

impl<S: Scheme> Default for Provider<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Scheme> CertificateProvider for Provider<S> {
    type Scope = Epoch;
    type Scheme = S;

    fn scoped(&self, epoch: Epoch) -> Option<Scoped<Self::Scheme>> {
        let schemes = self.schemes.lock();
        schemes.get(&epoch).cloned().map(Scoped::scheme)
    }
}
