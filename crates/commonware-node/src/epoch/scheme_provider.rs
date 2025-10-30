//! Epoch aware schemes and peers.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use commonware_consensus::{marshal, types::Epoch};
use commonware_cryptography::ed25519::PublicKey;
use commonware_resolver::p2p;
use commonware_utils::set::Ordered;

use crate::alias::ThresholdScheme;

#[derive(Clone)]
pub(crate) struct SchemeProvider {
    inner: Arc<Mutex<HashMap<Epoch, Arc<ThresholdScheme>>>>,
}

impl SchemeProvider {
    pub(crate) fn new() -> Self {
        Self {
            inner: Default::default(),
        }
    }

    pub(crate) fn register(&self, epoch: Epoch, scheme: ThresholdScheme) -> bool {
        self.inner
            .lock()
            .unwrap()
            .insert(epoch, Arc::new(scheme))
            .is_none()
    }

    pub(crate) fn delete(&self, epoch: &Epoch) -> bool {
        self.inner.lock().unwrap().remove(epoch).is_some()
    }
}

impl marshal::SchemeProvider for SchemeProvider {
    type Scheme = ThresholdScheme;

    fn scheme(&self, epoch: Epoch) -> Option<Arc<Self::Scheme>> {
        self.inner.lock().unwrap().get(&epoch).cloned()
    }
}

/// Implements trait `[p2p::Cordinatoor]` and is passed to the marshal actor.
#[derive(Clone)]
pub(crate) struct Coordinator {
    static_peers: Ordered<PublicKey>,
}

impl Coordinator {
    pub(crate) fn new(static_peers: Ordered<PublicKey>) -> Self {
        Self { static_peers }
    }
}

impl p2p::Coordinator for Coordinator {
    type PublicKey = PublicKey;

    fn peers(&self) -> &[Self::PublicKey] {
        self.static_peers.as_ref()
    }

    fn peer_set_id(&self) -> u64 {
        0
    }
}
