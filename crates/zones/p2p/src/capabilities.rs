//! Optional peer features. Silence always means legacy block encoding.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::P2pPeerId;

pub(crate) const ANNOUNCEMENT_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const ANNOUNCEMENT_TTL: Duration = Duration::from_secs(15);
/// Version 1 advertises witness-envelope v1 decoding. Unknown versions are not interpreted.
pub(crate) const LOCAL_CAPABILITIES_VERSION: u8 = 1;

/// Shared by live replication and backfill; never persisted across local restarts.
#[derive(Clone, Default)]
pub(crate) struct PeerCapabilities(Arc<Mutex<HashMap<P2pPeerId, (u8, Instant)>>>);

impl PeerCapabilities {
    pub(crate) fn announce(&self, peer: P2pPeerId, version: u8, now: Instant) {
        let mut peers = self.0.lock();
        peers.retain(|_, (_, last_seen)| now.duration_since(*last_seen) < ANNOUNCEMENT_TTL);
        peers.insert(peer, (version, now));
    }

    pub(crate) fn supports_witnesses(&self, peer: &P2pPeerId, now: Instant) -> bool {
        self.0.lock().get(peer).is_some_and(|(version, last_seen)| {
            *version == 1 && now.duration_since(*last_seen) < ANNOUNCEMENT_TTL
        })
    }
}

#[cfg(test)]
mod tests {
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::*;

    #[test]
    fn support_requires_an_announcement_and_expires_without_refresh() {
        let peer = PrivateKey::from_seed(1).public_key();
        let other = PrivateKey::from_seed(2).public_key();
        let capabilities = PeerCapabilities::default();
        let shared = capabilities.clone();
        let now = Instant::now();
        assert!(!capabilities.supports_witnesses(&peer, now));
        capabilities.announce(peer.clone(), 1, now);
        assert!(shared.supports_witnesses(&peer, now));
        assert!(!capabilities.supports_witnesses(&other, now));

        let refreshed = now + ANNOUNCEMENT_INTERVAL;
        capabilities.announce(peer.clone(), 1, refreshed);
        assert!(capabilities.supports_witnesses(&peer, now + ANNOUNCEMENT_TTL));
        assert!(!capabilities.supports_witnesses(&peer, refreshed + ANNOUNCEMENT_TTL));
        assert!(!PeerCapabilities::default().supports_witnesses(&peer, refreshed));
    }

    #[test]
    fn only_version_one_enables_witnesses() {
        let peer = PrivateKey::from_seed(1).public_key();
        let capabilities = PeerCapabilities::default();
        let now = Instant::now();
        for version in 0..=u8::MAX {
            capabilities.announce(peer.clone(), 1, now);
            assert!(capabilities.supports_witnesses(&peer, now));
            capabilities.announce(peer.clone(), version, now);
            assert_eq!(capabilities.supports_witnesses(&peer, now), version == 1);
        }
    }
}
