//! Simple in-memory broadcast relay for mock applications; not a network.

use bytes::Bytes;
use commonware_cryptography::{Digest, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::{channel::mpsc, sync::Mutex};
use std::collections::{btree_map::Entry, BTreeMap};
use tracing::{error, warn};

/// Relay is a mock for distributing artifacts between applications.
pub struct Relay<D: Digest, P: PublicKey> {
    #[allow(clippy::type_complexity)]
    recipients: Mutex<BTreeMap<P, Vec<mpsc::UnboundedSender<(D, Bytes)>>>>,
}

impl<D: Digest, P: PublicKey> Relay<D, P> {
    /// Creates a new relay.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            recipients: Mutex::new(BTreeMap::new()),
        }
    }

    /// Deregisters all recipients without clearing the payloads.
    pub fn deregister_all(&self) {
        let mut recipients = self.recipients.lock();
        recipients.clear();
    }

    /// Registers a new recipient that receives all broadcasts.
    pub fn register(&self, public_key: P) -> mpsc::UnboundedReceiver<(D, Bytes)> {
        let (sender, receiver) = mpsc::unbounded_channel();
        {
            let mut recipients = self.recipients.lock();
            match recipients.entry(public_key.clone()) {
                Entry::Vacant(vacant) => {
                    vacant.insert(vec![sender]);
                }
                Entry::Occupied(mut occupied) => {
                    warn!(?public_key, "duplicate registration");
                    occupied.get_mut().push(sender);
                }
            }
        }
        receiver
    }

    /// Broadcasts a payload to selected recipients.
    pub fn broadcast(&self, sender: &P, recipients: Recipients<P>, (payload, data): (D, Bytes)) {
        let channels = {
            let mut channels = Vec::new();
            let registered = self.recipients.lock();
            match recipients {
                Recipients::All => {
                    for (public_key, channel) in registered.iter() {
                        if public_key == sender {
                            continue;
                        }
                        channels.push((public_key.clone(), channel.clone()));
                    }
                }
                Recipients::Some(peers) => {
                    for public_key in peers {
                        if &public_key == sender {
                            continue;
                        }
                        if let Some(channel) = registered.get(&public_key) {
                            channels.push((public_key, channel.clone()));
                        }
                    }
                }
                Recipients::One(public_key) => {
                    if public_key != *sender {
                        if let Some(channel) = registered.get(&public_key) {
                            channels.push((public_key, channel.clone()));
                        }
                    }
                }
            }
            channels
        };
        for (recipient, listeners) in channels {
            for listener in listeners {
                if let Err(e) = listener.send((payload, data.clone())) {
                    error!(?e, ?recipient, "failed to send message to recipient");
                }
            }
        }
    }
}

impl<D: Digest, P: PublicKey> Default for Relay<D, P> {
    fn default() -> Self {
        Self::new()
    }
}
