use crate::{ordered_broadcast::types::SequencersProvider, types::Epoch};
use commonware_cryptography::PublicKey;
use commonware_utils::{ordered::Set, TryFromIterator};
use std::sync::Arc;

#[derive(Clone)]
pub struct Sequencers<P: PublicKey> {
    sequencers: Arc<Set<P>>,
}

impl<P: PublicKey> Sequencers<P> {
    pub fn new(participants: Vec<P>) -> Self {
        Self {
            sequencers: Arc::new(Set::try_from_iter(participants).unwrap()),
        }
    }
}

impl<P: PublicKey> SequencersProvider for Sequencers<P> {
    type PublicKey = P;

    fn sequencers(&self, _: Epoch) -> Option<Arc<Set<Self::PublicKey>>> {
        Some(self.sequencers.clone())
    }
}
