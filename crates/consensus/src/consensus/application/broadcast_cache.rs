//! Reuse a durably persisted proposal through the existing bounded broadcast cache.

use std::sync::Arc;

use commonware_broadcast::buffered;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::Recipients;

use crate::consensus::block::Block;

/// Prime only after the caller has awaited proposal durability. An empty-recipient
/// broadcast inserts the object without publishing it to peers. Reading it back
/// orders cache insertion before proposal release; a miss leaves archive fallback intact.
pub(super) async fn prime(
    broadcast: &buffered::Mailbox<PublicKey, Block>,
    block: Arc<Block>,
) -> bool {
    let digest = block.digest();
    if !broadcast
        .broadcast_shared(Recipients::Some(Vec::new()), block)
        .accepted()
    {
        return false;
    }
    broadcast.get(digest).await.is_some()
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Mutex,
        time::{Duration, SystemTime},
    };

    use commonware_actor::{Feedback, Unreliable};
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_p2p::{
        CheckedSender, LimitedSender,
        utils::{StaticProvider, mocks::inert_channel},
    };
    use commonware_runtime::{Clock as _, IoBufs, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, ordered::Set};
    use reth_primitives_traits::SealedBlock;

    use super::*;

    #[derive(Clone, Debug)]
    struct RecordingSender {
        peers: Vec<PublicKey>,
        attempts: Arc<Mutex<Vec<Vec<PublicKey>>>>,
    }

    struct Checked {
        peers: Vec<PublicKey>,
        attempts: Arc<Mutex<Vec<Vec<PublicKey>>>>,
    }

    impl LimitedSender for RecordingSender {
        type PublicKey = PublicKey;
        type Checked<'a> = Checked;

        fn check(&mut self, recipients: Recipients<PublicKey>) -> Result<Checked, SystemTime> {
            Ok(Checked {
                peers: match recipients {
                    Recipients::All => self.peers.clone(),
                    Recipients::Some(peers) => peers,
                    Recipients::One(peer) => vec![peer],
                },
                attempts: self.attempts.clone(),
            })
        }
    }

    impl CheckedSender for Checked {
        type PublicKey = PublicKey;

        fn recipients(&self) -> Vec<PublicKey> {
            self.peers.clone()
        }

        fn send(self, _message: impl Into<IoBufs> + Send, _priority: bool) -> Unreliable<Feedback> {
            self.attempts.lock().unwrap().push(self.peers);
            Unreliable::new(Feedback::Ok)
        }
    }

    fn block(number: u64) -> Arc<Block> {
        let mut block = tempo_primitives::Block::default();
        block.header.inner.number = number;
        Arc::new(Block::from_execution_block_unchecked(
            SealedBlock::seal_slow(block),
            None,
        ))
    }

    fn engine(
        context: deterministic::Context,
        capacity: usize,
        eligible: bool,
    ) -> (
        buffered::Engine<deterministic::Context, PublicKey, Block, StaticProvider<PublicKey>>,
        buffered::Mailbox<PublicKey, Block>,
        RecordingSender,
    ) {
        let local = PrivateKey::from_seed(0).public_key();
        let remote = PrivateKey::from_seed(1).public_key();
        let peers = if eligible {
            vec![local.clone(), remote.clone()]
        } else {
            vec![remote.clone()]
        };
        let (engine, mailbox) = buffered::Engine::new(
            context,
            buffered::Config {
                public_key: local,
                mailbox_size: NZUsize!(1),
                deque_size: capacity,
                priority: true,
                codec_config: (),
                peer_provider: StaticProvider::new(0, Set::from_iter_dedup(peers)),
            },
        );
        (
            engine,
            mailbox,
            RecordingSender {
                peers: vec![remote],
                attempts: Arc::default(),
            },
        )
    }

    #[test]
    fn prime_retains_same_block_without_peer_delivery() {
        deterministic::Runner::default().start(|context| async move {
            let (engine, mailbox, sender) = engine(context.child("broadcast"), 1, true);
            let attempts = sender.attempts.clone();
            let peers = sender.peers.clone();
            let _task = engine.start((sender, inert_channel::<PublicKey>([]).1));
            context.sleep(Duration::from_millis(1)).await;

            let block = block(1);
            assert!(prime(&mailbox, block.clone()).await);
            let cached = mailbox.get(block.digest()).await.expect("primed block");
            assert!(
                Arc::ptr_eq(&block, &cached),
                "priming must not decode a replacement"
            );
            assert_eq!(*attempts.lock().unwrap(), vec![Vec::<PublicKey>::new()]);

            assert!(mailbox.broadcast_shared(Recipients::All, cached).accepted());
            assert!(mailbox.get(block.digest()).await.is_some());
            assert_eq!(*attempts.lock().unwrap(), vec![Vec::new(), peers]);
        });
    }

    #[test]
    fn prime_preserves_bounded_cache_eviction() {
        deterministic::Runner::default().start(|context| async move {
            let (engine, mailbox, sender) = engine(context.child("broadcast"), 1, true);
            let _task = engine.start((sender, inert_channel::<PublicKey>([]).1));
            context.sleep(Duration::from_millis(1)).await;
            let first = block(1);
            assert!(prime(&mailbox, first.clone()).await);
            assert!(prime(&mailbox, block(2)).await);
            assert!(mailbox.get(first.digest()).await.is_none());
        });
    }

    #[test]
    fn prime_reports_miss_when_cache_cannot_retain_block() {
        for (capacity, eligible) in [(0, true), (1, false)] {
            deterministic::Runner::default().start(|context| async move {
                let (engine, mailbox, sender) =
                    engine(context.child("broadcast"), capacity, eligible);
                let _task = engine.start((sender, inert_channel::<PublicKey>([]).1));
                context.sleep(Duration::from_millis(1)).await;
                assert!(!prime(&mailbox, block(1)).await);
            });
        }
    }

    #[test]
    fn prime_reports_closed_broadcast_actor() {
        deterministic::Runner::default().start(|context| async move {
            let (engine, mailbox, _) = engine(context.child("broadcast"), 1, true);
            drop(engine);
            assert!(!prime(&mailbox, block(1)).await);
        });
    }
}
