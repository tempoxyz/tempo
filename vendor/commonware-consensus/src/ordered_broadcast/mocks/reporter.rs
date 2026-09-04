use crate::{
    ordered_broadcast::{
        scheme,
        types::{Activity, Chunk, ChunkVerifier, Lock, Proposal},
    },
    types::{Epoch, Height},
};
use commonware_actor::{
    mailbox::{self, Policy, Receiver, Sender},
    Feedback,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{certificate::Scheme, Digest, PublicKey};
use commonware_parallel::Sequential;
use commonware_runtime::{spawn_cell, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{channel::oneshot, NZUsize};
use rand_core::CryptoRng;
use std::collections::{btree_map::Entry, BTreeMap, HashMap, HashSet, VecDeque};

#[allow(clippy::large_enum_variant)]
enum Message<C: PublicKey, S: Scheme, D: Digest> {
    Proposal(Proposal<C, D>),
    Locked(Lock<C, S, D>),
    GetTip(C, oneshot::Sender<Option<(Height, Epoch)>>),
    GetContiguousTip(C, oneshot::Sender<Option<Height>>),
    Get(C, Height, oneshot::Sender<Option<(D, Epoch)>>),
}

impl<C: PublicKey, S: Scheme, D: Digest> Policy for Message<C, S, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        overflow.push_back(message);
    }
}

pub struct Reporter<R: CryptoRng, C: PublicKey, S: Scheme, D: Digest> {
    context: ContextCell<R>,
    mailbox: Receiver<Message<C, S, D>>,

    // Verifier for node signatures.
    chunk_verifier: ChunkVerifier,

    // Scheme for verification
    scheme: S,

    // Notified proposals
    proposals: HashSet<Chunk<C, D>>,
    limit_misses: Option<usize>,

    // All known digests
    digests: HashMap<C, BTreeMap<Height, (D, Epoch)>>,

    // Highest contiguous known height for each sequencer
    contiguous: HashMap<C, Height>,

    // Highest known height (and epoch) for each sequencer
    highest: HashMap<C, (Height, Epoch)>,
}

impl<R, C, S, D> Reporter<R, C, S, D>
where
    R: CryptoRng + Metrics,
    C: PublicKey,
    S: Scheme,
    D: Digest,
{
    pub fn new(
        rng: R,
        chunk_verifier: ChunkVerifier,
        scheme: S,
        limit_misses: Option<usize>,
    ) -> (Self, Mailbox<C, S, D>) {
        let (sender, receiver) = mailbox::new(rng.child("mailbox"), NZUsize!(1024));
        (
            Self {
                context: ContextCell::new(rng),
                mailbox: receiver,
                chunk_verifier,
                scheme,
                proposals: HashSet::new(),
                limit_misses,
                digests: HashMap::new(),
                contiguous: HashMap::new(),
                highest: HashMap::new(),
            },
            Mailbox { sender },
        )
    }

    pub fn start(mut self) -> Handle<()>
    where
        R: Spawner,
        S: scheme::Scheme<C, D>,
    {
        spawn_cell!(self.context, self.run())
    }

    pub async fn run(mut self)
    where
        S: scheme::Scheme<C, D>,
    {
        let mut misses = 0;
        while let Some(msg) = self.mailbox.recv().await {
            match msg {
                Message::Proposal(proposal) => {
                    // Verify properly constructed (not needed in production)
                    if !proposal.verify(&self.chunk_verifier) {
                        panic!("Invalid proof");
                    }

                    // Test encoding/decoding
                    let encoded = proposal.encode();
                    Proposal::<C, D>::decode(encoded).unwrap();

                    // Store the proposal
                    self.proposals.insert(proposal.chunk);
                }
                Message::Locked(lock) => {
                    // Verify properly constructed (not needed in production)
                    if !lock.verify(self.context.as_mut(), &self.scheme, &Sequential) {
                        panic!("Invalid proof");
                    }

                    // Test encoding/decoding
                    let encoded = lock.encode();
                    Lock::<C, S, D>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                        .unwrap();

                    // Check if the proposal is known
                    if let Some(misses_allowed) = self.limit_misses {
                        if !self.proposals.contains(&lock.chunk) {
                            misses += 1;
                        }
                        assert!(misses <= misses_allowed, "Missed too many proposals");
                    }

                    // Update the reporter
                    let chunk = lock.chunk;
                    let digests = self.digests.entry(chunk.sequencer.clone()).or_default();
                    let entry = digests.entry(chunk.height);
                    match entry {
                        Entry::Occupied(mut entry) => {
                            // It should never be possible to get a conflicting payload
                            let (existing_payload, existing_epoch) = entry.get();
                            assert_eq!(*existing_payload, chunk.payload);

                            // We may hear about a commitment again, however, this should
                            // only occur if the epoch has changed.
                            assert_ne!(*existing_epoch, lock.epoch);
                            if lock.epoch > *existing_epoch {
                                entry.insert((chunk.payload, lock.epoch));
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert((chunk.payload, lock.epoch));
                        }
                    }

                    // Update the highest height
                    let highest = self
                        .highest
                        .get(&chunk.sequencer)
                        .copied()
                        .unwrap_or((Height::zero(), Epoch::zero()));
                    if chunk.height > highest.0 {
                        self.highest
                            .insert(chunk.sequencer.clone(), (chunk.height, lock.epoch));
                    }

                    // Update the highest contiguous height
                    let highest = self.contiguous.get(&chunk.sequencer);
                    if (highest.is_none() && chunk.height.is_zero())
                        || (highest.is_some() && chunk.height == highest.unwrap().next())
                    {
                        let mut contiguous = chunk.height;
                        while digests.contains_key(&contiguous.next()) {
                            contiguous = contiguous.next();
                        }
                        self.contiguous.insert(chunk.sequencer, contiguous);
                    }
                }
                Message::GetTip(sequencer, sender) => {
                    let hi = self.highest.get(&sequencer).copied();
                    sender.send(hi).unwrap();
                }
                Message::GetContiguousTip(sequencer, sender) => {
                    let contiguous = self.contiguous.get(&sequencer).copied();
                    sender.send(contiguous).unwrap();
                }
                Message::Get(sequencer, height, sender) => {
                    let digest = self
                        .digests
                        .get(&sequencer)
                        .and_then(|map| map.get(&height))
                        .cloned();
                    sender.send(digest).unwrap();
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<C: PublicKey, S: Scheme, D: Digest> {
    sender: Sender<Message<C, S, D>>,
}

impl<C: PublicKey, S: Scheme, D: Digest> crate::Reporter for Mailbox<C, S, D> {
    type Activity = Activity<C, S, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Activity::Tip(proposal) => self.sender.enqueue(Message::Proposal(proposal)),
            Activity::Lock(lock) => self.sender.enqueue(Message::Locked(lock)),
        }
    }
}

impl<C: PublicKey, S: Scheme, D: Digest> Mailbox<C, S, D> {
    pub async fn get_tip(&mut self, sequencer: C) -> Option<(Height, Epoch)> {
        let (sender, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::GetTip(sequencer, sender))
                .accepted(),
            "Failed to send get tip"
        );
        receiver.await.unwrap()
    }

    pub async fn get_contiguous_tip(&mut self, sequencer: C) -> Option<Height> {
        let (sender, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::GetContiguousTip(sequencer, sender))
                .accepted(),
            "Failed to send get contiguous tip"
        );
        receiver.await.unwrap()
    }

    pub async fn get(&mut self, sequencer: C, height: Height) -> Option<(D, Epoch)> {
        let (sender, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Get(sequencer, height, sender))
                .accepted(),
            "Failed to send get"
        );
        receiver.await.unwrap()
    }
}
