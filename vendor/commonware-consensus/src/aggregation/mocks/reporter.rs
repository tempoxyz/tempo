use crate::{
    aggregation::{
        scheme,
        types::{Ack, Activity, Certificate},
    },
    types::{Epoch, Height},
};
use commonware_actor::{
    mailbox::{self, Policy, Receiver, Sender},
    Feedback,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{spawn_cell, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{channel::oneshot, NZUsize};
use rand_core::CryptoRng;
use std::collections::{btree_map::Entry, BTreeMap, HashSet, VecDeque};

#[allow(clippy::large_enum_variant)]
enum Message<S: Scheme, D: Digest> {
    Ack(Ack<S, D>),
    Certified(Certificate<S, D>),
    Tip(Height),
    GetTip(oneshot::Sender<Option<(Height, Epoch)>>),
    GetContiguousTip(oneshot::Sender<Option<Height>>),
    Get(Height, oneshot::Sender<Option<(D, Epoch)>>),
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        overflow.push_back(message);
    }
}

pub struct Reporter<R: CryptoRng, S: Scheme, D: Digest> {
    // RNG used for signature verification
    context: ContextCell<R>,

    // Messages from the engine
    mailbox: Receiver<Message<S, D>>,

    // Signing scheme for verification
    scheme: S,

    // Received acks (for validation)
    acks: HashSet<(Height, Epoch)>,

    // All known digests
    digests: BTreeMap<Height, (D, Epoch)>,

    // Highest contiguous known height
    contiguous: Option<Height>,

    // Highest known height (and epoch)
    highest: Option<(Height, Epoch)>,

    // Current epoch (tracked from acks)
    current_epoch: Epoch,
}

impl<R, S, D> Reporter<R, S, D>
where
    R: CryptoRng + Metrics,
    S: scheme::Scheme<D>,
    D: Digest,
{
    pub fn new(rng: R, scheme: S) -> (Self, Mailbox<S, D>) {
        let (sender, receiver) = mailbox::new(rng.child("mailbox"), NZUsize!(1024));
        (
            Self {
                context: ContextCell::new(rng),
                mailbox: receiver,
                scheme,
                acks: HashSet::new(),
                digests: BTreeMap::new(),
                contiguous: None,
                highest: None,
                current_epoch: Epoch::new(111), // Initialize with the expected epoch
            },
            Mailbox { sender },
        )
    }

    pub fn start(mut self) -> Handle<()>
    where
        R: Spawner,
    {
        spawn_cell!(self.context, self.run())
    }

    pub async fn run(mut self) {
        while let Some(msg) = self.mailbox.recv().await {
            match msg {
                Message::Ack(ack) => {
                    // Verify properly constructed (not needed in production)
                    assert!(ack.verify(self.context.as_mut(), &self.scheme, &Sequential));

                    // Test encoding/decoding
                    let encoded = ack.encode();
                    Ack::<S, D>::decode(encoded).unwrap();

                    // Update current epoch from ack
                    self.current_epoch = ack.epoch;

                    // Store the ack
                    self.acks.insert((ack.item.height, ack.epoch));
                }
                Message::Certified(certificate) => {
                    // Verify certificate
                    assert!(certificate.verify(self.context.as_mut(), &self.scheme, &Sequential));

                    // Test encoding/decoding
                    let encoded = certificate.encode();
                    let cfg = self.scheme.certificate_codec_config();
                    Certificate::<S, D>::decode_cfg(encoded, &cfg).unwrap();

                    // Update the reporter
                    let entry = self.digests.entry(certificate.item.height);
                    match entry {
                        Entry::Occupied(mut entry) => {
                            // It should never be possible to get a conflicting payload
                            let (existing_payload, _existing_epoch) = entry.get();
                            assert_eq!(*existing_payload, certificate.item.digest);

                            // We may hear about a commitment again, however, this should
                            // only occur if the epoch has changed.
                            // For now, we'll allow the same epoch to be overwritten
                            entry.insert((certificate.item.digest, self.current_epoch));
                        }
                        Entry::Vacant(entry) => {
                            entry.insert((certificate.item.digest, self.current_epoch));
                        }
                    }

                    // Update the highest height
                    if self
                        .highest
                        .is_none_or(|(h, _)| certificate.item.height > h)
                    {
                        self.highest = Some((certificate.item.height, self.current_epoch));
                    }

                    // Update the highest contiguous height
                    let mut next_contiguous =
                        self.contiguous.map(|c| c.next()).unwrap_or(Height::zero());
                    while self.digests.contains_key(&next_contiguous) {
                        next_contiguous = next_contiguous.next();
                    }
                    if !next_contiguous.is_zero() {
                        self.contiguous = Some(next_contiguous.previous().unwrap());
                    }
                }
                Message::Tip(height) => {
                    if self.highest.is_none_or(|(h, _)| height > h) {
                        self.highest = Some((height, self.current_epoch));
                    }
                }
                Message::GetTip(sender) => {
                    sender.send(self.highest).unwrap();
                }
                Message::GetContiguousTip(sender) => {
                    sender.send(self.contiguous).unwrap();
                }
                Message::Get(height, sender) => {
                    let digest = self.digests.get(&height).cloned();
                    sender.send(digest).unwrap();
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: Sender<Message<S, D>>,
}

impl<S, D> crate::Reporter for Mailbox<S, D>
where
    S: Scheme,
    D: Digest,
{
    type Activity = Activity<S, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Activity::Ack(ack) => self.sender.enqueue(Message::Ack(ack)),
            Activity::Certified(certificate) => {
                self.sender.enqueue(Message::Certified(certificate))
            }
            Activity::Tip(height) => self.sender.enqueue(Message::Tip(height)),
        }
    }
}

impl<S, D> Mailbox<S, D>
where
    S: Scheme,
    D: Digest,
{
    pub async fn get_tip(&mut self) -> Option<(Height, Epoch)> {
        let (sender, receiver) = oneshot::channel();
        assert!(
            self.sender.enqueue(Message::GetTip(sender)).accepted(),
            "Failed to send get tip"
        );
        receiver.await.unwrap()
    }

    pub async fn get_contiguous_tip(&mut self) -> Option<Height> {
        let (sender, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::GetContiguousTip(sender))
                .accepted(),
            "Failed to send get contiguous tip"
        );
        receiver.await.unwrap()
    }

    pub async fn get(&mut self, height: Height) -> Option<(D, Epoch)> {
        let (sender, receiver) = oneshot::channel();
        assert!(
            self.sender.enqueue(Message::Get(height, sender)).accepted(),
            "Failed to send get"
        );
        receiver.await.unwrap()
    }
}
