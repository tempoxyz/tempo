use crate::{Block, Reporter, marshal::Update, types::Height};
use commonware_actor::Feedback;
use commonware_utils::{
    Acknowledgement,
    acknowledgement::Exact,
    sync::{Mutex, Notify},
};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

/// A mock application that stores finalized blocks.
#[derive(Clone)]
pub struct Application<B: Block> {
    blocks: Arc<Mutex<BTreeMap<Height, Arc<B>>>>,
    #[allow(clippy::type_complexity)]
    tip: Arc<Mutex<Option<(Height, B::Digest)>>>,
    pending_acks: Arc<Mutex<VecDeque<(Height, Exact)>>>,
    notify: Arc<Notify>,
    auto_ack: bool,
}

impl<B: Block> Default for Application<B> {
    fn default() -> Self {
        Self {
            blocks: Default::default(),
            tip: Default::default(),
            pending_acks: Default::default(),
            notify: Arc::new(Notify::new()),
            auto_ack: true,
        }
    }
}

impl<B: Block> Application<B> {
    /// Returns an application that stores acks for manual release.
    pub fn manual_ack() -> Self {
        Self {
            auto_ack: false,
            ..Default::default()
        }
    }

    /// Returns the finalized blocks.
    pub fn blocks(&self) -> BTreeMap<Height, Arc<B>> {
        self.blocks.lock().clone()
    }

    /// Returns the tip.
    pub fn tip(&self) -> Option<(Height, B::Digest)> {
        *self.tip.lock()
    }

    /// Returns pending ack heights in arrival order.
    pub fn pending_ack_heights(&self) -> Vec<Height> {
        self.pending_acks
            .lock()
            .iter()
            .map(|(height, _)| *height)
            .collect()
    }

    /// Acknowledges the oldest pending block and returns its height.
    pub fn acknowledge_next(&self) -> Option<Height> {
        let (height, ack) = self.pending_acks.lock().pop_front()?;
        ack.acknowledge();
        Some(height)
    }

    /// Waits for the next block to be dispatched, acknowledges it, and returns its height.
    pub async fn acknowledged(&self) -> Height {
        loop {
            if let Some(height) = self.acknowledge_next() {
                return height;
            }
            self.notify.notified().await;
        }
    }
}

impl<B: Block> Reporter for Application<B> {
    type Activity = Update<B>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Update::Block(block, ack_tx) => {
                let height = block.height();
                self.blocks.lock().insert(height, block);
                if self.auto_ack {
                    ack_tx.acknowledge();
                } else {
                    self.pending_acks.lock().push_back((height, ack_tx));
                    self.notify.notify_one();
                }
            }
            Update::Tip(_, height, digest) => {
                *self.tip.lock() = Some((height, digest));
            }
        }
        Feedback::Ok
    }
}
