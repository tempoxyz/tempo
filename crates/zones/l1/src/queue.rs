use super::*;
use std::collections::VecDeque;

/// Bounded portal work crossed by canonical checkpoint-only Zone blocks.
///
/// Empty L1 blocks and events already applied during ingestion are represented only by the final
/// header. Blocks containing deposits or token enablements retain one compact event group. The
/// protocol caps bound the total number of retained groups.
#[derive(Debug, Clone)]
pub(crate) struct DeferredPortalWork {
    last_header: SealedHeader<TempoHeader>,
    event_blocks: Vec<L1PortalEvents>,
}

impl DeferredPortalWork {
    pub(crate) fn new(block: L1BlockDeposits) -> Self {
        let mut work = Self {
            last_header: block.header,
            event_blocks: Vec::new(),
        };
        work.push_events(block.events);
        work
    }

    pub(crate) fn last_num_hash(&self) -> NumHash {
        self.last_header.num_hash()
    }

    pub(crate) fn push(&mut self, block: L1BlockDeposits) {
        self.last_header = block.header;
        self.push_events(block.events);
    }

    fn aggregated_block(&self) -> L1BlockDeposits {
        let mut events = L1PortalEvents::default();
        for block in &self.event_blocks {
            events.extend_operational(block.clone());
        }
        L1BlockDeposits {
            header: self.last_header.clone(),
            events,
        }
    }

    fn push_events(&mut self, events: L1PortalEvents) {
        if !events.deposits.is_empty() || !events.enabled_tokens.is_empty() {
            self.event_blocks.push(events);
        }
    }

    #[cfg(test)]
    fn event_block_len(&self) -> usize {
        self.event_blocks.len()
    }
}

/// Finalized L1 blocks waiting to be processed by the Zone engine.
///
/// Tempo finality is deterministic, so this queue is append-only. Conflicting,
/// skipped, or disconnected finalized blocks are errors rather than forks to
/// reconcile locally.
#[derive(Debug, Default)]
pub(crate) struct PendingDeposits {
    /// Pending L1 blocks with their portal events, not yet processed by the Zone.
    pending: VecDeque<L1BlockDeposits>,
    /// Portal work crossed by checkpoint-only Zone blocks and owed by the next full block.
    deferred: Option<DeferredPortalWork>,
    /// Highest L1 block ever enqueued (number + hash). Survives `confirm` /
    /// `drain` so that reconnecting subscribers know where the queue left off,
    /// even if the engine has already consumed the blocks.
    last_enqueued: Option<NumHash>,
}

impl PendingDeposits {
    /// Enqueue a finalized L1 block.
    ///
    /// Returns `true` when the block was appended and `false` for an exact
    /// redelivery of the current tip. Any other non-contiguous observation is a
    /// finality or provider-integrity failure and leaves the queue unchanged.
    pub(crate) fn try_enqueue(
        &mut self,
        header: SealedHeader<TempoHeader>,
        events: L1PortalEvents,
    ) -> eyre::Result<bool> {
        let block_number = header.number();
        let block_hash = header.hash();

        if let Some(last) = self.last_enqueued {
            if block_number < last.number {
                eyre::bail!(
                    "out-of-order finalized L1 block {block_number}; latest enqueued block is {}",
                    last.number
                );
            }
            if block_number == last.number {
                eyre::ensure!(
                    block_hash == last.hash,
                    "conflicting finalized L1 block at height {block_number}: \
                     existing={}, received={block_hash}",
                    last.hash
                );
                return Ok(false);
            }

            let expected = last
                .number
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("finalized L1 block number overflow"))?;
            eyre::ensure!(
                block_number == expected,
                "non-contiguous finalized L1 block: expected {expected}, received {block_number}"
            );
            eyre::ensure!(
                header.parent_hash() == last.hash,
                "finalized L1 parent mismatch at height {block_number}: \
                 expected={}, received={}",
                last.hash,
                header.parent_hash()
            );
        }

        self.last_enqueued = Some(header.num_hash());
        self.pending.push_back(L1BlockDeposits { header, events });
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn enqueue(&mut self, header: TempoHeader, events: L1PortalEvents) {
        self.try_enqueue(SealedHeader::seal_slow(header), events)
            .expect("test finalized blocks must be contiguous");
    }

    /// Peek at the next pending L1 block without removing it.
    ///
    /// Returns `None` if no L1 blocks are queued. Use [`confirm`](Self::confirm)
    /// after a successful build to advance the queue.
    pub(crate) fn peek(&self) -> Option<&L1BlockDeposits> {
        self.pending.front()
    }

    /// Peek at the next `maximum` pending L1 block headers without removing them.
    pub(crate) fn peek_headers(&self, maximum: usize) -> Vec<SealedHeader<TempoHeader>> {
        self.pending
            .iter()
            .take(maximum)
            .map(|block| block.header.clone())
            .collect()
    }

    /// Return the latest queued L1 header, including headers beyond a bounded checkpoint batch.
    pub(crate) fn latest_header(&self) -> Option<&SealedHeader<TempoHeader>> {
        self.pending.back().map(|block| &block.header)
    }

    /// Confirm the next pending L1 block was successfully processed and remove it.
    ///
    /// The caller must pass the [`NumHash`] returned by [`Self::peek`]. A
    /// mismatch is an internal consumer-ordering error and leaves the queue
    /// unchanged.
    pub(crate) fn confirm(&mut self, expected: NumHash) -> eyre::Result<L1BlockDeposits> {
        let front = self
            .pending
            .front()
            .ok_or_else(|| eyre::eyre!("cannot confirm an empty finalized L1 queue"))?;
        eyre::ensure!(
            front.header.num_hash() == expected,
            "finalized L1 queue confirmation mismatch: expected {expected:?}, front is {:?}",
            front.header.num_hash()
        );
        Ok(self
            .pending
            .pop_front()
            .expect("front was checked immediately before pop"))
    }

    /// Defer every pending block through a canonical checkpoint anchor.
    pub(crate) fn defer_through(&mut self, expected: NumHash) -> eyre::Result<()> {
        while let Some(front) = self.pending.front().map(|entry| entry.header.num_hash())
            && front.number <= expected.number
        {
            eyre::ensure!(
                front.number < expected.number || front.hash == expected.hash,
                "deposit queue holds L1 block {} with hash {}, but the checkpoint consumed {}",
                front.number,
                front.hash,
                expected.hash,
            );
            self.defer_front();
        }
        if let Some(deferred) = &self.deferred
            && deferred.last_header.number() == expected.number
        {
            eyre::ensure!(
                deferred.last_header.hash() == expected.hash,
                "deferred L1 block {} has hash {}, but the checkpoint consumed {}",
                expected.number,
                deferred.last_header.hash(),
                expected.hash,
            );
        }
        Ok(())
    }

    /// Move the front block from the pending queue to the deferred state.
    fn defer_front(&mut self) {
        let block = self
            .pending
            .pop_front()
            .expect("defer_through checked the queue front");
        if let Some(deferred) = &mut self.deferred {
            deferred.push(block);
        } else {
            self.deferred = Some(DeferredPortalWork::new(block));
        }
    }

    /// Return deferred portal work followed by the current operational L1 block.
    pub(crate) fn operational_work(&self, expected: NumHash) -> eyre::Result<Vec<L1BlockDeposits>> {
        let current = self
            .pending
            .front()
            .ok_or_else(|| eyre::eyre!("cannot prepare work from an empty finalized L1 queue"))?;
        eyre::ensure!(
            current.header.num_hash() == expected,
            "operational L1 work does not match the expected anchor: expected {expected:?}, front is {:?}",
            current.header.num_hash()
        );
        let mut work = Vec::with_capacity(usize::from(self.deferred.is_some()) + 1);
        if let Some(deferred) = &self.deferred {
            work.push(deferred.aggregated_block());
        }
        work.push(current.clone());
        Ok(work)
    }

    /// Confirm a full operational import and release all deferred work it consumed.
    pub(crate) fn confirm_operational(&mut self, expected: NumHash) -> eyre::Result<()> {
        self.confirm(expected)?;
        self.deferred = None;
        Ok(())
    }

    /// Confirm every pending L1 block up to and including `expected`.
    ///
    /// Follower import calls this only after the corresponding zone block is
    /// canonical. It is therefore idempotent and tolerates stale entries before
    /// `expected`, but rejects a different hash at the expected height.
    pub(crate) fn confirm_operational_through(&mut self, expected: NumHash) -> eyre::Result<()> {
        while let Some(front) = self.pending.front().map(|entry| entry.header.num_hash()) {
            if front.number > expected.number {
                break;
            }
            eyre::ensure!(
                front.number < expected.number || front.hash == expected.hash,
                "deposit queue holds L1 block {} with hash {}, but the consumed block is {}",
                front.number,
                front.hash,
                expected.hash,
            );
            self.confirm(front)
                .expect("front was just read and matches by construction");
        }

        if let Some(deferred) = &mut self.deferred {
            // A delayed duplicate of an older full block must not erase checkpoint work deferred by
            // newer canonical blocks. Only release work at or before the full block's anchor.
            if deferred.last_header.number() <= expected.number {
                self.deferred = None;
            }
        }
        Ok(())
    }

    /// Returns the most recently enqueued L1 block (number + hash), if any.
    pub(crate) fn last_enqueued(&self) -> Option<NumHash> {
        self.last_enqueued
    }

    /// Drain all pending L1 block deposits.
    #[cfg(test)]
    pub(crate) fn drain(&mut self) -> Vec<L1BlockDeposits> {
        self.pending.drain(..).collect()
    }

    /// Returns the number of pending L1 blocks.
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    pub(crate) fn deferred_event_block_len(&self) -> usize {
        self.deferred
            .as_ref()
            .map_or(0, DeferredPortalWork::event_block_len)
    }
}

/// Shared deposit queue with notification support.
///
/// Wraps the pending deposits with a `Notify` so the ZoneEngine can be
/// woken instantly when new L1 blocks arrive.
#[derive(Debug, Clone)]
pub struct DepositQueue {
    inner: Arc<Mutex<PendingDeposits>>,
    notify: Arc<tokio::sync::Notify>,
}

impl DepositQueue {
    /// Create a new empty deposit queue.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PendingDeposits::default())),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Enqueue a finalized L1 block and notify waiters when it was appended.
    pub fn enqueue(&self, header: TempoHeader, events: L1PortalEvents) {
        self.enqueue_sealed(SealedHeader::seal_slow(header), events);
    }

    /// Enqueue an already-sealed header and report invariant violations to the
    /// caller instead of panicking.
    ///
    /// Subscriber and peer-import inputs are external, so they use this path.
    /// Returns whether the block was newly appended.
    pub fn try_enqueue_sealed(
        &self,
        header: SealedHeader<TempoHeader>,
        events: L1PortalEvents,
    ) -> eyre::Result<bool> {
        let mut queue = self.inner.lock();
        if let Some(queued) = queue
            .pending
            .iter()
            .find(|queued| queued.header.number() == header.number())
        {
            eyre::ensure!(
                queued.header.hash() == header.hash(),
                "conflicting finalized L1 block at height {}: existing={}, received={}",
                header.number(),
                queued.header.hash(),
                header.hash()
            );
            return Ok(false);
        }
        let appended = queue.try_enqueue(header, events)?;
        drop(queue);
        if appended {
            self.notify.notify_one();
        }
        Ok(appended)
    }

    /// Like [`enqueue`](Self::enqueue) but accepts an already-sealed header,
    /// avoiding a redundant hash computation.
    pub fn enqueue_sealed(
        &self,
        header: SealedHeader<TempoHeader>,
        events: L1PortalEvents,
    ) -> bool {
        let appended = self
            .inner
            .lock()
            .try_enqueue(header, events)
            .unwrap_or_else(|err| panic!("finalized L1 queue invariant violated: {err}"));
        if appended {
            self.notify.notify_one();
        }
        appended
    }

    /// Peek at the next L1 block without removing it.
    pub fn peek(&self) -> Option<L1BlockDeposits> {
        self.inner.lock().peek().cloned()
    }

    /// Peek at the next `maximum` pending L1 block headers without removing them.
    pub fn peek_headers(&self, maximum: usize) -> Vec<SealedHeader<TempoHeader>> {
        self.inner.lock().peek_headers(maximum)
    }

    /// Return the latest queued L1 header, including headers beyond a bounded checkpoint batch.
    pub fn latest_header(&self) -> Option<SealedHeader<TempoHeader>> {
        self.inner.lock().latest_header().cloned()
    }

    /// Confirm the next L1 block was successfully processed and remove it.
    ///
    pub fn confirm(&self, expected: NumHash) -> eyre::Result<L1BlockDeposits> {
        self.inner.lock().confirm(expected)
    }

    /// Idempotently move every pending block through a canonical checkpoint anchor to deferred
    /// portal work.
    pub fn defer_through(&self, expected: NumHash) -> eyre::Result<()> {
        self.inner.lock().defer_through(expected)
    }

    /// Return deferred portal work followed by the current operational L1 block.
    pub fn operational_work(&self, expected: NumHash) -> eyre::Result<Vec<L1BlockDeposits>> {
        self.inner.lock().operational_work(expected)
    }

    /// Restore portal work crossed by already-canonical checkpoint-only blocks after restart.
    pub(crate) fn restore_deferred(&self, deferred: DeferredPortalWork) -> eyre::Result<()> {
        let mut queue = self.inner.lock();
        eyre::ensure!(
            queue.pending.is_empty() && queue.deferred.is_none() && queue.last_enqueued.is_none(),
            "cannot seed deferred portal work into a nonempty queue"
        );
        queue.last_enqueued = Some(deferred.last_num_hash());
        queue.deferred = Some(deferred);
        Ok(())
    }

    /// Confirm a full operational import and release all deferred work it consumed.
    pub fn confirm_operational(&self, expected: NumHash) -> eyre::Result<()> {
        self.inner.lock().confirm_operational(expected)
    }

    /// Idempotently reconcile a canonical full import and release the deferred work it consumed.
    pub fn confirm_operational_through(&self, expected: NumHash) -> eyre::Result<()> {
        self.inner.lock().confirm_operational_through(expected)
    }

    /// Wait until an L1 block is available.
    pub async fn notified(&self) {
        self.notify.notified().await
    }

    /// Wake the queue consumer after external state makes a queued block processable.
    pub(crate) fn notify_consumer(&self) {
        self.notify.notify_one();
    }

    /// Returns the most recently enqueued L1 block (number + hash), if any.
    ///
    /// This is a high-water mark that survives `confirm` / `drain`, so it
    /// reflects the last block ever enqueued — not just what's still pending.
    pub fn last_enqueued(&self) -> Option<NumHash> {
        self.inner.lock().last_enqueued()
    }

    #[cfg(test)]
    pub(crate) fn drain(&self) -> Vec<L1BlockDeposits> {
        self.inner.lock().drain()
    }
}

impl Default for DepositQueue {
    fn default() -> Self {
        Self::new()
    }
}
