//! Fork-local expiring nonce state, reconstructed from the recent block history.
//!
//! The commitment binds expiry buckets and the replay IDs in their inclusion order.
//! Each bucket has an incremental hash chain; finalizing a block hashes only the
//! live bucket summaries, rather than every live ID. Persistent collections make
//! snapshots cheap and isolate speculative blocks, reorgs, and rejected transactions.
//!
//! # State transition
//!
//! At the beginning of a block, remove buckets with `expiry <= block.timestamp`.
//! Validate each replay ID against the live map, but insert it only when its
//! transaction is included, including EVM reverts. Discarded execution must not
//! consume IDs. Never evict a live ID to make room; reject at the live-set limit.
//!
//! The bucket digest is `keccak256(bucket_domain || previous_digest || replay_id)`,
//! starting from zero. The state root is `keccak256(state_domain || summaries)`,
//! with summaries in ascending expiry order. Each summary is the big-endian u64
//! expiry, big-endian u64 count, and 32-byte bucket digest. The domain strings are
//! versioned below. Inclusion order within each expiry bucket is consensus data.
//!
//! # Durability
//!
//! No per-ID persistence or EVM storage is necessary: block bodies already persist
//! the signed replay IDs and expiries. Rebuild in inclusion order from the last
//! 300 seconds on the requested branch, discard already-expired IDs, and verify
//! the resulting root against that branch's header. Missing history must fail
//! closed. Raising the protocol validity window requires raising the history
//! bound too. This backend is an STF change and requires a fresh chain or an
//! explicit migration of the old nonce-precompile state.

use alloy_primitives::{B256, Keccak256};
use imbl::{HashMap, OrdMap, Vector};

pub mod diagnostics;
use diagnostics::{Sample, Timer};

/// Maximum history required to reconstruct replay protection (TIP-1093).
pub const MAX_EXPIRY_SECS: u64 = 300;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Bucket {
    ids: Vector<B256>,
    digest: B256,
}

/// Replay protection state. Clone before advancing to another block or fork.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ExpiringNonceState {
    seen: HashMap<B256, u64>,
    buckets: OrdMap<u64, Bucket>,
    timestamp: u64,
}

impl core::fmt::Debug for ExpiringNonceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExpiringNonceState")
            .field("timestamp", &self.timestamp)
            .field("live_ids", &self.seen.len())
            .field("expiry_buckets", &self.buckets.len())
            .finish()
    }
}

/// A nonce update that cannot be applied to the current state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceError {
    /// The replay ID is still live.
    Replay,
    /// The expiry is not in the permitted interval.
    Expiry,
    /// Block time regressed. Restore an ancestor snapshot instead.
    TimestampRegression,
    /// The maximum number of live replay IDs was reached.
    Capacity,
}

impl core::fmt::Display for NonceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Replay => "expiring nonce replay",
            Self::Expiry => "invalid expiring nonce expiry",
            Self::TimestampRegression => "expiring nonce timestamp regression",
            Self::Capacity => "expiring nonce set full",
        })
    }
}

impl std::error::Error for NonceError {}

impl ExpiringNonceState {
    /// Number of live IDs.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the state contains no live IDs.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Drops expired buckets. This must precede validation at a new block time.
    pub fn advance(&mut self, timestamp: u64) -> Result<(), NonceError> {
        let _timer = Timer::start("advance");
        let started = std::time::Instant::now();
        let live_before = self.len();
        let mut expired = 0;
        let mut buckets = 0;
        if timestamp < self.timestamp {
            return Err(NonceError::TimestampRegression);
        }
        while let Some(expiry) = self.buckets.get_min().map(|(expiry, _)| *expiry) {
            if expiry > timestamp {
                break;
            }
            let bucket = self.buckets.remove(&expiry).expect("bucket exists");
            let _bucket_timer = Timer::start("expire_bucket");
            expired += bucket.ids.len();
            buckets += 1;
            for id in bucket.ids {
                self.seen.remove(&id);
            }
        }
        self.timestamp = timestamp;
        diagnostics::items("expired_ids", expired);
        diagnostics::items("expired_buckets", buckets);
        diagnostics::items("live_ids", self.len());
        if started.elapsed().as_millis() >= 10 {
            tracing::info!(target: "tempo::expiring_nonces", timestamp, live_before, expired, buckets,
                elapsed_ms = started.elapsed().as_secs_f64() * 1000.0, "Expiring nonce expiry batch");
        }
        Ok(())
    }

    /// Validates without consuming an ID. Invalid and discarded transactions do not mutate state.
    pub fn check(
        &self,
        id: B256,
        expiry: u64,
        max_expiry: u64,
        capacity: usize,
    ) -> Result<(), NonceError> {
        let mut timer = Timer::sampled(Sample::Check);
        if expiry <= self.timestamp
            || expiry
                > self
                    .timestamp
                    .saturating_add(max_expiry.min(MAX_EXPIRY_SECS))
        {
            return Err(NonceError::Expiry);
        }
        let mut membership = Timer::sampled(Sample::Membership);
        let seen = self.seen.contains_key(&id);
        Timer::stop_sample(&mut membership);
        let result = if seen {
            Err(NonceError::Replay)
        } else if self.len() >= capacity {
            Err(NonceError::Capacity)
        } else {
            Ok(())
        };
        Timer::stop_sample(&mut timer);
        result
    }

    /// Validates against an RPC timestamp override without modifying the snapshot.
    /// Normal execution uses the snapshot's timestamp and needs no extra copy.
    pub fn check_at(
        &self,
        timestamp: u64,
        id: B256,
        expiry: u64,
        max_expiry: u64,
        capacity: usize,
    ) -> Result<(), NonceError> {
        if timestamp == self.timestamp {
            return self.check(id, expiry, max_expiry, capacity);
        }
        let _timer = Timer::start("check_timestamp_override");
        let mut state = self.clone();
        state.advance(timestamp)?;
        state.check(id, expiry, max_expiry, capacity)
    }

    /// Records an included transaction, including transactions whose EVM calls reverted.
    pub fn insert(
        &mut self,
        id: B256,
        expiry: u64,
        max_expiry: u64,
        capacity: usize,
    ) -> Result<(), NonceError> {
        diagnostics::check_site(diagnostics::CheckSite::Insert);
        self.check(id, expiry, max_expiry, capacity)?;
        let mut sample = Timer::sampled(Sample::Insert);
        let mut index_stage = Timer::substage(&sample, "index_insert");
        self.seen.insert(id, expiry);
        Timer::stop_sample(&mut index_stage);
        let mut cow_stage = Timer::substage(&sample, "bucket_cow");
        let bucket = self.buckets.entry(expiry).or_default();
        Timer::stop_sample(&mut cow_stage);
        let mut hash_stage = Timer::substage(&sample, "commitment_update");
        let mut hash = Keccak256::new();
        hash.update(b"tempo.expiring-nonce.bucket.v1");
        hash.update(bucket.digest);
        hash.update(id);
        bucket.digest = hash.finalize();
        Timer::stop_sample(&mut hash_stage);
        let mut append_stage = Timer::substage(&sample, "bucket_append");
        bucket.ids.push_back(id);
        Timer::stop_sample(&mut append_stage);
        Timer::stop_sample(&mut sample);
        Ok(())
    }

    /// Deterministic commitment to all live replay IDs, their expiries and per-bucket order.
    pub fn root(&self) -> B256 {
        diagnostics::items("root_buckets", self.buckets.len());
        let _timer = Timer::start("root_aggregation");
        let mut hash = Keccak256::new();
        hash.update(b"tempo.expiring-nonce.state.v1");
        for (expiry, bucket) in &self.buckets {
            hash.update(expiry.to_be_bytes());
            hash.update((bucket.ids.len() as u64).to_be_bytes());
            hash.update(bucket.digest);
        }
        hash.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn matches_reference_model(operations in prop::collection::vec((0u8..40, 1u64..301, 0u64..4), 1..500)) {
            let mut state = ExpiringNonceState::default();
            let mut reference = std::collections::HashMap::new();
            let mut now = 0;
            for (id, lifetime, elapsed) in operations {
                now += elapsed;
                state.advance(now).unwrap();
                reference.retain(|_, expiry| *expiry > now);
                let id = B256::repeat_byte(id);
                let expected = if reference.contains_key(&id) { Err(NonceError::Replay) } else { Ok(()) };
                prop_assert_eq!(state.insert(id, now + lifetime, 300, 100), expected);
                if expected.is_ok() { reference.insert(id, now + lifetime); }
                prop_assert_eq!(state.len(), reference.len());
            }
        }
    }

    #[test]
    fn expiry_boundary_and_replay() {
        let mut state = ExpiringNonceState::default();
        state.advance(100).unwrap();
        let id = B256::repeat_byte(1);
        state.insert(id, 130, 300, 10).unwrap();
        assert_eq!(state.insert(id, 140, 300, 10), Err(NonceError::Replay));
        state.advance(129).unwrap();
        assert_eq!(state.check(id, 140, 300, 10), Err(NonceError::Replay));
        state.advance(130).unwrap();
        assert!(state.is_empty());
        assert_eq!(state.check(id, 130, 300, 10), Err(NonceError::Expiry));
        state.insert(id, 140, 300, 10).unwrap();
    }

    #[test]
    fn forks_and_discarded_execution_are_isolated() {
        let mut parent = ExpiringNonceState::default();
        parent.advance(100).unwrap();
        parent.insert(B256::repeat_byte(1), 120, 300, 10).unwrap();
        let root = parent.root();
        let mut child = parent.clone();
        child.advance(120).unwrap();
        child.insert(B256::repeat_byte(2), 130, 300, 10).unwrap();
        assert_eq!(parent.root(), root);
        assert_eq!(
            parent.check(B256::repeat_byte(1), 130, 300, 10),
            Err(NonceError::Replay)
        );
        assert!(parent.check(B256::repeat_byte(2), 130, 300, 10).is_ok());
        assert_ne!(child.root(), root);
    }

    #[test]
    fn simulation_time_overrides_expire_a_private_snapshot() {
        let mut state = ExpiringNonceState::default();
        state.advance(100).unwrap();
        state.insert(B256::ZERO, 110, 300, 1).unwrap();
        let before = state.clone();
        assert_eq!(
            state.check_at(110, B256::repeat_byte(1), 410, 300, 1),
            Ok(())
        );
        assert_eq!(state, before);
        assert_eq!(
            state.check(B256::ZERO, 120, 300, 1),
            Err(NonceError::Replay)
        );
    }

    #[test]
    fn failed_updates_are_atomic_and_live_entries_are_never_evicted() {
        let mut state = ExpiringNonceState::default();
        state.advance(100).unwrap();
        state.insert(B256::ZERO, 101, 300, 1).unwrap();
        let before = state.clone();
        assert_eq!(
            state.insert(B256::repeat_byte(1), 102, 300, 1),
            Err(NonceError::Capacity)
        );
        assert_eq!(
            state.insert(B256::repeat_byte(1), 401, 300, 2),
            Err(NonceError::Expiry)
        );
        assert_eq!(state.advance(99), Err(NonceError::TimestampRegression));
        assert_eq!(state, before);
    }

    #[test]
    fn commitment_binds_expiry_and_bucket_order() {
        let mut a = ExpiringNonceState::default();
        a.insert(B256::repeat_byte(1), 10, 300, 10).unwrap();
        a.insert(B256::repeat_byte(2), 10, 300, 10).unwrap();
        let mut b = ExpiringNonceState::default();
        b.insert(B256::repeat_byte(2), 10, 300, 10).unwrap();
        b.insert(B256::repeat_byte(1), 10, 300, 10).unwrap();
        assert_ne!(a.root(), b.root());
        let mut c = ExpiringNonceState::default();
        c.insert(B256::repeat_byte(1), 11, 300, 10).unwrap();
        c.insert(B256::repeat_byte(2), 11, 300, 10).unwrap();
        assert_ne!(a.root(), c.root());
        a.advance(10).unwrap();
        assert_eq!(a.root(), ExpiringNonceState::default().root());
    }
}
