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
//! Validate each replay ID against its expiry bucket, but insert it only when its
//! transaction is included, including EVM reverts. Discarded execution must not
//! consume IDs. Never evict a live ID to make room; reject at the live-set limit.
//! Replay IDs must cryptographically commit to their expiry, as Tempo's transaction
//! identifiers do. Callers must derive both values from the same authenticated transaction. This
//! allows membership checks within one bucket and expiry of whole buckets without
//! a second index or per-ID removals.
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
use imbl::{HashSet, OrdMap};

/// Maximum history required to reconstruct replay protection (TIP-1093).
pub const MAX_EXPIRY_SECS: u64 = 300;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Bucket {
    ids: HashSet<B256>,
    digest: B256,
}

/// Replay protection state. Clone before advancing to another block or fork.
/// Replay IDs must commit to their expiry; derive both from the same authenticated transaction.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ExpiringNonceState {
    buckets: OrdMap<u64, Bucket>,
    live_ids: usize,
    timestamp: u64,
}

impl core::fmt::Debug for ExpiringNonceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExpiringNonceState")
            .field("timestamp", &self.timestamp)
            .field("live_ids", &self.live_ids)
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
    /// Block timestamp at which this snapshot's expiry rules were applied.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Number of live IDs.
    pub fn len(&self) -> usize {
        self.live_ids
    }

    /// Whether the state contains no live IDs.
    pub fn is_empty(&self) -> bool {
        self.live_ids == 0
    }

    /// Drops expired buckets. This must precede validation at a new block time.
    pub fn advance(&mut self, timestamp: u64) -> Result<(), NonceError> {
        if timestamp < self.timestamp {
            return Err(NonceError::TimestampRegression);
        }
        if self
            .buckets
            .get_max()
            .is_some_and(|(expiry, _)| *expiry <= timestamp)
        {
            // Detach the entire map when no buckets survive.
            self.buckets.clear();
            self.live_ids = 0;
        } else {
            while let Some(expiry) = self.buckets.get_min().map(|(expiry, _)| *expiry) {
                if expiry > timestamp {
                    break;
                }
                let bucket = self.buckets.remove(&expiry).expect("bucket exists");
                self.live_ids -= bucket.ids.len();
            }
        }
        self.timestamp = timestamp;
        Ok(())
    }

    /// Validates without consuming an ID. Invalid and discarded transactions do not mutate state.
    /// The replay ID must commit to `expiry`; derive both from the same authenticated transaction.
    pub fn check(
        &self,
        id: B256,
        expiry: u64,
        max_expiry: u64,
        capacity: usize,
    ) -> Result<(), NonceError> {
        if expiry <= self.timestamp
            || expiry
                > self
                    .timestamp
                    .saturating_add(max_expiry.min(MAX_EXPIRY_SECS))
        {
            return Err(NonceError::Expiry);
        }
        if self
            .buckets
            .get(&expiry)
            .is_some_and(|bucket| bucket.ids.contains(&id))
        {
            Err(NonceError::Replay)
        } else if self.len() >= capacity {
            Err(NonceError::Capacity)
        } else {
            Ok(())
        }
    }

    /// Validates against an RPC timestamp override without modifying the snapshot.
    /// Normal execution uses the snapshot's timestamp and needs no extra copy.
    /// Requires the same ID/expiry binding as [`Self::check`].
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
        let mut state = self.clone();
        state.advance(timestamp)?;
        state.check(id, expiry, max_expiry, capacity)
    }

    /// Records an included transaction, including transactions whose EVM calls reverted.
    /// Requires the same ID/expiry binding as [`Self::check`].
    pub fn insert(
        &mut self,
        id: B256,
        expiry: u64,
        max_expiry: u64,
        capacity: usize,
    ) -> Result<(), NonceError> {
        self.check(id, expiry, max_expiry, capacity)?;
        let bucket = self.buckets.entry(expiry).or_default();
        let mut hash = Keccak256::new();
        hash.update(b"tempo.expiring-nonce.bucket.v1");
        hash.update(bucket.digest);
        hash.update(id);
        bucket.digest = hash.finalize();
        bucket.ids.insert(id);
        self.live_ids += 1;
        Ok(())
    }

    /// Deterministic commitment to all live replay IDs, their expiries and per-bucket order.
    pub fn root(&self) -> B256 {
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
    use alloy_primitives::b256;
    use proptest::prelude::*;

    fn replay_id(nonce: u64, expiry: u64) -> B256 {
        let mut hash = Keccak256::new();
        hash.update(nonce.to_be_bytes());
        hash.update(expiry.to_be_bytes());
        hash.finalize()
    }

    #[test]
    fn commitment_encoding_is_stable() {
        let mut state = ExpiringNonceState::default();
        state.advance(100).unwrap();
        assert_eq!(
            state.root(),
            b256!("0437898620ea8e67dcdce33b8994347e15ea4d82044866337f2e889b9a40448d")
        );
        for (nonce, expiry) in [(1, 110), (2, 120), (3, 110)] {
            state
                .insert(replay_id(nonce, expiry), expiry, 300, 10)
                .unwrap();
        }
        assert_eq!(
            state.root(),
            b256!("9cae1d540a5af2d52af1533282a66c72a9d835309df7abacdf0e3ed87e4b0794")
        );
        state.advance(110).unwrap();
        assert_eq!(
            state.root(),
            b256!("d068cb67257d9f18650afcb230aa9a43c4b1bf6008dda1719cfbb87109c576db")
        );
    }

    proptest! {
        #[test]
        fn matches_reference_model(operations in prop::collection::vec((0u8..40, 1u64..301, 0u64..4), 1..500)) {
            let mut state = ExpiringNonceState::default();
            let mut reference = std::collections::HashMap::new();
            let mut expiries = std::collections::HashMap::new();
            let mut now = 0;
            for (nonce, lifetime, elapsed) in operations {
                now += elapsed;
                state.advance(now).unwrap();
                reference.retain(|_, expiry| *expiry > now);
                // Keep two expiry variants per nonce so both live replays and
                // distinct transactions with the same nonce are exercised.
                let expiry = *expiries.entry((nonce, lifetime % 2)).and_modify(|expiry| {
                    if *expiry <= now { *expiry = now + lifetime; }
                }).or_insert(now + lifetime);
                let id = replay_id(u64::from(nonce), expiry);
                let expected = if reference.contains_key(&id) {
                    Err(NonceError::Replay)
                } else if reference.len() >= 30 {
                    Err(NonceError::Capacity)
                } else {
                    Ok(())
                };
                prop_assert_eq!(state.insert(id, expiry, 300, 30), expected);
                if expected.is_ok() { reference.insert(id, expiry); }
                prop_assert_eq!(state.len(), reference.len());
            }
        }
    }

    #[test]
    fn expiry_boundary_and_replay() {
        let mut state = ExpiringNonceState::default();
        state.advance(100).unwrap();
        let id = replay_id(1, 130);
        state.insert(id, 130, 300, 10).unwrap();
        assert_eq!(state.insert(id, 130, 300, 10), Err(NonceError::Replay));
        state.advance(129).unwrap();
        assert_eq!(state.check(id, 130, 300, 10), Err(NonceError::Replay));
        state.advance(130).unwrap();
        assert!(state.is_empty());
        assert_eq!(state.check(id, 130, 300, 10), Err(NonceError::Expiry));
        state.insert(replay_id(1, 140), 140, 300, 10).unwrap();
    }

    #[test]
    fn expiry_bursts_preserve_survivors_commitment_and_parent() {
        for expired in [10, 90, 100] {
            let mut parent = ExpiringNonceState::default();
            parent.advance(100).unwrap();
            for nonce in 0..100 {
                let expiry = if nonce < expired { 110 } else { 120 };
                parent
                    .insert(replay_id(nonce, expiry), expiry, 300, 100)
                    .unwrap();
            }
            let parent_root = parent.root();
            let mut child = parent.clone();
            child.advance(110).unwrap();
            let mut reconstructed = ExpiringNonceState::default();
            reconstructed.advance(110).unwrap();
            for nonce in 0..100 {
                let expiry = if nonce < expired { 110 } else { 120 };
                let id = replay_id(nonce, expiry);
                if nonce < expired {
                    assert_eq!(child.check(id, expiry, 300, 100), Err(NonceError::Expiry));
                    assert!(child.check(replay_id(nonce, 130), 130, 300, 100).is_ok());
                } else {
                    assert_eq!(child.check(id, expiry, 300, 100), Err(NonceError::Replay));
                    reconstructed.insert(id, expiry, 300, 100).unwrap();
                }
                assert_eq!(parent.check(id, expiry, 300, 100), Err(NonceError::Replay));
            }
            assert_eq!(child, reconstructed);
            assert_eq!(child.root(), reconstructed.root());
            let child_id = replay_id(100, 130);
            child.insert(child_id, 130, 300, 100).unwrap();
            assert!(parent.check(child_id, 130, 300, 101).is_ok());
            assert_eq!(parent.root(), parent_root);
        }
    }

    #[test]
    fn simulation_time_overrides_expire_a_private_snapshot() {
        let mut state = ExpiringNonceState::default();
        state.advance(100).unwrap();
        let id = replay_id(0, 110);
        state.insert(id, 110, 300, 1).unwrap();
        let before = state.clone();
        assert_eq!(state.check_at(110, replay_id(1, 410), 410, 300, 1), Ok(()));
        assert_eq!(state, before);
        assert_eq!(state.check(id, 110, 300, 1), Err(NonceError::Replay));
    }

    #[test]
    fn failed_updates_are_atomic_and_live_entries_are_never_evicted() {
        let mut state = ExpiringNonceState::default();
        state.advance(100).unwrap();
        state.insert(replay_id(0, 101), 101, 300, 1).unwrap();
        let before = state.clone();
        assert_eq!(
            state.insert(replay_id(1, 102), 102, 300, 1),
            Err(NonceError::Capacity)
        );
        assert_eq!(
            state.insert(replay_id(1, 401), 401, 300, 2),
            Err(NonceError::Expiry)
        );
        assert_eq!(state.advance(99), Err(NonceError::TimestampRegression));
        assert_eq!(state, before);
    }

    #[test]
    fn commitment_binds_expiry_and_bucket_order() {
        let mut a = ExpiringNonceState::default();
        a.insert(replay_id(1, 10), 10, 300, 10).unwrap();
        a.insert(replay_id(2, 10), 10, 300, 10).unwrap();
        let mut b = ExpiringNonceState::default();
        b.insert(replay_id(2, 10), 10, 300, 10).unwrap();
        b.insert(replay_id(1, 10), 10, 300, 10).unwrap();
        assert_ne!(a.root(), b.root());
        let mut c = ExpiringNonceState::default();
        c.insert(replay_id(1, 11), 11, 300, 10).unwrap();
        c.insert(replay_id(2, 11), 11, 300, 10).unwrap();
        assert_ne!(a.root(), c.root());
        a.advance(10).unwrap();
        assert_eq!(a.root(), ExpiringNonceState::default().root());
    }
}
