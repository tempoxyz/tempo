//! Deposit and withdrawal latencies derived from verified bridge evidence.

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::B256;

use crate::{
    l1::{L1BlockEvents, L1PortalEvent},
    l2::{L2BridgeAction, WithdrawalOrigin},
};

/// Zone blocks older than this are verified without recording latency samples, so rebuilds and
/// catch-up do not replay history into live metrics.
const MAX_SAMPLE_AGE: Duration = Duration::from_secs(10 * 60);

/// Latencies completed by one verified Zone block, in seconds.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct LatencySamples {
    /// From each deposit's Tempo block to the Zone block that processed it.
    pub(crate) deposits: Vec<f64>,
    /// From each user withdrawal's Zone request to the Tempo block that processed it.
    pub(crate) withdrawals: Vec<f64>,
}

/// Tracks user withdrawals between their Zone request and their processing on Tempo.
///
/// Requests are matched by sender tag and kept in memory only, so withdrawals in flight across a
/// restart are not sampled.
#[derive(Debug, Default)]
pub(crate) struct LatencyTracker {
    /// Request timestamp in milliseconds by withdrawal sender tag.
    requested_withdrawals: BTreeMap<B256, u64>,
}

impl LatencyTracker {
    /// Track one verified Zone block and return the latencies it completed.
    ///
    /// `tempo` holds the Tempo blocks imported by the Zone block, whose deposits it processed.
    pub(crate) fn observe<'a>(
        &mut self,
        tempo: &[L1BlockEvents],
        zone_actions: impl IntoIterator<Item = &'a L2BridgeAction>,
        zone_timestamp_millis: u64,
    ) -> LatencySamples {
        let mut samples = LatencySamples::default();
        for block in tempo {
            for event in &block.events {
                match event {
                    L1PortalEvent::DepositMade { .. } => samples.deposits.push(seconds_between(
                        block.timestamp_millis,
                        zone_timestamp_millis,
                    )),
                    L1PortalEvent::WithdrawalProcessed { sender_tag, .. } => {
                        if let Some(requested_at) = self.requested_withdrawals.remove(sender_tag) {
                            samples
                                .withdrawals
                                .push(seconds_between(requested_at, block.timestamp_millis));
                        }
                    }
                    _ => {}
                }
            }
        }
        for action in zone_actions {
            if let L2BridgeAction::WithdrawalRequested {
                origin: WithdrawalOrigin::User { sender_tag, .. },
                ..
            } = action
            {
                self.requested_withdrawals
                    .insert(*sender_tag, zone_timestamp_millis);
            }
        }
        samples
    }
}

/// Whether a Zone block is recent enough for its latency samples to be recorded.
pub(crate) fn is_recent(timestamp_millis: u64) -> bool {
    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    now_millis.saturating_sub(timestamp_millis) <= MAX_SAMPLE_AGE.as_millis() as u64
}

fn seconds_between(from_millis: u64, to_millis: u64) -> f64 {
    to_millis.saturating_sub(from_millis) as f64 / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};

    fn deposit() -> L1PortalEvent {
        L1PortalEvent::DepositMade {
            token: Address::ZERO,
            net_amount: 1,
        }
    }

    fn processed(sender_tag: B256) -> L1PortalEvent {
        L1PortalEvent::WithdrawalProcessed {
            sender_tag,
            token: Address::ZERO,
            amount: 1,
            callback_success: true,
        }
    }

    fn requested(origin: WithdrawalOrigin) -> L2BridgeAction {
        L2BridgeAction::WithdrawalRequested {
            withdrawal_index: 0,
            origin,
            token: Address::ZERO,
            principal: U256::from(1),
            fee: U256::ZERO,
        }
    }

    fn user(sender_tag: B256) -> WithdrawalOrigin {
        WithdrawalOrigin::User {
            sender: Address::with_last_byte(1),
            sender_tag,
        }
    }

    #[test]
    fn deposits_are_measured_from_their_tempo_block() {
        let mut tracker = LatencyTracker::default();
        let tempo = [
            L1BlockEvents {
                timestamp_millis: 1_000,
                events: vec![deposit(), deposit()],
            },
            L1BlockEvents {
                timestamp_millis: 2_500,
                events: vec![
                    deposit(),
                    L1PortalEvent::TokenEnabled {
                        token: Address::ZERO,
                    },
                ],
            },
        ];

        let samples = tracker.observe(&tempo, [], 4_000);

        assert_eq!(samples.deposits, vec![3.0, 3.0, 1.5]);
        assert!(samples.withdrawals.is_empty());
    }

    #[test]
    fn user_withdrawals_are_matched_by_sender_tag() {
        let mut tracker = LatencyTracker::default();
        let first = B256::with_last_byte(1);
        let second = B256::with_last_byte(2);
        let samples = tracker.observe(
            &[],
            &[
                requested(user(first)),
                requested(WithdrawalOrigin::DepositBounceBack),
            ],
            1_000,
        );
        assert_eq!(samples, LatencySamples::default());
        tracker.observe(&[], &[requested(user(second))], 2_000);

        // Processing order and unknown tags must not affect the pairing.
        let tempo = [L1BlockEvents {
            timestamp_millis: 7_000,
            events: vec![
                processed(second),
                processed(B256::with_last_byte(3)),
                processed(first),
            ],
        }];
        let samples = tracker.observe(&tempo, [], 8_000);

        assert_eq!(samples.withdrawals, vec![5.0, 6.0]);
        assert!(tracker.requested_withdrawals.is_empty());
    }

    #[test]
    fn only_recent_blocks_are_sampled() {
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert!(is_recent(now_millis));
        assert!(!is_recent(
            now_millis - MAX_SAMPLE_AGE.as_millis() as u64 - 1_000
        ));
    }
}
