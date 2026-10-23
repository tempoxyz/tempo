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

/// Latencies completed by one verified Zone block.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct LatencySamples {
    /// From each deposit's Tempo block to the Zone block that processed it.
    pub(crate) deposits: Vec<f64>,
    /// From each user withdrawal's Zone request to the Tempo block that processed it.
    pub(crate) withdrawals: Vec<f64>,
    /// From the request block's imported L1 reference to L1 withdrawal processing.
    pub(crate) l1_withdrawals: Vec<L1WithdrawalLatency>,
}

/// Tracks user withdrawals between their Zone request and their processing on Tempo.
///
/// Requests are matched by sender tag and kept in memory only, so withdrawals in flight across a
/// restart are not sampled.
#[derive(Debug, Default)]
pub(crate) struct LatencyTracker {
    /// Request coordinates by withdrawal sender tag.
    requested_withdrawals: BTreeMap<B256, WithdrawalRequest>,
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
                        if let Some(request) = self.requested_withdrawals.remove(sender_tag) {
                            samples.withdrawals.push(seconds_between(
                                request.zone_timestamp_millis,
                                block.timestamp_millis,
                            ));
                            if let Some((number, timestamp_millis)) = request.l1_reference
                                && let Some(blocks) = block.number.checked_sub(number)
                                && let Some(millis) =
                                    block.timestamp_millis.checked_sub(timestamp_millis)
                            {
                                samples.l1_withdrawals.push(L1WithdrawalLatency {
                                    seconds: millis as f64 / 1000.0,
                                    blocks,
                                });
                            }
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
                self.requested_withdrawals.insert(
                    *sender_tag,
                    WithdrawalRequest {
                        zone_timestamp_millis,
                        l1_reference: tempo
                            .last()
                            .map(|block| (block.number, block.timestamp_millis)),
                    },
                );
            }
        }
        samples
    }
}

/// A withdrawal's delay from its imported L1 reference to L1 processing.
#[derive(Debug, PartialEq)]
pub(crate) struct L1WithdrawalLatency {
    /// Difference between the two L1 block timestamps, in seconds.
    pub(crate) seconds: f64,
    /// Difference between the two L1 block numbers.
    pub(crate) blocks: u64,
}

/// Coordinates captured when a user requests a withdrawal.
#[derive(Debug)]
struct WithdrawalRequest {
    zone_timestamp_millis: u64,
    // No reference is available for checkpoint-only blocks, which perform no bridge work.
    l1_reference: Option<(u64, u64)>,
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
                number: 10,
                timestamp_millis: 1_000,
                events: vec![deposit(), deposit()],
            },
            L1BlockEvents {
                number: 13,
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

    #[test]
    fn user_withdrawals_are_matched_by_sender_tag() {
        let mut tracker = LatencyTracker::default();
        let first = B256::with_last_byte(1);
        let second = B256::with_last_byte(2);
        let reference = |number, timestamp_millis| L1BlockEvents {
            number,
            timestamp_millis,
            events: vec![],
        };
        tracker.observe(
            &[reference(44_982_397, 500), reference(44_982_398, 1_000)],
            &[
                requested(user(first)),
                requested(WithdrawalOrigin::DepositBounceBack),
            ],
            1_200,
        );
        tracker.observe(
            &[reference(44_982_400, 2_100)],
            &[requested(user(second))],
            2_300,
        );
        let samples = tracker.observe(
            &[L1BlockEvents {
                number: 44_982_409,
                timestamp_millis: 6_700,
                events: vec![processed(second), processed(B256::ZERO), processed(first)],
            }],
            [],
            7_000,
        );
        assert_eq!(samples.withdrawals, vec![4.4, 5.5]);
        assert_eq!(
            samples.l1_withdrawals,
            vec![
                L1WithdrawalLatency {
                    seconds: 4.6,
                    blocks: 9
                },
                L1WithdrawalLatency {
                    seconds: 5.7,
                    blocks: 11
                },
            ]
        );
        assert!(tracker.requested_withdrawals.is_empty());
    }

    #[test]
    fn l1_coordinate_boundaries() {
        for (number, timestamp_millis, expected) in [
            (9, 2_000, vec![]),
            (11, 999, vec![]),
            (
                10,
                1_000,
                vec![L1WithdrawalLatency {
                    seconds: 0.0,
                    blocks: 0,
                }],
            ),
        ] {
            let mut tracker = LatencyTracker::default();
            let tag = B256::with_last_byte(1);
            tracker.observe(
                &[L1BlockEvents {
                    number: 10,
                    timestamp_millis: 1_000,
                    events: vec![],
                }],
                &[requested(user(tag))],
                1_100,
            );
            let samples = tracker.observe(
                &[L1BlockEvents {
                    number,
                    timestamp_millis,
                    events: vec![processed(tag)],
                }],
                [],
                3_000,
            );
            assert_eq!(samples.l1_withdrawals, expected);
        }
    }
}
