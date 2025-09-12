//! Consensus related timeouts, both continuous and discrete time ("views").

use std::time::Duration;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(from = "crate::timeouts::_serde::Config")]
#[serde(into = "crate::timeouts::_serde::Config")]
pub struct Config {
    // The amount of time to wait for a peer to respond to a request.
    pub time_for_peer_response: Duration,

    /// The amount of time to wait for a quorum of notarizations in a view
    /// before attempting to skip the view.
    pub time_to_collect_notarizations: Duration,

    /// Amount of time to wait for a leader to propose a payload in a view.
    pub time_to_propose: Duration,

    /// The amount of time to wait before retrying a nullify broadcast if stuck
    /// in a view.
    pub time_to_retry_nullify_broadcast: Duration,

    /// The number of views to track. Also called an activity timeout.
    pub views_to_track: u64,

    /// The number of views until a new leader is elected. Also called a skip timeout.
    pub views_until_leader_skip: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            time_for_peer_response: Duration::from_secs(2),
            time_to_collect_notarizations: Duration::from_secs(2),
            time_to_propose: Duration::from_secs(2),
            time_to_retry_nullify_broadcast: Duration::from_secs(10),
            views_to_track: 256,
            views_until_leader_skip: 32,
        }
    }
}

impl From<_serde::Config> for Config {
    fn from(value: _serde::Config) -> Self {
        let _serde::Config {
            time_for_peer_response_ms,
            time_to_collect_notarizations_ms,
            time_to_propose_ms,
            time_to_retry_nullify_broadcast_ms,
            views_to_track,
            views_until_leader_skip,
        } = value;

        Self {
            time_for_peer_response: Duration::from_millis(time_for_peer_response_ms),
            time_to_collect_notarizations: Duration::from_millis(time_to_collect_notarizations_ms),
            time_to_propose: Duration::from_millis(time_to_propose_ms),
            time_to_retry_nullify_broadcast: Duration::from_millis(
                time_to_retry_nullify_broadcast_ms,
            ),
            views_to_track,
            views_until_leader_skip,
        }
    }
}

macro_rules! duration_to_millis {
    ($duration:expr) => {
        u64::try_from($duration.as_millis()).unwrap_or(u64::MAX)
    };
}

mod _serde {
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub(crate) struct Config {
        pub(crate) time_for_peer_response_ms: u64,
        pub(crate) time_to_collect_notarizations_ms: u64,
        pub(crate) time_to_propose_ms: u64,
        pub(crate) time_to_retry_nullify_broadcast_ms: u64,

        pub(crate) views_to_track: u64,
        pub(crate) views_until_leader_skip: u64,
    }

    impl From<super::Config> for Config {
        fn from(value: super::Config) -> Self {
            let super::Config {
                time_for_peer_response,
                time_to_collect_notarizations,
                time_to_propose,
                time_to_retry_nullify_broadcast,
                views_to_track,
                views_until_leader_skip,
            } = value;

            Self {
                time_for_peer_response_ms: duration_to_millis!(time_for_peer_response),
                time_to_collect_notarizations_ms: duration_to_millis!(
                    time_to_collect_notarizations
                ),
                time_to_propose_ms: duration_to_millis!(time_to_propose),
                time_to_retry_nullify_broadcast_ms: duration_to_millis!(
                    time_to_retry_nullify_broadcast
                ),
                views_to_track,
                views_until_leader_skip,
            }
        }
    }
}
