//! Consensus related timeouts, both continuous and discrete time ("views").

use std::time::Duration;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    // The amount of time to wait for a peer to respond to a request.
    #[serde(with = "humantime_serde")]
    pub time_for_peer_response: Duration,

    /// The amount of time to wait for a quorum of notarizations in a view
    /// before attempting to skip the view.
    #[serde(with = "humantime_serde")]
    pub time_to_collect_notarizations: Duration,

    /// Amount of time to wait for a leader to propose a payload in a view.
    #[serde(with = "humantime_serde")]
    pub time_to_propose: Duration,

    /// The amount of time to wait before retrying a nullify broadcast if stuck
    /// in a view.
    #[serde(with = "humantime_serde")]
    pub time_to_retry_nullify_broadcast: Duration,

    /// The number of views to track. Also called an activity timeout.
    pub views_to_track: u64,

    /// The number of views until a new leader is elected. Also called a skip timeout.
    pub views_until_leader_skip: u64,

    /// The amount of time to wait for payload builder before resolving payload.
    #[serde(with = "humantime_serde")]
    pub new_payload_wait_time: Duration,

    /// Timeout for subblock building.
    #[serde(with = "humantime_serde", default = "default_time_to_build_subblock")]
    pub time_to_build_subblock: Duration,
}

fn default_time_to_build_subblock() -> Duration {
    Duration::from_millis(100)
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
            new_payload_wait_time: Duration::from_millis(500),
            time_to_build_subblock: default_time_to_build_subblock(),
        }
    }
}
