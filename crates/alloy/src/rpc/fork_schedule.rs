//! Tempo hardfork schedule RPC response types.

use serde::{Deserialize, Serialize};

/// Response for `tempo_forkSchedule`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkSchedule {
    /// Ordered list of Tempo-specific forks (excludes Genesis and Ethereum forks).
    pub schedule: Vec<ForkInfo>,
    /// Name of the latest active Tempo fork at the chain head.
    ///
    /// Kept as a string so clients can read schedules containing unknown hardforks.
    pub active: String,
}

impl ForkSchedule {
    /// Returns the earliest scheduled fork that is not active at the chain head.
    ///
    /// This uses the RPC's activation flags, not the local clock. Its timestamp may already
    /// have passed if the chain head is lagging. Query the schedule again to confirm activation.
    pub fn next_activation(&self) -> Option<&ForkInfo> {
        self.schedule
            .iter()
            .filter(|fork| !fork.active)
            .min_by_key(|fork| fork.activation_time)
    }
}

/// Information about a single Tempo fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkInfo {
    /// Fork name (e.g. "T0", "T1", "T2"), including forks unknown to this SDK version.
    pub name: String,
    /// Activation timestamp.
    pub activation_time: u64,
    /// Whether this fork is active at the chain head.
    pub active: bool,
    /// EIP-2124 fork hash at this fork's activation point (e.g. `"0x471a451c"`).
    /// `None` if the fork is not yet active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_roundtrip_preserves_unknown_forks_and_wire_format() {
        let json = serde_json::json!({
            "active": "T0",
            "schedule": [
                { "name": "T0", "activationTime": 0, "active": true, "forkId": "0x471a451c" },
                { "name": "FutureFork", "activationTime": 100, "active": false }
            ]
        });
        let schedule: ForkSchedule = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(schedule.schedule[0].fork_id.as_deref(), Some("0x471a451c"));
        assert_eq!(schedule.schedule[1].fork_id, None);
        assert_eq!(schedule.next_activation(), Some(&schedule.schedule[1]));
        assert_eq!(serde_json::to_value(schedule).unwrap(), json);
    }

    #[test]
    fn next_activation_uses_the_earliest_inactive_fork() {
        let mut schedule: ForkSchedule = serde_json::from_value(serde_json::json!({
            "active": "T0",
            "schedule": [
                { "name": "T0", "activationTime": 0, "active": true },
                { "name": "T2", "activationTime": 200, "active": false },
                { "name": "T1", "activationTime": 100, "active": false }
            ]
        }))
        .unwrap();

        assert_eq!(schedule.next_activation(), Some(&schedule.schedule[2]));
        schedule.schedule[2].active = true;
        assert_eq!(schedule.next_activation(), Some(&schedule.schedule[1]));
        schedule.schedule[1].active = true;
        assert_eq!(schedule.next_activation(), None);
        schedule.schedule.clear();
        assert_eq!(schedule.next_activation(), None);
    }
}
