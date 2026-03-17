use clap::ValueEnum;
use serde::Deserialize;
use std::{fmt, path::Path, time::Duration};

/// Periodic burst/spike configuration within a phase.
#[derive(Debug, Clone, Deserialize)]
pub struct BurstConfig {
    /// TPS during the burst window.
    pub tps: u64,
    /// How long each burst lasts (seconds).
    pub duration: u64,
    /// Time between burst starts (seconds). Must be > burst duration.
    pub interval: u64,
}

/// A single phase in a load profile.
#[derive(Debug, Clone, Deserialize)]
pub struct Phase {
    /// Human-readable name for logging.
    pub name: String,
    /// Target TPS at the end of this phase.
    pub target_tps: u64,
    /// How long this phase lasts.
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub duration: Duration,
    /// If true, linearly ramp from previous phase's TPS to `target_tps`.
    /// If false, jump to `target_tps` immediately.
    #[serde(default)]
    pub ramp: bool,
    /// Optional periodic burst/spike overlay.
    #[serde(default)]
    pub burst: Option<BurstConfig>,
}

fn deserialize_duration_secs<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(secs))
}

/// A load profile defines TPS over time as a sequence of phases.
#[derive(Debug, Clone, Deserialize)]
pub struct LoadProfile {
    pub phases: Vec<Phase>,
}

impl LoadProfile {
    /// Load a profile from a YAML file.
    pub fn from_file(path: &Path) -> eyre::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let profile: LoadProfile = serde_yaml::from_str(&content)?;
        eyre::ensure!(
            !profile.phases.is_empty(),
            "profile must have at least one phase"
        );
        Ok(profile)
    }

    /// Total duration across all phases.
    pub fn total_duration(&self) -> Duration {
        self.phases.iter().map(|p| p.duration).sum()
    }

    /// Expected total transactions (area under the TPS curve).
    pub fn expected_total_txs(&self) -> u64 {
        let mut total = 0.0f64;
        let mut prev_tps = 0u64;
        for phase in &self.phases {
            let secs = phase.duration.as_secs_f64();
            if let Some(burst) = &phase.burst {
                let base_tps = if phase.ramp {
                    (prev_tps as f64 + phase.target_tps as f64) / 2.0
                } else {
                    phase.target_tps as f64
                };
                let interval = burst.interval as f64;
                let burst_dur = burst.duration as f64;
                let normal_dur = interval - burst_dur;
                let full_intervals = (secs / interval).floor() as u64;
                let remainder = secs - (full_intervals as f64 * interval);
                // Full intervals
                total +=
                    full_intervals as f64 * (burst.tps as f64 * burst_dur + base_tps * normal_dur);
                // Partial last interval
                if remainder > 0.0 {
                    if remainder <= burst_dur {
                        total += burst.tps as f64 * remainder;
                    } else {
                        total += burst.tps as f64 * burst_dur + base_tps * (remainder - burst_dur);
                    }
                }
            } else if phase.ramp {
                // Trapezoid: avg of start and end TPS
                total += (prev_tps as f64 + phase.target_tps as f64) / 2.0 * secs;
            } else {
                total += phase.target_tps as f64 * secs;
            }
            prev_tps = phase.target_tps;
        }
        total.ceil() as u64
    }

    /// Maximum TPS across all phases.
    pub fn max_tps(&self) -> u64 {
        self.phases
            .iter()
            .map(|p| p.target_tps.max(p.burst.as_ref().map_or(0, |b| b.tps)))
            .max()
            .unwrap_or(0)
    }

    /// Returns the target TPS at elapsed time `t` from profile start.
    pub fn tps_at(&self, t: Duration) -> f64 {
        let mut elapsed = Duration::ZERO;
        let mut prev_tps = 0u64;

        for phase in &self.phases {
            let phase_end = elapsed + phase.duration;
            if t < phase_end {
                let base = if phase.ramp && !phase.duration.is_zero() {
                    let progress = (t - elapsed).as_secs_f64() / phase.duration.as_secs_f64();
                    let start = prev_tps as f64;
                    let end = phase.target_tps as f64;
                    start + (end - start) * progress
                } else {
                    phase.target_tps as f64
                };

                if let Some(burst) = &phase.burst {
                    let time_in_phase = (t - elapsed).as_secs_f64();
                    let cycle_pos = time_in_phase % burst.interval as f64;
                    if cycle_pos < burst.duration as f64 {
                        return burst.tps as f64;
                    }
                }

                return base;
            }
            elapsed = phase_end;
            prev_tps = phase.target_tps;
        }

        // Past the end of the profile
        0.0
    }

    /// Compute number of transactions that should have been sent between `from` and `to`.
    pub fn tx_budget_between(&self, from: Duration, to: Duration) -> f64 {
        // Numerical integration with 100ms steps
        let step = Duration::from_millis(100);
        let mut t = from;
        let mut budget = 0.0f64;
        while t < to {
            let dt = (to - t).min(step);
            let tps = self.tps_at(t + dt / 2); // midpoint for better accuracy
            budget += tps * dt.as_secs_f64();
            t += dt;
        }
        budget
    }

    /// Name of the current phase at elapsed time `t`.
    pub fn phase_at(&self, t: Duration) -> Option<&str> {
        let mut elapsed = Duration::ZERO;
        for phase in &self.phases {
            let phase_end = elapsed + phase.duration;
            if t < phase_end {
                return Some(&phase.name);
            }
            elapsed = phase_end;
        }
        None
    }
}

/// Static overrides that a scenario applies to [`MaxTpsArgs`].
/// `None` means "keep whatever the user passed (or the CLI default)".
#[derive(Default)]
pub struct ScenarioOverrides {
    pub accounts: Option<u64>,
    pub max_concurrent_requests: Option<usize>,
    pub tip20_weight: Option<f64>,
    pub erc20_weight: Option<f64>,
    pub mpp_weight: Option<f64>,
    pub place_order_weight: Option<f64>,
    pub swap_weight: Option<f64>,
    pub existing_recipients: Option<bool>,
    pub benchmark_mode: Option<String>,
}

/// Predefined benchmark scenarios.
///
/// Each scenario provides a load profile (phases) plus static overrides
/// for accounts, weights, concurrency, etc.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Scenario {
    /// 10k TPS sustained for 5 minutes.
    SustainedMax,
    /// Realistic mainnet traffic: 80% TIP-20, 15% MPP, 5% ERC-20 at 5k TPS for 5 min.
    MixedWorkload,
    /// Ramp to 10k, hold, spike to 25k, crash to 1k, recover — 10 min total.
    BurstSpike,
    /// Low TPS placeholder for future fat-batch txs.
    FatBatch,
    /// Random new recipients (cold SSTOREs). Forces disk I/O.
    StateHeavy,
    /// 50k TPS flood for 60 seconds.
    TxpoolFlood,
    /// Existing recipients, placeholder for hot-spot mode.
    Conflicting,
    /// High concurrency (500 concurrent requests).
    RpcSaturation,
    /// Full stress cycle: warm up → sustain → spike → crash → recover → sustain → cool down.
    /// ~58 minutes total.
    FullStressCycle,
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scenario::SustainedMax => write!(f, "sustained-max"),
            Scenario::MixedWorkload => write!(f, "mixed-workload"),
            Scenario::BurstSpike => write!(f, "burst-spike"),
            Scenario::FatBatch => write!(f, "fat-batch"),
            Scenario::StateHeavy => write!(f, "state-heavy"),
            Scenario::TxpoolFlood => write!(f, "txpool-flood"),
            Scenario::Conflicting => write!(f, "conflicting"),
            Scenario::RpcSaturation => write!(f, "rpc-saturation"),
            Scenario::FullStressCycle => write!(f, "full-stress-cycle"),
        }
    }
}

impl Scenario {
    /// Load profile for this scenario.
    pub fn profile(self) -> LoadProfile {
        match self {
            Scenario::SustainedMax => LoadProfile {
                phases: vec![Phase {
                    name: "sustained-max".into(),
                    target_tps: 10_000,
                    duration: Duration::from_secs(300),
                    ramp: false,
                    burst: None,
                }],
            },
            Scenario::MixedWorkload => LoadProfile {
                phases: vec![Phase {
                    name: "mixed-workload".into(),
                    target_tps: 5_000,
                    duration: Duration::from_secs(300),
                    ramp: false,
                    burst: None,
                }],
            },
            Scenario::BurstSpike => LoadProfile {
                phases: vec![
                    Phase {
                        name: "ramp-up".into(),
                        target_tps: 10_000,
                        duration: Duration::from_secs(60),
                        ramp: true,
                        burst: None,
                    },
                    Phase {
                        name: "hold".into(),
                        target_tps: 10_000,
                        duration: Duration::from_secs(120),
                        ramp: false,
                        burst: None,
                    },
                    Phase {
                        name: "spike".into(),
                        target_tps: 25_000,
                        duration: Duration::from_secs(30),
                        ramp: true,
                        burst: None,
                    },
                    Phase {
                        name: "crash-down".into(),
                        target_tps: 1_000,
                        duration: Duration::from_secs(30),
                        ramp: true,
                        burst: None,
                    },
                    Phase {
                        name: "recover".into(),
                        target_tps: 5_000,
                        duration: Duration::from_secs(180),
                        ramp: true,
                        burst: None,
                    },
                    Phase {
                        name: "sustain".into(),
                        target_tps: 5_000,
                        duration: Duration::from_secs(180),
                        ramp: false,
                        burst: None,
                    },
                ],
            },
            Scenario::FatBatch => LoadProfile {
                phases: vec![Phase {
                    name: "fat-batch".into(),
                    target_tps: 100,
                    duration: Duration::from_secs(120),
                    ramp: false,
                    burst: None,
                }],
            },
            Scenario::StateHeavy => LoadProfile {
                phases: vec![Phase {
                    name: "state-heavy".into(),
                    target_tps: 5_000,
                    duration: Duration::from_secs(120),
                    ramp: false,
                    burst: None,
                }],
            },
            Scenario::TxpoolFlood => LoadProfile {
                phases: vec![Phase {
                    name: "txpool-flood".into(),
                    target_tps: 50_000,
                    duration: Duration::from_secs(60),
                    ramp: false,
                    burst: None,
                }],
            },
            Scenario::Conflicting => LoadProfile {
                phases: vec![Phase {
                    name: "conflicting".into(),
                    target_tps: 5_000,
                    duration: Duration::from_secs(120),
                    ramp: false,
                    burst: None,
                }],
            },
            Scenario::RpcSaturation => LoadProfile {
                phases: vec![Phase {
                    name: "rpc-saturation".into(),
                    target_tps: 10_000,
                    duration: Duration::from_secs(300),
                    ramp: false,
                    burst: None,
                }],
            },
            Scenario::FullStressCycle => LoadProfile {
                phases: vec![
                    Phase {
                        name: "warm-up".into(),
                        target_tps: 2_000,
                        duration: Duration::from_secs(120),
                        ramp: true,
                        burst: None,
                    },
                    Phase {
                        name: "sustain-low".into(),
                        target_tps: 2_000,
                        duration: Duration::from_secs(600),
                        ramp: false,
                        burst: None,
                    },
                    Phase {
                        name: "ramp-up".into(),
                        target_tps: 10_000,
                        duration: Duration::from_secs(180),
                        ramp: true,
                        burst: None,
                    },
                    Phase {
                        name: "sustain-high".into(),
                        target_tps: 10_000,
                        duration: Duration::from_secs(900),
                        ramp: false,
                        burst: None,
                    },
                    Phase {
                        name: "spike".into(),
                        target_tps: 25_000,
                        duration: Duration::from_secs(30),
                        ramp: true,
                        burst: None,
                    },
                    Phase {
                        name: "crash-down".into(),
                        target_tps: 1_000,
                        duration: Duration::from_secs(30),
                        ramp: true,
                        burst: None,
                    },
                    Phase {
                        name: "sustain-low-recovery".into(),
                        target_tps: 1_000,
                        duration: Duration::from_secs(600),
                        ramp: false,
                        burst: None,
                    },
                    Phase {
                        name: "ramp-back".into(),
                        target_tps: 10_000,
                        duration: Duration::from_secs(300),
                        ramp: true,
                        burst: None,
                    },
                    Phase {
                        name: "sustain-final".into(),
                        target_tps: 10_000,
                        duration: Duration::from_secs(600),
                        ramp: false,
                        burst: None,
                    },
                    Phase {
                        name: "cooldown".into(),
                        target_tps: 0,
                        duration: Duration::from_secs(120),
                        ramp: true,
                        burst: None,
                    },
                ],
            },
        }
    }

    /// Static overrides (accounts, weights, concurrency) for this scenario.
    pub fn overrides(self) -> ScenarioOverrides {
        match self {
            Scenario::SustainedMax | Scenario::FullStressCycle => ScenarioOverrides {
                accounts: Some(200),
                max_concurrent_requests: Some(200),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some(self.to_string()),
                ..ScenarioOverrides::default()
            },
            Scenario::MixedWorkload => ScenarioOverrides {
                accounts: Some(200),
                max_concurrent_requests: Some(200),
                tip20_weight: Some(0.80),
                mpp_weight: Some(0.15),
                erc20_weight: Some(0.05),
                existing_recipients: Some(true),
                benchmark_mode: Some("mixed-workload".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::BurstSpike => ScenarioOverrides {
                accounts: Some(200),
                max_concurrent_requests: Some(200),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some("burst-spike".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::FatBatch => ScenarioOverrides {
                accounts: Some(50),
                max_concurrent_requests: Some(50),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some("fat-batch".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::StateHeavy => ScenarioOverrides {
                accounts: Some(500),
                max_concurrent_requests: Some(200),
                tip20_weight: Some(1.0),
                existing_recipients: Some(false),
                benchmark_mode: Some("state-heavy".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::TxpoolFlood => ScenarioOverrides {
                accounts: Some(500),
                max_concurrent_requests: Some(500),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some("txpool-flood".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::Conflicting => ScenarioOverrides {
                accounts: Some(500),
                max_concurrent_requests: Some(200),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some("conflicting".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::RpcSaturation => ScenarioOverrides {
                accounts: Some(200),
                max_concurrent_requests: Some(500),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some("rpc-saturation".into()),
                ..ScenarioOverrides::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_phase_tps() {
        let profile = LoadProfile {
            phases: vec![Phase {
                name: "hold".into(),
                target_tps: 5000,
                duration: Duration::from_secs(60),
                ramp: false,
                burst: None,
            }],
        };
        assert_eq!(profile.tps_at(Duration::from_secs(0)), 5000.0);
        assert_eq!(profile.tps_at(Duration::from_secs(30)), 5000.0);
        assert_eq!(profile.tps_at(Duration::from_secs(59)), 5000.0);
        assert_eq!(profile.tps_at(Duration::from_secs(60)), 0.0); // past end
    }

    #[test]
    fn test_ramp_phase_tps() {
        let profile = LoadProfile {
            phases: vec![Phase {
                name: "ramp".into(),
                target_tps: 10_000,
                duration: Duration::from_secs(100),
                ramp: true,
                burst: None,
            }],
        };
        // Ramps from 0 (implicit start) to 10k over 100s
        assert_eq!(profile.tps_at(Duration::ZERO), 0.0);
        assert_eq!(profile.tps_at(Duration::from_secs(50)), 5000.0);
        assert_eq!(profile.tps_at(Duration::from_secs(100)), 0.0); // past end
    }

    #[test]
    fn test_multi_phase_tps() {
        let profile = LoadProfile {
            phases: vec![
                Phase {
                    name: "hold-low".into(),
                    target_tps: 1000,
                    duration: Duration::from_secs(10),
                    ramp: false,
                    burst: None,
                },
                Phase {
                    name: "ramp-up".into(),
                    target_tps: 5000,
                    duration: Duration::from_secs(10),
                    ramp: true,
                    burst: None,
                },
            ],
        };
        // First phase: constant 1000
        assert_eq!(profile.tps_at(Duration::from_secs(5)), 1000.0);
        // Second phase: ramp from 1000 to 5000 over 10s
        assert_eq!(profile.tps_at(Duration::from_secs(10)), 1000.0); // start of ramp
        assert_eq!(profile.tps_at(Duration::from_secs(15)), 3000.0); // midpoint
    }

    #[test]
    fn test_expected_total_txs() {
        let profile = LoadProfile {
            phases: vec![Phase {
                name: "hold".into(),
                target_tps: 1000,
                duration: Duration::from_secs(10),
                ramp: false,
                burst: None,
            }],
        };
        assert_eq!(profile.expected_total_txs(), 10_000);
    }

    #[test]
    fn test_expected_total_txs_ramp() {
        let profile = LoadProfile {
            phases: vec![Phase {
                name: "ramp".into(),
                target_tps: 1000,
                duration: Duration::from_secs(10),
                ramp: true,
                burst: None,
            }],
        };
        // Ramp from 0 to 1000 over 10s = avg 500 * 10 = 5000
        assert_eq!(profile.expected_total_txs(), 5000);
    }

    #[test]
    fn test_full_stress_cycle_duration() {
        let profile = Scenario::FullStressCycle.profile();
        // 120 + 600 + 180 + 900 + 30 + 30 + 600 + 300 + 600 + 120 = 3480s = 58 min
        assert_eq!(profile.total_duration(), Duration::from_secs(3480));
    }

    #[test]
    fn test_phase_at() {
        let profile = LoadProfile {
            phases: vec![
                Phase {
                    name: "a".into(),
                    target_tps: 100,
                    duration: Duration::from_secs(10),
                    ramp: false,
                    burst: None,
                },
                Phase {
                    name: "b".into(),
                    target_tps: 200,
                    duration: Duration::from_secs(10),
                    ramp: false,
                    burst: None,
                },
            ],
        };
        assert_eq!(profile.phase_at(Duration::from_secs(5)), Some("a"));
        assert_eq!(profile.phase_at(Duration::from_secs(15)), Some("b"));
        assert_eq!(profile.phase_at(Duration::from_secs(20)), None);
    }

    #[test]
    fn test_max_tps() {
        let profile = Scenario::BurstSpike.profile();
        assert_eq!(profile.max_tps(), 25_000);
    }

    #[test]
    fn test_burst_tps() {
        let profile = LoadProfile {
            phases: vec![Phase {
                name: "burst-phase".into(),
                target_tps: 2000,
                duration: Duration::from_secs(60),
                ramp: false,
                burst: Some(BurstConfig {
                    tps: 20_000,
                    duration: 5,
                    interval: 30,
                }),
            }],
        };
        // t=0: in burst window (cycle_pos=0 < 5)
        assert_eq!(profile.tps_at(Duration::from_secs(0)), 20_000.0);
        // t=6: outside burst window (cycle_pos=6 >= 5)
        assert_eq!(profile.tps_at(Duration::from_secs(6)), 2000.0);
        // t=30: second burst starts (cycle_pos=0 < 5)
        assert_eq!(profile.tps_at(Duration::from_secs(30)), 20_000.0);
        // t=36: outside second burst (cycle_pos=6 >= 5)
        assert_eq!(profile.tps_at(Duration::from_secs(36)), 2000.0);
    }

    #[test]
    fn test_burst_max_tps() {
        let profile = LoadProfile {
            phases: vec![Phase {
                name: "burst-phase".into(),
                target_tps: 2000,
                duration: Duration::from_secs(60),
                ramp: false,
                burst: Some(BurstConfig {
                    tps: 20_000,
                    duration: 5,
                    interval: 30,
                }),
            }],
        };
        assert_eq!(profile.max_tps(), 20_000);
    }

    #[test]
    fn test_burst_expected_txs() {
        let profile = LoadProfile {
            phases: vec![Phase {
                name: "burst-phase".into(),
                target_tps: 2000,
                duration: Duration::from_secs(60),
                ramp: false,
                burst: Some(BurstConfig {
                    tps: 20_000,
                    duration: 5,
                    interval: 30,
                }),
            }],
        };
        // 60s / 30s interval = 2 full intervals, no remainder
        // Each interval: 5s * 20000 + 25s * 2000 = 100000 + 50000 = 150000
        // Total: 2 * 150000 = 300000
        assert_eq!(profile.expected_total_txs(), 300_000);
    }
}
