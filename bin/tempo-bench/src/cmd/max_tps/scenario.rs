use clap::ValueEnum;
use std::fmt;

/// Predefined benchmark scenarios for stress testing.
///
/// Each scenario overrides specific CLI defaults (TPS, duration, weights, concurrency, etc.)
/// while still allowing individual flags to take precedence.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Scenario {
    /// 10k TPS sustained for 5 minutes. Tests txpool backlog and drain behavior
    /// when ingress exceeds processing capacity.
    SustainedMax,

    /// Realistic mainnet traffic: 80% TIP-20, 15% MPP, 5% ERC-20 at 5k TPS for 5 minutes.
    MixedWorkload,

    /// 1k TPS baseline → instant spike to 10k TPS → back to 1k.
    /// Tests txpool elasticity and recovery.
    BurstSpike,

    /// Low TPS with existing recipients — placeholder for future fat-batch tx generator
    /// that targets 30M gas cap per tx. Currently sends normal TIP-20 transfers at low TPS.
    FatBatch,

    /// Transactions to random new addresses (cold SSTOREs for account creation).
    /// Forces disk I/O and state growth, breaking the in-memory fast path.
    StateHeavy,

    /// 50k TPS flood of cheap TIP-20 transfers for 60 seconds.
    /// Tests txpool memory limits and OOM resilience.
    TxpoolFlood,

    /// Transfers to existing signer addresses from many accounts.
    /// Placeholder for future hot-spot recipient mode that forces serial state access.
    /// Currently uses random existing recipients from the signer set.
    Conflicting,

    /// 10k TPS with high concurrency (500 concurrent requests).
    /// Use multiple `--target-urls` for full RPC saturation effect.
    RpcSaturation,
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
        }
    }
}

/// Overrides that a scenario applies to [`MaxTpsArgs`].
/// `None` means "keep whatever the user passed (or the CLI default)".
#[derive(Default)]
pub struct ScenarioOverrides {
    pub tps: Option<u64>,
    pub duration: Option<u64>,
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

impl Scenario {
    pub fn overrides(self) -> ScenarioOverrides {
        match self {
            Scenario::SustainedMax => ScenarioOverrides {
                tps: Some(10_000),
                duration: Some(300),
                accounts: Some(200),
                max_concurrent_requests: Some(200),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some("sustained-max".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::MixedWorkload => ScenarioOverrides {
                tps: Some(5_000),
                duration: Some(300),
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
                // The burst is emulated by running at 10k TPS for a short window.
                // A real multi-phase ramp requires orchestrator changes;
                // for now, the spike phase is the interesting part.
                tps: Some(10_000),
                duration: Some(30),
                accounts: Some(200),
                max_concurrent_requests: Some(200),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some("burst-spike".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::FatBatch => ScenarioOverrides {
                // Lower TPS because each tx is huge (~30M gas).
                tps: Some(100),
                duration: Some(120),
                accounts: Some(50),
                max_concurrent_requests: Some(50),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some("fat-batch".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::StateHeavy => ScenarioOverrides {
                tps: Some(5_000),
                duration: Some(120),
                accounts: Some(500),
                max_concurrent_requests: Some(200),
                tip20_weight: Some(1.0),
                // Random recipients = cold SSTOREs for new accounts
                existing_recipients: Some(false),
                benchmark_mode: Some("state-heavy".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::TxpoolFlood => ScenarioOverrides {
                tps: Some(50_000),
                duration: Some(60),
                accounts: Some(500),
                max_concurrent_requests: Some(500),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some("txpool-flood".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::Conflicting => ScenarioOverrides {
                tps: Some(5_000),
                duration: Some(120),
                accounts: Some(500),
                max_concurrent_requests: Some(200),
                tip20_weight: Some(1.0),
                existing_recipients: Some(true),
                benchmark_mode: Some("conflicting".into()),
                ..ScenarioOverrides::default()
            },
            Scenario::RpcSaturation => ScenarioOverrides {
                tps: Some(10_000),
                duration: Some(300),
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
