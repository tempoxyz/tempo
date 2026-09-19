use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use url::Url;

pub const TEMPO_REVISION: &str = "731535b9808eda12e81ab6459703602554eaee5a";
pub const RETH_REVISION: &str = "8e55cc5";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub run: Run,
    pub source: Source,
    pub journal: JournalConfig,
    pub checkpoint: Option<Checkpoint>,
    pub shadow: Option<Shadow>,
    #[serde(default)]
    pub timing: Timing,
    #[serde(default)]
    pub delivery: Delivery,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub metrics: Metrics,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub schema_version: u32,
    pub id: String,
    pub mode: String,
    pub chain_id: u64,
    pub tempo_revision: String,
    pub reth_revision: String,
    pub workload_profile: Option<PathBuf>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub consensus_ws: String,
    pub rpc_http: String,
    pub finality: String,
    pub fallback: String,
    pub raw_blocks: String,
    pub recovery_horizon_blocks: u64,
    pub history_probe_blocks: u64,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub manifest: PathBuf,
    pub source_height: u64,
    pub source_hash: String,
    pub shadow_hash: String,
    pub bootstrap_artifact_digest: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shadow {
    pub deployment_manifest: PathBuf,
    pub ingress_policy: String,
    pub ca_file: PathBuf,
    pub identity_check_interval_ms: u64,
    pub validators: Vec<Validator>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    pub id: String,
    pub rpc_http: String,
    pub consensus_ws: String,
    pub credential_env: String,
    pub expected_validator_public_key: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Timing {
    pub live_speed: f64,
    pub max_catch_up_speed: f64,
    pub target_lag_ms: u64,
    pub guard_ms: u64,
    pub slip_warn_ms: u64,
    pub slip_window_blocks: u64,
    pub on_sustained_slip: String,
    pub target_progress_timeout_ms: u64,
    pub expected_inclusion_latency_ms: u64,
    pub expiry_safety_margin_ms: u64,
}
impl Default for Timing {
    fn default() -> Self {
        Self {
            live_speed: 1.,
            max_catch_up_speed: 4.,
            target_lag_ms: 2000,
            guard_ms: 100,
            slip_warn_ms: 1000,
            slip_window_blocks: 20,
            on_sustained_slip: "enter_catch_up".into(),
            target_progress_timeout_ms: 30000,
            expected_inclusion_latency_ms: 1000,
            expiry_safety_margin_ms: 1000,
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Delivery {
    pub on_permanent_gap: String,
    pub first_attempt: String,
    pub nonce_dependency_gap: String,
    pub unknown_transaction: String,
    pub subblock_transaction: String,
    pub system_transaction: String,
    pub ambiguous_resend_limit: u32,
    pub dependency_wait_timeout_ms: u64,
}
impl Default for Delivery {
    fn default() -> Self {
        Self {
            on_permanent_gap: "record_gap_and_continue".into(),
            first_attempt: "all_routable_unblocked".into(),
            nonce_dependency_gap: "block_lane".into(),
            unknown_transaction: "pause_dispatch".into(),
            subblock_transaction: "pause_dispatch".into(),
            system_transaction: "record_generated_by_shadow".into(),
            ambiguous_resend_limit: 1,
            dependency_wait_timeout_ms: 30000,
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_inflight_rpc: usize,
    pub max_inflight_per_lane: usize,
    pub pool_budget_fraction: f64,
    pub max_buffered_bytes: u64,
    pub max_blocks_ahead: u64,
    pub rpc_timeout_ms: u64,
    pub max_retry_attempts: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_inflight_rpc: 128,
            max_inflight_per_lane: 8,
            pool_budget_fraction: 0.8,
            max_buffered_bytes: 268435456,
            max_blocks_ahead: 64,
            rpc_timeout_ms: 2000,
            max_retry_attempts: 5,
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalConfig {
    pub path: PathBuf,
    pub sync_writes: bool,
    pub group_commit_max_ms: u64,
    pub max_bytes: u64,
    pub min_free_bytes: u64,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Metrics {
    pub listen: String,
    pub coverage_denominator: String,
    pub gap_warn_fraction: f64,
    pub gap_window_blocks: usize,
}
impl Default for Metrics {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9090".into(),
            coverage_denominator: "all_user_occurrences".into(),
            gap_warn_fraction: 0.01,
            gap_window_blocks: 100,
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self =
            toml::from_str(&std::fs::read_to_string(path)?).context("parse configuration")?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.run.schema_version == 2 && self.run.mode == "finalized_bursts",
            "unsupported schema or run mode"
        );
        ensure!(
            !self.run.id.is_empty() && self.run.chain_id > 0,
            "run id and chain id are required"
        );
        ensure!(
            self.run.tempo_revision == TEMPO_REVISION && self.run.reth_revision == RETH_REVISION,
            "configuration differs from compiled Tempo/Reth revisions"
        );
        ensure!(
            self.source.finality == "finalized"
                && self.source.fallback == "verified_execution_layer"
                && self.source.raw_blocks == "prefer_if_verified",
            "unsupported source policy"
        );
        endpoint(&self.source.rpc_http, false)?;
        endpoint(&self.source.consensus_ws, true)?;
        ensure!(
            self.source.recovery_horizon_blocks > 0 && self.source.history_probe_blocks > 16384,
            "history probe must cross the 16384-block recent cache"
        );
        let t = &self.timing;
        let l = &self.limits;
        ensure!(
            t.live_speed == 1. && t.max_catch_up_speed.is_finite() && t.max_catch_up_speed > 1.,
            "live speed must be 1; catch-up speed must be finite and > 1"
        );
        ensure!(
            t.guard_ms > 0
                && t.slip_window_blocks > 0
                && t.target_progress_timeout_ms > 0
                && t.on_sustained_slip == "enter_catch_up",
            "invalid timing policy"
        );
        ensure!(
            l.pool_budget_fraction.is_finite()
                && l.pool_budget_fraction > 0.
                && l.pool_budget_fraction < 1.,
            "pool fraction must be in (0,1)"
        );
        ensure!(
            l.max_inflight_rpc > 0
                && l.max_inflight_per_lane > 0
                && l.max_buffered_bytes > 0
                && l.max_blocks_ahead > 0
                && l.rpc_timeout_ms > 0
                && l.max_retry_attempts > 0,
            "limits must be positive"
        );
        ensure!(
            self.journal.sync_writes
                && self.journal.max_bytes > 0
                && self.journal.group_commit_max_ms > 0,
            "durable sync writes and positive disk/group bounds required"
        );
        let d = &self.delivery;
        ensure!(
            d.on_permanent_gap == "record_gap_and_continue"
                && d.first_attempt == "all_routable_unblocked"
                && d.nonce_dependency_gap == "block_lane"
                && d.unknown_transaction == "pause_dispatch"
                && d.subblock_transaction == "pause_dispatch"
                && d.system_transaction == "record_generated_by_shadow"
                && d.ambiguous_resend_limit <= 1
                && d.dependency_wait_timeout_ms > 0,
            "unsupported delivery policy"
        );
        ensure!(
            self.metrics.coverage_denominator == "all_user_occurrences"
                && self.metrics.gap_warn_fraction.is_finite()
                && (0. ..=1.).contains(&self.metrics.gap_warn_fraction)
                && self.metrics.gap_window_blocks > 0,
            "invalid metrics policy"
        );
        self.metrics
            .listen
            .parse::<std::net::SocketAddr>()
            .context("metrics listen address")?;
        if let Some(s) = &self.shadow {
            ensure!(
                s.ingress_policy == "sticky_sender"
                    && !s.validators.is_empty()
                    && s.identity_check_interval_ms > 0,
                "invalid shadow configuration"
            );
            let mut ids = BTreeSet::new();
            let mut urls = BTreeSet::new();
            for v in &s.validators {
                ensure!(
                    ids.insert(&v.id) && urls.insert(&v.rpc_http) && !v.id.is_empty(),
                    "duplicate/empty validator identity or endpoint"
                );
                endpoint(&v.rpc_http, false)?;
                endpoint(&v.consensus_ws, true)?;
                ensure!(
                    v.rpc_http != self.source.rpc_http,
                    "source cannot be a shadow ingress"
                );
                ensure!(
                    !v.credential_env.is_empty(),
                    "validator credential environment name required"
                );
            }
        }
        Ok(())
    }
    pub fn replay(&self) -> Result<(&Checkpoint, &Shadow)> {
        Ok((
            self.checkpoint
                .as_ref()
                .context("replay requires checkpoint")?,
            self.shadow
                .as_ref()
                .context("replay requires shadow configuration")?,
        ))
    }
}
fn endpoint(value: &str, websocket: bool) -> Result<()> {
    let u = Url::parse(value).context("invalid endpoint URL")?;
    ensure!(
        u.scheme() == if websocket { "wss" } else { "https" },
        "endpoints must use authenticated TLS (https/wss)"
    );
    ensure!(
        u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none(),
        "endpoints cannot embed credentials, queries, or fragments"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub schema_version: u32,
    pub run_id: String,
    pub chain_id: u64,
    pub tempo_revision: String,
    pub reth_revision: String,
    pub bootstrap_artifact_digest: String,
    pub binary_sha256: String,
    pub chainspec_sha256: String,
    pub isolated_network: bool,
    pub exclusive_workload: bool,
    pub fork_rules_match_source: bool,
    pub fee_token_and_amm_parity: bool,
    pub validity_buffer_seconds: u64,
    pub source_capture_p99_ms: u64,
    pub measured_rpc_p99_ms: u64,
    pub measured_sustained_tps: f64,
    pub validators: Vec<ValidatorEvidence>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorEvidence {
    pub id: String,
    pub public_key: String,
    pub rpc_http: String,
    pub max_sender_slots: usize,
    pub pending_count: usize,
    pub queued_count: usize,
    pub pending_bytes: u64,
    pub queued_bytes: u64,
    pub pool_fixed_overhead_bytes: u64,
    pub pool_raw_size_multiplier: u64,
    pub future_nonce_types: Vec<u8>,
    pub pool_observation: String,
}
