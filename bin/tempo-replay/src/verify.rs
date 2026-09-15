use crate::{
    config::*,
    model::{CapturedBlock, Point},
    profile::Profile,
    rpc::Rpc,
};
use alloy_primitives::{B256, keccak256};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone)]
pub struct Target {
    pub id: String,
    pub rpc: Rpc,
    pub evidence: ValidatorEvidence,
}
#[derive(Clone)]
pub struct Qualified {
    pub targets: Vec<Target>,
    pub deployment: Deployment,
    pub binding: String,
    pub sender_budget: usize,
    pub count_budget: usize,
    pub byte_budget: u64,
    pub overhead: u64,
    pub multiplier: u64,
}
#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub run_id: String,
    pub boundary: u64,
    pub binding: String,
    pub targets: usize,
    pub source_finalized: Point,
    pub sender_budget: usize,
    pub count_budget: usize,
    pub byte_budget: u64,
    pub measured_sustained_tps: f64,
    pub profile_mean_tps: Option<f64>,
    pub mode: VerificationMode,
    pub warnings: Vec<String>,
}
#[derive(Deserialize)]
struct NativeManifest {
    source_chain_id: u64,
    shadow_chain_id: u64,
    fork_block_number: u64,
    fork_block_hash: B256,
    fork_state_root: B256,
    validators: Vec<NativeValidator>,
}
#[derive(Deserialize)]
struct NativeValidator {
    validator_public_key: B256,
}
pub fn source_rpc(c: &Config) -> Result<Rpc> {
    Rpc::new(
        &c.source.rpc_http,
        c.limits.rpc_timeout_ms,
        c.limits.max_buffered_bytes,
        None,
        None,
    )
}
pub fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn valid_digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|v| v.len() == 64 && hex::decode(v).is_ok())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMode {
    Live,
    Qualification,
}

pub async fn verify(c: &Config, source: &Rpc) -> Result<(Qualified, VerificationReport)> {
    verify_with_mode(c, source, VerificationMode::Qualification).await
}

/// Identity and pool bounds remain mandatory. No pre-captured workload is needed:
/// live capture validates every range as it arrives, including an initial backlog.
pub async fn verify_live(c: &Config, source: &Rpc) -> Result<(Qualified, VerificationReport)> {
    verify_with_mode(c, source, VerificationMode::Live).await
}

fn load_profile(c: &Config, mode: VerificationMode) -> Result<Option<Profile>> {
    match &c.run.workload_profile {
        Some(path) => Ok(Some(serde_json::from_slice(
            &std::fs::read(path).context("read configured workload profile")?,
        )?)),
        None if mode == VerificationMode::Live => Ok(None),
        None => anyhow::bail!(
            "workload profile required for qualification; use run for continuous live mirroring without a prior profile"
        ),
    }
}

async fn verify_with_mode(
    c: &Config,
    source: &Rpc,
    mode: VerificationMode,
) -> Result<(Qualified, VerificationReport)> {
    let (checkpoint, shadow) = c.replay()?;
    let source_hash: B256 = checkpoint
        .source_hash
        .parse()
        .context("set actual source checkpoint hash")?;
    let shadow_hash: B256 = checkpoint
        .shadow_hash
        .parse()
        .context("set actual patched shadow checkpoint hash")?;
    ensure!(
        source_hash != shadow_hash,
        "native shadow checkpoint must differ from source"
    );
    let native_bytes =
        std::fs::read(&checkpoint.manifest).context("read native bootstrap manifest")?;
    ensure!(
        sha256(&native_bytes) == checkpoint.bootstrap_artifact_digest,
        "bootstrap manifest digest mismatch"
    );
    let native: NativeManifest = serde_json::from_slice(&native_bytes)?;
    ensure!(
        native.source_chain_id == c.run.chain_id
            && native.shadow_chain_id == c.run.chain_id
            && native.fork_block_number == checkpoint.source_height
            && native.fork_block_hash == source_hash,
        "native bootstrap manifest disagrees with checkpoint"
    );
    let deployment_bytes =
        std::fs::read(&shadow.deployment_manifest).context("read deployment evidence")?;
    let deployment: Deployment = serde_json::from_slice(&deployment_bytes)?;
    ensure!(
        deployment.schema_version == 1
            && deployment.run_id == c.run.id
            && deployment.chain_id == c.run.chain_id
            && deployment.tempo_revision == TEMPO_REVISION
            && deployment.reth_revision == RETH_REVISION
            && deployment.bootstrap_artifact_digest == checkpoint.bootstrap_artifact_digest,
        "deployment revision/identity mismatch"
    );
    ensure!(
        valid_digest(&deployment.binary_sha256) && valid_digest(&deployment.chainspec_sha256),
        "binary/chainspec SHA256 evidence required"
    );
    ensure!(
        deployment.isolated_network
            && deployment.exclusive_workload
            && deployment.fork_rules_match_source
            && deployment.fee_token_and_amm_parity
            && deployment.validity_buffer_seconds == 3,
        "deployment isolation, validation, fee, or validity-buffer qualification failed"
    );
    let p = load_profile(c, mode)?;
    let mut warnings = vec!["Validator configuration, keys, binary digests and measured capacity are operator attestations; standard RPC cannot independently verify them.".into(), "Accepted or ambiguous transactions retain pool reservations until finalized or definitively rejected. Unobservable eviction pauses progress instead of inventing free capacity.".into()];
    if let Some(p) = &p {
        ensure!(
            p.schema_version == 1
                && p.chain_id == c.run.chain_id
                && p.blocks >= 2
                && p.duration_ms > 0
                && p.users > 0
                && p.mean_tps.is_finite()
                && p.mean_tps > 0.,
            "profile must contain a nonempty representative interval"
        );
        ensure!(
            p.subblocks == 0
                && p.transaction_types
                    .keys()
                    .all(|t| [0, 1, 2, 4, 0x76].contains(t)),
            "profile contains unsupported routes or transaction types"
        );
        ensure!(
            p.peak_block_raw_bytes <= c.limits.max_buffered_bytes,
            "profile peak block exceeds byte bound"
        );
    }
    ensure!(
        deployment.measured_sustained_tps.is_finite() && deployment.measured_sustained_tps >= 0.,
        "invalid measured throughput"
    );
    let throughput_qualified = p
        .as_ref()
        .is_some_and(|p| deployment.measured_sustained_tps > p.mean_tps);
    let latency_qualified = deployment.measured_rpc_p99_ms > 0
        && deployment.source_capture_p99_ms > 0
        && deployment.source_capture_p99_ms < c.timing.target_lag_ms;
    if mode == VerificationMode::Qualification {
        ensure!(
            throughput_qualified,
            "measured target throughput cannot catch up with source"
        );
        ensure!(
            latency_qualified,
            "measured latency does not qualify configured live lag"
        );
    } else {
        if !throughput_qualified {
            warnings.push("Starting continuous mirroring without a qualified throughput profile; catch-up and live lag are measured at runtime.".into());
        }
        if !latency_qualified {
            warnings.push("Configured live lag is a pacing target; measured source/target latency has not qualified it.".into());
        }
    }
    ensure!(
        source.chain_id().await? == c.run.chain_id,
        "source chain id mismatch"
    );
    ensure!(
        source.header_point(checkpoint.source_height).await?.hash == source_hash,
        "source checkpoint mismatch"
    );
    let source_boundary = source
        .call(
            "eth_getBlockByNumber",
            json!([format!("0x{:x}", checkpoint.source_height), false]),
        )
        .await?;
    ensure!(
        serde_json::from_value::<B256>(source_boundary["stateRoot"].clone())?
            == native.fork_state_root,
        "native source state root mismatch"
    );
    if let Some(p) = &p {
        ensure!(
            source.header_point(p.first_height).await?.hash.to_string() == p.first_hash
                && source.header_point(p.last_height).await?.hash.to_string() == p.last_hash,
            "workload profile is not from this source history"
        );
    }
    let anchor = source.latest_finalized(c.run.chain_id).await?;
    ensure!(
        anchor.point.height >= checkpoint.source_height,
        "source finality has not reached the configured fork checkpoint"
    );
    // A live start probes the complete execution adapter at the trusted tip. Capture
    // verifies the actual backlog, then each new range, while dispatch runs concurrently.
    // The separate qualification command performs the exhaustive retention-horizon scan.
    let history_start = match mode {
        VerificationMode::Live => anchor.point.height,
        VerificationMode::Qualification => anchor
            .point
            .height
            .saturating_sub(
                c.source
                    .recovery_horizon_blocks
                    .max(c.source.history_probe_blocks),
            )
            .min(checkpoint.source_height),
    };
    verify_execution_range(source, c.run.chain_id, history_start, &anchor).await?;
    let ca = std::fs::read(&shadow.ca_file).context("read shadow CA certificate")?;
    let native_keys: BTreeSet<_> = native
        .validators
        .iter()
        .map(|v| v.validator_public_key)
        .collect();
    let deployed_keys = deployment
        .validators
        .iter()
        .map(|v| {
            v.public_key
                .parse::<B256>()
                .context("invalid deployment validator public key")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        native_keys == deployed_keys && native_keys.len() == shadow.validators.len(),
        "deployment validator set disagrees with native bootstrap artifact"
    );
    let mut targets = vec![];
    let mut ids = BTreeSet::new();
    let mut sender = usize::MAX;
    let mut count = usize::MAX;
    let mut bytes = u64::MAX;
    let mut overhead = 0;
    let mut multiplier = 0;
    ensure!(
        deployment.validators.len() == shadow.validators.len(),
        "configure every participating validator"
    );
    for v in &shadow.validators {
        let e = deployment
            .validators
            .iter()
            .find(|e| e.id == v.id)
            .context("validator missing from deployment evidence")?;
        ensure!(
            ids.insert(e.id.clone())
                && e.public_key == v.expected_validator_public_key
                && e.rpc_http == v.rpc_http,
            "validator identity/endpoint evidence mismatch"
        );
        ensure!(
            !e.public_key.contains("REPLACE") && !e.public_key.is_empty(),
            "validator public key is a placeholder"
        );
        ensure!(
            e.max_sender_slots > 0
                && e.pending_count > 0
                && e.queued_count > 0
                && e.pending_bytes > 0
                && e.queued_bytes > 0
                && e.pool_fixed_overhead_bytes > 0
                && e.pool_raw_size_multiplier >= 1,
            "missing pool capacity measurements"
        );
        ensure!(
            e.pool_observation == "conservative_retained_reservations",
            "unsupported pool observation adapter"
        );
        let credential = std::env::var(&v.credential_env).with_context(|| {
            format!(
                "missing credential environment variable for validator {}",
                v.id
            )
        })?;
        let rpc = Rpc::new(
            &v.rpc_http,
            c.limits.rpc_timeout_ms,
            c.limits.max_buffered_bytes,
            Some(&ca),
            Some(&credential),
        )?;
        check_target(&rpc, c).await?;
        sender = sender.min(e.max_sender_slots);
        count = count.min(e.pending_count.min(e.queued_count));
        bytes = bytes.min(e.pending_bytes.min(e.queued_bytes));
        overhead = overhead.max(e.pool_fixed_overhead_bytes);
        multiplier = multiplier.max(e.pool_raw_size_multiplier);
        targets.push(Target {
            id: v.id.clone(),
            rpc,
            evidence: e.clone(),
        });
    }
    let sender_budget = (sender as f64 * c.limits.pool_budget_fraction).floor() as usize;
    let count_budget = (count as f64 * c.limits.pool_budget_fraction).floor() as usize;
    let byte_budget = (bytes as f64 * c.limits.pool_budget_fraction).floor() as u64;
    ensure!(
        sender_budget > 0 && count_budget > 0 && byte_budget > overhead,
        "budget fraction leaves no capacity"
    );
    for ty in [0, 1, 2, 4, 0x76] {
        if !targets
            .iter()
            .all(|t| t.evidence.future_nonce_types.contains(&ty))
        {
            warnings.push(format!("Transaction family 0x{ty:x} uses a one-outstanding-transaction lane window until future-nonce queuing is qualified."));
        }
    }
    let binding = sha256(
        &[
            native_bytes,
            deployment_bytes,
            checkpoint.shadow_hash.as_bytes().to_vec(),
            c.run.id.as_bytes().to_vec(),
        ]
        .concat(),
    );
    let q = Qualified {
        targets,
        deployment,
        binding: binding.clone(),
        sender_budget,
        count_budget,
        byte_budget,
        overhead,
        multiplier,
    };
    let report = VerificationReport {
        run_id: c.run.id.clone(),
        boundary: checkpoint.source_height,
        binding,
        targets: q.targets.len(),
        source_finalized: anchor.point,
        sender_budget,
        count_budget,
        byte_budget,
        measured_sustained_tps: q.deployment.measured_sustained_tps,
        profile_mean_tps: p.as_ref().map(|p| p.mean_tps),
        mode,
        warnings,
    };
    Ok((q, report))
}
pub async fn check_target(rpc: &Rpc, c: &Config) -> Result<()> {
    let (checkpoint, _) = c.replay()?;
    ensure!(
        rpc.chain_id().await? == c.run.chain_id,
        "shadow chain id mismatch"
    );
    ensure!(
        rpc.header_point(checkpoint.source_height).await?.hash
            == checkpoint.shadow_hash.parse::<B256>()?,
        "shadow boundary hash mismatch"
    );
    let tip = rpc.latest_finalized(c.run.chain_id).await?;
    ensure!(
        tip.point.height >= checkpoint.source_height,
        "shadow finalized head precedes boundary"
    );
    Ok(())
}
pub async fn verify_execution_range(
    rpc: &Rpc,
    chain: u64,
    start: u64,
    anchor: &CapturedBlock,
) -> Result<()> {
    ensure!(
        start <= anchor.point.height,
        "invalid verification interval"
    );
    let mut expected = anchor.point.hash;
    for h in (start..=anchor.point.height).rev() {
        let block = rpc
            .execution(h, chain, h == start || h == anchor.point.height)
            .await?;
        ensure!(
            block.point.hash == expected,
            "execution fallback does not link to trusted finalized anchor at {h}"
        );
        expected = block.parent;
    }
    if start > 0 {
        ensure!(
            rpc.header_point(start - 1).await?.hash == expected,
            "execution recovery lower anchor mismatch"
        );
    }
    Ok(())
}
pub fn route(
    sender: alloy_primitives::Address,
    targets: &[Target],
    available: &[bool],
) -> Option<usize> {
    targets
        .iter()
        .enumerate()
        .filter(|(i, _)| available[*i])
        .max_by_key(|(_, t)| {
            let mut input = sender.as_slice().to_vec();
            input.extend_from_slice(t.id.as_bytes());
            keccak256(input)
        })
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_start_does_not_need_a_prior_capture_profile_but_qualification_does() {
        let mut c: Config = toml::from_str(include_str!("../tempo-replay.example.toml")).unwrap();
        c.run.workload_profile = None;
        assert!(load_profile(&c, VerificationMode::Live).unwrap().is_none());
        assert!(load_profile(&c, VerificationMode::Qualification).is_err());
        c.run.workload_profile = Some(std::path::PathBuf::from("missing-explicit-profile.json"));
        assert!(
            load_profile(&c, VerificationMode::Live).is_err(),
            "an explicitly configured missing profile must not be silently ignored"
        );
    }
}
