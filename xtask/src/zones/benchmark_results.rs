use clap::Parser;
use eyre::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::PathBuf,
};

/// Render a txgen benchmark report as a GitHub-compatible Markdown summary.
#[derive(Debug, Parser)]
pub(crate) struct BenchmarkResults {
    /// JSON report written by txgen.
    #[arg(long)]
    report: PathBuf,

    /// Rendered scenario YAML used to produce the report.
    #[arg(long)]
    scenario: PathBuf,

    /// Destination for the rendered Markdown.
    #[arg(long)]
    output: PathBuf,
}

impl BenchmarkResults {
    pub(crate) fn run(self) -> Result<()> {
        let report = fs::read_to_string(&self.report)
            .wrap_err_with(|| format!("failed to read report {}", self.report.display()))?;
        let scenario = fs::read_to_string(&self.scenario)
            .wrap_err_with(|| format!("failed to read scenario {}", self.scenario.display()))?;
        let markdown = render_results(&report, &scenario)?;

        if let Some(parent) = self
            .output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).wrap_err_with(|| {
                format!("failed to create output directory {}", parent.display())
            })?;
        }
        fs::write(&self.output, markdown)
            .wrap_err_with(|| format!("failed to write results to {}", self.output.display()))?;
        println!("Benchmark results written to {}", self.output.display());
        Ok(())
    }
}

fn render_results(report_json: &str, scenario_yaml: &str) -> Result<String> {
    let report: ScenarioReport =
        serde_json::from_str(report_json).wrap_err("failed to parse txgen scenario report")?;
    let scenario: ScenarioSpec =
        serde_yaml::from_str(scenario_yaml).wrap_err("failed to parse rendered scenario YAML")?;
    render_scenario_results(&report, &scenario)
}

#[derive(Debug, Deserialize)]
struct ScenarioReport {
    version: u32,
    scenario: String,
    configuration: ScenarioConfiguration,
    elapsed_ms: u64,
    started: u64,
    completed: u64,
    failed: u64,
    timed_out: u64,
    completed_scenarios_per_second: f64,
    maximum_in_flight: usize,
    steps: Vec<StepReport>,
    total_scenario_latency: Latency,
    #[serde(default)]
    client_observed_e2e_latency: Option<Latency>,
    #[serde(default)]
    observed_critical_path_latency: Option<Latency>,
    #[serde(default)]
    causal_edges: Vec<CausalEdgeReport>,
    #[serde(default)]
    receipt_metrics: Vec<ReceiptMetricReport>,
    #[serde(default)]
    failures: Vec<FailureReport>,
    #[serde(default)]
    sampled_instances: Vec<serde_json::Value>,
}

impl ScenarioReport {
    fn client_observed_e2e_latency(&self) -> &Latency {
        self.client_observed_e2e_latency
            .as_ref()
            .unwrap_or(&self.total_scenario_latency)
    }
}

#[derive(Debug, Deserialize)]
struct ScenarioConfiguration {
    chains: Vec<ReportChain>,
    requested_instances: Option<u64>,
    starts_per_second: f64,
    maximum_in_flight: usize,
}

#[derive(Debug, Deserialize)]
struct ReportChain {
    name: String,
    chain_id: u64,
    #[serde(default)]
    observation_mode: Option<String>,
    #[serde(default)]
    observation_poll_interval_ms: Option<u64>,
    #[serde(default)]
    subscription_configured: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct StepReport {
    index: usize,
    #[serde(default)]
    id: Option<String>,
    name: String,
    #[serde(default)]
    chain: Option<String>,
    kind: String,
    #[serde(default)]
    depends_on: Vec<String>,
    success: u64,
    failed: u64,
    latency: Latency,
    #[serde(default)]
    command_latency: Option<Latency>,
}

impl StepReport {
    fn command_latency(&self) -> &Latency {
        self.command_latency.as_ref().unwrap_or(&self.latency)
    }
}

#[derive(Debug, Deserialize)]
struct CausalEdgeReport {
    relation: String,
    source_step_id: String,
    destination_step_id: String,
    source_milestone: String,
    destination_milestone: String,
    observed_latency: Latency,
    chain_timestamp_delta: Latency,
    destination_observation_lag: Latency,
}

#[derive(Debug, Deserialize)]
struct FailureReport {
    step_index: usize,
    step_name: String,
    classification: String,
    count: u64,
}

#[derive(Debug, Deserialize)]
struct Latency {
    samples: usize,
    min_ms: f64,
    max_ms: f64,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

#[derive(Debug, Deserialize)]
struct ScenarioSpec {
    version: u32,
    chains: BTreeMap<String, ScenarioChain>,
    scenario: ScenarioDefinition,
}

#[derive(Debug, Deserialize)]
struct ScenarioChain {
    chain_id: u64,
}

#[derive(Debug, Deserialize)]
struct ScenarioDefinition {
    name: String,
    steps: Vec<ScenarioStep>,
}

#[derive(Debug, Deserialize)]
struct ScenarioStep {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    depends_on: Vec<String>,
    #[serde(default)]
    save: Option<String>,
    #[serde(default, rename = "timeout")]
    _timeout: Option<serde_yaml::Value>,
    #[serde(flatten)]
    operation: BTreeMap<String, serde_yaml::Value>,
}

struct ResolvedStep<'a> {
    report: &'a StepReport,
    chain: &'a str,
}

fn render_scenario_results(report: &ScenarioReport, scenario: &ScenarioSpec) -> Result<String> {
    validate_scenario_report(report, scenario)?;
    let steps = resolve_steps(report, scenario)?;
    let elapsed_secs = scenario_elapsed_secs(report)?;

    let submit_steps = steps
        .iter()
        .filter(|step| step.report.kind == "submit")
        .collect::<Vec<_>>();
    ensure!(
        !submit_steps.is_empty(),
        "scenario has no submit steps to report"
    );

    let submitted = submit_steps.iter().try_fold(0_u64, |total, step| {
        total
            .checked_add(step.report.success)
            .ok_or_else(|| eyre::eyre!("successful submit count overflow"))
    })?;
    let aggregate_tps = submitted as f64 / elapsed_secs;

    let mut output = String::new();
    writeln!(output, "# Zones benchmark results\n")?;
    writeln!(output, "Scenario: {}\n", code(&report.scenario))?;
    writeln!(output, "## Outcome\n")?;
    writeln!(
        output,
        "| Requested | Started | Completed | Failed | Timed out | Measured time |"
    )?;
    writeln!(output, "| ---: | ---: | ---: | ---: | ---: | ---: |")?;
    writeln!(
        output,
        "| {} | {} | {} | {} | {} | {} |\n",
        report
            .configuration
            .requested_instances
            .map_or_else(|| "duration-based".to_owned(), |value| value.to_string()),
        report.started,
        report.completed,
        report.failed,
        report.timed_out,
        format_seconds(report.elapsed_ms as f64 / 1_000.0),
    )?;
    writeln!(
        output,
        "Offered load: **{:.3} journey starts/s**. Maximum in flight: **{} observed / {} configured**.\n",
        report.configuration.starts_per_second,
        report.maximum_in_flight,
        report.configuration.maximum_in_flight,
    )?;

    write_observation_configuration(&mut output, &report.configuration.chains)?;

    writeln!(output, "## Throughput\n")?;
    writeln!(output, "| Scope | Count | Effective rate |")?;
    writeln!(output, "| --- | ---: | ---: |")?;
    writeln!(
        output,
        "| Complete journeys | {} | **{:.3} journeys/s** |",
        report.completed, report.completed_scenarios_per_second,
    )?;
    writeln!(
        output,
        "| All successful user submit steps | {submitted} | **{aggregate_tps:.3} TPS** |",
    )?;
    for chain in &report.configuration.chains {
        let mut has_submit_step = false;
        let mut successes = 0_u64;
        for step in &submit_steps {
            if step.chain != chain.name {
                continue;
            }
            has_submit_step = true;
            successes = successes
                .checked_add(step.report.success)
                .ok_or_else(|| eyre::eyre!("successful chain submit count overflow"))?;
        }
        if !has_submit_step {
            continue;
        }
        writeln!(
            output,
            "| {} successful user submit steps (chain ID {}) | {} | {:.3} TPS |",
            code(&chain.name),
            chain.chain_id,
            successes,
            successes as f64 / elapsed_secs,
        )?;
    }
    writeln!(output)?;

    writeln!(output, "### Transaction legs\n")?;
    writeln!(
        output,
        "| Step | Chain | Successful | Failed | Effective TPS | Submit-step p50 | Submit-step p95 |"
    )?;
    writeln!(output, "| --- | --- | ---: | ---: | ---: | ---: | ---: |")?;
    for step in &submit_steps {
        writeln!(
            output,
            "| {} | {} | {} | {} | {:.3} | {} | {} |",
            code(&step.report.name),
            code(step.chain),
            step.report.success,
            step.report.failed,
            step.report.success as f64 / elapsed_secs,
            format_millis(step.report.command_latency().p50_ms),
            format_millis(step.report.command_latency().p95_ms),
        )?;
    }
    writeln!(output)?;

    writeln!(output, "## Client-observed end-to-end journey latency\n")?;
    write_latency_header(&mut output)?;
    write_latency_row(&mut output, report.client_observed_e2e_latency())?;
    writeln!(output)?;

    if let Some(latency) = &report.observed_critical_path_latency {
        writeln!(output, "## Observed critical-path latency\n")?;
        write_latency_header(&mut output)?;
        write_latency_row(&mut output, latency)?;
        writeln!(output)?;
    }

    write_causal_edges(&mut output, &report.causal_edges)?;

    writeln!(output, "## Step command duration\n")?;
    writeln!(
        output,
        "| Step | Step ID | Depends on | Chain | Operation | Successful | Failed | Mean | P50 | P95 | P99 |"
    )?;
    writeln!(
        output,
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"
    )?;
    for step in steps.iter().filter(|step| step.report.kind != "checkpoint") {
        writeln!(
            output,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            code(&step.report.name),
            code(step.report.id.as_deref().unwrap_or(&step.report.name)),
            if step.report.depends_on.is_empty() {
                "—".to_owned()
            } else {
                code(&step.report.depends_on.join(", "))
            },
            code(step.chain),
            code(&step.report.kind),
            step.report.success,
            step.report.failed,
            format_millis(step.report.command_latency().mean_ms),
            format_millis(step.report.command_latency().p50_ms),
            format_millis(step.report.command_latency().p95_ms),
            format_millis(step.report.command_latency().p99_ms),
        )?;
    }
    writeln!(output)?;

    if !report.sampled_instances.is_empty() {
        writeln!(
            output,
            "Sampled lifecycle traces retained in the JSON report: **{}**.\n",
            report.sampled_instances.len()
        )?;
    }

    write_receipt_metrics(&mut output, &report.receipt_metrics)?;

    if !report.failures.is_empty() {
        writeln!(output, "## Failure classifications\n")?;
        writeln!(output, "| Step | Classification | Count |")?;
        writeln!(output, "| --- | --- | ---: |")?;
        for failure in &report.failures {
            writeln!(
                output,
                "| {} (# {}) | {} | {} |",
                code(&failure.step_name),
                failure.step_index,
                code(&failure.classification),
                failure.count
            )?;
        }
        writeln!(output)?;
    }

    writeln!(
        output,
        "> Effective rates use the complete measured window, including ramp-up and drain. Aggregate user TPS sums submit steps across chains and is not a single-chain saturation result. Setup outside the measured scenario is excluded. Journey percentiles are computed from complete per-instance journeys; step and edge percentiles are never summed. Step command duration is client orchestration time, while causal edges separate observed dependency time, chain inclusion deltas, and destination observation lag."
    )?;

    Ok(output)
}

fn validate_scenario_report(report: &ScenarioReport, scenario: &ScenarioSpec) -> Result<()> {
    ensure!(
        matches!(report.version, 1 | 2),
        "unsupported txgen scenario report version {}",
        report.version
    );
    ensure!(
        scenario.version == 1,
        "unsupported rendered scenario version {}",
        scenario.version
    );
    ensure!(
        report.scenario == scenario.scenario.name,
        "report scenario {} does not match rendered scenario {}",
        report.scenario,
        scenario.scenario.name
    );
    ensure!(
        report.steps.len() == scenario.scenario.steps.len(),
        "report has {} steps but rendered scenario has {}",
        report.steps.len(),
        scenario.scenario.steps.len()
    );
    ensure!(
        !report.configuration.chains.is_empty(),
        "report has no configured chains"
    );
    ensure!(
        report.configuration.chains.len() == scenario.chains.len(),
        "report has {} chains but rendered scenario has {}",
        report.configuration.chains.len(),
        scenario.chains.len()
    );

    validate_nonnegative_finite(
        "completed scenario rate",
        report.completed_scenarios_per_second,
    )?;
    validate_nonnegative_finite(
        "configured start rate",
        report.configuration.starts_per_second,
    )?;
    validate_latency("total scenario latency", &report.total_scenario_latency)?;
    if report.version >= 2 {
        let client_observed = report.client_observed_e2e_latency.as_ref().ok_or_else(|| {
            eyre::eyre!("txgen scenario report version 2 has no client-observed E2E latency")
        })?;
        let critical_path = report
            .observed_critical_path_latency
            .as_ref()
            .ok_or_else(|| {
                eyre::eyre!("txgen scenario report version 2 has no observed critical-path latency")
            })?;
        validate_latency("client-observed E2E latency", client_observed)?;
        validate_latency("observed critical-path latency", critical_path)?;
    }
    let step_ids = report
        .steps
        .iter()
        .filter_map(|step| step.id.as_deref())
        .collect::<BTreeSet<_>>();
    if report.version >= 2 {
        ensure!(
            step_ids.len() == report.steps.len(),
            "txgen scenario report version 2 has missing or duplicate step IDs"
        );
    }
    for edge in &report.causal_edges {
        ensure!(
            step_ids.contains(edge.source_step_id.as_str()),
            "causal edge references unknown source step {}",
            edge.source_step_id
        );
        ensure!(
            step_ids.contains(edge.destination_step_id.as_str()),
            "causal edge references unknown destination step {}",
            edge.destination_step_id
        );
        validate_latency(
            &format!(
                "causal edge {} -> {} observed latency",
                edge.source_step_id, edge.destination_step_id
            ),
            &edge.observed_latency,
        )?;
        validate_signed_latency(
            &format!(
                "causal edge {} -> {} chain timestamp delta",
                edge.source_step_id, edge.destination_step_id
            ),
            &edge.chain_timestamp_delta,
        )?;
        validate_signed_latency(
            &format!(
                "causal edge {} -> {} destination observation lag",
                edge.source_step_id, edge.destination_step_id
            ),
            &edge.destination_observation_lag,
        )?;
    }

    let mut names = BTreeSet::new();
    for chain in &report.configuration.chains {
        ensure!(
            names.insert(chain.name.as_str()),
            "duplicate report chain {}",
            chain.name
        );
        if report.version >= 2 {
            ensure!(
                chain
                    .observation_mode
                    .as_deref()
                    .is_some_and(|mode| !mode.is_empty()),
                "report chain {} has no observation mode",
                chain.name
            );
            ensure!(
                chain
                    .observation_poll_interval_ms
                    .is_some_and(|milliseconds| milliseconds > 0),
                "report chain {} has no positive observation poll interval",
                chain.name
            );
            ensure!(
                chain.subscription_configured.is_some(),
                "report chain {} does not say whether subscription observation is configured",
                chain.name
            );
        }
        let rendered = scenario.chains.get(&chain.name).ok_or_else(|| {
            eyre::eyre!(
                "report chain {} is missing from rendered scenario",
                chain.name
            )
        })?;
        ensure!(
            chain.chain_id == rendered.chain_id,
            "report chain {} uses ID {} but rendered scenario uses {}",
            chain.name,
            chain.chain_id,
            rendered.chain_id
        );
    }
    Ok(())
}

fn resolve_steps<'a>(
    report: &'a ScenarioReport,
    scenario: &'a ScenarioSpec,
) -> Result<Vec<ResolvedStep<'a>>> {
    report
        .steps
        .iter()
        .zip(&scenario.scenario.steps)
        .enumerate()
        .map(|(index, (reported, rendered))| {
            ensure!(
                reported.index == index,
                "report step {} has index {}, expected {}",
                reported.name,
                reported.index,
                index
            );
            ensure!(
                rendered.operation.len() == 1,
                "rendered scenario step {} must contain exactly one operation",
                index + 1
            );
            let (kind, body) = rendered.operation.iter().next().expect("length checked");
            let expected_name = rendered
                .save
                .clone()
                .unwrap_or_else(|| format!("step_{}_{}", index + 1, kind));
            let expected_id = rendered
                .id
                .clone()
                .or_else(|| rendered.save.clone())
                .unwrap_or_else(|| format!("step_{}_{}", index + 1, kind));
            ensure!(
                reported.name == expected_name,
                "report step {} is named {} but rendered scenario names it {}",
                index,
                reported.name,
                expected_name
            );
            ensure!(
                reported.kind == *kind,
                "report step {} has kind {} but rendered scenario uses {}",
                reported.name,
                reported.kind,
                kind
            );
            if report.version >= 2 {
                ensure!(
                    reported.id.as_deref() == Some(expected_id.as_str()),
                    "report step {} has ID {:?} but rendered scenario uses {}",
                    reported.name,
                    reported.id,
                    expected_id
                );
                ensure!(
                    reported.depends_on == rendered.depends_on,
                    "report step {} has dependencies {:?} but rendered scenario uses {:?}",
                    reported.name,
                    reported.depends_on,
                    rendered.depends_on
                );
                ensure!(
                    reported.command_latency.is_some(),
                    "report step {} has no command latency",
                    reported.name
                );
            }
            let body = body.as_mapping().ok_or_else(|| {
                eyre::eyre!(
                    "rendered scenario step {} operation must be a mapping",
                    expected_name
                )
            })?;
            let chain = body
                .get(serde_yaml::Value::String("chain".to_owned()))
                .and_then(serde_yaml::Value::as_str)
                .ok_or_else(|| {
                    eyre::eyre!("rendered scenario step {} has no chain", expected_name)
                })?;
            ensure!(
                scenario.chains.contains_key(chain),
                "rendered scenario step {} references unknown chain {}",
                expected_name,
                chain
            );
            if let Some(reported_chain) = reported.chain.as_deref() {
                ensure!(
                    reported_chain == chain,
                    "report step {} uses chain {} but rendered scenario uses {}",
                    reported.name,
                    reported_chain,
                    chain
                );
            }
            validate_latency(
                &format!("step {} command latency", reported.name),
                reported.command_latency(),
            )?;
            Ok(ResolvedStep {
                report: reported,
                chain: reported.chain.as_deref().unwrap_or(chain),
            })
        })
        .collect()
}

fn scenario_elapsed_secs(report: &ScenarioReport) -> Result<f64> {
    let elapsed = if report.completed > 0 && report.completed_scenarios_per_second > 0.0 {
        report.completed as f64 / report.completed_scenarios_per_second
    } else {
        report.elapsed_ms as f64 / 1_000.0
    };
    ensure!(
        elapsed.is_finite() && elapsed > 0.0,
        "scenario measured time must be greater than zero"
    );
    Ok(elapsed)
}

fn write_observation_configuration(output: &mut String, chains: &[ReportChain]) -> Result<()> {
    if !chains.iter().any(|chain| {
        chain.observation_mode.is_some()
            || chain.observation_poll_interval_ms.is_some()
            || chain.subscription_configured.is_some()
    }) {
        return Ok(());
    }

    writeln!(output, "## Chain observation\n")?;
    writeln!(
        output,
        "| Chain | Mode | Poll fallback | Subscription configured |"
    )?;
    writeln!(output, "| --- | --- | ---: | --- |")?;
    for chain in chains {
        writeln!(
            output,
            "| {} | {} | {} | {} |",
            code(&chain.name),
            chain
                .observation_mode
                .as_deref()
                .map_or_else(|| "—".to_owned(), code),
            chain.observation_poll_interval_ms.map_or_else(
                || "—".to_owned(),
                |milliseconds| { format!("{milliseconds} ms") }
            ),
            chain
                .subscription_configured
                .map_or_else(|| "—".to_owned(), |configured| configured.to_string()),
        )?;
    }
    writeln!(output)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ReceiptMetricReport {
    #[serde(default)]
    labels: BTreeMap<String, String>,
    gas_used: QuantityDistribution,
    effective_gas_price: QuantityDistribution,
    fee_paid: QuantityDistribution,
}

#[derive(Debug, Deserialize)]
struct QuantityDistribution {
    count: u64,
    min: Option<f64>,
    mean: Option<f64>,
    p50: Option<f64>,
    p95: Option<f64>,
    p99: Option<f64>,
}

fn validate_latency(name: &str, latency: &Latency) -> Result<()> {
    for (field, value) in [
        ("min", latency.min_ms),
        ("max", latency.max_ms),
        ("mean", latency.mean_ms),
        ("p50", latency.p50_ms),
        ("p95", latency.p95_ms),
        ("p99", latency.p99_ms),
    ] {
        validate_nonnegative_finite(&format!("{name} {field}"), value)?;
    }
    if latency.samples > 0 {
        ensure!(
            latency.min_ms <= latency.max_ms,
            "{name} minimum exceeds maximum"
        );
    }
    Ok(())
}

fn validate_signed_latency(name: &str, latency: &Latency) -> Result<()> {
    for (field, value) in [
        ("min", latency.min_ms),
        ("max", latency.max_ms),
        ("mean", latency.mean_ms),
        ("p50", latency.p50_ms),
        ("p95", latency.p95_ms),
        ("p99", latency.p99_ms),
    ] {
        ensure!(value.is_finite(), "{name} {field} must be finite");
    }
    if latency.samples > 0 {
        ensure!(
            latency.min_ms <= latency.max_ms,
            "{name} minimum exceeds maximum"
        );
    }
    Ok(())
}

fn validate_nonnegative_finite(name: &str, value: f64) -> Result<()> {
    ensure!(
        value.is_finite() && value >= 0.0,
        "{name} must be finite and nonnegative"
    );
    Ok(())
}

fn write_latency_header(output: &mut String) -> Result<()> {
    writeln!(output, "| Samples | Min | Mean | P50 | P95 | P99 | Max |")?;
    writeln!(output, "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |")?;
    Ok(())
}

fn write_latency_row(output: &mut String, latency: &Latency) -> Result<()> {
    writeln!(
        output,
        "| {} | {} | {} | {} | {} | {} | {} |",
        latency.samples,
        format_millis(latency.min_ms),
        format_millis(latency.mean_ms),
        format_millis(latency.p50_ms),
        format_millis(latency.p95_ms),
        format_millis(latency.p99_ms),
        format_millis(latency.max_ms),
    )?;
    Ok(())
}

fn write_causal_edges(output: &mut String, edges: &[CausalEdgeReport]) -> Result<()> {
    if edges.is_empty() {
        return Ok(());
    }

    writeln!(output, "## Causal-edge timing\n")?;
    writeln!(
        output,
        "| Dependency edge | Relation | Milestones | Timing | Samples | Mean | P50 | P95 | P99 |"
    )?;
    writeln!(
        output,
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |"
    )?;
    for edge in edges {
        let dependency = code(&format!(
            "{} -> {}",
            edge.source_step_id, edge.destination_step_id
        ));
        let milestones = code(&format!(
            "{} -> {}",
            edge.source_milestone, edge.destination_milestone
        ));
        for (timing, latency) in [
            ("observed causal-edge latency", &edge.observed_latency),
            (
                "chain inclusion latency (timestamp delta)",
                &edge.chain_timestamp_delta,
            ),
            (
                "destination observation lag",
                &edge.destination_observation_lag,
            ),
        ] {
            writeln!(
                output,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                dependency,
                code(&edge.relation),
                milestones,
                timing,
                latency.samples,
                format_millis(latency.mean_ms),
                format_millis(latency.p50_ms),
                format_millis(latency.p95_ms),
                format_millis(latency.p99_ms),
            )?;
        }
    }
    writeln!(output)?;
    Ok(())
}

fn write_receipt_metrics(output: &mut String, reports: &[ReceiptMetricReport]) -> Result<()> {
    if reports.is_empty() {
        return Ok(());
    }

    writeln!(output, "## Receipt gas metrics\n")?;
    writeln!(
        output,
        "| Input / labels | Metric | Count | Min | Mean | P50 | P95 | P99 |"
    )?;
    writeln!(
        output,
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"
    )?;

    for report in reports {
        let labels = format_receipt_labels(&report.labels);
        for (name, unit, distribution) in [
            ("gas_used", "gas", &report.gas_used),
            ("effective_gas_price", "wei", &report.effective_gas_price),
            ("fee_paid", "wei", &report.fee_paid),
        ] {
            validate_quantity_distribution(name, distribution)?;
            writeln!(
                output,
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                labels,
                code(name),
                distribution.count,
                format_quantity(distribution.min, unit),
                format_quantity(distribution.mean, unit),
                format_quantity(distribution.p50, unit),
                format_quantity(distribution.p95, unit),
                format_quantity(distribution.p99, unit),
            )?;
        }
    }
    writeln!(output)?;
    Ok(())
}

fn validate_quantity_distribution(name: &str, distribution: &QuantityDistribution) -> Result<()> {
    for (field, value) in [
        ("min", distribution.min),
        ("mean", distribution.mean),
        ("p50", distribution.p50),
        ("p95", distribution.p95),
        ("p99", distribution.p99),
    ] {
        if let Some(value) = value {
            validate_nonnegative_finite(&format!("receipt {name} {field}"), value)?;
        }
    }
    Ok(())
}

fn format_receipt_labels(labels: &BTreeMap<String, String>) -> String {
    if labels.is_empty() {
        return "—".to_owned();
    }

    code(
        &labels
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn format_quantity(value: Option<f64>, unit: &str) -> String {
    value.map_or_else(|| "—".to_owned(), |value| format!("{value:.3} {unit}"))
}

fn format_seconds(value: f64) -> String {
    format!("{value:.3} s")
}

fn format_millis(value: f64) -> String {
    if value.abs() >= 1_000.0 {
        format!("{:.3} s", value / 1_000.0)
    } else {
        format!("{value:.3} ms")
    }
}

fn code(value: &str) -> String {
    let escaped = value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
        .replace('`', "&#96;")
        .replace(['\n', '\r'], " ");
    format!("`{escaped}`")
}
