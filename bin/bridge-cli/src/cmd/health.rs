use alloy::providers::{Provider, ProviderBuilder};
use clap::Parser;
use eyre::Result;
use std::{path::PathBuf, time::Instant};
use tempo_bridge_exex::BridgeConfig;

#[derive(Parser, Debug)]
pub struct HealthArgs {
    /// Path to bridge config file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Output format (table, json)
    #[arg(short, long, default_value = "table")]
    format: String,
}

#[derive(serde::Serialize)]
struct RpcHealth {
    name: String,
    url: String,
    healthy: bool,
    block_number: Option<u64>,
    latency_ms: Option<u64>,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct QuorumStatus {
    chain: String,
    primary_block: Option<u64>,
    secondary_block: Option<u64>,
    blocks_match: Option<bool>,
    quorum_required: bool,
}

#[derive(serde::Serialize)]
struct HealthReport {
    rpcs: Vec<RpcHealth>,
    quorum: Vec<QuorumStatus>,
    overall_healthy: bool,
}

impl HealthArgs {
    pub async fn run(self) -> Result<()> {
        let config = if let Some(config_path) = &self.config {
            BridgeConfig::load(config_path)?
        } else {
            BridgeConfig::default_test_config()
        };

        let mut rpcs = Vec::new();
        let mut quorum_statuses = Vec::new();

        // Check Tempo RPC
        if let Some(tempo_url) = &config.tempo_rpc_url {
            let health = check_rpc("tempo-primary", tempo_url).await;
            let primary_block = health.block_number;
            rpcs.push(health);

            // Check secondary if configured
            if let Some(secondary_url) = &config.tempo_secondary_rpc_url {
                let secondary_health = check_rpc("tempo-secondary", secondary_url).await;
                let secondary_block = secondary_health.block_number;
                rpcs.push(secondary_health);

                quorum_statuses.push(QuorumStatus {
                    chain: "tempo".to_string(),
                    primary_block,
                    secondary_block,
                    blocks_match: match (primary_block, secondary_block) {
                        (Some(p), Some(s)) => Some(p == s),
                        _ => None,
                    },
                    quorum_required: config.require_tempo_rpc_quorum,
                });
            }
        }

        // Check origin chain RPCs
        for (name, chain_config) in &config.chains {
            let health = check_rpc(&format!("{name}-primary"), &chain_config.rpc_url).await;
            let primary_block = health.block_number;
            rpcs.push(health);

            if let Some(secondary_url) = &chain_config.secondary_rpc_url {
                let secondary_health = check_rpc(&format!("{name}-secondary"), secondary_url).await;
                let secondary_block = secondary_health.block_number;
                rpcs.push(secondary_health);

                quorum_statuses.push(QuorumStatus {
                    chain: name.clone(),
                    primary_block,
                    secondary_block,
                    blocks_match: match (primary_block, secondary_block) {
                        (Some(p), Some(s)) => Some(p == s),
                        _ => None,
                    },
                    quorum_required: chain_config.require_rpc_quorum,
                });
            }
        }

        let overall_healthy = rpcs.iter().all(|r| r.healthy)
            && quorum_statuses
                .iter()
                .filter(|q| q.quorum_required)
                .all(|q| q.blocks_match == Some(true));

        let report = HealthReport {
            rpcs,
            quorum: quorum_statuses,
            overall_healthy,
        };

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }

        // Table output
        println!("Bridge Health Check");
        println!("===================");
        println!();

        println!("RPC Endpoints:");
        println!(
            "{:<20} {:<8} {:>10} {:>12}",
            "Name", "Status", "Block", "Latency"
        );
        println!("{}", "-".repeat(55));

        for rpc in &report.rpcs {
            let status = if rpc.healthy { "✓ OK" } else { "✗ FAIL" };
            let block = rpc
                .block_number
                .map(|b| b.to_string())
                .unwrap_or_else(|| "-".to_string());
            let latency = rpc
                .latency_ms
                .map(|l| format!("{l}ms"))
                .unwrap_or_else(|| "-".to_string());

            println!(
                "{:<20} {:<8} {:>10} {:>12}",
                rpc.name, status, block, latency
            );

            if let Some(err) = &rpc.error {
                println!("  Error: {err}");
            }
        }

        if !report.quorum.is_empty() {
            println!();
            println!("Quorum Status:");
            println!(
                "{:<15} {:>12} {:>12} {:>10} {:>10}",
                "Chain", "Primary", "Secondary", "Match", "Required"
            );
            println!("{}", "-".repeat(60));

            for q in &report.quorum {
                let primary = q
                    .primary_block
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let secondary = q
                    .secondary_block
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let matches = match q.blocks_match {
                    Some(true) => "✓",
                    Some(false) => "✗",
                    None => "-",
                };
                let required = if q.quorum_required { "yes" } else { "no" };

                println!(
                    "{:<15} {:>12} {:>12} {:>10} {:>10}",
                    q.chain, primary, secondary, matches, required
                );
            }
        }

        println!();
        if report.overall_healthy {
            println!("Overall Status: ✓ HEALTHY");
        } else {
            println!("Overall Status: ✗ UNHEALTHY");
        }

        Ok(())
    }
}

async fn check_rpc(name: &str, url: &str) -> RpcHealth {
    let start = Instant::now();

    match ProviderBuilder::new().connect(url).await {
        Ok(provider) => match provider.get_block_number().await {
            Ok(block) => RpcHealth {
                name: name.to_string(),
                url: url.to_string(),
                healthy: true,
                block_number: Some(block),
                latency_ms: Some(start.elapsed().as_millis() as u64),
                error: None,
            },
            Err(e) => RpcHealth {
                name: name.to_string(),
                url: url.to_string(),
                healthy: false,
                block_number: None,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                error: Some(e.to_string()),
            },
        },
        Err(e) => RpcHealth {
            name: name.to_string(),
            url: url.to_string(),
            healthy: false,
            block_number: None,
            latency_ms: None,
            error: Some(e.to_string()),
        },
    }
}
