//! ABI compatibility checker between Rust `#[abi]` definitions and Foundry Solidity artifacts.
//!
//! Loads Rust ABI manifests from `tempo_precompiles::all_abi_manifests()` and compares
//! them against Foundry JSON artifacts in `tips/ref-impls/out/`.

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use eyre::{Context, bail, eyre};

#[derive(Debug, clap::Args)]
pub(crate) struct CheckAbi {
    /// Only check a specific interface (by Solidity name, e.g. "ITIP403Registry").
    #[arg(long)]
    only: Option<String>,
}

impl CheckAbi {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let workspace_root = find_workspace_root()?;
        let artifacts_dir = workspace_root.join("tips/ref-impls/out");

        if !artifacts_dir.exists() {
            bail!(
                "Foundry artifacts not found at {}. Run `forge build` in tips/ref-impls/ first.",
                artifacts_dir.display()
            );
        }

        let manifests = tempo_precompiles::all_abi_manifests();

        let manifests_by_name: HashMap<&str, &tempo_precompiles::AbiManifest> =
            manifests.iter().map(|s| (s.solidity_name, s)).collect();

        let mut passed = 0;
        let mut checked = 0;
        let mut prev_ok = false;

        for manifest in manifests {
            if let Some(ref only) = self.only {
                if manifest.solidity_name != only.as_str() {
                    continue;
                }
            }

            let artifact_path = artifacts_dir
                .join(format!("{}.sol", manifest.solidity_name))
                .join(format!("{}.json", manifest.solidity_name));

            if !artifact_path.exists() {
                if checked > 0 && prev_ok {
                    eprintln!();
                }
                eprintln!("  ⊘  {} — no Foundry artifact", manifest.solidity_name);
                prev_ok = false;
                continue;
            }

            let result = check_manifest(manifest, &artifact_path, &manifests_by_name)?;

            checked += 1;

            let current_ok = result.rust_only.is_empty() && result.solidity_only.is_empty();
            if current_ok {
                passed += 1;
            }

            if checked > 1 && !(prev_ok && current_ok) {
                eprintln!();
            }

            let (status, suffix) = if current_ok {
                ("  ✓", "")
            } else {
                ("  ✗", ":")
            };
            eprintln!("{status}  {}{suffix}", manifest.solidity_name);

            print_grouped_diffs(&result.rust_only, "Solidity");
            print_grouped_diffs(&result.solidity_only, "Rust");

            prev_ok = current_ok;
        }

        if checked == 0 {
            if let Some(ref only) = self.only {
                bail!("No ABI manifest found matching --only {only}");
            }
            bail!("No ABI manifests found");
        }

        eprintln!();
        if passed < checked {
            eprintln!("Summary: {passed}/{checked} interfaces are ABI-compatible.");
            bail!("ABI compatibility check found differences (see above)");
        }

        eprintln!("Summary: {checked}/{checked} interfaces are ABI-compatible.");
        Ok(())
    }
}

fn print_grouped_diffs(diffs: &[(String, String)], missing_in: &str) {
    let mut current_kind = "";
    for (kind, sig) in diffs {
        if kind != current_kind {
            let plural = if diffs.iter().filter(|(k, _)| k == kind).count() > 1 {
                "s"
            } else {
                ""
            };
            eprintln!("       {kind}{plural} missing in {missing_in}:");
            current_kind = kind;
        }
        eprintln!("         {sig}");
    }
}

struct CheckResult {
    rust_only: Vec<(String, String)>,
    solidity_only: Vec<(String, String)>,
}

fn check_manifest(
    manifest: &tempo_precompiles::AbiManifest,
    artifact_path: &Path,
    all_manifests: &HashMap<&str, &tempo_precompiles::AbiManifest>,
) -> eyre::Result<CheckResult> {
    let solidity_sigs = parse_foundry_artifact(artifact_path)
        .with_context(|| format!("parsing {}", artifact_path.display()))?;

    let mut rust_fns: BTreeSet<String> = manifest.functions.iter().map(|s| s.to_string()).collect();
    let mut rust_errors: BTreeSet<String> = manifest.errors.iter().map(|s| s.to_string()).collect();
    let mut rust_events: BTreeSet<String> = manifest.events.iter().map(|s| s.to_string()).collect();

    for parent_name in manifest.inherits {
        if let Some(parent) = all_manifests.get(parent_name) {
            rust_fns.extend(parent.functions.iter().map(|s| s.to_string()));
            rust_errors.extend(parent.errors.iter().map(|s| s.to_string()));
            rust_events.extend(parent.events.iter().map(|s| s.to_string()));
        } else {
            eprintln!(
                "  WARN  {}: inherits unknown manifest '{parent_name}'",
                manifest.solidity_name
            );
        }
    }

    let sol_fns: BTreeSet<String> = solidity_sigs
        .iter()
        .filter(|(k, _)| k == "function")
        .map(|(_, v)| v.clone())
        .collect();
    let sol_errors: BTreeSet<String> = solidity_sigs
        .iter()
        .filter(|(k, _)| k == "error")
        .map(|(_, v)| v.clone())
        .collect();
    let sol_events: BTreeSet<String> = solidity_sigs
        .iter()
        .filter(|(k, _)| k == "event")
        .map(|(_, v)| v.clone())
        .collect();

    let excluded: BTreeSet<String> = manifest.exclude.iter().map(|s| s.to_string()).collect();

    let mut rust_only = Vec::new();
    let mut solidity_only = Vec::new();

    diff_sets(
        "function",
        &rust_fns,
        &sol_fns,
        &excluded,
        &mut rust_only,
        &mut solidity_only,
    );
    diff_sets(
        "error",
        &rust_errors,
        &sol_errors,
        &excluded,
        &mut rust_only,
        &mut solidity_only,
    );
    diff_sets(
        "event",
        &rust_events,
        &sol_events,
        &excluded,
        &mut rust_only,
        &mut solidity_only,
    );

    Ok(CheckResult {
        rust_only,
        solidity_only,
    })
}

fn diff_sets(
    kind: &str,
    rust: &BTreeSet<String>,
    solidity: &BTreeSet<String>,
    excluded: &BTreeSet<String>,
    rust_only: &mut Vec<(String, String)>,
    solidity_only: &mut Vec<(String, String)>,
) {
    for sig in rust.difference(solidity) {
        if !excluded.contains(&format!("{kind}:{sig}")) {
            rust_only.push((kind.to_string(), sig.clone()));
        }
    }
    for sig in solidity.difference(rust) {
        if !excluded.contains(&format!("{kind}:{sig}")) {
            solidity_only.push((kind.to_string(), sig.clone()));
        }
    }
}

/// Parse a Foundry JSON artifact and extract canonical signatures.
///
/// Returns `Vec<(kind, signature)>` where kind is "function", "error", or "event".
fn parse_foundry_artifact(path: &Path) -> eyre::Result<Vec<(String, String)>> {
    let content = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;
    let abi = json
        .get("abi")
        .ok_or_else(|| eyre!("missing 'abi' field"))?
        .as_array()
        .ok_or_else(|| eyre!("'abi' is not an array"))?;

    let mut result = Vec::new();

    for entry in abi {
        let kind = entry.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match kind {
            "function" | "error" | "event" => {
                let name = entry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| eyre!("missing 'name' in {kind}"))?;

                let inputs = entry
                    .get("inputs")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let param_types: Vec<String> = inputs
                    .iter()
                    .map(|p| abi_param_to_canonical(p))
                    .collect::<eyre::Result<Vec<_>>>()?;

                let sig = format!("{name}({})", param_types.join(","));
                result.push((kind.to_string(), sig));
            }
            _ => {}
        }
    }

    Ok(result)
}

/// Convert a Foundry ABI parameter to its canonical type string.
///
/// Handles tuple/struct types by recursively expanding components.
fn abi_param_to_canonical(param: &serde_json::Value) -> eyre::Result<String> {
    let ty = param
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("uint256");

    if let Some(components) = param.get("components").and_then(|v| v.as_array()) {
        let inner: Vec<String> = components
            .iter()
            .map(|c| abi_param_to_canonical(c))
            .collect::<eyre::Result<Vec<_>>>()?;
        let tuple_sig = format!("({})", inner.join(","));

        let suffix = if ty == "tuple" {
            String::new()
        } else if let Some(rest) = ty.strip_prefix("tuple") {
            rest.to_string()
        } else {
            String::new()
        };

        Ok(format!("{tuple_sig}{suffix}"))
    } else {
        Ok(ty.to_string())
    }
}

fn find_workspace_root() -> eyre::Result<PathBuf> {
    let output = std::process::Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version=1"])
        .output()
        .context("failed to run cargo metadata")?;

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse cargo metadata")?;

    let root = metadata
        .get("workspace_root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre!("missing workspace_root in cargo metadata"))?;

    Ok(PathBuf::from(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abi_param_to_canonical_simple() {
        let param = serde_json::json!({"type": "address"});
        assert_eq!(abi_param_to_canonical(&param).unwrap(), "address");
    }

    #[test]
    fn test_abi_param_to_canonical_tuple() {
        let param = serde_json::json!({
            "type": "tuple",
            "components": [
                {"type": "address"},
                {"type": "uint256"}
            ]
        });
        assert_eq!(abi_param_to_canonical(&param).unwrap(), "(address,uint256)");
    }

    #[test]
    fn test_abi_param_to_canonical_tuple_array() {
        let param = serde_json::json!({
            "type": "tuple[]",
            "components": [
                {"type": "bytes32"},
                {"type": "bool"}
            ]
        });
        assert_eq!(abi_param_to_canonical(&param).unwrap(), "(bytes32,bool)[]");
    }

    #[test]
    fn test_abi_param_to_canonical_nested_tuple() {
        let param = serde_json::json!({
            "type": "tuple",
            "components": [
                {"type": "address"},
                {
                    "type": "tuple",
                    "components": [
                        {"type": "uint128"},
                        {"type": "uint128"}
                    ]
                }
            ]
        });
        assert_eq!(
            abi_param_to_canonical(&param).unwrap(),
            "(address,(uint128,uint128))"
        );
    }
}
