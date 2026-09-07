//! ABI compatibility checker between Rust `sol!` bindings and tempo-std Solidity interfaces.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use alloy_json_abi::JsonAbi;
use eyre::{Context, bail, eyre};
use itertools::Itertools;
use tempo_precompiles::test_util::abi_conformance::{AbiSurface, DiffEntries, load_foundry_abi};

#[derive(Clone, Copy)]
struct InterfaceSpec {
    solidity_name: &'static str,
    abi: fn() -> JsonAbi,
    inherits: &'static [&'static str],
}

impl InterfaceSpec {
    const fn inherits(mut self, inherits: &'static [&'static str]) -> Self {
        self.inherits = inherits;
        self
    }

    const fn with_name(mut self, name: &'static str) -> Self {
        self.solidity_name = name;
        self
    }
}

macro_rules! interface_spec {
    ($ty:ident) => {
        InterfaceSpec {
            solidity_name: stringify!($ty),
            abi: tempo_contracts::precompiles::$ty::abi::contract,
            inherits: &[],
        }
    };
}

// `tempo-std` is the published Solidity interface surface for Tempo precompiles.
static INTERFACE_SPECS: &[InterfaceSpec] = &[
    interface_spec!(INonce),
    interface_spec!(IAccountKeychain),
    interface_spec!(ITIP20),
    interface_spec!(ITIP20Factory),
    interface_spec!(IRolesAuth).with_name("ITIP20RolesAuth"),
    interface_spec!(ITIP403Registry),
    interface_spec!(IReceivePolicyGuard),
    interface_spec!(IStorageCredits),
    interface_spec!(ITIPFeeAMM).with_name("IFeeAMM"),
    interface_spec!(IFeeManager).inherits(&["IFeeAMM"]),
    interface_spec!(IStablecoinDEX),
    interface_spec!(IValidatorConfig),
    interface_spec!(IValidatorConfigV2),
];

#[derive(Debug, clap::Args)]
pub(crate) struct CheckAbi {
    /// Only check a specific interface (by Solidity name, e.g. "ITIP20").
    #[arg(long)]
    only: Option<String>,

    /// Path to a tempo-std repo root (uses the workspace submodule by default).
    #[arg(long)]
    tempo_std: Option<PathBuf>,
}

impl CheckAbi {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let tempo_std_root = match self.tempo_std {
            Some(p) => p,
            None => find_workspace_root()?.join("tips/verify/lib/tempo-std"),
        };
        let artifacts_dir = tempo_std_root.join("out");

        if !artifacts_dir.exists() {
            bail!(
                "tempo-std artifacts not found at {}. Run `forge build` in {} first.",
                artifacts_dir.display(),
                tempo_std_root.display(),
            );
        }

        let specs_by_name: HashMap<&str, &InterfaceSpec> = INTERFACE_SPECS
            .iter()
            .map(|spec| (spec.solidity_name, spec))
            .collect();

        let (mut passed, mut checked, mut missing, mut prev_ok) = (0, 0, Vec::new(), false);
        for spec in INTERFACE_SPECS {
            if let Some(ref only) = self.only
                && spec.solidity_name != only.as_str()
            {
                continue;
            }

            let artifact_path = artifacts_dir
                .join(format!("{}.sol", spec.solidity_name))
                .join(format!("{}.json", spec.solidity_name));

            if !artifact_path.exists() {
                if checked > 0 && prev_ok {
                    eprintln!();
                }
                eprintln!("  ⊘  {} — no Foundry artifact", spec.solidity_name);
                missing.push(spec.solidity_name);
                prev_ok = false;
                continue;
            }

            let (rust_only, sol_only) = check_interface(spec, &artifact_path, &specs_by_name)?;
            checked += 1;

            let current_ok = rust_only.is_empty() && sol_only.is_empty();
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
            eprintln!("{status}  {}{suffix}", spec.solidity_name);

            print_grouped_diffs(&rust_only, "Solidity");
            print_grouped_diffs(&sol_only, "Rust");

            prev_ok = current_ok;
        }

        if checked == 0 && missing.is_empty() {
            if let Some(ref only) = self.only {
                bail!("No ABI interface found matching --only {only}");
            }
            bail!("No ABI interfaces found");
        }

        eprintln!();
        if !missing.is_empty() || passed < checked {
            eprintln!("Summary: {passed}/{checked} interfaces are ABI-compatible.");
            if !missing.is_empty() {
                eprintln!(
                    "Missing Foundry artifacts: {}",
                    missing.iter().copied().join(", ")
                );
            }
            bail!("ABI compatibility check found differences or missing artifacts (see above)");
        }

        eprintln!("Summary: {checked}/{checked} interfaces are ABI-compatible.");
        Ok(())
    }
}

fn check_interface(
    spec: &InterfaceSpec,
    artifact_path: &Path,
    all_specs: &HashMap<&str, &InterfaceSpec>,
) -> eyre::Result<(DiffEntries, DiffEntries)> {
    let rust_surface = surface_for_spec(spec, all_specs, &mut Vec::new())?;

    let solidity_abi = load_foundry_abi(artifact_path)
        .map_err(|error| eyre!(error))
        .with_context(|| format!("parsing {}", artifact_path.display()))?;
    let solidity_surface = AbiSurface::from_abi(&solidity_abi);

    Ok(rust_surface.diff(&solidity_surface))
}

fn surface_for_spec(
    spec: &InterfaceSpec,
    all_specs: &HashMap<&str, &InterfaceSpec>,
    visiting: &mut Vec<&'static str>,
) -> eyre::Result<AbiSurface> {
    if visiting.contains(&spec.solidity_name) {
        let cycle = visiting
            .iter()
            .copied()
            .chain(std::iter::once(spec.solidity_name))
            .join(" -> ");
        bail!("cyclic ABI inheritance detected: {cycle}");
    }

    visiting.push(spec.solidity_name);

    let mut surface = AbiSurface::from_abi(&(spec.abi)());
    for parent_name in spec.inherits {
        let parent = all_specs.get(parent_name).ok_or_else(|| {
            eyre!(
                "{} inherits unknown interface {parent_name}",
                spec.solidity_name
            )
        })?;
        surface.extend(surface_for_spec(parent, all_specs, visiting)?);
    }

    visiting.pop();
    Ok(surface)
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

fn find_workspace_root() -> eyre::Result<PathBuf> {
    let output = std::process::Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version=1"])
        .output()
        .context("failed to run cargo metadata")?;

    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse cargo metadata")?;

    let root = metadata
        .get("workspace_root")
        .and_then(|value| value.as_str())
        .ok_or_else(|| eyre!("missing workspace_root in cargo metadata"))?;

    Ok(PathBuf::from(root))
}
