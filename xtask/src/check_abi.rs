//! ABI compatibility checker between Rust `sol!` bindings and tempo-std Solidity interfaces.

use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};

use alloy_json_abi::{
    ContractObject, Error, Event, EventParam, Function, JsonAbi, Param, StateMutability,
};
use eyre::{Context, bail, eyre};
use itertools::Itertools;
use tempo_contracts::precompiles as pc;

#[derive(Debug, clap::Args)]
pub(crate) struct CheckAbi {
    /// Only check a specific interface (by Solidity name, e.g. "ITIP20").
    #[arg(long)]
    only: Option<String>,
}

#[derive(Clone, Copy)]
struct InterfaceSpec {
    solidity_name: &'static str,
    abi: fn() -> JsonAbi,
    inherits: &'static [&'static str],
}

#[derive(Default)]
struct AbiSurface {
    functions: BTreeSet<String>,
    errors: BTreeSet<String>,
    events: BTreeSet<String>,
}

struct CheckResult {
    rust_only: Vec<(String, String)>,
    solidity_only: Vec<(String, String)>,
}

impl CheckAbi {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let workspace_root = find_workspace_root()?;
        let artifacts_dir = workspace_root.join("tips/ref-impls/lib/tempo-std/out");

        if !artifacts_dir.exists() {
            bail!(
                "tempo-std artifacts not found at {}. Run `forge build` in tips/ref-impls/lib/tempo-std first.",
                artifacts_dir.display()
            );
        }

        let specs = interface_specs();
        let specs_by_name: HashMap<&str, &InterfaceSpec> = specs
            .iter()
            .map(|spec| (spec.solidity_name, spec))
            .collect();

        let mut passed = 0;
        let mut checked = 0;
        let mut missing_artifacts = Vec::new();
        let mut prev_ok = false;

        for spec in specs {
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
                missing_artifacts.push(spec.solidity_name);
                prev_ok = false;
                continue;
            }

            let result = check_interface(spec, &artifact_path, &specs_by_name)?;
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
            eprintln!("{status}  {}{suffix}", spec.solidity_name);

            print_grouped_diffs(&result.rust_only, "Solidity");
            print_grouped_diffs(&result.solidity_only, "Rust");

            prev_ok = current_ok;
        }

        if checked == 0 && missing_artifacts.is_empty() {
            if let Some(ref only) = self.only {
                bail!("No ABI interface found matching --only {only}");
            }
            bail!("No ABI interfaces found");
        }

        eprintln!();
        if !missing_artifacts.is_empty() || passed < checked {
            eprintln!("Summary: {passed}/{checked} interfaces are ABI-compatible.");
            if !missing_artifacts.is_empty() {
                eprintln!(
                    "Missing Foundry artifacts: {}",
                    missing_artifacts.iter().copied().join(", ")
                );
            }
            bail!("ABI compatibility check found differences or missing artifacts (see above)");
        }

        eprintln!("Summary: {checked}/{checked} interfaces are ABI-compatible.");
        Ok(())
    }
}

fn interface_specs() -> &'static [InterfaceSpec] {
    &[
        // tempo-std is the published Solidity interface surface for Tempo precompiles.
        // Interfaces not exported there are intentionally not checked here.
        InterfaceSpec {
            solidity_name: "IAccountKeychain",
            abi: pc::IAccountKeychain::abi::contract,
            inherits: &[],
        },
        InterfaceSpec {
            solidity_name: "IFeeAMM",
            abi: pc::ITIPFeeAMM::abi::contract,
            inherits: &[],
        },
        InterfaceSpec {
            solidity_name: "IFeeManager",
            abi: pc::IFeeManager::abi::contract,
            inherits: &["IFeeAMM"],
        },
        InterfaceSpec {
            solidity_name: "INonce",
            abi: pc::INonce::abi::contract,
            inherits: &[],
        },
        InterfaceSpec {
            solidity_name: "IStablecoinDEX",
            abi: pc::IStablecoinDEX::abi::contract,
            inherits: &[],
        },
        InterfaceSpec {
            solidity_name: "ITIP20",
            abi: pc::ITIP20::abi::contract,
            inherits: &[],
        },
        InterfaceSpec {
            solidity_name: "ITIP20Internal",
            abi: pc::ITIP20Internal::abi::contract,
            inherits: &[],
        },
        InterfaceSpec {
            solidity_name: "ITIP20Factory",
            abi: pc::ITIP20Factory::abi::contract,
            inherits: &[],
        },
        InterfaceSpec {
            solidity_name: "ITIP20RolesAuth",
            abi: pc::IRolesAuth::abi::contract,
            inherits: &[],
        },
        InterfaceSpec {
            solidity_name: "ITIP403Registry",
            abi: pc::ITIP403Registry::abi::contract,
            inherits: &[],
        },
        InterfaceSpec {
            solidity_name: "IValidatorConfig",
            abi: pc::IValidatorConfig::abi::contract,
            inherits: &[],
        },
    ]
}

fn check_interface(
    spec: &InterfaceSpec,
    artifact_path: &Path,
    all_specs: &HashMap<&str, &InterfaceSpec>,
) -> eyre::Result<CheckResult> {
    let rust_surface = surface_for_spec(spec, all_specs, &mut Vec::new())?;

    let solidity_abi = load_foundry_abi(artifact_path)
        .with_context(|| format!("parsing {}", artifact_path.display()))?;
    let solidity_surface = surface_from_abi(&solidity_abi);

    let mut rust_only = Vec::new();
    let mut solidity_only = Vec::new();

    diff_sets(
        "function",
        &rust_surface.functions,
        &solidity_surface.functions,
        &mut rust_only,
        &mut solidity_only,
    );
    diff_sets(
        "error",
        &rust_surface.errors,
        &solidity_surface.errors,
        &mut rust_only,
        &mut solidity_only,
    );
    diff_sets(
        "event",
        &rust_surface.events,
        &solidity_surface.events,
        &mut rust_only,
        &mut solidity_only,
    );

    Ok(CheckResult {
        rust_only,
        solidity_only,
    })
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

    let mut surface = surface_from_abi(&(spec.abi)());
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

fn load_foundry_abi(path: &Path) -> eyre::Result<JsonAbi> {
    let content = fs::read_to_string(path)?;
    let artifact: ContractObject = serde_json::from_str(&content)?;
    artifact
        .abi
        .ok_or_else(|| eyre!("missing 'abi' field in {}", path.display()))
}

fn surface_from_abi(abi: &JsonAbi) -> AbiSurface {
    AbiSurface {
        functions: abi.functions().map(function_signature).collect(),
        errors: abi.errors().map(error_signature).collect(),
        events: abi.events().map(event_signature).collect(),
    }
}

impl AbiSurface {
    fn extend(&mut self, other: Self) {
        self.functions.extend(other.functions);
        self.errors.extend(other.errors);
        self.events.extend(other.events);
    }
}

fn diff_sets(
    kind: &str,
    rust: &BTreeSet<String>,
    solidity: &BTreeSet<String>,
    rust_only: &mut Vec<(String, String)>,
    solidity_only: &mut Vec<(String, String)>,
) {
    for sig in rust.difference(solidity) {
        rust_only.push((kind.to_string(), sig.clone()));
    }
    for sig in solidity.difference(rust) {
        solidity_only.push((kind.to_string(), sig.clone()));
    }
}

fn function_signature(function: &Function) -> String {
    let inputs = function.inputs.iter().map(param_type).join(",");
    let mut signature = format!("{}({inputs})", function.name);

    if !function.outputs.is_empty() {
        let outputs = canonical_output_types(&function.outputs);
        signature.push_str(&format!(" returns ({outputs})"));
    }

    signature.push_str(&format!(
        " [{}]",
        state_mutability(function.state_mutability)
    ));
    signature
}

fn error_signature(error: &Error) -> String {
    let inputs = error.inputs.iter().map(param_type).join(",");
    format!("{}({inputs})", error.name)
}

fn event_signature(event: &Event) -> String {
    let inputs = event.inputs.iter().map(event_param_signature).join(",");
    let mut signature = format!("{}({inputs})", event.name);
    if event.anonymous {
        signature.push_str(" [anonymous]");
    }
    signature
}

fn event_param_signature(param: &EventParam) -> String {
    let ty = event_param_type(param);
    if param.indexed {
        format!("indexed {ty}")
    } else {
        ty
    }
}

fn param_type(param: &Param) -> String {
    canonical_param_type(&param.ty, &param.components)
}

fn event_param_type(param: &EventParam) -> String {
    canonical_param_type(&param.ty, &param.components)
}

fn canonical_output_types(outputs: &[Param]) -> String {
    match outputs {
        [output] if output.ty == "tuple" => output.components.iter().map(param_type).join(","),
        _ => outputs.iter().map(param_type).join(","),
    }
}

fn canonical_param_type(ty: &str, components: &[Param]) -> String {
    if components.is_empty() {
        return ty.to_string();
    }

    let inner = components.iter().map(param_type).join(",");
    let tuple = format!("({inner})");

    if ty == "tuple" {
        tuple
    } else if let Some(suffix) = ty.strip_prefix("tuple") {
        format!("{tuple}{suffix}")
    } else {
        ty.to_string()
    }
}

fn state_mutability(state_mutability: StateMutability) -> &'static str {
    match state_mutability {
        StateMutability::Pure => "pure",
        StateMutability::View => "view",
        StateMutability::NonPayable => "nonpayable",
        StateMutability::Payable => "payable",
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

fn find_workspace_root() -> eyre::Result<PathBuf> {
    let output = std::process::Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version=1"])
        .output()
        .context("failed to run cargo metadata")?;

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse cargo metadata")?;

    let root = metadata
        .get("workspace_root")
        .and_then(|value| value.as_str())
        .ok_or_else(|| eyre!("missing workspace_root in cargo metadata"))?;

    Ok(PathBuf::from(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_from_abi_preserves_tuple_signatures() {
        let abi = JsonAbi::parse([
            "function addPerson(tuple(string,uint16) person)",
            "event PersonAdded(uint indexed id, tuple(string,uint16) person)",
            "error BadPerson(tuple(string,uint16) person)",
        ])
        .unwrap();

        let surface = surface_from_abi(&abi);
        assert!(
            surface
                .functions
                .contains("addPerson((string,uint16)) [nonpayable]")
        );
        assert!(
            surface
                .events
                .contains("PersonAdded(indexed uint256,(string,uint16))")
        );
        assert!(surface.errors.contains("BadPerson((string,uint16))"));
    }

    #[test]
    fn surface_from_abi_tracks_returns_mutability_and_anonymous_events() {
        let abi = JsonAbi::parse([
            "function foo(uint256 value) external view returns (bool ok)",
            "event Bar(address indexed from, uint256 amount) anonymous",
        ])
        .unwrap();

        let surface = surface_from_abi(&abi);
        assert!(
            surface
                .functions
                .contains("foo(uint256) returns (bool) [view]")
        );
        assert!(
            surface
                .events
                .contains("Bar(indexed address,uint256) [anonymous]")
        );
    }

    #[test]
    fn function_signature_treats_single_tuple_outputs_like_flat_outputs() {
        let tuple_output =
            JsonAbi::parse(["function pool() external view returns ((uint128,uint128) reserves)"])
                .unwrap();
        let flat_output = JsonAbi::parse([
            "function pool() external view returns (uint128 reserveUserToken, uint128 reserveValidatorToken)",
        ])
        .unwrap();

        let tuple_signature = tuple_output
            .functions()
            .next()
            .map(function_signature)
            .unwrap();
        let flat_signature = flat_output
            .functions()
            .next()
            .map(function_signature)
            .unwrap();

        assert_eq!(tuple_signature, flat_signature);
        assert_eq!(tuple_signature, "pool() returns (uint128,uint128) [view]");
    }

    #[test]
    fn diff_sets_reports_symmetric_differences() {
        let rust = BTreeSet::from(["foo(uint256) [nonpayable]".to_string()]);
        let solidity = BTreeSet::from(["bar(uint256) [nonpayable]".to_string()]);

        let mut rust_only = Vec::new();
        let mut solidity_only = Vec::new();
        diff_sets(
            "function",
            &rust,
            &solidity,
            &mut rust_only,
            &mut solidity_only,
        );

        assert_eq!(
            rust_only,
            [(
                "function".to_string(),
                "foo(uint256) [nonpayable]".to_string()
            )]
        );
        assert_eq!(
            solidity_only,
            [(
                "function".to_string(),
                "bar(uint256) [nonpayable]".to_string()
            )]
        );
    }
}
