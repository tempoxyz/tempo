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
    interface_spec!(ITIPFeeAMM).with_name("IFeeAMM"),
    interface_spec!(IFeeManager).inherits(&["IFeeAMM"]),
    interface_spec!(IStablecoinDEX),
    interface_spec!(IValidatorConfig),
    interface_spec!(IValidatorConfigV2),
];

/// List of `(kind, signature)` pairs, e.g. `("function", "foo(uint256) [view]")`.
type DiffEntries = Vec<(String, String)>;

#[derive(Default)]
struct AbiSurface {
    functions: BTreeSet<String>,
    errors: BTreeSet<String>,
    events: BTreeSet<String>,
}

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
            None => find_workspace_root()?.join("tips/ref-impls/lib/tempo-std"),
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
        .with_context(|| format!("parsing {}", artifact_path.display()))?;
    let solidity_surface = surface_from_abi(&solidity_abi);

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

    /// Returns `(only_in_self, only_in_other)` diffs grouped by kind.
    fn diff(&self, other: &Self) -> (DiffEntries, DiffEntries) {
        let mut only_self = Vec::new();
        let mut only_other = Vec::new();
        for (kind, a, b) in [
            ("function", &self.functions, &other.functions),
            ("error", &self.errors, &other.errors),
            ("event", &self.events, &other.events),
        ] {
            for sig in a.difference(b) {
                only_self.push((kind.to_string(), sig.clone()));
            }
            for sig in b.difference(a) {
                only_other.push((kind.to_string(), sig.clone()));
            }
        }
        (only_self, only_other)
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
    let ty = canonical_param_type(&param.ty, &param.components);
    if param.indexed {
        format!("indexed {ty}")
    } else {
        ty
    }
}

fn param_type(param: &Param) -> String {
    canonical_param_type(&param.ty, &param.components)
}

/// Flattens a single bare-tuples so that if they share the same abi encoding they are equivalent.
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
    fn diff_reports_symmetric_differences() {
        let rust = AbiSurface {
            functions: BTreeSet::from(["foo(uint256) [nonpayable]".to_string()]),
            ..Default::default()
        };
        let solidity = AbiSurface {
            functions: BTreeSet::from(["bar(uint256) [nonpayable]".to_string()]),
            ..Default::default()
        };

        let (rust_only, sol_only) = rust.diff(&solidity);

        assert_eq!(
            rust_only,
            [(
                "function".to_string(),
                "foo(uint256) [nonpayable]".to_string()
            )]
        );
        assert_eq!(
            sol_only,
            [(
                "function".to_string(),
                "bar(uint256) [nonpayable]".to_string()
            )]
        );
    }
}
