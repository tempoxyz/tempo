//! Shared helpers for checking Solidity artifacts against Rust ABI metadata.

use std::{collections::BTreeSet, fs, path::Path};

use alloy_json_abi::{
    ContractObject, Error, Event, EventParam, Function, JsonAbi, Param, StateMutability,
};
use itertools::Itertools;

/// List of `(kind, signature)` pairs.
pub type DiffEntries = Vec<(String, String)>;

/// The ABI surface relevant to Solidity/Rust compatibility.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AbiSurface {
    functions: BTreeSet<String>,
    errors: BTreeSet<String>,
    events: BTreeSet<String>,
}

impl AbiSurface {
    /// Builds a canonical function, error, and event signature set.
    pub fn from_abi(abi: &JsonAbi) -> Self {
        Self {
            functions: abi.functions().map(function_signature).collect(),
            errors: abi.errors().map(error_signature).collect(),
            events: abi.events().map(event_signature).collect(),
        }
    }

    /// Adds another interface surface, for explicit Solidity inheritance.
    pub fn extend(&mut self, other: Self) {
        self.functions.extend(other.functions);
        self.errors.extend(other.errors);
        self.events.extend(other.events);
    }

    /// Removes function signatures that are intentionally absent from the compared surface.
    pub fn remove_functions(&mut self, functions: &[&str]) {
        for function in functions {
            self.functions.remove(*function);
        }
    }

    /// Returns `(only_in_self, only_in_other)` diffs grouped by ABI kind.
    pub fn diff(&self, other: &Self) -> (DiffEntries, DiffEntries) {
        let mut only_self = Vec::new();
        let mut only_other = Vec::new();
        for (kind, left, right) in [
            ("function", &self.functions, &other.functions),
            ("error", &self.errors, &other.errors),
            ("event", &self.events, &other.events),
        ] {
            only_self.extend(
                left.difference(right)
                    .cloned()
                    .map(|signature| (kind.to_string(), signature)),
            );
            only_other.extend(
                right
                    .difference(left)
                    .cloned()
                    .map(|signature| (kind.to_string(), signature)),
            );
        }
        (only_self, only_other)
    }
}

/// Reads the ABI from a Foundry JSON artifact.
pub fn load_foundry_abi(path: &Path) -> Result<JsonAbi, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let artifact: ContractObject =
        serde_json::from_str(&content).map_err(|error| format!("{}: {error}", path.display()))?;
    artifact
        .abi
        .ok_or_else(|| format!("{} has no ABI", path.display()))
}

/// Loads a Foundry ABI and compares it with a Rust ABI surface, excluding explicitly listed
/// Solidity-only function signatures.
pub fn compare_abi(
    path: &Path,
    rust: &AbiSurface,
    ignored_functions: &[&str],
) -> Result<(), Vec<String>> {
    let mut solidity = load_foundry_abi(path)
        .map(|abi| AbiSurface::from_abi(&abi))
        .map_err(|error| vec![error])?;
    solidity.remove_functions(ignored_functions);
    let (rust_only, solidity_only) = rust.diff(&solidity);
    let mut errors = Vec::new();
    errors.extend(
        rust_only
            .into_iter()
            .map(|(kind, entry)| format!("{kind} only in Rust: {entry}")),
    );
    errors.extend(
        solidity_only
            .into_iter()
            .map(|(kind, entry)| format!("{kind} only in Solidity: {entry}")),
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn function_signature(function: &Function) -> String {
    let inputs = function.inputs.iter().map(param_type).join(",");
    let mut signature = format!("{}({inputs})", function.name);
    if !function.outputs.is_empty() {
        signature.push_str(&format!(
            " returns ({})",
            canonical_output_types(&function.outputs)
        ));
    }
    signature.push_str(&format!(
        " [{}]",
        state_mutability(function.state_mutability)
    ));
    signature
}

fn error_signature(error: &Error) -> String {
    format!(
        "{}({})",
        error.name,
        error.inputs.iter().map(param_type).join(",")
    )
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
    let tuple = format!("({})", components.iter().map(param_type).join(","));
    if ty == "tuple" {
        tuple
    } else if let Some(suffix) = ty.strip_prefix("tuple") {
        format!("{tuple}{suffix}")
    } else {
        ty.to_string()
    }
}

fn state_mutability(state: StateMutability) -> &'static str {
    match state {
        StateMutability::Pure => "pure",
        StateMutability::View => "view",
        StateMutability::NonPayable => "nonpayable",
        StateMutability::Payable => "payable",
    }
}

/// Asserts that a Foundry artifact's ABI matches a Rust ABI surface.
pub fn assert_abi(path: &Path, rust: &AbiSurface) {
    compare_abi(path, rust, &[]).unwrap_or_else(|errors| {
        panic!(
            "ABI mismatch for {}:\n{}",
            path.display(),
            errors.join("\n")
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_tuple_returns_mutability_and_events() {
        let abi = JsonAbi::parse([
            "function pool() external view returns ((uint128,uint128) reserves)",
            "event Bar(address indexed from, uint256 amount) anonymous",
            "error BadPerson(tuple(string,uint16) person)",
        ])
        .unwrap();
        let surface = AbiSurface::from_abi(&abi);
        assert!(
            surface
                .functions
                .contains("pool() returns (uint128,uint128) [view]")
        );
        assert!(
            surface
                .events
                .contains("Bar(indexed address,uint256) [anonymous]")
        );
        assert!(surface.errors.contains("BadPerson((string,uint16))"));
    }

    #[test]
    fn reports_grouped_symmetric_differences() {
        let left = AbiSurface {
            functions: BTreeSet::from(["foo(uint256) [nonpayable]".to_string()]),
            ..Default::default()
        };
        let right = AbiSurface {
            functions: BTreeSet::from(["bar(uint256) [nonpayable]".to_string()]),
            ..Default::default()
        };
        assert_eq!(
            left.diff(&right),
            (
                vec![(
                    "function".to_string(),
                    "foo(uint256) [nonpayable]".to_string()
                )],
                vec![(
                    "function".to_string(),
                    "bar(uint256) [nonpayable]".to_string()
                )],
            )
        );
    }

    #[test]
    fn ignores_explicit_solidity_only_functions() {
        let mut solidity = AbiSurface {
            functions: BTreeSet::from([
                "foo() [view]".to_string(),
                "referenceOnly() [view]".to_string(),
            ]),
            ..Default::default()
        };
        solidity.remove_functions(&["referenceOnly() [view]"]);
        let rust = AbiSurface {
            functions: BTreeSet::from(["foo() [view]".to_string()]),
            ..Default::default()
        };
        assert_eq!(rust.diff(&solidity), (Vec::new(), Vec::new()));
    }
}
