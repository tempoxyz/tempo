//! Shared helpers for checking Solidity artifacts against Rust ABI metadata.

use std::{collections::BTreeSet, fs, path::Path};

use alloy_json_abi::{ContractObject, Error, Event, Function, JsonAbi};

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
    /// Builds full function and event signature sets and a canonical error signature set.
    ///
    /// Function and event parameter names are included to detect swapped same-typed parameters,
    /// which canonical ABI signatures cannot distinguish.
    pub fn from_abi(abi: &JsonAbi) -> Self {
        Self {
            functions: abi.functions().map(Function::full_signature).collect(),
            errors: abi.errors().map(Error::signature).collect(),
            events: abi.events().map(Event::full_signature).collect(),
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
                .contains("function pool() view returns (tuple(uint128, uint128) reserves)")
        );
        assert!(
            surface
                .events
                .contains("event Bar(address indexed from, uint256 amount) anonymous")
        );
        assert!(surface.errors.contains("BadPerson((string,uint16))"));
    }

    #[test]
    fn function_parameter_names_are_part_of_conformance() {
        let rust = JsonAbi::parse([
            "function deliverWithdrawal(address to, address token, uint128 amount, bytes32 memo, uint64 gasLimit, bytes callbackData)",
        ])
        .unwrap();
        let solidity = JsonAbi::parse([
            "function deliverWithdrawal(address token, address target, uint128 amount, bytes32 senderTag, uint64 gasLimit, bytes data)",
        ])
        .unwrap();

        let rust = AbiSurface::from_abi(&rust);
        let solidity = AbiSurface::from_abi(&solidity);

        assert_ne!(rust, solidity);
        let (rust_only, solidity_only) = rust.diff(&solidity);
        assert_eq!(rust_only.len(), 1);
        assert_eq!(solidity_only.len(), 1);
        assert_eq!(rust_only[0].0, "function");
        assert!(rust_only[0].1.contains("address to, address token"));
        assert!(solidity_only[0].1.contains("address token, address target"));
    }

    #[test]
    fn event_parameter_names_are_part_of_conformance() {
        let rust =
            JsonAbi::parse(["event Transfer(address indexed from, address indexed to)"]).unwrap();
        let solidity =
            JsonAbi::parse(["event Transfer(address indexed sender, address indexed recipient)"])
                .unwrap();

        let rust = AbiSurface::from_abi(&rust);
        let solidity = AbiSurface::from_abi(&solidity);

        assert_ne!(rust, solidity);
        let (rust_only, solidity_only) = rust.diff(&solidity);
        assert_eq!(rust_only.len(), 1);
        assert_eq!(solidity_only.len(), 1);
        assert_eq!(rust_only[0].0, "event");
        assert!(rust_only[0].1.contains("address indexed from"));
        assert!(solidity_only[0].1.contains("address indexed sender"));
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
