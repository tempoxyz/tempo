//! Shared helpers for checking Solidity artifacts against Rust storage metadata.

use std::{collections::HashMap, fs, path::Path, process::Command};

use alloy::primitives::U256;
use serde::Deserialize;

/// One Rust field emitted by the `#[contract]` storage-layout macro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustStorageField {
    pub name: &'static str,
    pub slot: U256,
    pub offset: usize,
    pub bytes: usize,
}

/// One Rust storage-slot constant that should match a Solidity field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustStorageSlot {
    pub name: &'static str,
    pub slot: U256,
}

impl RustStorageSlot {
    pub const fn new(name: &'static str, slot: U256) -> Self {
        Self { name, slot }
    }
}

impl RustStorageField {
    pub fn new(name: &'static str, slot: U256, offset: usize, bytes: usize) -> Self {
        Self {
            name,
            slot,
            offset,
            bytes,
        }
    }

    /// Overrides the generated Rust field name when Solidity uses another label.
    pub fn solidity_name(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }
}

#[derive(Debug, Clone, Deserialize)]
struct FoundryArtifact {
    #[serde(rename = "storageLayout")]
    storage_layout: SolidityStorageLayout,
}

#[derive(Debug, Deserialize)]
struct SolcOutput {
    contracts: HashMap<String, SolcContractOutput>,
}

#[derive(Debug, Deserialize)]
struct SolcContractOutput {
    #[serde(rename = "storage-layout")]
    storage_layout: SolidityStorageLayout,
}

/// Solidity storage metadata emitted by Foundry.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SolidityStorageLayout {
    storage: Vec<SolidityStorageField>,
    types: std::collections::BTreeMap<String, SolidityType>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct SolidityStorageField {
    #[serde(default)]
    contract: String,
    label: String,
    slot: String,
    offset: usize,
    #[serde(rename = "type")]
    ty: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct SolidityType {
    #[serde(default)]
    encoding: String,
    #[serde(default)]
    label: String,
    #[serde(rename = "numberOfBytes")]
    number_of_bytes: String,
    #[serde(default)]
    base: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    members: Option<Vec<SolidityStorageField>>,
}

/// Reads storage metadata from a Foundry JSON artifact.
pub fn load_foundry_layout(path: &Path) -> Result<SolidityStorageLayout, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str::<FoundryArtifact>(&content)
        .map(|artifact| artifact.storage_layout)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Loads a Foundry artifact and compares its full storage layout with Rust metadata.
pub fn compare_foundry_layout(path: &Path, rust: &[RustStorageField]) -> Result<(), Vec<String>> {
    let solidity = load_foundry_layout(path).map_err(|error| vec![error])?;
    compare_layouts(&solidity, rust)
}

/// Loads a Foundry artifact and compares selected storage slots with Rust metadata.
pub fn compare_foundry_slots(path: &Path, rust: &[RustStorageSlot]) -> Result<(), Vec<String>> {
    let solidity = load_foundry_layout(path).map_err(|error| vec![error])?;
    compare_slots(&solidity, rust)
}

/// Asserts that a Foundry artifact's full storage layout matches Rust metadata.
pub fn assert_foundry_layout(path: &Path, rust: &[RustStorageField]) {
    compare_foundry_layout(path, rust).unwrap_or_else(|errors| {
        panic!(
            "storage layout mismatch for {}:\n{}",
            path.display(),
            errors.join("\n")
        )
    });
}

/// Asserts that selected slots in a Foundry artifact match Rust metadata.
pub fn assert_foundry_slots(path: &Path, rust: &[RustStorageSlot]) {
    compare_foundry_slots(path, rust).unwrap_or_else(|errors| {
        panic!(
            "storage slot mismatch for {}:\n{}",
            path.display(),
            errors.join("\n")
        )
    });
}

/// Loads a cached solc layout, generating it from a Solidity source file when absent.
pub fn load_solc_layout(sol_file: &Path) -> SolidityStorageLayout {
    assert_eq!(
        sol_file
            .extension()
            .and_then(|extension| extension.to_str()),
        Some("sol"),
        "expected .sol file, got: {}",
        sol_file.display()
    );
    let json_path = sol_file.with_extension("layout.json");
    let content = fs::read_to_string(&json_path).unwrap_or_else(|_| {
        let output = Command::new("solc")
            .arg("--combined-json")
            .arg("storage-layout")
            .arg(sol_file)
            .output()
            .expect("failed to run solc");
        assert!(
            output.status.success(),
            "solc failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("failed to parse solc JSON output");
        let content = serde_json::to_string_pretty(&json).expect("failed to format solc output");
        fs::write(&json_path, &content).expect("failed to cache solc layout");
        content
    });
    serde_json::from_str::<SolcOutput>(&content)
        .expect("failed to parse solc output")
        .contracts
        .into_values()
        .next()
        .map(|contract| contract.storage_layout)
        .expect("no contracts found in solc output")
}

/// Panics with a storage-layout mismatch and cache-refresh instructions.
pub fn panic_layout_mismatch(context: &str, errors: Vec<String>, sol_path: &Path) -> ! {
    let json_path = sol_path.with_extension("layout.json");
    panic!(
        "{context} mismatch:\n{errors}\n\nupdate {sol_path}, delete {json_path}, and rerun the tests",
        errors = errors.join("\n"),
        sol_path = sol_path.display(),
        json_path = json_path.display(),
    )
}

/// Compares all top-level Solidity and Rust fields, including slots, offsets, and widths.
pub fn compare_layouts(
    solidity: &SolidityStorageLayout,
    rust: &[RustStorageField],
) -> Result<(), Vec<String>> {
    let fields: std::collections::BTreeMap<_, _> = solidity
        .storage
        .iter()
        .map(|field| (field.label.as_str(), field))
        .collect();
    let mut errors = Vec::new();
    for field in rust {
        let Some(solidity_field) = fields.get(field.name) else {
            errors.push(format!("{} exists in Rust but not Solidity", field.name));
            continue;
        };
        let slot =
            U256::from_str_radix(&solidity_field.slot, 10).expect("solc emits decimal slots");
        let bytes = solidity
            .types
            .get(&solidity_field.ty)
            .and_then(|ty| ty.number_of_bytes.parse::<usize>().ok())
            .expect("solc emits type widths");
        if (slot, solidity_field.offset, bytes) != (field.slot, field.offset, field.bytes) {
            errors.push(format!(
                "{}: Solidity=({slot},{},{bytes}), Rust=({},{},{})",
                field.name, solidity_field.offset, field.slot, field.offset, field.bytes
            ));
        }
    }
    for name in fields.keys() {
        if !rust.iter().any(|field| field.name == *name) {
            errors.push(format!("{name} exists in Solidity but not Rust"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Compares selected Rust slot constants with fields in a Solidity storage layout.
pub fn compare_slots(
    solidity: &SolidityStorageLayout,
    rust: &[RustStorageSlot],
) -> Result<(), Vec<String>> {
    let fields: std::collections::BTreeMap<_, _> = solidity
        .storage
        .iter()
        .map(|field| (field.label.as_str(), field))
        .collect();
    let mut errors = Vec::new();
    for field in rust {
        let Some(solidity_field) = fields.get(field.name) else {
            errors.push(format!("{} exists in Rust but not Solidity", field.name));
            continue;
        };
        let slot =
            U256::from_str_radix(&solidity_field.slot, 10).expect("solc emits decimal slots");
        if slot != field.slot {
            errors.push(format!(
                "{}: Solidity slot={slot}, Rust slot={}",
                field.name, field.slot
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Compares members of a Solidity struct field with generated Rust metadata.
pub fn compare_struct_members(
    solidity: &SolidityStorageLayout,
    field_name: &str,
    rust: &[RustStorageField],
) -> Result<(), Vec<String>> {
    let field = solidity
        .storage
        .iter()
        .find(|field| field.label == field_name)
        .ok_or_else(|| {
            vec![format!(
                "Struct field '{field_name}' not found in Solidity layout"
            )]
        })?;
    let base_slot = parse_slot(&field.slot).map_err(|error| vec![error])?;
    let ty = solidity
        .types
        .get(&field.ty)
        .ok_or_else(|| vec![format!("Type definition '{}' not found", field.ty)])?;
    let struct_ty = match ty.encoding.as_str() {
        "mapping" => ty
            .value
            .as_ref()
            .and_then(|name| solidity.types.get(name))
            .ok_or_else(|| vec![format!("Mapping '{}' has no struct value type", field.ty)])?,
        "dynamic_array" => ty
            .base
            .as_ref()
            .and_then(|name| solidity.types.get(name))
            .ok_or_else(|| vec![format!("Array '{}' has no struct element type", field.ty)])?,
        _ => ty,
    };
    compare_type_members(solidity, struct_ty, field_name, rust, Some(base_slot))
}

/// Compares a named nested Solidity struct type with generated Rust metadata.
pub fn compare_nested_struct_type(
    solidity: &SolidityStorageLayout,
    type_name: &str,
    rust: &[RustStorageField],
) -> Result<(), Vec<String>> {
    let ty = solidity
        .types
        .values()
        .find(|ty| ty.label.rsplit('.').next() == Some(type_name))
        .ok_or_else(|| vec![format!("Type '{type_name}' not found in Solidity layout")])?;
    compare_type_members(solidity, ty, type_name, rust, None)
}

fn compare_type_members(
    solidity: &SolidityStorageLayout,
    ty: &SolidityType,
    context: &str,
    rust: &[RustStorageField],
    base_slot: Option<U256>,
) -> Result<(), Vec<String>> {
    let members = ty
        .members
        .as_ref()
        .ok_or_else(|| vec![format!("Type '{}' is not a struct", ty.label)])?;
    let solidity_members: std::collections::BTreeMap<_, _> = members
        .iter()
        .map(|member| (member.label.as_str(), member))
        .collect();
    let mut errors = Vec::new();
    for field in rust {
        let Some(member) = solidity_members.get(field.name) else {
            errors.push(format!(
                "{context}.{} exists in Rust but not Solidity",
                field.name
            ));
            continue;
        };
        if let Some(base) = base_slot
            && let Ok(relative) = parse_slot(&member.slot)
            && base + relative != field.slot
        {
            errors.push(format!(
                "{context}.{}: Solidity slot={}, Rust slot={}",
                field.name,
                base + relative,
                field.slot
            ));
        }
        let bytes = solidity
            .types
            .get(&member.ty)
            .and_then(|ty| ty.number_of_bytes.parse::<usize>().ok());
        if member.offset != field.offset || bytes.is_some_and(|bytes| bytes != field.bytes) {
            errors.push(format!(
                "{context}.{}: Solidity=({},{:?}), Rust=({},{})",
                field.name, member.offset, bytes, field.offset, field.bytes
            ));
        }
    }
    for name in solidity_members.keys() {
        if !rust.iter().any(|field| field.name == *name) {
            errors.push(format!("{context}.{name} exists in Solidity but not Rust"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn parse_slot(slot: &str) -> Result<U256, String> {
    U256::from_str_radix(slot, 10).map_err(|error| format!("invalid slot '{slot}': {error}"))
}
