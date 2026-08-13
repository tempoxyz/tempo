//! Shared helpers for checking Solidity artifacts against Rust ABI and storage metadata.

use std::{collections::BTreeSet, fs, path::Path};

use alloy::primitives::U256;
use alloy_json_abi::{ContractObject, JsonAbi};
use serde::Deserialize;

/// The ABI surface relevant to Solidity/Rust compatibility.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AbiSurface {
    entries: BTreeSet<String>,
}

impl AbiSurface {
    /// Builds a canonical function, error, and event signature set.
    pub fn from_abi(abi: &JsonAbi) -> Self {
        let mut entries = BTreeSet::new();
        entries.extend(
            abi.functions()
                .map(|item| format!("function {}", item.signature())),
        );
        entries.extend(
            abi.errors()
                .map(|item| format!("error {}", item.signature())),
        );
        entries.extend(
            abi.events()
                .map(|item| format!("event {}", item.signature())),
        );
        Self { entries }
    }

    /// Returns signatures present only in `self` and only in `other`.
    pub fn diff(&self, other: &Self) -> (Vec<String>, Vec<String>) {
        (
            self.entries.difference(&other.entries).cloned().collect(),
            other.entries.difference(&self.entries).cloned().collect(),
        )
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

#[derive(Debug, Deserialize)]
struct FoundryArtifact {
    #[serde(rename = "storageLayout")]
    storage_layout: SolidityStorageLayout,
}

/// Solidity storage metadata emitted by Foundry.
#[derive(Debug, Deserialize)]
pub struct SolidityStorageLayout {
    storage: Vec<SolidityStorageField>,
    types: std::collections::BTreeMap<String, SolidityType>,
}

#[derive(Debug, Deserialize)]
struct SolidityStorageField {
    label: String,
    slot: String,
    offset: usize,
    #[serde(rename = "type")]
    ty: String,
}

#[derive(Debug, Deserialize)]
struct SolidityType {
    #[serde(rename = "numberOfBytes")]
    number_of_bytes: String,
}

/// Reads storage metadata from a Foundry JSON artifact.
pub fn load_foundry_storage_layout(path: &Path) -> Result<SolidityStorageLayout, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str::<FoundryArtifact>(&content)
        .map(|artifact| artifact.storage_layout)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Compares all top-level Solidity and Rust fields, including slots, offsets, and widths.
pub fn compare_storage_layout(
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
pub fn compare_storage_slots(
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
