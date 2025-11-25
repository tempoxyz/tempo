use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path, process::Command};

/// Represents the full compiler output.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SolcOutput {
    contracts: HashMap<String, ContractOutput>,
    #[serde(default)]
    version: Option<String>,
}

/// Represents the full compiler output for a given contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContractOutput {
    #[serde(rename = "storage-layout")]
    storage_layout: StorageLayout,
}

/// Represents the storage layout for a contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct StorageLayout {
    pub(super) storage: Vec<StorageVariable>,
    pub(super) types: HashMap<String, TypeDefinition>,
}

/// Represents a storage layout variable from solc's JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct StorageVariable {
    /// Contract name
    pub(super) contract: String,
    /// Variable name
    pub(super) label: String,
    /// Storage slot number
    pub(super) slot: String,
    /// Byte offset within the storage slot
    pub(super) offset: u64,
    /// Solidity type string: "t_uint256", "t_struct$_Block_$123_storage"
    #[serde(rename = "type")]
    pub(super) ty: String,
}

/// Represents a type definition from Solidity compiler output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct TypeDefinition {
    /// Encoding type: "inplace", "mapping", "dynamic_array"
    pub(super) encoding: String,
    /// Human-readable label
    pub(super) label: String,
    /// Number of bytes this type occupies
    #[serde(rename = "numberOfBytes")]
    pub(super) number_of_bytes: String,
    /// Base type for arrays/mappings
    #[serde(default)]
    pub(super) base: Option<String>,
    /// Key type for mappings
    #[serde(default)]
    pub(super) key: Option<String>,
    /// Value type for mappings
    #[serde(default)]
    pub(super) value: Option<String>,
    /// Struct members
    #[serde(default)]
    pub(super) members: Option<Vec<StorageVariable>>,
}

/// Loads a storage layout from a Solidity source file by running solc.
///
/// **NOTE:** assumes 1 contract per file.
pub(super) fn load_solc_layout(sol_file: &Path) -> StorageLayout {
    if sol_file.extension().and_then(|s| s.to_str()) != Some("sol") {
        panic!("expected .sol file, got: {}", sol_file.display());
    }

    let json_path = sol_file.with_extension("layout.json");
    let content = std::fs::read_to_string(&json_path).unwrap_or_else(|_| {
        // Run solc with storage-layout output
        let output = Command::new("solc")
            .arg("--combined-json")
            .arg("storage-layout")
            .arg(sol_file)
            .output()
            .expect("failed to run solc");

        if !output.status.success() {
            panic!("solc failed: {}", String::from_utf8_lossy(&output.stderr));
        }

        // (De)serialize the value back to a pretty-printed string, and save it
        let json_value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("failed to parse solc JSON output");
        let content = serde_json::to_string_pretty(&json_value).expect("failed to format JSON");
        std::fs::write(&json_path, &content).expect("failed to write JSON file");

        content
    });

    let solc_output: SolcOutput =
        serde_json::from_str(&content).expect("failed to parse solc output");

    // Extract the first contract's storage layout
    solc_output
        .contracts
        .values()
        .next()
        .map(|contract| contract.storage_layout.clone())
        .expect("no contracts found in solc output")
}

/// Represents a Rust storage field extracted from generated constants.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct RustStorageField {
    pub(super) name: &'static str,
    pub(super) slot: U256,
    pub(super) offset: usize,
    pub(super) bytes: usize,
}

impl RustStorageField {
    pub(super) fn new(name: &'static str, slot: U256, offset: usize, bytes: usize) -> Self {
        Self {
            name,
            slot,
            offset,
            bytes,
        }
    }
}

/// Helper to convert Solidity slot string to U256.
pub(super) fn parse_slot(slot_str: &str) -> Result<U256, String> {
    U256::from_str_radix(slot_str, 10)
        .map_err(|e| format!("Failed to parse slot '{slot_str}': {e}"))
}

/// Compares two storage layouts and returns detailed differences.
pub(super) fn compare_layouts(
    solc_layout: &StorageLayout,
    rust_fields: &[RustStorageField],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Build a map of Solidity field names to their storage info
    let solc_fields: HashMap<String, (&StorageVariable, U256)> = solc_layout
        .storage
        .iter()
        .filter_map(|var| {
            parse_slot(&var.slot)
                .ok()
                .map(|slot| (var.label.clone(), (var, slot)))
        })
        .collect();

    // Check that all Rust fields match Solidity fields
    for rust_field in rust_fields {
        match solc_fields.get(rust_field.name) {
            Some((solc_var, solc_slot)) => {
                // Compare slot
                if *solc_slot != rust_field.slot {
                    errors.push(format!(
                        "Field '{}': Solidity slot {} != Rust slot {}",
                        rust_field.name, solc_slot, rust_field.slot
                    ));
                }

                // Compare offset
                if solc_var.offset as usize != rust_field.offset {
                    errors.push(format!(
                        "Field '{}': Solidity offset {} != Rust offset {}",
                        rust_field.name, solc_var.offset, rust_field.offset
                    ));
                }

                // Compare bytes
                if let Some(type_def) = solc_layout.types.get(&solc_var.ty)
                    && let Ok(solc_bytes) = type_def.number_of_bytes.parse::<usize>()
                    && solc_bytes != rust_field.bytes
                {
                    errors.push(format!(
                        "Field '{}': Solidity bytes {} != Rust bytes {}",
                        rust_field.name, solc_bytes, rust_field.bytes
                    ));
                }
            }
            None => {
                errors.push(format!(
                    "Field '{}' exists in Rust but not in Solidity layout",
                    rust_field.name
                ));
            }
        }
    }

    // Check for Solidity fields missing in Rust
    for solc_field_name in solc_fields.keys() {
        if !rust_fields.iter().any(|rf| rf.name == solc_field_name) {
            errors.push(format!(
                "Field '{solc_field_name}' exists in Solidity but not in Rust layout"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Compares struct member layouts within a specific struct field.
///
/// This verifies that struct members have the correct relative offsets
/// from the base slot of the struct.
pub(super) fn compare_struct_members(
    solc_layout: &StorageLayout,
    struct_field_name: &str,
    rust_member_slots: &[RustStorageField],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Find the struct field in the top-level storage
    let struct_var = solc_layout
        .storage
        .iter()
        .find(|v| v.label == struct_field_name)
        .ok_or_else(|| {
            vec![format!(
                "Struct field '{}' not found in Solidity layout",
                struct_field_name
            )]
        })?;

    // Get the base slot of the struct
    let struct_base_slot = parse_slot(&struct_var.slot).map_err(|e| vec![e])?;

    // Get the type definition
    let type_def = solc_layout.types.get(&struct_var.ty).ok_or_else(|| {
        vec![format!(
            "Type definition '{}' not found for field '{}'",
            struct_var.ty, struct_field_name
        )]
    })?;

    // Handle both direct struct fields and mappings with struct values
    let struct_type_def = if type_def.encoding == "mapping" {
        // It's a mapping - get the value type
        let value_type_name = type_def.value.as_ref().ok_or_else(|| {
            vec![format!(
                "Mapping type '{}' does not have a value type",
                struct_var.ty
            )]
        })?;

        // Get the struct type definition from the value type
        solc_layout.types.get(value_type_name).ok_or_else(|| {
            vec![format!(
                "Value type '{}' not found in type definitions",
                value_type_name
            )]
        })?
    } else {
        // It's a direct struct field
        type_def
    };

    // Get the struct members
    let members = struct_type_def.members.as_ref().ok_or_else(|| {
        vec![format!(
            "Type '{}' does not have members (not a struct?)",
            struct_type_def.label
        )]
    })?;

    // Build a map of Solidity member names to their storage info
    let solc_member_info: HashMap<String, (&StorageVariable, U256)> = members
        .iter()
        .filter_map(|member| {
            parse_slot(&member.slot).ok().map(|relative_slot| {
                (
                    member.label.clone(),
                    (member, struct_base_slot + relative_slot),
                )
            })
        })
        .collect();

    // Compare Rust member slots against Solidity
    for rust_member in rust_member_slots {
        match solc_member_info.get(rust_member.name) {
            Some((solc_member, solc_slot)) => {
                // Compare slot
                if *solc_slot != rust_member.slot {
                    errors.push(format!(
                        "Struct member '{}.{}': Solidity slot {} != Rust slot {}",
                        struct_field_name, rust_member.name, solc_slot, rust_member.slot
                    ));
                }

                // Compare offset
                if solc_member.offset as usize != rust_member.offset {
                    errors.push(format!(
                        "Struct member '{}.{}': Solidity offset {} != Rust offset {}",
                        struct_field_name, rust_member.name, solc_member.offset, rust_member.offset
                    ));
                }

                // Compare bytes
                if let Some(member_type_def) = solc_layout.types.get(&solc_member.ty)
                    && let Ok(solc_bytes) = member_type_def.number_of_bytes.parse::<usize>()
                    && solc_bytes != rust_member.bytes
                {
                    errors.push(format!(
                        "Struct member '{}.{}': Solidity bytes {} != Rust bytes {}",
                        struct_field_name, rust_member.name, solc_bytes, rust_member.bytes
                    ));
                }
            }
            None => {
                errors.push(format!(
                    "Struct member '{}.{}' exists in Rust but not in Solidity",
                    struct_field_name, rust_member.name
                ));
            }
        }
    }

    // Check for Solidity members missing in Rust
    for solc_member_name in solc_member_info.keys() {
        if !rust_member_slots
            .iter()
            .any(|rm| rm.name == solc_member_name)
        {
            errors.push(format!(
                "Struct member '{struct_field_name}.{solc_member_name}' exists in Solidity but not in Rust"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Panics with a detailed error message when a storage layout mismatch is detected.
///
/// Includes instructions for updating the Solidity test file when the spec changes.
pub(super) fn panic_layout_mismatch(context: &str, errors: Vec<String>, sol_path: &Path) -> ! {
    let json_path = sol_path.with_extension("layout.json");
    panic!(
        "{context} mismatch:\n{errors}\n\n\
         To fix this mismatch:\n\n\
         1. Update the Solidity file: {sol_path}\n\
            - Add any new fields to match the Rust contract storage layout\n\
            - Use the same field order and types as the Rust definition\n\n\
         2. Update the Rust test (if needed):\n\
            - Add new fields to the `layout_fields!()` macro call\n\
            - For new structs, add a `compare_struct_members()` check using:\n\
              `struct_fields!(slots::FIELD_NAME, member1, member2, ...)`\n\n\
         3. Delete the cached layout: {json_path}\n\n\
         4. Re-run the tests",
        context = context,
        errors = errors.join("\n"),
        sol_path = sol_path.display(),
        json_path = json_path.display(),
    )
}
