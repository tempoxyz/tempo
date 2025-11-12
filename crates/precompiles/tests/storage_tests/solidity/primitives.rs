//! Tests for basic storage layout primitives.
//!
//! This module validates that the `contract` macro correctly handles fundamental
//! storage patterns like primitive types, arrays, mappings, structs, and enums.

use super::*;
use tempo_precompiles_macros::{
    gen_test_fields_layout as layout_fields, gen_test_fields_struct as struct_fields,
};
use utils::*;

#[test]
fn test_basic_types_layout() {
    #[contract]
    struct BasicTypes {
        field_a: U256,
        field_b: Address,
        field_c: bool,
        field_d: u64,
    }

    let rust_layout = layout_fields!(field_a, field_b, field_c, field_d);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("basic_types.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_mixed_slots_layout() {
    #[contract]
    struct MixedSlots {
        field_a: U256,
        field_c: U256,
    }

    let rust_layout = layout_fields!(field_a, field_c);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("mixed_slots.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_arrays_layout() {
    #[contract]
    struct Arrays {
        field_a: U256,
        large_array: [U256; 5],
        field_b: U256,
    }

    let rust_layout = layout_fields!(field_a, large_array, field_b);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("arrays.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_mappings_layout() {
    #[contract]
    struct Mappings {
        field_a: U256,
        address_mapping: Mapping<Address, U256>,
        uint_mapping: Mapping<u64, U256>,
    }

    let rust_layout = layout_fields!(field_a, address_mapping, uint_mapping);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("mappings.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

// Test struct storage layout including individual struct member verification
#[test]
fn test_structs_layout() {
    use crate::storage_tests::solidity::__packing_test_block_inner::*;

    #[contract]
    struct Structs {
        field_a: U256,
        block_data: TestBlockInner,
        field_b: U256,
    }

    let solc_layout = load_solc_layout(&testdata("structs.sol"));

    // Verify top-level fields
    let rust_layout = layout_fields!(field_a, block_data, field_b);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }

    // Verify struct member slots
    let base_slot = slots::BLOCK_DATA;
    let rust_struct = struct_fields!(base_slot, field1, field2, field3);

    if let Err(errors) = compare_struct_members(&solc_layout, "blockData", &rust_struct) {
        panic!("Struct member layout mismatch:\n{}", errors.join("\n"));
    }
}

// Test enum storage layout with packing
#[test]
fn test_enums_layout() {
    use alloy::primitives::Address;

    #[contract]
    struct Enums {
        field_a: u16,     // 2 bytes - slot 0, offset 0
        field_b: u8,      // 1 byte (enum) - slot 0, offset 2
        field_c: Address, // 20 bytes - slot 0, offset 3
    }

    let rust_layout = layout_fields!(field_a, field_b, field_c);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("enum.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_double_mappings_layout() {
    use alloy::primitives::FixedBytes;

    #[contract]
    struct DoubleMappings {
        field_a: U256,
        account_role: Mapping<Address, Mapping<FixedBytes<32>, bool>>,
        allowances: Mapping<Address, Mapping<Address, U256>>,
    }

    let rust_fields = layout_fields!(field_a, account_role, allowances);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("double_mappings.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_fields) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}
