//! Tests for basic storage layout primitives.
//!
//! This module validates that the `contract` macro correctly handles fundamental
//! storage patterns like primitive types, arrays, mappings, structs, and enums.

use super::*;
use alloy_primitives::{Address, FixedBytes};
use tempo_precompiles::storage::Mapping;
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
    let sol_path = testdata("basic_types.sol");
    let solc_layout = load_solc_layout(&sol_path);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
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
    let sol_path = testdata("mixed_slots.sol");
    let solc_layout = load_solc_layout(&sol_path);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
    }
}

#[test]
fn test_arrays_layout() {
    #[contract]
    struct Arrays {
        field_a: U256,
        large_array: [U256; 5],
        field_b: U256,
        nested_array: [[u8; 4]; 8],
        another_nested_array: [[u16; 2]; 6],
    }

    let rust_layout = layout_fields!(
        field_a,
        large_array,
        field_b,
        nested_array,
        another_nested_array
    );

    // Compare against expected layout from Solidity
    let sol_path = testdata("arrays.sol");
    let solc_layout = load_solc_layout(&sol_path);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
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
    let sol_path = testdata("mappings.sol");
    let solc_layout = load_solc_layout(&sol_path);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
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

    let sol_path = testdata("structs.sol");
    let solc_layout = load_solc_layout(&sol_path);

    // Verify top-level fields
    let rust_layout = layout_fields!(field_a, block_data, field_b);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
    }

    // Verify struct member slots
    let base_slot = slots::BLOCK_DATA;
    let rust_struct = struct_fields!(base_slot, field1, field2, field3);

    if let Err(errors) = compare_struct_members(&solc_layout, "blockData", &rust_struct) {
        panic_layout_mismatch("Struct member layout", errors, &sol_path);
    }
}

// Test enum storage layout with packing
#[test]
fn test_enums_layout() {
    #[contract]
    struct Enums {
        field_a: u16,     // 2 bytes - slot 0, offset 0
        field_b: u8,      // 1 byte (enum) - slot 0, offset 2
        field_c: Address, // 20 bytes - slot 0, offset 3
    }

    let rust_layout = layout_fields!(field_a, field_b, field_c);

    // Compare against expected layout from Solidity
    let sol_path = testdata("enum.sol");
    let solc_layout = load_solc_layout(&sol_path);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
    }
}

#[test]
fn test_double_mappings_layout() {
    #[contract]
    struct DoubleMappings {
        field_a: U256,
        account_role: Mapping<Address, Mapping<FixedBytes<32>, bool>>,
        allowances: Mapping<Address, Mapping<Address, U256>>,
    }

    let rust_fields = layout_fields!(field_a, account_role, allowances);

    // Compare against expected layout from Solidity
    let sol_path = testdata("double_mappings.sol");
    let solc_layout = load_solc_layout(&sol_path);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_fields) {
        panic_layout_mismatch("Layout", errors, &sol_path);
    }
}
