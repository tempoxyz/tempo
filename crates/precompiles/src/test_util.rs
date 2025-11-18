//! Test utilities for precompile dispatch testing

use crate::Precompile;
use alloy::{
    primitives::{Address, Bytes},
    sol_types::SolError,
};
use revm::precompile::PrecompileError;
use tempo_contracts::precompiles::UnknownFunctionSelector;

/// Checks that all selectors in an interface have dispatch handlers.
///
/// Calls each selector with dummy parameters and checks for "Unknown function selector" errors.
/// Returns unsupported selectors as `(selector_bytes, function_name)` tuples.
pub fn check_selector_coverage<P: Precompile>(
    precompile: &mut P,
    selectors: &[[u8; 4]],
    interface_name: &str,
    name_lookup: impl Fn([u8; 4]) -> Option<&'static str>,
) -> Vec<([u8; 4], &'static str)> {
    let mut unsupported_selectors = Vec::new();

    for selector in selectors.iter() {
        let mut calldata = selector.to_vec();
        // Add some dummy data for functions that require parameters
        calldata.extend_from_slice(&[0u8; 32]);

        let result = precompile.call(&Bytes::from(calldata), Address::ZERO);

        // Check if we got "Unknown function selector" error (old format)
        let is_unsupported_old = matches!(&result,
            Err(PrecompileError::Other(msg)) if msg.contains("Unknown function selector")
        );

        // Check if we got "Unknown function selector" error (new format - ABI-encoded)
        let is_unsupported_new = if let Ok(output) = &result {
            output.reverted && UnknownFunctionSelector::abi_decode(&output.bytes).is_ok()
        } else {
            false
        };

        if (is_unsupported_old || is_unsupported_new)
            && let Some(name) = name_lookup(*selector)
        {
            unsupported_selectors.push((*selector, name));
        }
    }

    // Print unsupported selectors for visibility
    if !unsupported_selectors.is_empty() {
        eprintln!("Unsupported {interface_name} selectors:");
        for (selector, name) in &unsupported_selectors {
            eprintln!("  - {name} ({selector:?})");
        }
    }

    unsupported_selectors
}

/// Asserts that multiple selector coverage checks all pass (no unsupported selectors).
///
/// Takes an iterator of unsupported selector results and panics if any are found.
pub fn assert_full_coverage(results: impl IntoIterator<Item = Vec<([u8; 4], &'static str)>>) {
    let all_unsupported: Vec<_> = results
        .into_iter()
        .flat_map(|r| r.into_iter())
        .map(|(_, name)| name)
        .collect();

    assert!(
        all_unsupported.is_empty(),
        "Found {} unsupported selectors: {:?}",
        all_unsupported.len(),
        all_unsupported
    );
}
