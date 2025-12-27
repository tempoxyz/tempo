//! Selector computation for the `#[solidity]` module macro.
//!
//! This module provides utilities for computing 4-byte function/error selectors
//! and 32-byte event topic selectors using keccak256 hashing.
//!
//! Selectors are computed from fully-resolved ABI signatures (with struct types
//! expanded to their tuple representations) and generated as literal `[u8; 4]`
//! or `[u8; 32]` values for zero runtime overhead.
//!
//! # Function/Error Selectors
//!
//! ```text
//! transfer(address,uint256)  ->  keccak256(...)[:4]  ->  0xa9059cbb
//! ```
//!
//! # Event Topic Selectors
//!
//! ```text
//! Transfer(address,address,uint256)  ->  keccak256(...)  ->  0xddf2...
//! ```

#![allow(dead_code)]

use alloy_sol_macro_expander::selector as alloy_selector;
use proc_macro2::TokenStream;
use quote::quote;
use syn::Type;

use super::registry::TypeRegistry;

/// Compute the 4-byte selector for a function or error signature.
///
/// This is a direct wrapper around `alloy_sol_macro_expander::selector`
/// for cases where the signature string is already resolved.
///
/// # Example
///
/// ```ignore
/// let sel = selector("transfer(address,uint256)");
/// assert_eq!(sel, [0xa9, 0x05, 0x9c, 0xbb]);
/// ```
#[inline]
pub(super) fn selector(signature: &str) -> [u8; 4] {
    alloy_selector(signature)
}

/// Compute the 4-byte selector for a function/error with parameters.
///
/// Uses the registry to resolve struct types to their ABI tuple representations.
///
/// # Example
///
/// ```ignore
/// // Given struct Transfer { from: Address, to: Address, amount: U256 }
/// let sig = compute_function_selector(&registry, "transfer", &[parse_quote!(Transfer)])?;
/// // Returns selector for "transfer((address,address,uint256))"
/// ```
pub(super) fn compute_function_selector(
    registry: &TypeRegistry,
    name: &str,
    params: &[Type],
) -> syn::Result<[u8; 4]> {
    let signature = registry.compute_signature(name, params)?;
    Ok(selector(&signature))
}

/// Compute the 32-byte keccak256 hash for an event signature (topic0).
///
/// Events use the full 32-byte hash as their topic selector.
///
/// # Example
///
/// ```ignore
/// let topic = event_selector("Transfer(address,address,uint256)");
/// ```
pub(super) fn event_selector(signature: &str) -> [u8; 32] {
    use alloy::primitives::keccak256;
    *keccak256(signature.as_bytes())
}

/// Compute the event selector for an event with parameters.
///
/// Uses the registry to resolve struct types to their ABI tuple representations.
pub(super) fn compute_event_selector(
    registry: &TypeRegistry,
    name: &str,
    params: &[Type],
) -> syn::Result<[u8; 32]> {
    let signature = registry.compute_signature(name, params)?;
    Ok(event_selector(&signature))
}

/// Generate a TokenStream for a literal `[u8; 4]` selector constant.
///
/// This generates code that embeds the selector directly as a constant,
/// avoiding any runtime computation.
///
/// # Example
///
/// ```ignore
/// let selector_tokens = generate_selector_literal(&[0xa9, 0x05, 0x9c, 0xbb]);
/// // Generates: [0xa9u8, 0x05u8, 0x9cu8, 0xbbu8]
/// ```
pub(super) fn generate_selector_literal(sel: &[u8; 4]) -> TokenStream {
    let bytes = sel.iter().map(|b| quote! { #b });
    quote! { [#(#bytes),*] }
}

/// Generate a TokenStream for a literal `[u8; 32]` event topic constant.
///
/// This generates code that embeds the topic selector directly as a constant.
pub(super) fn generate_topic_literal(topic: &[u8; 32]) -> TokenStream {
    let bytes = topic.iter().map(|b| quote! { #b });
    quote! { [#(#bytes),*] }
}

/// Generate selector and signature constants for a function/error.
///
/// Returns a TokenStream containing:
/// - `const SIGNATURE: &'static str = "name(params)";`
/// - `const SELECTOR: [u8; 4] = [...];`
pub(super) fn generate_selector_constants(
    registry: &TypeRegistry,
    name: &str,
    params: &[Type],
) -> syn::Result<TokenStream> {
    let signature = registry.compute_signature(name, params)?;
    let sel = selector(&signature);
    let sel_literal = generate_selector_literal(&sel);

    Ok(quote! {
        const SIGNATURE: &'static str = #signature;
        const SELECTOR: [u8; 4] = #sel_literal;
    })
}

/// Generate topic selector constant for an event.
///
/// Returns a TokenStream containing:
/// - `const SIGNATURE: &'static str = "EventName(params)";`
/// - `const SIGNATURE_HASH: alloy_sol_types::private::B256 = ...;`
pub(super) fn generate_event_topic_constants(
    registry: &TypeRegistry,
    name: &str,
    params: &[Type],
) -> syn::Result<TokenStream> {
    let signature = registry.compute_signature(name, params)?;
    let topic = event_selector(&signature);
    let topic_literal = generate_topic_literal(&topic);

    Ok(quote! {
        const SIGNATURE: &'static str = #signature;
        const SIGNATURE_HASH: alloy_sol_types::private::B256 =
            alloy_sol_types::private::B256::new(#topic_literal);
    })
}

/// Compute selector hex string for documentation.
///
/// Returns a string like "0xa9059cbb" for use in doc comments.
pub(super) fn selector_hex(sel: &[u8; 4]) -> String {
    format!("0x{}", hex::encode(sel))
}

/// Compute topic hex string for documentation.
///
/// Returns a string like "0xddf252ad..." for use in doc comments.
pub(super) fn topic_hex(topic: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(topic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solidity::parser::{FieldDef, SolStructDef, SolidityModule};
    use proc_macro2::Span;
    use quote::format_ident;
    use syn::{parse_quote, Visibility};

    fn make_field(name: &str, ty: Type) -> FieldDef {
        FieldDef {
            name: format_ident!("{}", name),
            ty,
            indexed: false,
            vis: Visibility::Public(syn::token::Pub {
                span: Span::call_site(),
            }),
        }
    }

    fn make_struct(name: &str, fields: Vec<FieldDef>) -> SolStructDef {
        SolStructDef {
            name: format_ident!("{}", name),
            fields,
            derives: vec![],
            attrs: vec![],
            vis: Visibility::Public(syn::token::Pub {
                span: Span::call_site(),
            }),
        }
    }

    fn empty_module() -> SolidityModule {
        SolidityModule {
            name: format_ident!("test"),
            vis: Visibility::Public(syn::token::Pub {
                span: Span::call_site(),
            }),
            imports: vec![],
            structs: vec![],
            unit_enums: vec![],
            error: None,
            event: None,
            interface: None,
            other_items: vec![],
        }
    }

    #[test]
    fn test_selector_erc20_transfer() {
        // ERC20 transfer(address,uint256) selector is 0xa9059cbb
        let sel = selector("transfer(address,uint256)");
        assert_eq!(sel, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_selector_erc20_approve() {
        // ERC20 approve(address,uint256) selector is 0x095ea7b3
        let sel = selector("approve(address,uint256)");
        assert_eq!(sel, [0x09, 0x5e, 0xa7, 0xb3]);
    }

    #[test]
    fn test_selector_erc20_balance_of() {
        // ERC20 balanceOf(address) selector is 0x70a08231
        let sel = selector("balanceOf(address)");
        assert_eq!(sel, [0x70, 0xa0, 0x82, 0x31]);
    }

    #[test]
    fn test_event_selector_transfer() {
        // ERC20 Transfer(address,address,uint256) topic
        let topic = event_selector("Transfer(address,address,uint256)");
        assert_eq!(
            hex::encode(topic),
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    #[test]
    fn test_compute_function_selector_with_struct() -> syn::Result<()> {
        let mut module = empty_module();
        module.structs.push(make_struct(
            "Transfer",
            vec![
                make_field("from", parse_quote!(Address)),
                make_field("to", parse_quote!(Address)),
                make_field("amount", parse_quote!(U256)),
            ],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        // transfer((address,address,uint256))
        let sel = compute_function_selector(&registry, "transfer", &[parse_quote!(Transfer)])?;

        // Verify the signature is correct
        let sig = registry.compute_signature("transfer", &[parse_quote!(Transfer)])?;
        assert_eq!(sig, "transfer((address,address,uint256))");

        // Verify selector matches manual computation
        let expected = selector("transfer((address,address,uint256))");
        assert_eq!(sel, expected);

        Ok(())
    }

    #[test]
    fn test_compute_event_selector_with_struct() -> syn::Result<()> {
        let mut module = empty_module();
        module.structs.push(make_struct(
            "Order",
            vec![
                make_field("id", parse_quote!(U256)),
                make_field("amount", parse_quote!(U256)),
            ],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        // OrderCreated((uint256,uint256))
        let topic = compute_event_selector(&registry, "OrderCreated", &[parse_quote!(Order)])?;

        // Verify signature is correct
        let sig = registry.compute_signature("OrderCreated", &[parse_quote!(Order)])?;
        assert_eq!(sig, "OrderCreated((uint256,uint256))");

        // Verify topic matches manual computation
        let expected = event_selector("OrderCreated((uint256,uint256))");
        assert_eq!(topic, expected);

        Ok(())
    }

    #[test]
    fn test_generate_selector_literal() {
        let sel = [0xa9, 0x05, 0x9c, 0xbb];
        let tokens = generate_selector_literal(&sel);
        let expected = quote! { [169u8, 5u8, 156u8, 187u8] };
        assert_eq!(tokens.to_string(), expected.to_string());
    }

    #[test]
    fn test_selector_hex() {
        let sel = [0xa9, 0x05, 0x9c, 0xbb];
        assert_eq!(selector_hex(&sel), "0xa9059cbb");
    }

    #[test]
    fn test_generate_selector_constants() -> syn::Result<()> {
        let registry = TypeRegistry::default();
        let tokens = generate_selector_constants(
            &registry,
            "transfer",
            &[parse_quote!(Address), parse_quote!(U256)],
        )?;

        let code = tokens.to_string();
        assert!(code.contains("const SIGNATURE"));
        assert!(code.contains("transfer(address,uint256)"));
        assert!(code.contains("const SELECTOR"));

        Ok(())
    }

    #[test]
    fn test_generate_event_topic_constants() -> syn::Result<()> {
        let registry = TypeRegistry::default();
        let tokens = generate_event_topic_constants(
            &registry,
            "Transfer",
            &[
                parse_quote!(Address),
                parse_quote!(Address),
                parse_quote!(U256),
            ],
        )?;

        let code = tokens.to_string();
        assert!(code.contains("const SIGNATURE"));
        assert!(code.contains("Transfer(address,address,uint256)"));
        assert!(code.contains("SIGNATURE_HASH"));

        Ok(())
    }

    #[test]
    fn test_nested_struct_selector() -> syn::Result<()> {
        let mut module = empty_module();

        module.structs.push(make_struct(
            "Inner",
            vec![make_field("value", parse_quote!(U256))],
        ));

        module.structs.push(make_struct(
            "Outer",
            vec![
                make_field("inner", parse_quote!(Inner)),
                make_field("extra", parse_quote!(Address)),
            ],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        // process(((uint256),address))
        let sel = compute_function_selector(&registry, "process", &[parse_quote!(Outer)])?;

        let sig = registry.compute_signature("process", &[parse_quote!(Outer)])?;
        assert_eq!(sig, "process(((uint256),address))");

        let expected = selector("process(((uint256),address))");
        assert_eq!(sel, expected);

        Ok(())
    }

    #[test]
    fn test_array_of_structs_selector() -> syn::Result<()> {
        let mut module = empty_module();

        module.structs.push(make_struct(
            "Item",
            vec![make_field("id", parse_quote!(U256))],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        // processItems((uint256)[])
        let sel =
            compute_function_selector(&registry, "processItems", &[parse_quote!(Vec<Item>)])?;

        let sig = registry.compute_signature("processItems", &[parse_quote!(Vec<Item>)])?;
        assert_eq!(sig, "processItems((uint256)[])");

        let expected = selector("processItems((uint256)[])");
        assert_eq!(sel, expected);

        Ok(())
    }
}
