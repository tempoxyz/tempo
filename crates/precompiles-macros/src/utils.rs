//! Utility functions for the contract macro implementation.

use alloy::primitives::{U256, keccak256};
use syn::{Attribute, Lit, Type};

/// Return type for [`extract_attributes`]: (slot, base_slot)
type ExtractedAttributes = (Option<U256>, Option<U256>);

/// Parses a slot value from a literal.
///
/// Supports:
/// - Integer literals: decimal (`42`) or hexadecimal (`0x2a`)
/// - String literals: computes keccak256 hash of the string
fn parse_slot_value(value: &Lit) -> syn::Result<U256> {
    match value {
        Lit::Int(int) => {
            let lit_str = int.to_string();
            let slot = if let Some(hex) = lit_str.strip_prefix("0x") {
                U256::from_str_radix(hex, 16)
            } else {
                U256::from_str_radix(&lit_str, 10)
            }
            .map_err(|_| syn::Error::new_spanned(int, "Invalid slot number"))?;
            Ok(slot)
        }
        Lit::Str(lit) => Ok(keccak256(lit.value().as_bytes()).into()),
        _ => Err(syn::Error::new_spanned(
            value,
            "slot attribute must be an integer or a string literal",
        )),
    }
}

/// Converts a string from CamelCase or snake_case to snake_case.
/// Preserves SCREAMING_SNAKE_CASE, as those are assumed to be constant/immutable names.
pub(crate) fn to_snake_case(s: &str) -> String {
    let constant = s.to_uppercase();
    if s == constant {
        return constant;
    }

    let mut result = String::with_capacity(s.len() + 4);
    let mut chars = s.chars().peekable();
    let mut prev_upper = false;

    while let Some(c) = chars.next() {
        if c.is_uppercase() {
            if !result.is_empty() &&
                (!prev_upper || chars.peek().is_some_and(|&next| next.is_lowercase()))
            {
                result.push('_');
            }
            result.push(c.to_ascii_lowercase());
            prev_upper = true;
        } else {
            result.push(c);
            prev_upper = false;
        }
    }

    result
}

/// Converts a string from snake_case to camelCase.
pub(crate) fn to_camel_case(s: &str) -> String {
    let mut result = String::new();
    let mut first_word = true;

    for word in s.split('_') {
        if word.is_empty() {
            continue;
        }

        if first_word {
            result.push_str(word);
            first_word = false;
        } else {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                result.push_str(&first.to_uppercase().collect::<String>());
                result.push_str(chars.as_str());
            }
        }
    }
    result
}

/// Extracts `#[slot(N)]`, `#[base_slot(N)]` attributes from a field's attributes.
///
/// This function iterates through the attributes a single time to find all
/// relevant values. It returns a tuple containing:
/// - The slot number (if present)
/// - The base_slot number (if present)
///
/// # Errors
///
/// Returns an error if:
/// - Both `#[slot]` and `#[base_slot]` are present on the same field
/// - Duplicate attributes of the same type are found
pub(crate) fn extract_attributes(attrs: &[Attribute]) -> syn::Result<ExtractedAttributes> {
    let mut slot_attr: Option<U256> = None;
    let mut base_slot_attr: Option<U256> = None;

    for attr in attrs {
        // Extract `#[slot(N)]` attribute
        if attr.path().is_ident("slot") {
            if slot_attr.is_some() {
                return Err(syn::Error::new_spanned(attr, "duplicate `slot` attribute"));
            }
            if base_slot_attr.is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "cannot use both `slot` and `base_slot` attributes on the same field",
                ));
            }

            let value: Lit = attr.parse_args()?;
            slot_attr = Some(parse_slot_value(&value)?);
        }
        // Extract `#[base_slot(N)]` attribute
        else if attr.path().is_ident("base_slot") {
            if base_slot_attr.is_some() {
                return Err(syn::Error::new_spanned(attr, "duplicate `base_slot` attribute"));
            }
            if slot_attr.is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "cannot use both `slot` and `base_slot` attributes on the same field",
                ));
            }

            let value: Lit = attr.parse_args()?;
            base_slot_attr = Some(parse_slot_value(&value)?);
        }
    }

    Ok((slot_attr, base_slot_attr))
}

/// Extracts array sizes from the `#[storable_arrays(...)]` attribute.
///
/// Parses attributes like `#[storable_arrays(1, 2, 4, 8)]` and returns a vector
/// of the specified sizes. Returns `None` if the attribute is not present.
///
/// # Format
///
/// The attribute should be a comma-separated list of positive integer literals:
/// ```ignore
/// #[storable_arrays(1, 2, 4, 8, 16, 32)]
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The attribute is present but has invalid syntax
/// - Any size is 0 or exceeds 256
/// - Duplicate array sizes are specified
pub(crate) fn extract_storable_array_sizes(attrs: &[Attribute]) -> syn::Result<Option<Vec<usize>>> {
    for attr in attrs {
        if attr.path().is_ident("storable_arrays") {
            // Parse the attribute arguments as a comma-separated list
            let parsed = attr.parse_args_with(
                syn::punctuated::Punctuated::<Lit, syn::Token![,]>::parse_terminated,
            )?;

            let mut sizes = Vec::new();
            for lit in parsed {
                if let Lit::Int(int) = lit {
                    let size = int.base10_parse::<usize>().map_err(|_| {
                        syn::Error::new_spanned(
                            &int,
                            "Invalid array size: must be a positive integer",
                        )
                    })?;

                    if size == 0 {
                        return Err(syn::Error::new_spanned(
                            &int,
                            "Array size must be greater than 0",
                        ));
                    }

                    if size > 256 {
                        return Err(syn::Error::new_spanned(&int, "Array size must not exceed 256"));
                    }

                    if sizes.contains(&size) {
                        return Err(syn::Error::new_spanned(
                            &int,
                            format!("Duplicate array size: {size}"),
                        ));
                    }

                    sizes.push(size);
                } else {
                    return Err(syn::Error::new_spanned(
                        lit,
                        "Array sizes must be integer literals",
                    ));
                }
            }

            if sizes.is_empty() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "storable_arrays attribute requires at least one size",
                ));
            }

            return Ok(Some(sizes));
        }
    }

    Ok(None)
}

/// Extracts the type parameters from Mapping<K, V>.
///
/// Returns Some((key_type, value_type)) if the type is a Mapping, None otherwise.
pub(crate) fn extract_mapping_types(ty: &Type) -> Option<(&Type, &Type)> {
    if let Type::Path(type_path) = ty {
        let last_segment = type_path.path.segments.last()?;

        // Check if the type is named "Mapping"
        if last_segment.ident != "Mapping" {
            return None;
        }

        // Extract generic arguments
        if let syn::PathArguments::AngleBracketed(args) = &last_segment.arguments {
            let mut iter = args.args.iter();

            // First argument: key type
            let key_type = if let Some(syn::GenericArgument::Type(ty)) = iter.next() {
                ty
            } else {
                return None;
            };

            // Second argument: value type
            let value_type = if let Some(syn::GenericArgument::Type(ty)) = iter.next() {
                ty
            } else {
                return None;
            };

            return Some((key_type, value_type));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("balanceOf"), "balance_of");
        assert_eq!(to_snake_case("transferFrom"), "transfer_from");
        assert_eq!(to_snake_case("name"), "name");
        assert_eq!(to_snake_case("already_snake"), "already_snake");
        assert_eq!(to_snake_case("updateQuoteToken"), "update_quote_token");
        assert_eq!(to_snake_case("DOMAIN_SEPARATOR"), "DOMAIN_SEPARATOR");
        assert_eq!(to_snake_case("ERC20Token"), "erc20_token");
    }

    #[test]
    fn test_to_camel_case() {
        assert_eq!(to_camel_case("balance_of"), "balanceOf");
        assert_eq!(to_camel_case("transfer_from"), "transferFrom");
        assert_eq!(to_camel_case("update_quote_token"), "updateQuoteToken");
        assert_eq!(to_camel_case("name"), "name");
        assert_eq!(to_camel_case("token"), "token");
        assert_eq!(to_camel_case("alreadycamelCase"), "alreadycamelCase");
        assert_eq!(to_camel_case("DOMAIN_SEPARATOR"), "DOMAINSEPARATOR");
    }

    #[test]
    fn test_extract_mapping_types() {
        // Test simple mapping
        let ty: Type = parse_quote!(Mapping<Address, U256>);
        let result = extract_mapping_types(&ty);
        assert!(result.is_some());

        // Test nested mapping
        let ty: Type = parse_quote!(Mapping<Address, Mapping<Address, U256>>);
        let result = extract_mapping_types(&ty);
        assert!(result.is_some());

        // Test non-mapping type
        let ty: Type = parse_quote!(String);
        let result = extract_mapping_types(&ty);
        assert!(result.is_none());

        // Test non-mapping generic type
        let ty: Type = parse_quote!(Vec<u8>);
        let result = extract_mapping_types(&ty);
        assert!(result.is_none());
    }
}
