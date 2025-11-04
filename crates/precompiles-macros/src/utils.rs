//! Utility functions for the contract macro implementation.

use alloy::primitives::{U256, keccak256};
use syn::{Attribute, Lit, Type};

/// Return type for [`extract_attributes`]: (slot, base_slot, slot_count, map)
type ExtractedAttributes = (Option<U256>, Option<U256>, Option<usize>, Option<String>);

/// Parses a slot value from a literal.
///
/// Supports:
/// - Integer literals: decimal (e.g., `42`) or hexadecimal (e.g., `0x2a`)
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
pub(crate) fn normalize_to_snake_case(s: &str) -> String {
    let constant = s.to_uppercase();
    if s == constant {
        return constant;
    }

    let mut result = String::with_capacity(s.len() + 4);
    let mut chars = s.chars().peekable();
    let mut prev_upper = false;

    while let Some(c) = chars.next() {
        if c.is_uppercase() {
            if !result.is_empty()
                && (!prev_upper || chars.peek().is_some_and(|&next| next.is_lowercase()))
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

/// Extracts `#[slot(N)]`, `#[base_slot(N)]`, `#[slot_count(N)]`, and `#[map = "..."]` attributes from a field's attributes.
///
/// This function iterates through the attributes a single time to find all
/// relevant values. It returns a tuple containing:
/// - The slot number (if present)
/// - The base_slot number (if present)
/// - The slot_count (if present, for `Storable` types)
/// - The map string value (if present, normalized to snake_case)
///
/// # Errors
///
/// Returns an error if:
/// - Both `#[slot]` and `#[base_slot]` are present on the same field
/// - Duplicate attributes of the same type are found
pub(crate) fn extract_attributes(attrs: &[Attribute]) -> syn::Result<ExtractedAttributes> {
    let mut slot_attr: Option<U256> = None;
    let mut base_slot_attr: Option<U256> = None;
    let mut slot_count_attr: Option<usize> = None;
    let mut map_attr: Option<String> = None;

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
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate `base_slot` attribute",
                ));
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
        // Extract `#[slot_count(N)]` attribute
        else if attr.path().is_ident("slot_count") {
            if slot_count_attr.is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate `slot_count` attribute",
                ));
            }

            let value: Lit = attr.parse_args()?;
            if let Lit::Int(int) = value {
                let count = int
                    .base10_parse::<usize>()
                    .map_err(|_| syn::Error::new_spanned(int, "invalid `slot_count`"))?;
                slot_count_attr = Some(count);
            } else {
                return Err(syn::Error::new_spanned(
                    value,
                    "`slot_count` attribute must be an integer literal",
                ));
            }
        }
        // Extract `#[map = "..."]` attribute
        else if attr.path().is_ident("map") {
            if map_attr.is_some() {
                return Err(syn::Error::new_spanned(attr, "duplicate `map` attribute"));
            }

            let meta: syn::Meta = attr.meta.clone();
            if let syn::Meta::NameValue(meta_name_value) = meta {
                if let syn::Expr::Lit(expr_lit) = meta_name_value.value {
                    if let Lit::Str(lit_str) = expr_lit.lit {
                        map_attr = Some(normalize_to_snake_case(&lit_str.value()));
                    } else {
                        return Err(syn::Error::new_spanned(
                            expr_lit,
                            "map attribute must be a string literal",
                        ));
                    }
                }
            } else {
                return Err(syn::Error::new_spanned(
                    attr,
                    "map attribute must use the form: #[map = \"value\"]",
                ));
            }
        }
    }

    Ok((slot_attr, base_slot_attr, slot_count_attr, map_attr))
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

/// Checks if a type is the unit type `()`.
pub(crate) fn is_unit(ty: &Type) -> bool {
    matches!(ty, Type::Tuple(tuple) if tuple.elems.is_empty())
}

/// Guesses if a type is a custom struct by checking known storage types.
///
/// # Supported Types
///
/// - Rust: `bool`, `u<N>`, `i<N>`, String
/// - Alloy: Address, `B<N>`, `U<N>`, `I<N>`, `Bytes`
pub(crate) fn is_custom_struct(ty: &Type) -> bool {
    let Type::Path(type_path) = ty else {
        return false;
    };

    let Some(segment) = type_path.path.segments.last() else {
        return false;
    };

    !matches!(
        segment.ident.to_string().as_str(),
        // Rust
        "bool" | "String" |
        "u8" | "u16" | "u32" | "u64" | "u128" |
        "i8" | "i16" | "i32" | "i64" | "i128" |
        // Alloy
        "U8" | "U16" | "U32" | "U64" | "U128" | "U160" | "U256" |
        "I8" | "I16" | "I32" | "I64" | "I128" | "I160" | "I256" |
        "B8" | "B16" | "B32" | "B64" | "B128" | "B160" | "B256" |
        "Address" | "Bytes"
    )
}

/// Checks if a type is a dynamic type that forces slot boundaries.
///
/// Dynamic types (like `String`, `Bytes`, and `Vec`) always:
/// - Start at offset 0 of a new slot
/// - Force the next field to start at a new slot
/// - Cannot be packed with other fields
///
/// This matches Solidity's storage layout rules for dynamic types.
pub(crate) fn is_dynamic_type(ty: &Type) -> bool {
    let Type::Path(type_path) = ty else {
        return false;
    };

    let Some(segment) = type_path.path.segments.last() else {
        return false;
    };

    matches!(
        segment.ident.to_string().as_str(),
        "String" | "Bytes" | "Vec"
    )
}

/// Checks if a type is a fixed-size array type `[T; N]`.
///
/// Arrays, like structs and dynamic types, force slot boundaries:
/// - Start at offset 0 of a new slot
/// - Force the next field to start at a new slot
/// - Cannot be packed with other fields
///
/// This ensures arrays maintain contiguous storage layout.
pub(crate) fn is_array_type(ty: &Type) -> bool {
    matches!(ty, Type::Array(_))
}

/// Checks if a type is a `Vec<T>` type.
///
/// Vec types, like arrays and other dynamic types, force slot boundaries:
/// - Start at offset 0 of a new slot
/// - Force the next field to start at a new slot
/// - Cannot be packed with other fields
///
/// This ensures Vec maintains Solidity-compatible dynamic array storage layout.
pub(crate) fn is_vec_type(ty: &Type) -> bool {
    let Type::Path(type_path) = ty else {
        return false;
    };

    let Some(segment) = type_path.path.segments.last() else {
        return false;
    };

    segment.ident == "Vec"
}

/// Extracts the identifier (last segment) from a type path.
///
/// For example, given `Foo::Bar::Baz`, this returns `Ok(Baz)`.
/// Given a simple type like `MyType`, this returns `Ok(MyType)`.
pub(crate) fn try_extract_type_ident(ty: &Type) -> syn::Result<syn::Ident> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        return Ok(segment.ident.clone());
    }

    Err(syn::Error::new_spanned(
        ty,
        "Interface type must be a simple path or qualified path",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_normalize_to_snake_case() {
        assert_eq!(normalize_to_snake_case("balanceOf"), "balance_of");
        assert_eq!(normalize_to_snake_case("transferFrom"), "transfer_from");
        assert_eq!(normalize_to_snake_case("name"), "name");
        assert_eq!(normalize_to_snake_case("already_snake"), "already_snake");
        assert_eq!(
            normalize_to_snake_case("updateQuoteToken"),
            "update_quote_token"
        );
        assert_eq!(
            normalize_to_snake_case("DOMAIN_SEPARATOR"),
            "DOMAIN_SEPARATOR"
        );
        assert_eq!(normalize_to_snake_case("ERC20Token"), "erc20_token");
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

    #[test]
    fn test_is_unit_type() {
        let unit: Type = parse_quote!(());
        assert!(is_unit(&unit));

        let non_unit: Type = parse_quote!(bool);
        assert!(!is_unit(&non_unit));
    }

    #[test]
    fn test_try_extract_type_ident() {
        // Simple path
        let ty: Type = parse_quote!(ITIP20);
        let ident = try_extract_type_ident(&ty).unwrap();
        assert_eq!(ident.to_string(), "ITIP20");

        // Qualified path
        let ty: Type = parse_quote!(crate::ITIP20);
        let ident = try_extract_type_ident(&ty).unwrap();
        assert_eq!(ident.to_string(), "ITIP20");

        // Nested path
        let ty: Type = parse_quote!(foo::bar::Baz);
        let ident = try_extract_type_ident(&ty).unwrap();
        assert_eq!(ident.to_string(), "Baz");

        // Non-path type should return error
        let ty: Type = parse_quote!(&str);
        assert!(try_extract_type_ident(&ty).is_err());
    }

    #[test]
    fn test_is_custom_struct() {
        // Rust primitives
        assert!(!is_custom_struct(&parse_quote!(bool)));
        assert!(!is_custom_struct(&parse_quote!(u8)));
        assert!(!is_custom_struct(&parse_quote!(u64)));
        assert!(!is_custom_struct(&parse_quote!(u128)));
        assert!(!is_custom_struct(&parse_quote!(i32)));
        assert!(!is_custom_struct(&parse_quote!(String)));

        // Alloy types
        assert!(!is_custom_struct(&parse_quote!(U256)));
        assert!(!is_custom_struct(&parse_quote!(B256)));
        assert!(!is_custom_struct(&parse_quote!(Address)));
        assert!(!is_custom_struct(&parse_quote!(Bytes)));
        assert!(!is_custom_struct(&parse_quote!(I256)));

        // Custom types should return false
        assert!(is_custom_struct(&parse_quote!(RewardStream)));
        assert!(is_custom_struct(&parse_quote!(MyCustomStruct)));
    }

    #[test]
    fn test_is_dynamic_type() {
        // Dynamic types
        assert!(is_dynamic_type(&parse_quote!(String)));
        assert!(is_dynamic_type(&parse_quote!(Bytes)));
        assert!(is_dynamic_type(&parse_quote!(Vec<u8>)));
        assert!(is_dynamic_type(&parse_quote!(Vec<U256>)));

        // Non-dynamic types
        assert!(!is_dynamic_type(&parse_quote!(bool)));
        assert!(!is_dynamic_type(&parse_quote!(u8)));
        assert!(!is_dynamic_type(&parse_quote!(u64)));
        assert!(!is_dynamic_type(&parse_quote!(U256)));
        assert!(!is_dynamic_type(&parse_quote!(Address)));
        assert!(!is_dynamic_type(&parse_quote!(MyCustomStruct)));
    }

    #[test]
    fn test_is_vec_type() {
        // Vec types
        assert!(is_vec_type(&parse_quote!(Vec<u8>)));
        assert!(is_vec_type(&parse_quote!(Vec<U256>)));
        assert!(is_vec_type(&parse_quote!(Vec<Address>)));
        assert!(is_vec_type(&parse_quote!(Vec<Vec<u8>>)));

        // Non-Vec types
        assert!(!is_vec_type(&parse_quote!(String)));
        assert!(!is_vec_type(&parse_quote!(Bytes)));
        assert!(!is_vec_type(&parse_quote!(bool)));
        assert!(!is_vec_type(&parse_quote!(u8)));
        assert!(!is_vec_type(&parse_quote!([u8; 10])));
        assert!(!is_vec_type(&parse_quote!(MyCustomStruct)));
    }
}
