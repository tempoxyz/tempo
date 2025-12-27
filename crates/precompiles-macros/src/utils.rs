//! Utility functions for the contract macro implementation.

use alloy::primitives::{U256, keccak256};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{Attribute, GenericArgument, Lit, PathArguments, Type, TypePath};

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

// ============================================================================
// Solidity Signature Generation
// ============================================================================

/// Check if a TypePath represents a Vec<T>
pub(crate) fn is_vec(type_path: &TypePath) -> bool {
    type_path
        .path
        .segments
        .last()
        .map(|s| s.ident == "Vec")
        .unwrap_or(false)
}

/// Extract the first generic type argument from a TypePath (e.g., T from Vec<T>)
fn extract_generic_type_arg(type_path: &TypePath) -> Option<&Type> {
    type_path.path.segments.last().and_then(|seg| {
        if let PathArguments::AngleBracketed(args) = &seg.arguments {
            args.args.first().and_then(|arg| {
                if let GenericArgument::Type(ty) = arg {
                    Some(ty)
                } else {
                    None
                }
            })
        } else {
            None
        }
    })
}

/// Extract size N from `FixedBytes<N>` type path.
fn extract_fixed_bytes_size(type_path: &TypePath) -> Option<usize> {
    let seg = type_path.path.segments.last()?;
    if seg.ident != "FixedBytes" {
        return None;
    }

    if let PathArguments::AngleBracketed(args) = &seg.arguments {
        if let Some(GenericArgument::Const(expr)) = args.args.first() {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(int),
                ..
            }) = expr
            {
                return int.base10_parse().ok();
            }
        }
    }
    Some(32) // default
}

/// Extract array length from a syn::Expr (for [T; N] arrays)
fn extract_array_len(expr: &syn::Expr) -> Option<usize> {
    if let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Int(int),
        ..
    }) = expr
    {
        int.base10_parse().ok()
    } else {
        None
    }
}

// ============================================================================
// SolType - Solidity Type Representation for Codegen
// ============================================================================

/// Represents a Solidity type for code generation purposes.
///
/// Unlike `alloy::dyn_abi::DynSolType`, this is designed specifically for
/// proc-macro codegen and with custom structs.
#[derive(Debug, Clone)]
pub(crate) enum SolType {
    // Primitives
    Bool,
    Address,
    Uint(usize),       // bits: 8, 16, ..., 256
    Int(usize),        // bits: 8, 16, ..., 256
    FixedBytes(usize), // bytes: 1..32
    Bytes,
    String,

    // Compound types
    Array(Box<SolType>),             // T[]
    FixedArray(Box<SolType>, usize), // T[N]
    Tuple(Vec<SolType>),             // (T1, T2, ...)

    // Custom struct (implements SolStruct)
    Struct(syn::Ident),
}

impl SolType {
    /// Returns the Solidity type name
    pub(crate) fn sol_name(&self) -> String {
        match self {
            Self::Bool => "bool".into(),
            Self::Address => "address".into(),
            Self::Uint(bits) => format!("uint{bits}"),
            Self::Int(bits) => format!("int{bits}"),
            Self::FixedBytes(n) => format!("bytes{n}"),
            Self::Bytes => "bytes".into(),
            Self::String => "string".into(),
            Self::Array(inner) => format!("{}[]", inner.sol_name()),
            Self::FixedArray(inner, len) => format!("{}[{len}]", inner.sol_name()),
            Self::Tuple(elems) if elems.is_empty() => "()".into(),
            Self::Tuple(elems) => {
                let inner: Vec<_> = elems.iter().map(|e| e.sol_name()).collect();
                format!("({})", inner.join(","))
            }
            Self::Struct(ident) => ident.to_string(),
        }
    }

    /// Returns whether this type is dynamically sized in ABI encoding.
    pub(crate) fn is_dynamic(&self) -> bool {
        match self {
            Self::Bool | Self::Address | Self::Uint(_) | Self::Int(_) | Self::FixedBytes(_) => {
                false
            }
            Self::Bytes | Self::String | Self::Array(_) => true,
            Self::FixedArray(inner, _) => inner.is_dynamic(),
            Self::Tuple(elems) => elems.iter().any(|e| e.is_dynamic()),
            Self::Struct(_) => true, // Structs are always dynamic
        }
    }

    /// Generates the `alloy_sol_types::sol_data::*` TokenStream for this type.
    pub(crate) fn to_sol_data(&self) -> TokenStream {
        match self {
            Self::Bool => quote! { alloy_sol_types::sol_data::Bool },
            Self::Address => quote! { alloy_sol_types::sol_data::Address },
            Self::Uint(bits) => quote! { alloy_sol_types::sol_data::Uint<#bits> },
            Self::Int(bits) => quote! { alloy_sol_types::sol_data::Int<#bits> },
            Self::FixedBytes(n) => quote! { alloy_sol_types::sol_data::FixedBytes<#n> },
            Self::Bytes => quote! { alloy_sol_types::sol_data::Bytes },
            Self::String => quote! { alloy_sol_types::sol_data::String },
            Self::Array(inner) => {
                let inner_ts = inner.to_sol_data();
                quote! { alloy_sol_types::sol_data::Array<#inner_ts> }
            }
            Self::FixedArray(inner, len) => {
                let inner_ts = inner.to_sol_data();
                quote! { alloy_sol_types::sol_data::FixedArray<#inner_ts, #len> }
            }
            Self::Tuple(elems) if elems.is_empty() => quote! { () },
            Self::Tuple(elems) => {
                let parts: Vec<_> = elems.iter().map(|e| e.to_sol_data()).collect();
                quote! { (#(#parts,)*) }
            }
            Self::Struct(ident) => quote! { #ident },
        }
    }

    /// Parse a `syn::Type` into a `SolType`.
    pub(crate) fn from_syn(ty: &Type) -> syn::Result<Self> {
        match ty {
            Type::Path(type_path) if is_vec(type_path) => {
                let inner = extract_generic_type_arg(type_path).ok_or_else(|| {
                    syn::Error::new_spanned(type_path, "Vec must have a generic argument")
                })?;
                Ok(Self::Array(Box::new(Self::from_syn(inner)?)))
            }
            Type::Array(arr) => {
                let len = extract_array_len(&arr.len).ok_or_else(|| {
                    syn::Error::new_spanned(&arr.len, "array length must be a literal integer")
                })?;
                Ok(Self::FixedArray(Box::new(Self::from_syn(&arr.elem)?), len))
            }
            Type::Tuple(tuple) => {
                let elems: syn::Result<Vec<_>> =
                    tuple.elems.iter().map(Self::from_syn).collect();
                Ok(Self::Tuple(elems?))
            }
            Type::Path(type_path) => {
                if let Some(seg) = type_path.path.segments.last() {
                    if let Some(n) = extract_fixed_bytes_size(type_path) {
                        return Ok(Self::FixedBytes(n));
                    }
                    return Ok(Self::parse_primitive(&seg.ident));
                }
                Err(syn::Error::new_spanned(type_path, "empty type path"))
            }
            _ => Err(syn::Error::new_spanned(ty, "unsupported type")),
        }
    }

    fn parse_primitive(ident: &syn::Ident) -> Self {
        let name = ident.to_string();
        match name.as_str() {
            "Address" => Self::Address,
            "Bytes" => Self::Bytes,
            "bool" => Self::Bool,
            "String" => Self::String,
            _ => {
                let lower = name.to_lowercase();
                // U8..U256, u8..u256
                if let Some(bits) = lower
                    .strip_prefix('u')
                    .and_then(|s| s.parse::<usize>().ok())
                {
                    if bits > 0 && bits <= 256 && bits % 8 == 0 {
                        return Self::Uint(bits);
                    }
                }
                // I8..I256, i8..i256
                if let Some(bits) = lower
                    .strip_prefix('i')
                    .and_then(|s| s.parse::<usize>().ok())
                {
                    if bits > 0 && bits <= 256 && bits % 8 == 0 {
                        return Self::Int(bits);
                    }
                }
                // B8..B256 (FixedBytes)
                if let Some(bits) = lower
                    .strip_prefix('b')
                    .and_then(|s| s.parse::<usize>().ok())
                {
                    let bytes = bits / 8;
                    if bytes > 0 && bytes <= 32 && bits % 8 == 0 {
                        return Self::FixedBytes(bytes);
                    }
                }
                // Treat unknown types as custom struct
                Self::Struct(ident.clone())
            }
        }
    }

    /// Returns true if this type contains a struct (directly or nested).
    ///
    /// Used to determine if we need const composition for ABI signatures.
    pub(crate) fn contains_struct(&self) -> bool {
        match self {
            Self::Struct(_) => true,
            Self::Array(inner) | Self::FixedArray(inner, _) => inner.contains_struct(),
            Self::Tuple(elems) => elems.iter().any(|e| e.contains_struct()),
            _ => false,
        }
    }

    /// Collects all struct idents from this type (recursively).
    ///
    /// Used for:
    /// - EIP-712 component collection (nested struct dependencies)
    /// - Detecting if interface/error/event containers need deferred selector computation
    pub(crate) fn collect_struct_idents(&self) -> Vec<syn::Ident> {
        match self {
            Self::Struct(ident) => vec![ident.clone()],
            Self::Array(inner) | Self::FixedArray(inner, _) => inner.collect_struct_idents(),
            Self::Tuple(elems) => elems.iter().flat_map(|e| e.collect_struct_idents()).collect(),
            _ => Vec::new(),
        }
    }

    /// Generates a TokenStream expression that evaluates to the ABI signature string.
    ///
    /// For primitive types: returns a literal string like `"address"`.
    /// For struct types: returns `<T as SolTupleSignature>::ABI_TUPLE`.
    /// For arrays: handles composition with "[]" suffix.
    pub(crate) fn to_abi_signature_expr(&self, ty: &syn::Type) -> TokenStream {
        match self {
            Self::Struct(_) => {
                quote! { <#ty as tempo_precompiles::SolTupleSignature>::ABI_TUPLE }
            }
            Self::Array(inner) => {
                if inner.contains_struct() {
                    let inner_ty = extract_generic_type_arg_from_type(ty);
                    let inner_expr = inner.to_abi_signature_expr(inner_ty);
                    quote! {
                        tempo_precompiles::const_format::concatcp!(#inner_expr, "[]")
                    }
                } else {
                    let name = self.sol_name();
                    quote! { #name }
                }
            }
            Self::FixedArray(inner, len) => {
                if inner.contains_struct() {
                    let inner_ty = extract_array_element_type(ty);
                    let inner_expr = inner.to_abi_signature_expr(inner_ty);
                    let len_str = len.to_string();
                    quote! {
                        tempo_precompiles::const_format::concatcp!(#inner_expr, "[", #len_str, "]")
                    }
                } else {
                    let name = self.sol_name();
                    quote! { #name }
                }
            }
            Self::Tuple(elems) => {
                if elems.iter().any(|e| e.contains_struct()) {
                    // Need to compose tuple elements
                    let tuple_ty = match ty {
                        syn::Type::Tuple(t) => t,
                        _ => panic!("expected tuple type"),
                    };
                    let parts: Vec<TokenStream> = elems
                        .iter()
                        .zip(tuple_ty.elems.iter())
                        .enumerate()
                        .flat_map(|(i, (sol_ty, elem_ty))| {
                            let mut tokens = Vec::new();
                            if i > 0 {
                                tokens.push(quote! { "," });
                            }
                            tokens.push(sol_ty.to_abi_signature_expr(elem_ty));
                            tokens
                        })
                        .collect();
                    quote! {
                        tempo_precompiles::const_format::concatcp!("(", #(#parts,)* ")")
                    }
                } else {
                    let name = self.sol_name();
                    quote! { #name }
                }
            }
            _ => {
                let name = self.sol_name();
                quote! { #name }
            }
        }
    }
}

/// Extract inner type from Vec<T>
fn extract_generic_type_arg_from_type(ty: &syn::Type) -> &syn::Type {
    if let syn::Type::Path(type_path) = ty {
        if let Some(inner) = extract_generic_type_arg(type_path) {
            return inner;
        }
    }
    ty
}

/// Extract element type from [T; N]
fn extract_array_element_type(ty: &syn::Type) -> &syn::Type {
    if let syn::Type::Array(arr) = ty {
        return &arr.elem;
    }
    ty
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
                        return Err(syn::Error::new_spanned(
                            &int,
                            "Array size must not exceed 256",
                        ));
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

    #[test]
    fn test_sol_type_sol_name() -> syn::Result<()> {
        assert_eq!(SolType::from_syn(&parse_quote!(Address))?.sol_name(), "address");
        assert_eq!(SolType::from_syn(&parse_quote!(B256))?.sol_name(), "bytes32");
        assert_eq!(SolType::from_syn(&parse_quote!(U256))?.sol_name(), "uint256");
        assert_eq!(SolType::from_syn(&parse_quote!(u64))?.sol_name(), "uint64");
        assert_eq!(SolType::from_syn(&parse_quote!(bool))?.sol_name(), "bool");
        assert_eq!(SolType::from_syn(&parse_quote!(String))?.sol_name(), "string");
        assert_eq!(SolType::from_syn(&parse_quote!(Bytes))?.sol_name(), "bytes");
        Ok(())
    }

    #[test]
    fn test_sol_type_sol_name_arrays() -> syn::Result<()> {
        // Dynamic array: Vec<T> → "T[]"
        assert_eq!(SolType::from_syn(&parse_quote!(Vec<Address>))?.sol_name(), "address[]");
        assert_eq!(SolType::from_syn(&parse_quote!(Vec<U256>))?.sol_name(), "uint256[]");

        // Fixed array: [T; N] → "T[N]"
        assert_eq!(SolType::from_syn(&parse_quote!([U256; 3]))?.sol_name(), "uint256[3]");
        assert_eq!(SolType::from_syn(&parse_quote!([Address; 10]))?.sol_name(), "address[10]");
        Ok(())
    }

    #[test]
    fn test_sol_type_sol_name_tuples() -> syn::Result<()> {
        assert_eq!(SolType::from_syn(&parse_quote!((Address, U256)))?.sol_name(), "(address,uint256)");
        assert_eq!(SolType::from_syn(&parse_quote!((bool, Address, U256)))?.sol_name(), "(bool,address,uint256)");
        assert_eq!(SolType::from_syn(&parse_quote!(()))?.sol_name(), "()");
        Ok(())
    }

    #[test]
    fn test_sol_type_sol_name_nested() -> syn::Result<()> {
        assert_eq!(SolType::from_syn(&parse_quote!(Vec<Vec<U256>>))?.sol_name(), "uint256[][]");
        assert_eq!(SolType::from_syn(&parse_quote!(Vec<(Address, U256)>))?.sol_name(), "(address,uint256)[]");
        assert_eq!(SolType::from_syn(&parse_quote!((Vec<Address>, U256)))?.sol_name(), "(address[],uint256)");
        assert_eq!(SolType::from_syn(&parse_quote!([Vec<U256>; 2]))?.sol_name(), "uint256[][2]");
        Ok(())
    }

    #[test]
    fn test_sol_type_is_dynamic_primitives() -> syn::Result<()> {
        // Static primitives
        assert!(!SolType::from_syn(&parse_quote!(Address))?.is_dynamic());
        assert!(!SolType::from_syn(&parse_quote!(U256))?.is_dynamic());
        assert!(!SolType::from_syn(&parse_quote!(bool))?.is_dynamic());
        assert!(!SolType::from_syn(&parse_quote!(B256))?.is_dynamic());

        // Dynamic primitives
        assert!(SolType::from_syn(&parse_quote!(String))?.is_dynamic());
        assert!(SolType::from_syn(&parse_quote!(Bytes))?.is_dynamic());
        Ok(())
    }

    #[test]
    fn test_sol_type_is_dynamic_arrays() -> syn::Result<()> {
        // Dynamic arrays are always dynamic
        assert!(SolType::from_syn(&parse_quote!(Vec<U256>))?.is_dynamic());
        assert!(SolType::from_syn(&parse_quote!(Vec<Address>))?.is_dynamic());

        // Fixed arrays of static types are static
        assert!(!SolType::from_syn(&parse_quote!([U256; 3]))?.is_dynamic());
        assert!(!SolType::from_syn(&parse_quote!([Address; 10]))?.is_dynamic());

        // Fixed arrays of dynamic types are dynamic
        assert!(SolType::from_syn(&parse_quote!([String; 2]))?.is_dynamic());
        assert!(SolType::from_syn(&parse_quote!([Vec<U256>; 2]))?.is_dynamic());
        Ok(())
    }

    #[test]
    fn test_sol_type_is_dynamic_tuples() -> syn::Result<()> {
        // Tuple of static types is static
        assert!(!SolType::from_syn(&parse_quote!((Address, U256)))?.is_dynamic());
        assert!(!SolType::from_syn(&parse_quote!((bool, B256, U256)))?.is_dynamic());

        // Tuple containing any dynamic type is dynamic
        assert!(SolType::from_syn(&parse_quote!((Address, String)))?.is_dynamic());
        assert!(SolType::from_syn(&parse_quote!((Vec<U256>, bool)))?.is_dynamic());

        // Empty tuple is static
        assert!(!SolType::from_syn(&parse_quote!(()))?.is_dynamic());
        Ok(())
    }

    #[test]
    fn test_sol_type_is_dynamic_nested() -> syn::Result<()> {
        assert!(SolType::from_syn(&parse_quote!(Vec<Vec<U256>>))?.is_dynamic());
        assert!(SolType::from_syn(&parse_quote!((Address, (String, U256))))?.is_dynamic());
        assert!(SolType::from_syn(&parse_quote!([(Address, Bytes); 3]))?.is_dynamic());
        Ok(())
    }

    #[test]
    fn test_sol_type_custom_struct() -> syn::Result<()> {
        // Custom struct
        let ty: Type = parse_quote!(MyCustomStruct);
        let sol_ty = SolType::from_syn(&ty)?;
        assert_eq!(sol_ty.sol_name(), "MyCustomStruct");
        assert!(sol_ty.is_dynamic()); // Structs are always dynamic

        // Array of custom struct
        let ty: Type = parse_quote!(Vec<MyCustomStruct>);
        let sol_ty = SolType::from_syn(&ty)?;
        assert_eq!(sol_ty.sol_name(), "MyCustomStruct[]");
        assert!(sol_ty.is_dynamic());

        // Fixed array of custom struct
        let ty: Type = parse_quote!([MyCustomStruct; 5]);
        let sol_ty = SolType::from_syn(&ty)?;
        assert_eq!(sol_ty.sol_name(), "MyCustomStruct[5]");
        assert!(sol_ty.is_dynamic()); // Contains dynamic type
        Ok(())
    }

    #[test]
    fn test_collect_struct_idents() -> syn::Result<()> {
        // Primitive - no structs
        let sol_ty = SolType::from_syn(&parse_quote!(Address))?;
        assert!(sol_ty.collect_struct_idents().is_empty());

        // Single struct
        let sol_ty = SolType::from_syn(&parse_quote!(MyStruct))?;
        let idents = sol_ty.collect_struct_idents();
        assert_eq!(idents.len(), 1);
        assert_eq!(idents[0].to_string(), "MyStruct");

        // Array of structs
        let sol_ty = SolType::from_syn(&parse_quote!(Vec<Inner>))?;
        let idents = sol_ty.collect_struct_idents();
        assert_eq!(idents.len(), 1);
        assert_eq!(idents[0].to_string(), "Inner");

        // Fixed array of structs
        let sol_ty = SolType::from_syn(&parse_quote!([Inner; 3]))?;
        let idents = sol_ty.collect_struct_idents();
        assert_eq!(idents.len(), 1);
        assert_eq!(idents[0].to_string(), "Inner");

        // Tuple with multiple structs
        let sol_ty = SolType::from_syn(&parse_quote!((Foo, Bar, u64)))?;
        let idents = sol_ty.collect_struct_idents();
        assert_eq!(idents.len(), 2);
        assert_eq!(idents[0].to_string(), "Foo");
        assert_eq!(idents[1].to_string(), "Bar");

        // Nested: array of tuples containing structs
        let sol_ty = SolType::from_syn(&parse_quote!(Vec<(Inner, Address)>))?;
        let idents = sol_ty.collect_struct_idents();
        assert_eq!(idents.len(), 1);
        assert_eq!(idents[0].to_string(), "Inner");

        Ok(())
    }
}
