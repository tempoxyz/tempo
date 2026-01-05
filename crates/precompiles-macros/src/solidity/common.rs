//! Shared utilities for code generation.

use alloy_sol_macro_expander::{InterfaceCodegen, SolInterfaceKind, gen_tokenize, selector};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use syn::{GenericArgument, PathArguments, Type, TypePath};

use super::parser::EnumVariantDef;
use super::registry::TypeRegistry;

/// Represents a Solidity type for code generation purposes.
///
/// Unlike `alloy::dyn_abi::DynSolType`, `SynSolType` is designed specifically for (compile-time)
/// proc-macro codegen. Custom structs are supported, but functions are not.
#[derive(Debug, Clone)]
pub(super) enum SynSolType {
    // Primitives
    Bool,
    Address,
    Uint(usize),       // bits: 8, 16, ..., 256
    Int(usize),        // bits: 8, 16, ..., 256
    FixedBytes(usize), // bytes: 1..32
    Bytes,
    String,

    // Compound types
    Array(Box<SynSolType>),             // T[]
    FixedArray(Box<SynSolType>, usize), // T[N]
    Tuple(Vec<SynSolType>),             // (T1, T2, ...)

    // Custom struct (implements SolStruct)
    Struct(syn::Ident),
}

impl SynSolType {
    /// Returns the Solidity type name
    pub(super) fn sol_name(&self) -> String {
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

    /// Returns whether this type is guaranteed to fit in a single EVM word.
    pub(super) fn is_value_type(&self) -> bool {
        match self {
            Self::Bool | Self::Address | Self::Uint(_) | Self::Int(_) | Self::FixedBytes(_) => true,
            Self::Bytes
            | Self::String
            | Self::Array(_)
            | Self::FixedArray(_, _)
            | Self::Tuple(_)
            | Self::Struct(_) => false,
        }
    }

    /// Generates the `alloy_sol_types::sol_data::*` TokenStream for this type.
    pub(super) fn to_sol_data(&self) -> TokenStream {
        match self {
            Self::Bool => quote! { ::alloy_sol_types::sol_data::Bool },
            Self::Address => quote! { ::alloy_sol_types::sol_data::Address },
            Self::Uint(bits) => {
                let bits = proc_macro2::Literal::usize_unsuffixed(*bits);
                quote! { ::alloy_sol_types::sol_data::Uint<#bits> }
            }
            Self::Int(bits) => {
                let bits = proc_macro2::Literal::usize_unsuffixed(*bits);
                quote! { ::alloy_sol_types::sol_data::Int<#bits> }
            }
            Self::FixedBytes(n) => {
                let n = proc_macro2::Literal::usize_unsuffixed(*n);
                quote! { ::alloy_sol_types::sol_data::FixedBytes<#n> }
            }
            Self::Bytes => quote! { ::alloy_sol_types::sol_data::Bytes },
            Self::String => quote! { ::alloy_sol_types::sol_data::String },
            Self::Array(inner) => {
                let inner_ts = inner.to_sol_data();
                quote! { ::alloy_sol_types::sol_data::Array<#inner_ts> }
            }
            Self::FixedArray(inner, len) => {
                let inner_ts = inner.to_sol_data();
                let len = proc_macro2::Literal::usize_unsuffixed(*len);
                quote! { ::alloy_sol_types::sol_data::FixedArray<#inner_ts, #len> }
            }
            Self::Tuple(elems) if elems.is_empty() => quote! { () },
            Self::Tuple(elems) => {
                let parts: Vec<_> = elems.iter().map(|e| e.to_sol_data()).collect();
                quote! { (#(#parts,)*) }
            }
            Self::Struct(ident) => quote! { #ident },
        }
    }

    /// Parse a `syn::Type` into a `SynSolType`.
    pub(super) fn parse(ty: &Type) -> syn::Result<Self> {
        match ty {
            Type::Path(type_path) if crate::utils::is_vec(type_path) => {
                let inner = extract_generic_type_arg(type_path).ok_or_else(|| {
                    syn::Error::new_spanned(type_path, "Vec must have a generic argument")
                })?;
                Ok(Self::Array(Box::new(Self::parse(inner)?)))
            }
            Type::Array(arr) => {
                let len = extract_array_len(&arr.len).ok_or_else(|| {
                    syn::Error::new_spanned(&arr.len, "array length must be a literal integer")
                })?;
                Ok(Self::FixedArray(Box::new(Self::parse(&arr.elem)?), len))
            }
            Type::Tuple(tuple) => {
                let elems: syn::Result<Vec<_>> = tuple.elems.iter().map(Self::parse).collect();
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
                    && bits > 0
                    && bits <= 256
                    && bits % 8 == 0
                {
                    return Self::Uint(bits);
                }
                // I8..I256, i8..i256
                if let Some(bits) = lower
                    .strip_prefix('i')
                    .and_then(|s| s.parse::<usize>().ok())
                    && bits > 0
                    && bits <= 256
                    && bits % 8 == 0
                {
                    return Self::Int(bits);
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
}

/// Convert types to sol_data types.
pub(super) fn types_to_sol_types(types: &[syn::Type]) -> syn::Result<Vec<TokenStream>> {
    types
        .iter()
        .map(|ty| Ok(SynSolType::parse(ty)?.to_sol_data()))
        .collect()
}

/// Encoded parameter information for ABI generation.
pub(super) struct EncodedParams {
    pub param_tuple: TokenStream,
    pub tokenize_impl: TokenStream,
}

/// Encode parameters for ABI generation.
pub(super) fn encode_params(names: &[Ident], types: &[Type]) -> syn::Result<EncodedParams> {
    let sol_types = types_to_sol_types(types)?;
    let param_tuple = quote! { (#(#sol_types,)*) };
    let tokenize_impl = gen_tokenize(names, &sol_types, false);
    Ok(EncodedParams {
        param_tuple,
        tokenize_impl,
    })
}

/// Generate signature doc string with selector.
///
/// For events, `use_full_hash` should be true to show the full 32-byte keccak256 hash.
/// For errors and functions, use the 4-byte selector.
pub(super) fn signature_doc(
    kind: &str,
    signature: &str,
    use_full_hash: bool,
    solidity_decl: Option<String>,
) -> String {
    let hash = if use_full_hash {
        hex::encode(alloy::primitives::keccak256(signature))
    } else {
        hex::encode(selector(signature))
    };

    if let Some(sol) = solidity_decl {
        format!(
            "{} with signature `{}` and selector `0x{}`.\n```solidity\n{}\n```",
            kind, signature, hash, sol
        )
    } else {
        format!(
            "{} with signature `{}` and selector `0x{}`.",
            kind, signature, hash
        )
    }
}

/// Generate a `SolInterface` container enum (`Calls`, `Error`, or `Event`).
///
/// Takes variant names, type names, signatures, and field counts to build
/// the `InterfaceCodegen` and expand it.
///
/// NOTE: Generated container enums are always `pub` within the module,
/// regardless of the original item's visibility.
pub(super) fn generate_sol_interface_container(
    container_name: &str,
    variants: &[Ident],
    types: &[Ident],
    signatures: &[String],
    field_counts: &[usize],
    kind: SolInterfaceKind,
) -> TokenStream {
    InterfaceCodegen::precomputed(
        format_ident!("{}", container_name),
        variants.to_vec(),
        types.to_vec(),
        signatures.iter().map(selector).collect(),
        signatures.to_vec(),
        field_counts.iter().copied().min().unwrap_or(0) * 32,
        kind,
    )
    .expand()
}

/// Generate Error container enum from variants.
pub(super) fn generate_error_container(
    variants: &[EnumVariantDef],
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let names: Vec<Ident> = variants.iter().map(|v| v.name.clone()).collect();
    let signatures = variants
        .iter()
        .map(|v| registry.compute_signature_from_fields(&v.name.to_string(), &v.fields))
        .collect::<syn::Result<Vec<_>>>()?;
    let field_counts: Vec<usize> = variants.iter().map(|v| v.fields.len()).collect();
    Ok(generate_sol_interface_container(
        "Error",
        &names,
        &names,
        &signatures,
        &field_counts,
        SolInterfaceKind::Error,
    ))
}

/// Generate Event container enum with IntoLogData impl and From conversions.
///
/// NOTE: Generated container enums are always `pub` within the module,
/// regardless of the original item's visibility.
pub(super) fn generate_event_container(variants: &[EnumVariantDef]) -> TokenStream {
    let names: Vec<&Ident> = variants.iter().map(|v| &v.name).collect();

    quote! {
        /// Container enum for all event types.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum Event {
            #(#[allow(missing_docs)] #names(#names),)*
        }

        #[automatically_derived]
        impl ::alloy::primitives::IntoLogData for Event {
            fn to_log_data(&self) -> ::alloy::primitives::LogData {
                match self { #(Self::#names(inner) => inner.to_log_data(),)* }
            }
            fn into_log_data(self) -> ::alloy::primitives::LogData {
                match self { #(Self::#names(inner) => inner.into_log_data(),)* }
            }
        }

        #(
            #[automatically_derived]
            impl ::core::convert::From<#names> for Event {
                #[inline]
                fn from(value: #names) -> Self {
                    Self::#names(value)
                }
            }
        )*
    }
}

/// Generate simple struct (unit or with named fields).
pub(super) fn generate_simple_struct(
    name: &Ident,
    fields: &[(&Ident, &Type)],
    doc: &str,
) -> TokenStream {
    if fields.is_empty() {
        quote! {
            #[doc = #doc]
            #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style)]
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct #name;
        }
    } else {
        let names: Vec<_> = fields.iter().map(|(n, _)| *n).collect();
        let types: Vec<_> = fields.iter().map(|(_, t)| *t).collect();
        quote! {
            #[doc = #doc]
            #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style)]
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct #name {
                #(
                    #[allow(missing_docs)]
                    pub #names: #types
                ),*
            }
        }
    }
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
    if seg.ident == "FixedBytes"
        && let PathArguments::AngleBracketed(args) = &seg.arguments
        && let Some(GenericArgument::Const(expr)) = args.args.first()
        && let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(int),
            ..
        }) = expr
    {
        return int.base10_parse().ok();
    }

    None
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

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;
    #[test]
    fn test_sol_type_sol_name() -> syn::Result<()> {
        assert_eq!(
            SynSolType::parse(&parse_quote!(Address))?.sol_name(),
            "address"
        );
        assert_eq!(
            SynSolType::parse(&parse_quote!(B256))?.sol_name(),
            "bytes32"
        );
        assert_eq!(
            SynSolType::parse(&parse_quote!(U256))?.sol_name(),
            "uint256"
        );
        assert_eq!(SynSolType::parse(&parse_quote!(u64))?.sol_name(), "uint64");
        assert_eq!(SynSolType::parse(&parse_quote!(bool))?.sol_name(), "bool");
        assert_eq!(
            SynSolType::parse(&parse_quote!(String))?.sol_name(),
            "string"
        );
        assert_eq!(SynSolType::parse(&parse_quote!(Bytes))?.sol_name(), "bytes");

        // Dynamic array: Vec<T> → "T[]"
        assert_eq!(
            SynSolType::parse(&parse_quote!(Vec<Address>))?.sol_name(),
            "address[]"
        );
        assert_eq!(
            SynSolType::parse(&parse_quote!(Vec<U256>))?.sol_name(),
            "uint256[]"
        );

        // Fixed array: [T; N] → "T[N]"
        assert_eq!(
            SynSolType::parse(&parse_quote!([U256; 3]))?.sol_name(),
            "uint256[3]"
        );
        assert_eq!(
            SynSolType::parse(&parse_quote!([Address; 10]))?.sol_name(),
            "address[10]"
        );

        // Tuples
        assert_eq!(
            SynSolType::parse(&parse_quote!((Address, U256)))?.sol_name(),
            "(address,uint256)"
        );
        assert_eq!(
            SynSolType::parse(&parse_quote!((bool, Address, U256)))?.sol_name(),
            "(bool,address,uint256)"
        );
        assert_eq!(SynSolType::parse(&parse_quote!(()))?.sol_name(), "()");

        // Nested
        assert_eq!(
            SynSolType::parse(&parse_quote!(Vec<Vec<U256>>))?.sol_name(),
            "uint256[][]"
        );
        assert_eq!(
            SynSolType::parse(&parse_quote!(Vec<(Address, U256)>))?.sol_name(),
            "(address,uint256)[]"
        );
        assert_eq!(
            SynSolType::parse(&parse_quote!((Vec<Address>, U256)))?.sol_name(),
            "(address[],uint256)"
        );
        assert_eq!(
            SynSolType::parse(&parse_quote!([Vec<U256>; 2]))?.sol_name(),
            "uint256[][2]"
        );
        Ok(())
    }

    #[test]
    fn test_sol_type_is_value_type() -> syn::Result<()> {
        // Static primitives
        assert!(SynSolType::Address.is_value_type());
        assert!(SynSolType::Uint(256).is_value_type());
        assert!(SynSolType::Bool.is_value_type());
        assert!(SynSolType::FixedBytes(32).is_value_type());

        // Dynamic primitives
        assert!(!SynSolType::String.is_value_type());
        assert!(!SynSolType::Bytes.is_value_type());

        // Dynamic arrays
        assert!(!SynSolType::Array(Box::new(SynSolType::Uint(256))).is_value_type());
        assert!(!SynSolType::Array(Box::new(SynSolType::Address)).is_value_type());

        // Fixed arrays
        assert!(!SynSolType::FixedArray(Box::new(SynSolType::Uint(256)), 1).is_value_type());
        assert!(!SynSolType::FixedArray(Box::new(SynSolType::Address), 2).is_value_type());

        // Tuples
        assert!(!SynSolType::Tuple(vec![SynSolType::Address, SynSolType::Bool]).is_value_type());
        assert!(!SynSolType::Tuple(vec![SynSolType::Bool]).is_value_type());
        Ok(())
    }

    #[test]
    fn test_sol_type_custom_struct() -> syn::Result<()> {
        // Custom struct
        let ty: Type = parse_quote!(MyCustomStruct);
        let sol_ty = SynSolType::parse(&ty)?;
        assert_eq!(sol_ty.sol_name(), "MyCustomStruct");
        assert!(!sol_ty.is_value_type());

        // Array of custom struct
        let ty: Type = parse_quote!(Vec<MyCustomStruct>);
        let sol_ty = SynSolType::parse(&ty)?;
        assert_eq!(sol_ty.sol_name(), "MyCustomStruct[]");
        assert!(!sol_ty.is_value_type());

        // Fixed array of custom struct
        let ty: Type = parse_quote!([MyCustomStruct; 5]);
        let sol_ty = SynSolType::parse(&ty)?;
        assert_eq!(sol_ty.sol_name(), "MyCustomStruct[5]");
        assert!(!sol_ty.is_value_type());
        Ok(())
    }
}
