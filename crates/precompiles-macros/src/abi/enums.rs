//! Enum code generation for the `#[abi]` module macro.
//!
//! Handles two types of enums:
//! - **Unit enums**: Encoded as `uint8`, like Solidity's `enum Status { Pending, Filled }`
//! - **Variant enums**: Error and Event enums with fields

use alloy_sol_macro_expander::{
    ErrorCodegen, EventCodegen, EventFieldInfo, StructLayout, gen_from_into_tuple,
};
use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use syn::spanned::Spanned;

use crate::utils::to_snake_case;

use super::{
    common::{self, AbiType, SynSolType},
    parser::{EnumVariantDef, FieldAccessors, FieldDef, SolEnumDef, UnitEnumDef},
    registry::TypeRegistry,
};

/// Generate code for a unit enum definition (uint8-encoded).
pub(super) fn generate_unit_enum(def: &UnitEnumDef) -> TokenStream {
    let enum_name = &def.name;
    let vis = &def.vis;
    let attrs = &def.attrs;

    let (variants_with_discriminants, from_u8_arms): (Vec<_>, Vec<_>) = def
        .variants
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let idx = i as u8;
            (quote! { #v = #idx }, quote! { #idx => Ok(Self::#v) })
        })
        .unzip();

    // Emit cfg-gated Storable derive if the enum originally had it
    let storable_attr = if def.has_storable {
        quote! { #[cfg_attr(feature = "precompile", derive(tempo_precompiles_macros::Storable))] }
    } else {
        quote! {}
    };

    let enum_def = quote! {
        #(#attrs)*
        #[repr(u8)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[allow(non_camel_case_types)]
        #storable_attr
        #vis enum #enum_name {
            #(#variants_with_discriminants),*
        }
    };

    let trait_impls = expand_unit_enum_traits(
        enum_name,
        def.variants.len() as u8,
        &from_u8_arms,
        def.variants.first(),
    );

    quote! {
        #enum_def
        #trait_impls
    }
}

/// Generate all trait implementations for a unit enum (uint8-encoded).
fn expand_unit_enum_traits(
    enum_name: &Ident,
    variant_count: u8,
    from_u8_arms: &[TokenStream],
    first_variant: Option<&Ident>,
) -> TokenStream {
    let from_impl = quote! {
        #[automatically_derived]
        impl ::core::convert::From<#enum_name> for u8 {
            #[inline]
            fn from(value: #enum_name) -> u8 {
                value as u8
            }
        }
    };

    let try_from_impl = quote! {
        #[automatically_derived]
        impl ::core::convert::TryFrom<u8> for #enum_name {
            type Error = ();

            #[inline]
            fn try_from(value: u8) -> ::core::result::Result<Self, ()> {
                match value {
                    #(#from_u8_arms,)*
                    _ => Err(()),
                }
            }
        }
    };

    let sol_type_impl = quote! {
        #[automatically_derived]
        impl alloy_sol_types::SolType for #enum_name {
            type RustType = Self;
            type Token<'a> = <alloy_sol_types::sol_data::Uint<8> as alloy_sol_types::SolType>::Token<'a>;

            const SOL_NAME: &'static str = "uint8";
            const ENCODED_SIZE: Option<usize> = Some(32);
            const PACKED_ENCODED_SIZE: Option<usize> = Some(1);

            #[inline]
            fn valid_token(token: &Self::Token<'_>) -> bool {
                let value: u8 = alloy::primitives::U256::from_be_bytes(token.0.0).to::<u8>();
                value < #variant_count
            }

            #[inline]
            fn detokenize(token: Self::Token<'_>) -> Self::RustType {
                let value: u8 = alloy::primitives::U256::from_be_bytes(token.0.0).to::<u8>();
                debug_assert!(
                    value < #variant_count,
                    "invalid {} discriminant: {}",
                    stringify!(#enum_name),
                    value
                );
                Self::try_from(value).unwrap_or_default()
            }
        }
    };

    let sol_type_value_impl = quote! {
        #[automatically_derived]
        impl alloy_sol_types::private::SolTypeValue<#enum_name> for #enum_name {
            #[inline]
            fn stv_to_tokens(&self) -> <#enum_name as alloy_sol_types::SolType>::Token<'_> {
                <alloy_sol_types::sol_data::Uint<8> as alloy_sol_types::SolType>::tokenize(&(*self as u8))
            }

            #[inline]
            fn stv_abi_encode_packed_to(&self, out: &mut alloy_sol_types::private::Vec<u8>) {
                out.push(*self as u8);
            }

            #[inline]
            fn stv_eip712_data_word(&self) -> alloy_sol_types::Word {
                <alloy_sol_types::sol_data::Uint<8> as alloy_sol_types::SolType>::tokenize(&(*self as u8)).0
            }
        }
    };

    let sol_value_impl = quote! {
        #[automatically_derived]
        impl alloy_sol_types::SolValue for #enum_name {
            type SolType = Self;
        }
    };

    let default_impl = first_variant.map(|fv| {
        quote! {
            #[automatically_derived]
            impl ::core::default::Default for #enum_name {
                #[inline]
                fn default() -> Self {
                    Self::#fv
                }
            }
        }
    });

    quote! {
        #from_impl
        #try_from_impl
        #sol_type_impl
        #sol_type_value_impl
        #sol_value_impl
        #default_impl
    }
}

/// Generate code for Error or Event enum.
pub(super) fn generate_variant_enum(
    def: &SolEnumDef,
    registry: &TypeRegistry,
    kind: AbiType,
) -> syn::Result<TokenStream> {
    debug_assert!(
        matches!(kind, AbiType::Error | AbiType::Event),
        "generate_variant_enum only supports Error and Event"
    );
    let variant_impls = def
        .variants
        .iter()
        .map(|v| generate_variant(v, registry, kind))
        .collect::<syn::Result<Vec<_>>>()?;

    let container_name = match kind {
        AbiType::Error => format_ident!("Error"),
        AbiType::Event => format_ident!("Event"),
    };

    let container = match kind {
        AbiType::Error => common::generate_error_container(&def.variants, registry)?,
        AbiType::Event => common::generate_event_container(&def.variants),
    };

    let constructors = generate_constructors(&container_name, &def.variants, kind)?;

    Ok(quote! {
        #(#variant_impls)*
        #container
        #constructors
    })
}

/// Precomputed field projections for event code generation.
///
/// In Solidity, indexed dynamic types (String, Bytes, arrays) are stored as their
/// keccak256 hash in event topics. This struct computes type conversions once
/// and provides all the data needed for struct generation, trait impls, and constructors.
struct EventFieldProjection {
    /// Field name
    name: Ident,
    /// Type for the Rust struct definition (converted for indexed dynamic types)
    struct_type: syn::Type,
    /// Rust type as TokenStream for from/into tuple
    rust_type: TokenStream,
    /// Sol type as TokenStream for SolEvent codegen
    sol_type: TokenStream,
    /// Whether this field is indexed
    is_indexed: bool,
    /// Whether this indexed field is stored as a hash (dynamic types)
    indexed_as_hash: bool,
    /// Span for error reporting
    span: Span,
}

impl EventFieldProjection {
    /// Compute field projection from a field definition.
    fn from_field(field: &FieldDef) -> syn::Result<Self> {
        let sol_ty = SynSolType::parse(&field.ty)?;
        let indexed_as_hash = field.indexed && !sol_ty.is_value_type();

        let (struct_type, rust_type, sol_type) = if indexed_as_hash {
            (
                syn::parse_quote!(::alloy::primitives::FixedBytes<32>),
                quote!(::alloy::primitives::FixedBytes<32>),
                quote!(alloy_sol_types::sol_data::FixedBytes<32>),
            )
        } else {
            let ty = &field.ty;
            (field.ty.clone(), quote!(#ty), sol_ty.to_sol_data())
        };

        Ok(Self {
            name: field.name.clone(),
            struct_type,
            rust_type,
            sol_type,
            is_indexed: field.indexed,
            indexed_as_hash,
            span: field.ty.span(),
        })
    }

    /// Compute projections for all fields in a variant.
    fn from_variant(variant: &EnumVariantDef) -> syn::Result<Vec<Self>> {
        variant.fields.iter().map(Self::from_field).collect()
    }
}

/// Generate code for a single variant (Error or Event).
fn generate_variant(
    variant: &EnumVariantDef,
    registry: &TypeRegistry,
    kind: AbiType,
) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;
    let signature =
        registry.compute_signature_from_fields(&variant.name.to_string(), &variant.fields)?;

    let (doc_kind, sol_kind, use_full_hash) = match kind {
        AbiType::Error => ("Custom error", "error", false),
        AbiType::Event => ("Event", "event", true),
    };

    let doc = common::signature_doc(
        doc_kind,
        &signature,
        use_full_hash,
        variant.solidity_decl(sol_kind),
    );

    let (variant_struct, trait_impl) = match kind {
        AbiType::Event => {
            let projections = EventFieldProjection::from_variant(variant)?;
            let struct_ts = generate_event_struct(struct_name, &projections, &doc);
            let impl_ts = generate_sol_event_impl(struct_name, &projections, &signature);
            (struct_ts, impl_ts)
        }
        AbiType::Error => {
            let field_pairs: Vec<_> = variant.fields().collect();
            let struct_ts = common::generate_simple_struct(struct_name, &field_pairs, &doc);
            let impl_ts = generate_sol_error_impl(variant, &signature)?;
            (struct_ts, impl_ts)
        }
    };

    Ok(quote! {
        #variant_struct
        #trait_impl
    })
}

/// Generate event struct using precomputed projections.
fn generate_event_struct(
    name: &Ident,
    projections: &[EventFieldProjection],
    doc: &str,
) -> TokenStream {
    if projections.is_empty() {
        quote! {
            #[doc = #doc]
            #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style)]
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct #name;
        }
    } else {
        let fields: Vec<_> = projections
            .iter()
            .map(|p| {
                let n = &p.name;
                let t = &p.struct_type;
                quote! {
                    #[allow(missing_docs)]
                    pub #n: #t
                }
            })
            .collect();

        quote! {
            #[doc = #doc]
            #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style)]
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct #name {
                #(#fields),*
            }
        }
    }
}

/// Generate SolError trait implementation (wrapped in const block to avoid type alias conflicts).
fn generate_sol_error_impl(variant: &EnumVariantDef, signature: &str) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;
    let param_names = variant.field_names();
    let sol_types = common::types_to_sol_types(&variant.field_raw_types())?;
    let rust_types = variant.field_types();

    let error_impl =
        ErrorCodegen::new(param_names, sol_types, rust_types, false).expand(struct_name, signature);

    Ok(common::wrap_const_block(error_impl))
}

/// Generate SolEvent trait implementation using precomputed projections.
fn generate_sol_event_impl(
    struct_name: &Ident,
    projections: &[EventFieldProjection],
    signature: &str,
) -> TokenStream {
    let field_names: Vec<_> = projections.iter().map(|p| p.name.clone()).collect();
    let rust_types: Vec<_> = projections.iter().map(|p| p.rust_type.clone()).collect();
    let sol_types: Vec<_> = projections.iter().map(|p| p.sol_type.clone()).collect();

    let layout = if field_names.is_empty() {
        StructLayout::Unit
    } else {
        StructLayout::Named
    };
    let from_tuple =
        gen_from_into_tuple(struct_name, &field_names, &sol_types, &rust_types, layout);

    let fields: Vec<EventFieldInfo> = projections
        .iter()
        .map(|p| EventFieldInfo {
            name: p.name.clone(),
            sol_type: p.sol_type.clone(),
            is_indexed: p.is_indexed,
            indexed_as_hash: p.indexed_as_hash,
            span: p.span,
        })
        .collect();

    let event_impl = EventCodegen::new(false, fields).expand(struct_name, signature);

    common::wrap_const_block(quote! {
        #from_tuple
        #event_impl
    })
}

/// Generate constructor methods for container enum.
fn generate_constructors(
    container: &Ident,
    variants: &[EnumVariantDef],
    kind: AbiType,
) -> syn::Result<TokenStream> {
    let constructors: Vec<TokenStream> = variants
        .iter()
        .map(|v| generate_constructor(v, kind))
        .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        impl #container {
            #(#constructors)*
        }
    })
}

/// Generate a single constructor method.
fn generate_constructor(variant: &EnumVariantDef, kind: AbiType) -> syn::Result<TokenStream> {
    let variant_name = &variant.name;
    let fn_name = format_ident!("{}", to_snake_case(&variant.name.to_string()));

    if variant.fields.is_empty() {
        return Ok(quote! {
            #[doc = concat!("Creates a new `", stringify!(#variant_name), "`.")]
            pub const fn #fn_name() -> Self {
                Self::#variant_name(#variant_name)
            }
        });
    }

    let (param_names, param_types): (Vec<_>, Vec<_>) = match kind {
        AbiType::Event => {
            let projections = EventFieldProjection::from_variant(variant)?;
            projections
                .into_iter()
                .map(|p| (p.name, p.struct_type))
                .unzip()
        }
        AbiType::Error => variant
            .fields
            .iter()
            .map(|f| (f.name.clone(), f.ty.clone()))
            .unzip(),
    };

    Ok(quote! {
        #[doc = concat!("Creates a new `", stringify!(#variant_name), "`.")]
        pub fn #fn_name(#(#param_names: #param_types),*) -> Self {
            Self::#variant_name(#variant_name { #(#param_names),* })
        }
    })
}
