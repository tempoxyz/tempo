//! Enum code generation for the `#[solidity]` module macro.
//!
//! Handles two types of enums:
//! - **Unit enums**: Encoded as `uint8`, like Solidity's `enum Status { Pending, Filled }`
//! - **Variant enums**: Error and Event enums with fields

use alloy_sol_macro_expander::{
    ErrorCodegen, EventCodegen, EventFieldInfo, StructLayout, gen_from_into_tuple,
};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use syn::spanned::Spanned;

use crate::utils::to_snake_case;

use super::{
    common::{self, SynSolType},
    parser::{EnumVariantDef, FieldAccessors, SolEnumDef, UnitEnumDef},
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

    let enum_def = quote! {
        #(#attrs)*
        #[repr(u8)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

/// Kind of variant enum being generated.
#[derive(Clone, Copy)]
pub(super) enum VariantEnumKind {
    Error,
    Event,
}

/// Generate code for Error or Event enum.
pub(super) fn generate_variant_enum(
    def: &SolEnumDef,
    registry: &TypeRegistry,
    kind: VariantEnumKind,
) -> syn::Result<TokenStream> {
    let variant_impls = def
        .variants
        .iter()
        .map(|v| generate_variant(v, registry, kind))
        .collect::<syn::Result<Vec<_>>>()?;

    let container_name = match kind {
        VariantEnumKind::Error => format_ident!("Error"),
        VariantEnumKind::Event => format_ident!("Event"),
    };

    let container = match kind {
        VariantEnumKind::Error => common::generate_error_container(&def.variants, registry)?,
        VariantEnumKind::Event => common::generate_event_container(&def.variants),
    };

    let constructors = generate_constructors(&container_name, &def.variants, kind)?;

    Ok(quote! {
        #(#variant_impls)*
        #container
        #constructors
    })
}

/// Check if an indexed field should be stored as a hash (keccak256).
///
/// In Solidity, indexed dynamic types (String, Bytes, arrays) are stored as their
/// keccak256 hash in event topics. This function identifies such fields so their
/// struct type can be converted to `FixedBytes<32>`.
fn is_indexed_as_hash(field: &super::parser::FieldDef) -> syn::Result<bool> {
    if !field.indexed {
        return Ok(false);
    }
    let sol_ty = SynSolType::parse(&field.ty)?;
    Ok(!sol_ty.is_value_type())
}

/// Generate code for a single variant (Error or Event).
fn generate_variant(
    variant: &EnumVariantDef,
    registry: &TypeRegistry,
    kind: VariantEnumKind,
) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;
    let signature =
        registry.compute_signature_from_fields(&variant.name.to_string(), &variant.fields)?;

    let (doc_kind, sol_kind, use_full_hash) = match kind {
        VariantEnumKind::Error => ("Custom error", "error", false),
        VariantEnumKind::Event => ("Event", "event", true),
    };

    let doc = common::signature_doc(
        doc_kind,
        &signature,
        use_full_hash,
        variant.solidity_decl(sol_kind),
    );

    // For events, convert indexed dynamic types to FixedBytes<32> (B256) in the struct.
    // This matches sol! macro behavior where indexed String/Bytes/arrays are stored as hashes.
    let variant_struct = match kind {
        VariantEnumKind::Event => {
            let converted_fields: Vec<(Ident, syn::Type)> = variant
                .fields
                .iter()
                .map(|f| {
                    let ty = if is_indexed_as_hash(f)? {
                        syn::parse_quote!(::alloy::primitives::FixedBytes<32>)
                    } else {
                        f.ty.clone()
                    };
                    Ok((f.name.clone(), ty))
                })
                .collect::<syn::Result<Vec<_>>>()?;
            let field_refs: Vec<_> = converted_fields.iter().map(|(n, t)| (n, t)).collect();
            common::generate_simple_struct(struct_name, &field_refs, &doc)
        }
        VariantEnumKind::Error => {
            let field_pairs: Vec<_> = variant.fields().collect();
            common::generate_simple_struct(struct_name, &field_pairs, &doc)
        }
    };

    let trait_impl = match kind {
        VariantEnumKind::Error => generate_sol_error_impl(variant, &signature)?,
        VariantEnumKind::Event => generate_sol_event_impl(variant, &signature)?,
    };

    Ok(quote! {
        #variant_struct
        #trait_impl
    })
}

/// Generate SolError trait implementation (wrapped in const block to avoid type alias conflicts).
///
/// Note: Unlike `EventCodegen`, `ErrorCodegen.expand()` already includes `gen_from_into_tuple`
/// internally, so we only need to wrap it in a const block.
fn generate_sol_error_impl(variant: &EnumVariantDef, signature: &str) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;
    let param_names = variant.field_names();
    let sol_types = common::types_to_sol_types(&variant.field_raw_types())?;
    let rust_types = variant.field_types();

    let error_impl =
        ErrorCodegen::new(param_names, sol_types, rust_types, false).expand(struct_name, signature);

    Ok(quote! {
        #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style)]
        const _: () = {
            use alloy_sol_types as alloy_sol_types;
            #error_impl
        };
    })
}

/// Generate SolEvent trait implementation (wrapped in const block to avoid type alias conflicts).
///
/// For indexed dynamic types (String, Bytes, arrays), both the Rust type and sol_data type
/// are converted to FixedBytes<32> to match the struct definition and sol! macro behavior.
fn generate_sol_event_impl(variant: &EnumVariantDef, signature: &str) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;
    let field_names = variant.field_names();

    // Build field info with type conversions for indexed dynamic types
    let field_data: Vec<_> = variant
        .fields
        .iter()
        .map(|f| {
            let sol_ty = SynSolType::parse(&f.ty)?;
            let indexed_as_hash = f.indexed && !sol_ty.is_value_type();

            // For both struct and tuple conversion, use converted types
            let (rust_type_ts, sol_type_ts) = if indexed_as_hash {
                (
                    quote!(::alloy::primitives::FixedBytes<32>),
                    quote!(alloy_sol_types::sol_data::FixedBytes<32>),
                )
            } else {
                let ty = &f.ty;
                (quote!(#ty), sol_ty.to_sol_data())
            };

            Ok((f, rust_type_ts, sol_type_ts, indexed_as_hash))
        })
        .collect::<syn::Result<Vec<_>>>()?;

    let rust_types: Vec<_> = field_data.iter().map(|(_, r, _, _)| r.clone()).collect();
    let sol_types: Vec<_> = field_data.iter().map(|(_, _, s, _)| s.clone()).collect();

    let layout = if field_names.is_empty() {
        StructLayout::Unit
    } else {
        StructLayout::Named
    };
    let from_tuple =
        gen_from_into_tuple(struct_name, &field_names, &sol_types, &rust_types, layout);

    let fields: Vec<EventFieldInfo> = field_data
        .iter()
        .map(|(f, _, sol_type, indexed_as_hash)| EventFieldInfo {
            name: f.name.clone(),
            sol_type: sol_type.clone(),
            is_indexed: f.indexed,
            indexed_as_hash: *indexed_as_hash,
            span: f.ty.span(),
        })
        .collect();

    let event_impl = EventCodegen::new(false, fields).expand(struct_name, signature);

    // Wrap in const block to avoid type alias conflicts between events
    Ok(quote! {
        #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style)]
        const _: () = {
            use alloy_sol_types as alloy_sol_types;
            #from_tuple
            #event_impl
        };
    })
}

/// Generate constructor methods for container enum.
///
/// For Events, indexed dynamic types are converted to FixedBytes<32> to match the struct fields.
fn generate_constructors(
    container: &Ident,
    variants: &[EnumVariantDef],
    kind: VariantEnumKind,
) -> syn::Result<TokenStream> {
    let constructors: Vec<TokenStream> = variants
        .iter()
        .map(|v| {
            let variant_name = &v.name;
            let fn_name = format_ident!("{}", to_snake_case(&v.name.to_string()));

            if v.fields.is_empty() {
                Ok(quote! {
                    #[doc = concat!("Creates a new `", stringify!(#variant_name), "`.")]
                    pub const fn #fn_name() -> Self {
                        Self::#variant_name(#variant_name)
                    }
                })
            } else {
                let param_names: Vec<_> = v.fields.iter().map(|f| &f.name).collect();

                // For events, convert indexed dynamic types to FixedBytes<32>
                let param_types: Vec<syn::Type> = match kind {
                    VariantEnumKind::Event => v
                        .fields
                        .iter()
                        .map(|f| {
                            if is_indexed_as_hash(f)? {
                                Ok(syn::parse_quote!(::alloy::primitives::FixedBytes<32>))
                            } else {
                                Ok(f.ty.clone())
                            }
                        })
                        .collect::<syn::Result<Vec<_>>>()?,
                    VariantEnumKind::Error => v.fields.iter().map(|f| f.ty.clone()).collect(),
                };

                Ok(quote! {
                    #[doc = concat!("Creates a new `", stringify!(#variant_name), "`.")]
                    pub fn #fn_name(#(#param_names: #param_types),*) -> Self {
                        Self::#variant_name(#variant_name { #(#param_names),* })
                    }
                })
            }
        })
        .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        impl #container {
            #(#constructors)*
        }
    })
}
