//! Struct code generation for the `#[solidity]` module macro.
//!
//! Generates `SolStruct`, `SolType`, `SolValue`, and `EventTopic`
//! implementations for structs defined within a `#[solidity]` module.

use alloy_sol_macro_expander::{Eip712Options, SolStructData};
use proc_macro2::{Ident, TokenStream};
use quote::quote;

use super::common::SynSolType;
use crate::utils::to_camel_case;

use super::common;
use super::parser::{FieldAccessors, SolStructDef};
use super::registry::TypeRegistry;

/// Generate code for a single struct definition.
pub(super) fn generate_struct(
    def: &SolStructDef,
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let struct_name = &def.name;
    let field_names = def.field_names();
    let rust_types = def.field_types();
    let sol_types = common::types_to_sol_types(&def.field_raw_types())?;

    let eip712_signature = build_eip712_signature(struct_name, def)?;

    let has_deps = !registry
        .get_transitive_dependencies(&struct_name.to_string())
        .is_empty();

    // encode_type_impl: `None` lets alloy infer from `components_impl`
    let sol_struct_impl = SolStructData {
        field_names,
        rust_types,
        sol_types,
        eip712: Eip712Options {
            signature: eip712_signature,
            components_impl: if has_deps {
                Some(registry.generate_eip712_components(struct_name))
            } else {
                None
            },
            encode_type_impl: None,
        },
    }
    .expand(struct_name);

    let derives = &def.derives;
    let attrs = &def.attrs;
    let vis = &def.vis;

    let field_defs: Vec<TokenStream> = def
        .fields
        .iter()
        .map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            let vis = &f.vis;
            quote! { #vis #name: #ty }
        })
        .collect();

    let struct_def = quote! {
        #(#attrs)*
        #(#derives)*
        #vis struct #struct_name {
            #(#field_defs),*
        }
    };

    Ok(quote! {
        #struct_def
        #sol_struct_impl
    })
}

/// Build EIP-712 type signature.
fn build_eip712_signature(name: &Ident, def: &SolStructDef) -> syn::Result<String> {
    let mut sig = name.to_string();
    sig.push('(');

    for (i, field) in def.fields.iter().enumerate() {
        if i > 0 {
            sig.push(',');
        }
        let field_name = to_camel_case(&field.name.to_string());
        let sol_ty = SynSolType::parse(&field.ty)?;
        sig.push_str(&sol_ty.sol_name());
        sig.push(' ');
        sig.push_str(&field_name);
    }

    sig.push(')');
    Ok(sig)
}
