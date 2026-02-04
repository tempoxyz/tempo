//! Struct code generation for the `#[abi]` module macro.
//!
//! Generates `SolStruct`, `SolType`, `SolValue`, and `EventTopic`
//! implementations for structs defined within a `#[abi]` module.

use alloy_sol_macro_expander::{Eip712Options, StructCodegen};
use proc_macro2::{Ident, TokenStream};
use quote::quote;

use super::common::SynSolType;
use crate::utils::to_camel_case;

use super::{
    common,
    parser::{FieldAccessors, SolStructDef},
    registry::TypeRegistry,
};

/// Generate code for a single struct definition.
pub(super) fn generate_struct(
    def: &SolStructDef,
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let struct_name = &def.name;
    let field_names = def.field_names();
    let rust_types = def.field_types();
    let sol_types = common::types_to_sol_types(&def.field_raw_types())?;

    let eip712_root = build_eip712_root(struct_name, def)?;

    let has_deps = !registry
        .get_transitive_dependencies(&struct_name.to_string())
        .is_empty();

    // encode_type_impl: `None` lets alloy infer from `components_impl`
    let sol_struct_impl = StructCodegen::new(
        field_names,
        rust_types,
        sol_types,
        Eip712Options {
            root: eip712_root,
            components_impl: if has_deps {
                Some(registry.generate_eip712_components(struct_name))
            } else {
                None
            },
            encode_type_impl: None,
        },
    )
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

    // Emit cfg-gated Storable derive if the struct originally had it
    let storable_attr = if def.has_storable {
        quote! { #[cfg_attr(feature = "precompile", derive(tempo_precompiles_macros::Storable))] }
    } else {
        quote! {}
    };

    let struct_def = quote! {
        #(#attrs)*
        #(#derives)*
        #storable_attr
        #vis struct #struct_name {
            #(#field_defs),*
        }
    };

    let const_block = common::wrap_const_block(sol_struct_impl);

    Ok(quote! {
        #struct_def
        #const_block
    })
}

/// Build EIP-712 root type signature.
fn build_eip712_root(name: &Ident, def: &SolStructDef) -> syn::Result<String> {
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
