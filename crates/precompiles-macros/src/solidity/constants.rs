//! Constants code generation for the `#[solidity]` module macro.
//!
//! Generates view function call structs for each constant and a `ConstantsCalls` enum.

use alloy_sol_macro_expander::{
    CallCodegen, ReturnInfo, SolInterfaceKind, StructLayout, gen_from_into_tuple,
};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::{
    common::{self, SynSolType, Unzip4},
    parser::ConstantDef,
    registry::TypeRegistry,
};

/// Generate code for all constants as view functions.
pub(super) fn generate_constants(
    constants: &[ConstantDef],
    _registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    if constants.is_empty() {
        return Ok(quote! {});
    }

    let constant_defs = generate_definitions(constants);
    let trait_def = generate_trait(constants);
    let call_impls = constants
        .iter()
        .map(generate_call_code)
        .collect::<syn::Result<Vec<_>>>()?;
    let calls_enum = generate_calls_enum(constants);

    Ok(quote! {
        #constant_defs
        #trait_def
        #(#call_impls)*
        #calls_enum
    })
}

/// Generate the original constant/static definitions (preserved).
fn generate_definitions(constants: &[ConstantDef]) -> TokenStream {
    let defs = constants.iter().map(|c| {
        let (name, ty, expr, vis, attrs) = (&c.name, &c.ty, &c.expr, &c.vis, &c.attrs);
        match (c.is_static, c.is_lazy) {
            (true, true) => quote! {
                #(#attrs)* #vis static #name: ::std::sync::LazyLock<#ty> = #expr;
            },
            (true, false) => quote! {
                #(#attrs)* #vis static #name: #ty = #expr;
            },
            (false, _) => quote! {
                #(#attrs)* #vis const #name: #ty = #expr;
            },
        }
    });
    quote! { #(#defs)* }
}

/// Generate the IConstants trait.
fn generate_trait(constants: &[ConstantDef]) -> TokenStream {
    let methods = constants.iter().map(|c| {
        let (name, ty) = (&c.name, &c.ty);
        quote! { fn #name(&self) -> Result<#ty>; }
    });
    quote! {
        pub trait IConstants {
            #(#methods)*
        }
    }
}

/// Generate call/return structs for a single constant.
fn generate_call_code(c: &ConstantDef) -> syn::Result<TokenStream> {
    let sol_name = c.sol_name();
    let signature = format!("{}()", sol_name);
    let call_name = format_ident!("{}Call", sol_name);
    let return_name = format_ident!("{}Return", sol_name);
    let ret_ty = &c.ty;
    let ret_sol = SynSolType::parse(ret_ty)?.to_sol_data();

    let doc = common::signature_doc(
        "Function",
        &signature,
        false,
        Some(format!(
            "function {}() view returns ({});",
            sol_name,
            SynSolType::parse(ret_ty)?.sol_name()
        )),
    );

    let field_name = format_ident!("_0");
    let return_from_tuple = gen_from_into_tuple(
        &return_name,
        &[field_name.clone()],
        &[ret_sol.clone()],
        &[quote! { #ret_ty }],
        StructLayout::Named,
    );
    let call_from_tuple = gen_from_into_tuple(&call_name, &[], &[], &[], StructLayout::Unit);

    let sol_call_impl = CallCodegen::new(
        quote! { () },
        quote! { (#ret_sol,) },
        quote! { () },
        ReturnInfo::Single {
            sol_type: ret_sol,
            rust_type: quote! { #ret_ty },
            field_name,
            return_name: return_name.clone(),
        },
    )
    .expand(&call_name, &signature);

    let call_const_block = common::wrap_const_block(quote! { #call_from_tuple #sol_call_impl });
    let return_const_block = common::wrap_const_block(return_from_tuple);

    Ok(quote! {
        #[doc = #doc]
        #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style)]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct #call_name;

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct #return_name { pub _0: #ret_ty }

        #call_const_block
        #return_const_block
    })
}

/// Generate the `ConstantsCalls` container enum.
fn generate_calls_enum(constants: &[ConstantDef]) -> TokenStream {
    let (variants, types, signatures, field_counts): (Vec<_>, Vec<_>, Vec<_>, Vec<_>) = constants
        .iter()
        .map(|c| {
            let name = c.sol_name();
            (format_ident!("{}", name), format_ident!("{}Call", name), format!("{}()", name), 0usize)
        })
        .unzip4();

    common::generate_sol_interface_container(
        "ConstantsCalls",
        &variants,
        &types,
        &signatures,
        &field_counts,
        SolInterfaceKind::Call,
    )
}
