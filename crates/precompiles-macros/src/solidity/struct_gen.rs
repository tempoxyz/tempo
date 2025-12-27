//! Struct code generation for the `#[solidity]` module macro.
//!
//! Generates `SolStruct`, `SolType`, `SolValue`, `EventTopic`, and `SolTupleSignature`
//! implementations for structs defined within a `#[solidity]` module.

use alloy_sol_macro_expander::{Eip712Options, SolStructData};
use proc_macro2::{Ident, TokenStream};
use quote::quote;

use crate::utils::{to_camel_case, SolType};

use super::parser::SolStructDef;
use super::registry::TypeRegistry;

/// Generate code for a single struct definition.
pub(super) fn generate_struct(
    def: &SolStructDef,
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let struct_name = &def.name;

    let field_names: Vec<Ident> = def.fields.iter().map(|f| f.name.clone()).collect();

    let rust_types: Vec<TokenStream> = def
        .fields
        .iter()
        .map(|f| {
            let ty = &f.ty;
            quote! { #ty }
        })
        .collect();

    let sol_types: syn::Result<Vec<TokenStream>> = def
        .fields
        .iter()
        .map(|f| Ok(SolType::from_syn(&f.ty)?.to_sol_data()))
        .collect();
    let sol_types = sol_types?;

    let eip712_signature = build_eip712_signature(struct_name, def);

    let abi_tuple_impl = build_abi_tuple_impl(def, registry)?;

    let components_impl = registry.generate_eip712_components(struct_name);
    let has_deps = !registry
        .get_transitive_dependencies(&struct_name.to_string())
        .is_empty();

    let sol_struct_impl = SolStructData {
        field_names: field_names.clone(),
        rust_types,
        sol_types,
        eip712: Eip712Options {
            signature: eip712_signature,
            components_impl: if has_deps {
                Some(components_impl)
            } else {
                None
            },
            encode_type_impl: None,
        },
    }
    .expand(struct_name);

    let sol_tuple_sig_impl = quote! {
        impl tempo_precompiles::SolTupleSignature for #struct_name {
            const ABI_TUPLE: &'static str = #abi_tuple_impl;
        }
    };

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
        #sol_tuple_sig_impl
    })
}

/// Build EIP-712 type signature.
fn build_eip712_signature(name: &Ident, def: &SolStructDef) -> String {
    let mut sig = name.to_string();
    sig.push('(');

    for (i, field) in def.fields.iter().enumerate() {
        if i > 0 {
            sig.push(',');
        }
        let field_name = to_camel_case(&field.name.to_string());
        let sol_ty = SolType::from_syn(&field.ty).expect("type already validated");
        sig.push_str(&sol_ty.sol_name());
        sig.push(' ');
        sig.push_str(&field_name);
    }

    sig.push(')');
    sig
}

/// Build ABI tuple signature implementation.
///
/// Uses the registry to resolve nested struct types correctly.
fn build_abi_tuple_impl(def: &SolStructDef, registry: &TypeRegistry) -> syn::Result<TokenStream> {
    let has_struct_fields = registry.has_struct_params(
        &def.fields
            .iter()
            .map(|f| f.ty.clone())
            .collect::<Vec<_>>(),
    );

    if has_struct_fields {
        let parts: Vec<TokenStream> = def
            .fields
            .iter()
            .enumerate()
            .flat_map(|(i, f)| {
                let mut tokens = Vec::new();
                if i > 0 {
                    tokens.push(quote! { "," });
                }
                tokens.push(
                    registry
                        .to_abi_signature_expr(&f.ty)
                        .expect("type already validated"),
                );
                tokens
            })
            .collect();

        Ok(quote! {
            tempo_precompiles::const_format::concatcp!("(", #(#parts,)* ")")
        })
    } else {
        let abi_tuple = registry
            .get_struct_abi(&def.name.to_string())
            .expect("struct already registered");
        Ok(quote! { #abi_tuple })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solidity::parser::{FieldDef, SolStructDef, SolidityModule};
    use proc_macro2::Span;
    use quote::format_ident;
    use syn::{parse_quote, Visibility};

    fn make_field(name: &str, ty: syn::Type) -> FieldDef {
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
    fn test_build_eip712_signature() {
        let def = make_struct(
            "Transfer",
            vec![
                make_field("from", parse_quote!(Address)),
                make_field("to", parse_quote!(Address)),
                make_field("amount", parse_quote!(U256)),
            ],
        );

        let sig = build_eip712_signature(&def.name, &def);
        assert_eq!(sig, "Transfer(address from,address to,uint256 amount)");
    }

    #[test]
    fn test_build_eip712_signature_snake_case() {
        let def = make_struct(
            "RewardStream",
            vec![
                make_field("start_time", parse_quote!(u64)),
                make_field("rate_per_second", parse_quote!(U256)),
            ],
        );

        let sig = build_eip712_signature(&def.name, &def);
        assert_eq!(
            sig,
            "RewardStream(uint64 startTime,uint256 ratePerSecond)"
        );
    }

    #[test]
    fn test_generate_struct_simple() -> syn::Result<()> {
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
        let def = &module.structs[0];

        let tokens = generate_struct(def, &registry)?;
        let code = tokens.to_string();

        assert!(code.contains("struct Transfer"));
        assert!(code.contains("SolTupleSignature"));
        assert!(code.contains("ABI_TUPLE"));

        Ok(())
    }
}
