//! Interface trait code generation for the `#[solidity]` module macro.
//!
//! Generates `SolCall` structs for each method and a container `Calls`
//! enum with `SolInterface` implementation.
//!
//! Also transforms the trait to inject `msg_sender: Address` for mutable methods.

use alloy_sol_macro_expander::{
    CallCodegen, CallLayout, ContractCodegen, ContractFunctionInfo, ReturnInfo, SolInterfaceKind,
    StructLayout, gen_from_into_tuple, is_reserved_method_name,
};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use super::{
    common::{self, SynSolType},
    parser::{FieldAccessors, InterfaceDef, MethodDef},
    registry::TypeRegistry,
};

/// Precomputed method metadata to avoid redundant signature computation.
struct MethodCodegen<'a> {
    method: &'a MethodDef,
    signature: String,
    call_name: Ident,
    variant_name: Ident,
}

impl<'a> MethodCodegen<'a> {
    fn from_method(method: &'a MethodDef, registry: &TypeRegistry) -> syn::Result<Self> {
        let signature = registry.compute_signature(&method.sol_name, &method.field_raw_types())?;
        Ok(Self {
            method,
            signature,
            call_name: format_ident!("{}Call", method.sol_name),
            variant_name: format_ident!("{}", method.sol_name),
        })
    }
}

/// Generate code for a single interface trait.
///
/// Returns the transformed trait, method call structs, and the `{TraitName}Calls` enum.
pub(super) fn generate_interface(
    def: &InterfaceDef,
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let methods: Vec<MethodCodegen<'_>> = def
        .methods
        .iter()
        .map(|m| MethodCodegen::from_method(m, registry))
        .collect::<syn::Result<Vec<_>>>()?;

    let method_impls = methods
        .iter()
        .map(generate_method_code)
        .collect::<syn::Result<Vec<_>>>()?;

    let calls_enum_name = format_ident!("{}Calls", def.name);
    let calls_enum = generate_calls_enum(&calls_enum_name, &methods);

    let transformed_trait = generate_transformed_trait(def);

    Ok(quote! {
        #transformed_trait
        #(#method_impls)*
        #calls_enum
    })
}

/// Generate the unified `Calls` enum that composes all interface Calls enums.
pub(super) fn generate_unified_calls(interfaces: &[InterfaceDef]) -> TokenStream {
    if interfaces.is_empty() {
        return quote! {
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub enum Calls {}

            impl Calls {
                /// Function selectors (empty).
                pub const SELECTORS: &'static [[u8; 4]] = &[];

                #[inline]
                pub fn valid_selector(_: [u8; 4]) -> bool { false }
            }

            impl ::alloy_sol_types::SolInterface for Calls {
                const NAME: &'static str = "Calls";
                const MIN_DATA_LENGTH: usize = 0;
                const COUNT: usize = 0;
                #[inline] fn selector(&self) -> [u8; 4] { match *self {} }
                #[inline] fn selector_at(_i: usize) -> Option<[u8; 4]> { None }
                #[inline] fn valid_selector(_s: [u8; 4]) -> bool { false }
                #[inline] fn abi_decode_raw(_s: [u8; 4], _d: &[u8]) -> ::alloy_sol_types::Result<Self> {
                    Err(::alloy_sol_types::Error::Other("no variants".into()))
                }
                #[inline] fn abi_decode_raw_validate(s: [u8; 4], d: &[u8]) -> ::alloy_sol_types::Result<Self> { Self::abi_decode_raw(s, d) }
                #[inline] fn abi_encoded_size(&self) -> usize { match *self {} }
                #[inline] fn abi_encode_raw(&self, _o: &mut Vec<u8>) { match *self {} }
            }
        };
    }

    // If there's only one interface, just alias Calls to {TraitName}Calls
    if interfaces.len() == 1 {
        let calls_name = format_ident!("{}Calls", interfaces[0].name);
        return quote! {
            pub type Calls = #calls_name;
        };
    }

    // Multiple interfaces: compose them
    let variant_names: Vec<_> = interfaces.iter().map(|i| i.name.clone()).collect();
    let calls_names: Vec<_> = interfaces
        .iter()
        .map(|i| format_ident!("{}Calls", i.name))
        .collect();
    let n = interfaces.len();

    let decls: Vec<_> = variant_names
        .iter()
        .zip(&calls_names)
        .map(|(v, c)| quote! { #v(#c) })
        .collect();

    let selectors: Vec<_> = calls_names
        .iter()
        .map(|c| quote! { #c::SELECTORS })
        .collect();

    let counts: Vec<_> = calls_names
        .iter()
        .map(|c| quote! { <#c as ::alloy_sol_types::SolInterface>::COUNT })
        .collect();

    let decode: Vec<_> = variant_names
        .iter()
        .zip(&calls_names)
        .map(|(v, c)| {
            quote! {
                if <#c as ::alloy_sol_types::SolInterface>::valid_selector(sel) {
                    return <#c as ::alloy_sol_types::SolInterface>::abi_decode(data).map(Self::#v);
                }
            }
        })
        .collect();

    let sel_match: Vec<_> = variant_names
        .iter()
        .zip(&calls_names)
        .map(|(v, c)| {
            quote! { Self::#v(inner) => <#c as ::alloy_sol_types::SolInterface>::selector(inner) }
        })
        .collect();

    let size_match: Vec<_> = variant_names
        .iter()
        .zip(&calls_names)
        .map(|(v, c)| {
            quote! { Self::#v(inner) => <#c as ::alloy_sol_types::SolInterface>::abi_encoded_size(inner) }
        })
        .collect();

    let enc_match: Vec<_> = variant_names
        .iter()
        .zip(&calls_names)
        .map(|(v, c)| {
            quote! { Self::#v(inner) => <#c as ::alloy_sol_types::SolInterface>::abi_encode_raw(inner, out) }
        })
        .collect();

    let from_impls: Vec<_> = variant_names
        .iter()
        .zip(&calls_names)
        .map(|(v, c)| {
            quote! {
                impl From<#c> for Calls {
                    #[inline]
                    fn from(c: #c) -> Self { Self::#v(c) }
                }
            }
        })
        .collect();

    quote! {
        #[doc(hidden)]
        mod __calls_compose_helpers {
            pub const fn concat_4<const N: usize, const M: usize>(
                a: [&'static [[u8; 4]]; N]
            ) -> [[u8; 4]; M] {
                let mut r = [[0u8; 4]; M];
                let (mut i, mut n_idx) = (0, 0);
                while n_idx < N {
                    let s = a[n_idx];
                    let mut j = 0;
                    while j < s.len() { r[i] = s[j]; i += 1; j += 1; }
                    n_idx += 1;
                }
                r
            }
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        #[allow(non_camel_case_types, clippy::large_enum_variant)]
        pub enum Calls { #(#decls),* }

        impl Calls {
            pub const SELECTORS: &'static [[u8; 4]] = &{
                const TOTAL: usize = #(#selectors.len())+*;
                __calls_compose_helpers::concat_4::<#n, TOTAL>([#(#selectors),*])
            };

            #[inline]
            pub fn valid_selector(s: [u8; 4]) -> bool { Self::SELECTORS.contains(&s) }

            pub fn abi_decode(data: &[u8]) -> ::alloy_sol_types::Result<Self> {
                let sel: [u8; 4] = data.get(..4).and_then(|s| s.try_into().ok())
                    .ok_or_else(|| ::alloy_sol_types::Error::Other("calldata too short".into()))?;
                #(#decode)*
                Err(::alloy_sol_types::Error::unknown_selector(<Self as ::alloy_sol_types::SolInterface>::NAME, sel))
            }
        }

        impl ::alloy_sol_types::SolInterface for Calls {
            const NAME: &'static str = "Calls";
            const MIN_DATA_LENGTH: usize = 0;
            const COUNT: usize = #(#counts)+*;
            #[inline] fn selector(&self) -> [u8; 4] { match self { #(#sel_match),* } }
            #[inline] fn selector_at(i: usize) -> Option<[u8; 4]> { Self::SELECTORS.get(i).copied() }
            #[inline] fn valid_selector(s: [u8; 4]) -> bool { Self::valid_selector(s) }
            #[inline] fn abi_decode_raw(sel: [u8; 4], data: &[u8]) -> ::alloy_sol_types::Result<Self> {
                let mut buf = Vec::with_capacity(4 + data.len()); buf.extend_from_slice(&sel); buf.extend_from_slice(data);
                Self::abi_decode(&buf)
            }
            #[inline] fn abi_decode_raw_validate(sel: [u8; 4], data: &[u8]) -> ::alloy_sol_types::Result<Self> { Self::abi_decode_raw(sel, data) }
            #[inline] fn abi_encoded_size(&self) -> usize { match self { #(#size_match),* } }
            #[inline] fn abi_encode_raw(&self, out: &mut Vec<u8>) { match self { #(#enc_match),* } }
        }

        #(#from_impls)*
    }
}

/// Generate the transformed trait with msg_sender injection.
fn generate_transformed_trait(def: &InterfaceDef) -> TokenStream {
    let trait_name = &def.name;
    let vis = &def.vis;
    let attrs = &def.attrs;

    let methods: Vec<TokenStream> = def
        .methods
        .iter()
        .map(|m| {
            let name = &m.name;
            let params: Vec<TokenStream> =
                m.params.iter().map(|(n, ty)| quote! { #n: #ty }).collect();

            let return_type = if let Some(ref ty) = m.return_type {
                quote! { -> Result<#ty> }
            } else {
                quote! { -> Result<()> }
            };

            if m.is_mutable {
                quote! {
                    fn #name(&mut self, msg_sender: Address, #(#params),*) #return_type;
                }
            } else {
                quote! {
                    fn #name(&self, #(#params),*) #return_type;
                }
            }
        })
        .collect();

    quote! {
        #(#attrs)*
        #vis trait #trait_name {
            #(#methods)*
        }
    }
}

/// Generate code for a single method using precomputed metadata.
fn generate_method_code(mc: &MethodCodegen<'_>) -> syn::Result<TokenStream> {
    let method = mc.method;
    let call_name = &mc.call_name;
    let signature = &mc.signature;
    let return_name = format_ident!("{}Return", method.sol_name);

    let param_names = method.field_names();
    let param_rust_types = method.field_types();
    let param_raw_types = method.field_raw_types();
    let param_sol_types = common::types_to_sol_types(&param_raw_types)?;

    let common::EncodedParams {
        param_tuple: call_tuple,
        tokenize_impl,
    } = common::encode_params(&param_names, &param_raw_types)?;

    let doc = common::signature_doc(
        "Function",
        signature,
        false,
        method.solidity_decl("function"),
    );

    let call_fields: Vec<_> = method.fields().collect();
    let call_struct = common::generate_simple_struct(call_name, &call_fields, &doc);

    let (return_struct, return_from_tuple, return_sol_tuple, return_info) =
        if let Some(ref ret_ty) = method.return_type {
            let ret_sol = SynSolType::parse(ret_ty)?.to_sol_data();
            let field_name = format_ident!("_0");
            let return_field_names = vec![field_name.clone()];
            let return_sol_types = vec![ret_sol.clone()];
            let return_rust_types = vec![quote! { #ret_ty }];
            (
                quote! {
                    #[derive(Clone, Debug, PartialEq, Eq)]
                    pub struct #return_name {
                        pub _0: #ret_ty,
                    }
                },
                gen_from_into_tuple(
                    &return_name,
                    &return_field_names,
                    &return_sol_types,
                    &return_rust_types,
                    StructLayout::Named,
                ),
                quote! { (#ret_sol,) },
                ReturnInfo::Single {
                    sol_type: ret_sol,
                    rust_type: quote! { #ret_ty },
                    field_name,
                    return_name: return_name.clone(),
                },
            )
        } else {
            (
                quote! {
                    #[derive(Clone, Debug, PartialEq, Eq)]
                    pub struct #return_name;

                    impl #return_name {
                        #[doc(hidden)]
                        pub fn _tokenize(_: &Self) -> () {
                            ()
                        }
                    }
                },
                gen_from_into_tuple(&return_name, &[], &[], &[], StructLayout::Unit),
                quote! { () },
                ReturnInfo::Empty {
                    return_name: return_name.clone(),
                },
            )
        };

    let call_layout = if param_names.is_empty() {
        StructLayout::Unit
    } else {
        StructLayout::Named
    };
    let call_from_tuple = gen_from_into_tuple(
        call_name,
        &param_names,
        &param_sol_types,
        &param_rust_types,
        call_layout,
    );

    let sol_call_impl = CallCodegen::new(call_tuple, return_sol_tuple, tokenize_impl, return_info)
        .expand(call_name, signature);

    let call_const_block = common::wrap_const_block(quote! {
        #call_from_tuple
        #sol_call_impl
    });
    let return_const_block = common::wrap_const_block(return_from_tuple);

    Ok(quote! {
        #call_struct
        #return_struct
        #call_const_block
        #return_const_block
    })
}

/// Generate the container enum for all calls using precomputed metadata.
fn generate_calls_enum(enum_name: &Ident, methods: &[MethodCodegen<'_>]) -> TokenStream {
    let (variants, types, signatures, field_counts): (Vec<_>, Vec<_>, Vec<_>, Vec<_>) = methods
        .iter()
        .map(|mc| {
            (
                mc.variant_name.clone(),
                mc.call_name.clone(),
                mc.signature.clone(),
                mc.method.params.len(),
            )
        })
        .unzip4();

    common::generate_sol_interface_container(
        &enum_name.to_string(),
        &variants,
        &types,
        &signatures,
        &field_counts,
        SolInterfaceKind::Call,
    )
}

/// Helper trait to unzip an iterator of 4-tuples.
trait Unzip4<A, B, C, D> {
    fn unzip4(self) -> (Vec<A>, Vec<B>, Vec<C>, Vec<D>);
}

impl<I, A, B, C, D> Unzip4<A, B, C, D> for I
where
    I: Iterator<Item = (A, B, C, D)>,
{
    fn unzip4(self) -> (Vec<A>, Vec<B>, Vec<C>, Vec<D>) {
        let (mut a_vec, mut b_vec, mut c_vec, mut d_vec) = (vec![], vec![], vec![], vec![]);
        for (a, b, c, d) in self {
            a_vec.push(a);
            b_vec.push(b);
            c_vec.push(c);
            d_vec.push(d);
        }

        (a_vec, b_vec, c_vec, d_vec)
    }
}

/// Generate provider-bound instance struct for RPC interactions.
///
/// When an Interface trait exists, this generates a `{ModuleName}Instance<P, N>`
/// struct with methods for each interface function that return `SolCallBuilder`.
pub(super) fn generate_instance(
    module_name: &proc_macro2::Ident,
    def: &InterfaceDef,
) -> syn::Result<TokenStream> {
    let functions: Vec<ContractFunctionInfo> = def
        .methods
        .iter()
        .map(|m| {
            let method_name = if is_reserved_method_name(&m.sol_name) {
                format_ident!("{}_call", m.sol_name)
            } else {
                format_ident!("{}", m.sol_name)
            };

            let layout = if m.params.is_empty() {
                CallLayout::Unit
            } else {
                CallLayout::Named
            };

            ContractFunctionInfo {
                method_name,
                call_name: format_ident!("{}Call", m.sol_name),
                param_names: m.params.iter().map(|(n, _)| n.clone()).collect(),
                rust_types: m.params.iter().map(|(_, ty)| quote! { #ty }).collect(),
                layout,
            }
        })
        .collect();

    let codegen = ContractCodegen::new(
        module_name.clone(),
        functions,
        vec![], // No events for Interface
        false,  // No bytecode
        None,   // No constructor
    );

    Ok(codegen.expand())
}
