//! Trait generation for contract macro.
//!
//! This module generates custom traits, with a default implementation for getter functions,
//! that allow for easy call interactions with the contract.

use crate::{
    FieldInfo,
    interface::{Interface, InterfaceFunction},
    utils::extract_mapping_types,
};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Ident, Type};

/// Represents the info associated with a getter function.
#[derive(Debug, Clone)]
pub(crate) enum GetterInfo<'a> {
    Direct {
        field: &'a FieldInfo,
    },
    Mapping {
        field: &'a FieldInfo,
        key_param: &'a str,
    },
    NestedMapping {
        field: &'a FieldInfo,
        key1_param: &'a str,
        key2_param: &'a str,
    },
    NoMatch,
}

/// Represents the info associated with a getter function.
#[derive(Debug, Clone)]
pub(crate) struct GetterFn<'a> {
    pub function: &'a InterfaceFunction,
    pub field_match: GetterInfo<'a>,
}

/// Matches interface functions and storage fields to find the getters.
pub(crate) fn find_getters<'a>(
    funcs: &'a [InterfaceFunction],
    fields: &'a [FieldInfo],
) -> Vec<GetterFn<'a>> {
    funcs
        .iter()
        .map(|func| {
            let field_match = find_field_getter(func, fields);
            GetterFn {
                function: func,
                field_match,
            }
        })
        .collect()
}

/// For a given function, finds a getter method that matches a field.
fn find_field_getter<'a>(func: &'a InterfaceFunction, fields: &'a [FieldInfo]) -> GetterInfo<'a> {
    fields
        .iter()
        .find_map(|field| {
            // Exclude state-modifying functions
            if !func.is_view {
                return None;
            }

            // Determine if the field matches by custom map (if informed) or name.
            if field.name() != func.name {
                return None;
            }

            // Valid match if fn signature types are compatible with the field getter/setter
            let res = match_by_type(func, field);
            if !matches!(res, GetterInfo::NoMatch) {
                return Some(res);
            }

            None
        })
        .unwrap_or(GetterInfo::NoMatch)
}

/// Compares `syn::Type` instances for equality.
///
/// For custom structs, this compares only the base type name (last path segment)
/// since custom types can be converted via `.into()`. For primitive and known types,
/// this requires exact token stream equality.
fn types_equal(a: &Type, b: &Type) -> bool {
    use crate::utils::{is_custom_struct, try_extract_type_ident};
    use quote::ToTokens;

    // For custom structs, compare base names only (allows conversion via .into())
    if is_custom_struct(a)
        && is_custom_struct(b)
        && let (Ok(ident_a), Ok(ident_b)) = (try_extract_type_ident(a), try_extract_type_ident(b))
    {
        return ident_a == ident_b;
    }

    // For primitives and known types, require exact match
    a.to_token_stream().to_string() == b.to_token_stream().to_string()
}

/// Matches a function to a field based on type compatibility.
///
/// This function validates that both, the parameter count and the types, match:
/// - Direct fields: No params, return type matches field type
/// - Mapping fields: 1 param matching key type, return type matches value type
/// - Nested Mapping fields: 2 params matching key types, return type matches inner value type
fn match_by_type<'a>(func: &'a InterfaceFunction, field: &'a FieldInfo) -> GetterInfo<'a> {
    match (func.params.len(), extract_mapping_types(&field.ty)) {
        // Direct field: no params, return type must match field type
        (0, None) => {
            if types_equal(&func.return_type, &field.ty) {
                GetterInfo::Direct { field }
            } else {
                GetterInfo::NoMatch
            }
        }
        // Mapping: 1 param must match key type, return type must match value type
        (1, Some((key_ty, value_ty))) if extract_mapping_types(value_ty).is_none() => {
            let param_ty = &func.params[0].1;
            if types_equal(param_ty, key_ty) && types_equal(&func.return_type, value_ty) {
                GetterInfo::Mapping {
                    field,
                    key_param: &func.params[0].0.rust,
                }
            } else {
                GetterInfo::NoMatch
            }
        }
        // Nested Mapping: 2 params must match key types, return type must match inner value type
        (2, Some((key1_ty, value))) if extract_mapping_types(value).is_some() => {
            let Some((key2_ty, inner_value_ty)) = extract_mapping_types(value) else {
                return GetterInfo::NoMatch;
            };
            let param1_ty = &func.params[0].1;
            let param2_ty = &func.params[1].1;
            if types_equal(param1_ty, key1_ty)
                && types_equal(param2_ty, key2_ty)
                && types_equal(&func.return_type, inner_value_ty)
            {
                GetterInfo::NestedMapping {
                    field,
                    key1_param: &func.params[0].0.rust,
                    key2_param: &func.params[1].0.rust,
                }
            } else {
                GetterInfo::NoMatch
            }
        }
        _ => GetterInfo::NoMatch,
    }
}

/// Generates storage trait, storage impl, and per-interface traits with default methods.
pub(crate) fn gen_traits_and_impls(
    struct_name: &Ident,
    interface_data: &[(Ident, Interface)],
    fields: &[FieldInfo],
) -> TokenStream {
    let storage_trait_name = format_ident!("_{}Storage", struct_name);

    // Collect all functions across all interfaces for storage trait generation
    let all_funcs: Vec<InterfaceFunction> = interface_data
        .iter()
        .flat_map(|(_, interface)| interface.functions.clone())
        .collect();

    let all_getters = find_getters(&all_funcs, fields);

    let storage_trait = gen_storage_trait(&storage_trait_name, &all_getters);
    let storage_impl = gen_storage_impl(struct_name, &storage_trait_name, &all_getters);

    // Generate one trait per interface
    let num_interfaces = interface_data.len();
    let interface_traits: Vec<TokenStream> = interface_data
        .iter()
        .map(|(interface_ident, interface)| {
            let interface_getters = find_getters(&interface.functions, fields);
            gen_interface_trait(
                struct_name,
                interface_ident,
                &storage_trait_name,
                &interface_getters,
                num_interfaces,
            )
        })
        .collect();

    quote! {
        #storage_trait
        #storage_impl
        #(#interface_traits)*
    }
}

/// Generates a single interface trait.
///
/// Naming pattern:
/// - Single interface: `<ContractName>Call`
/// - Multiple interfaces: `<ContractName>_<InterfaceName>Call`
fn gen_interface_trait(
    struct_name: &Ident,
    interface_ident: &Ident,
    storage_trait_name: &Ident,
    match_results: &[GetterFn<'_>],
    num_interfaces: usize,
) -> TokenStream {
    // Use simpler naming for single-interface contracts
    let trait_name = if num_interfaces == 1 {
        format_ident!("{}Call", struct_name)
    } else {
        format_ident!("{}_{}", struct_name, interface_ident)
    };

    let interface_methods: Vec<TokenStream> = match_results
        .iter()
        .map(|result| gen_call_trait_method(result))
        .collect();

    // Collect auto-implemented getter signatures for documentation
    let auto_impl_getters: Vec<String> = match_results
        .iter()
        .filter(|result| !matches!(result.field_match, GetterInfo::NoMatch))
        .map(|result| format!("- `{}`", gen_method_signature(result.function)))
        .collect();

    let trait_doc = if auto_impl_getters.is_empty() {
        quote! {
            #[doc = concat!("Trait for `", stringify!(#interface_ident), "` interface implementation.")]
        }
    } else {
        let getter_list = auto_impl_getters.join("\n");
        let doc = format!(
            "Trait for `{interface_ident}` interface implementation.\n\n## Auto-implemented getters:\n{getter_list}",
        );
        quote! {
            #[doc = #doc]
        }
    };

    quote! {
        #trait_doc
        #[allow(non_camel_case_types)]
        pub trait #trait_name: #storage_trait_name {
            #(#interface_methods)*
        }
    }
}

/// Generates the internal storage trait that enables the default impl for the getter methods.
fn gen_storage_trait(storage_trait_name: &Ident, match_results: &[GetterFn<'_>]) -> TokenStream {
    let storage_methods: Vec<TokenStream> = match_results
        .iter()
        .filter_map(|result| match &result.field_match {
            GetterInfo::NoMatch => None,
            _ => Some(gen_storage_method_sig_or_impl(true, result)),
        })
        .collect();

    quote! {
        /// Internal storage trait for accessing contract storage.
        ///
        /// This trait is auto-generated and provides low-level storage operations,
        /// which enables the default impl for the contract's getter methods.
        ///
        /// IMPORTANT: Do not implement this trait manually.
        trait #storage_trait_name {
            #(#storage_methods)*
        }
    }
}

/// Generates the internal storage trait impl that enables the default impl for the getter methods.
fn gen_storage_impl(
    struct_name: &Ident,
    trait_name: &Ident,
    match_results: &[GetterFn<'_>],
) -> TokenStream {
    let storage_impls: Vec<TokenStream> = match_results
        .iter()
        .filter_map(|result| match &result.field_match {
            GetterInfo::NoMatch => None,
            _ => Some(gen_storage_method_sig_or_impl(false, result)),
        })
        .collect();

    quote! {
        /// Auto-generated storage trait implementation.
        impl<'a, S: crate::storage::PrecompileStorageProvider> #trait_name for #struct_name<'a, S> {
            #(#storage_impls)*
        }
    }
}

/// Generates a storage method signature or its implementation, based on what's requested.
fn gen_storage_method_sig_or_impl(gen_sig: bool, result: &GetterFn<'_>) -> TokenStream {
    let func = &result.function;
    let return_type = &func.return_type;

    match &result.field_match {
        GetterInfo::Direct { field } => {
            let getter_name = format_ident!("sload_{}", field.name);
            if gen_sig {
                quote! { fn #getter_name(&mut self) -> crate::error::Result<#return_type>; }
            } else {
                quote! {
                    fn #getter_name(&mut self) -> crate::error::Result<#return_type> {
                        self.#getter_name().map(|v| v.into())
                    }
                }
            }
        }
        GetterInfo::Mapping { field, key_param } => {
            let getter_name = format_ident!("sload_{}", field.name);
            let (key, ty) = (format_ident!("{}", key_param), &func.params[0].1);
            if gen_sig {
                quote! { fn #getter_name(&mut self, #key: #ty) -> crate::error::Result<#return_type>; }
            } else {
                quote! {
                    fn #getter_name(&mut self, #key: #ty) -> crate::error::Result<#return_type> {
                        self.#getter_name(#key).map(|v| v.into())
                    }
                }
            }
        }
        GetterInfo::NestedMapping {
            field,
            key1_param,
            key2_param,
        } => {
            let getter_name = format_ident!("sload_{}", field.name);
            let (key1, ty1) = (format_ident!("{}", key1_param), &func.params[0].1);
            let (key2, ty2) = (format_ident!("{}", key2_param), &func.params[1].1);
            if gen_sig {
                quote! { fn #getter_name(&mut self, #key1: #ty1, #key2: #ty2) -> crate::error::Result<#return_type>; }
            } else {
                quote! {
                    fn #getter_name(&mut self, #key1: #ty1, #key2: #ty2) -> crate::error::Result<#return_type> {
                        self.#getter_name(#key1, #key2).map(|v| v.into())
                    }
                }
            }
        }
        GetterInfo::NoMatch => unreachable!("`GetterInfo::NoMatch` should be filtered out"),
    }
}

/// Generates the function signature string for a method.
fn gen_method_signature(func: &InterfaceFunction) -> String {
    let return_type = &func.return_type;

    let params_str = if func.is_view {
        func.params
            .iter()
            .map(|(param_name, ty)| format!("{}: {}", param_name.rust, quote!(#ty)))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        // State-changing functions have msg_sender as first param
        let mut params = vec!["msg_sender: Address".to_string()];
        params.extend(
            func.params
                .iter()
                .map(|(param_name, ty)| format!("{}: {}", param_name.rust, quote!(#ty))),
        );
        params.join(", ")
    };

    format!(
        "fn {}(&mut self, {}) -> Result<{}>",
        func.name,
        params_str,
        quote!(#return_type)
    )
}

/// Generates doc comment for a call trait method showing the function signature.
fn gen_method_doc_comment(func: &InterfaceFunction, is_auto_implemented: bool) -> TokenStream {
    let sig = gen_method_signature(func);
    let auto_impl_note = if is_auto_implemented {
        "\n///\n/// **Auto-implemented** - default implementation provided for getters."
    } else {
        ""
    };
    let doc = format!("```rust,ignore\n{sig}\n```{auto_impl_note}");

    quote! { #[doc = #doc] }
}

/// Generates a call method defined in the contract's interface.
fn gen_call_trait_method(result: &GetterFn<'_>) -> TokenStream {
    if let GetterInfo::NoMatch = &result.field_match {
        return gen_call_sig(result);
    }

    let func = &result.function;
    let doc_comment = gen_method_doc_comment(func, true); // true = auto-implemented
    let method_name = format_ident!("{}", func.name);
    let return_type = &func.return_type;
    let has_params = !func.params.is_empty();

    // Extract individual parameters using Rust-style (snake_case) names
    let params = func.params.iter().map(|(param_name, ty)| {
        let ident = format_ident!("{}", param_name.rust);
        quote! { #ident: #ty }
    });

    // Generate default impl for getter methods
    let body = gen_default_getter(result);
    match func.is_view {
        true if has_params => quote! {
            #doc_comment
            fn #method_name(&mut self, #(#params),*) -> crate::error::Result<#return_type> {
                #body
            }
        },
        true => quote! {
            #doc_comment
            fn #method_name(&mut self) -> crate::error::Result<#return_type> {
                #body
            }
        },
        false if has_params => quote! {
            #doc_comment
            fn #method_name(&mut self, msg_sender: ::alloy::primitives::Address, #(#params),*) -> crate::error::Result<#return_type> {
                #body
            }
        },
        false => quote! {
            #doc_comment
            fn #method_name(&mut self, msg_sender: ::alloy::primitives::Address) -> crate::error::Result<#return_type> {
                #body
            }
        },
    }
}

/// Generates the default method body that calls storage operations.
fn gen_default_getter(result: &GetterFn<'_>) -> TokenStream {
    match &result.field_match {
        GetterInfo::Direct { field } => {
            let getter_name = format_ident!("sload_{}", field.name);
            quote! { self.#getter_name() }
        }
        GetterInfo::Mapping { field, key_param } => {
            let getter_name = format_ident!("sload_{}", field.name);
            let key_field = format_ident!("{}", key_param);
            quote! { self.#getter_name(#key_field) }
        }
        GetterInfo::NestedMapping {
            field,
            key1_param,
            key2_param,
        } => {
            let getter_name = format_ident!("sload_{}", field.name);
            let key1_field = format_ident!("{}", key1_param);
            let key2_field = format_ident!("{}", key2_param);
            quote! { self.#getter_name(#key1_field, #key2_field) }
        }
        GetterInfo::NoMatch => unreachable!("NoMatch should not generate default body"),
    }
}

/// Generates a trait method signature (no implementation).
fn gen_call_sig(result: &GetterFn<'_>) -> TokenStream {
    let func = &result.function;
    let doc_comment = gen_method_doc_comment(func, false);
    let method_name = format_ident!("{}", func.name);
    let return_type = &func.return_type;
    let has_params = !func.params.is_empty();

    // Extract individual parameters using Rust-style (snake_case) names
    let params = func.params.iter().map(|(param_name, ty)| {
        let ident = format_ident!("{}", param_name.rust);
        quote! { #ident: #ty }
    });

    match func.is_view {
        true if has_params => quote! {
            #doc_comment
            fn #method_name(&mut self, #(#params),*) -> crate::error::Result<#return_type>;
        },
        true => quote! {
            #doc_comment
            fn #method_name(&mut self) -> crate::error::Result<#return_type>;
        },
        false if has_params => quote! {
            #doc_comment
            fn #method_name(&mut self, msg_sender: ::alloy::primitives::Address, #(#params),*) -> crate::error::Result<#return_type>;
        },
        false => quote! {
            #doc_comment
            fn #method_name(&mut self, msg_sender: ::alloy::primitives::Address) -> crate::error::Result<#return_type>;
        },
    }
}

#[cfg(test)]
mod tests_match {

    use super::*;
    use crate::utils::extract_attributes;
    use syn::{Attribute, Type, parse_quote};

    fn create_field(name: &str, ty: Type, attrs: Vec<Attribute>) -> FieldInfo {
        let (slot, base_slot, slot_count, map) =
            extract_attributes(&attrs).expect("invalid attribute");
        let field_name = syn::Ident::new(name, proc_macro2::Span::call_site());
        FieldInfo {
            name: field_name,
            ty,
            slot,
            base_slot,
            slot_count,
            map,
            effective_name: std::cell::OnceCell::new(),
        }
    }

    fn create_function(name: &'static str, params: Vec<(&'static str, Type)>) -> InterfaceFunction {
        use crate::interface::ParamName;
        InterfaceFunction {
            name,
            params: params
                .into_iter()
                .map(|(name, ty)| (ParamName::new(name), ty))
                .collect(),
            return_type: parse_quote!(U256),
            is_view: true,
            gas: None,
            call_type_path: quote::quote!(ITIP20::testCall),
        }
    }

    #[test]
    fn test_direct_field_getter() {
        let func = InterfaceFunction {
            name: "name",
            params: vec![],
            return_type: parse_quote!(String),
            is_view: true,
            gas: None,
            call_type_path: quote::quote!(ITIP20::nameCall),
        };
        let fields = vec![create_field("name", parse_quote!(String), vec![])];

        let field_match = find_field_getter(&func, &fields);
        match field_match {
            GetterInfo::Direct { field } => {
                assert_eq!(field.name, "name");
            }
            _ => panic!("Expected Direct match"),
        }
    }

    #[test]
    fn test_single_mapping_getter() {
        let func = create_function("balance_of", vec![("account", parse_quote!(Address))]);
        let fields = vec![create_field(
            "balances",
            parse_quote!(Mapping<Address, U256>),
            vec![parse_quote!(#[map = "balance_of"])],
        )];

        let field_match = find_field_getter(&func, &fields);
        match field_match {
            GetterInfo::Mapping { field, key_param } => {
                assert_eq!(field.name, "balances");
                assert_eq!(key_param, "account");
            }
            _ => panic!("Expected Mapping match, got {field_match:?}"),
        }
    }

    #[test]
    fn test_nested_mapping_getter() {
        let func = create_function(
            "allowance",
            vec![
                ("owner", parse_quote!(Address)),
                ("spender", parse_quote!(Address)),
            ],
        );
        let fields = vec![create_field(
            "allowances",
            parse_quote!(Mapping<Address, Mapping<Address, U256>>),
            vec![parse_quote!(#[map = "allowance"])], // Add map attribute for name match
        )];

        let field_match = find_field_getter(&func, &fields);
        match field_match {
            GetterInfo::NestedMapping {
                field,
                key1_param,
                key2_param,
            } => {
                assert_eq!(field.name, "allowances");
                assert_eq!(key1_param, "owner");
                assert_eq!(key2_param, "spender");
            }
            _ => panic!("Expected NestedMapping match, got {field_match:?}"),
        }
    }

    #[test]
    fn test_no_match() {
        let func = create_function("transfer", vec![("to", parse_quote!(Address))]);
        let fields = vec![create_field("name", parse_quote!(String), vec![])];

        let field_match = find_field_getter(&func, &fields);
        assert!(matches!(field_match, GetterInfo::NoMatch));
    }

    #[test]
    fn test_map_attribute_camel_case() {
        let func = create_function("balance_of", vec![("account", parse_quote!(Address))]);
        let fields = vec![create_field(
            "balances",
            parse_quote!(Mapping<Address, U256>),
            vec![parse_quote!(#[map = "balanceOf"])],
        )];

        let field_match = find_field_getter(&func, &fields);
        match field_match {
            GetterInfo::Mapping { field, .. } => {
                assert_eq!(field.name, "balances");
            }
            _ => panic!("Expected Mapping match with CamelCase map attribute"),
        }
    }

    #[test]
    fn test_direct_field_type_mismatch() {
        let func = InterfaceFunction {
            name: "name",
            params: vec![],
            return_type: parse_quote!(U256), // Wrong return type
            is_view: true,
            gas: None,
            call_type_path: quote::quote!(ITIP20::nameCall),
        };
        let fields = vec![create_field("name", parse_quote!(String), vec![])];

        let field_match = find_field_getter(&func, &fields);
        assert!(
            matches!(field_match, GetterInfo::NoMatch),
            "Expected NoMatch due to return type mismatch"
        );
    }

    #[test]
    fn test_mapping_type_mismatch() {
        // key mismatch
        let func = create_function("balance_of", vec![("account", parse_quote!(U256))]);
        let fields = vec![create_field(
            "balances",
            parse_quote!(Mapping<Address, U256>),
            vec![parse_quote!(#[map = "balance_of"])],
        )];

        let field_match = find_field_getter(&func, &fields);
        assert!(
            matches!(field_match, GetterInfo::NoMatch),
            "Expected NoMatch due to key type mismatch (U256 vs Address)"
        );

        // return mismatch
        use crate::interface::ParamName;
        let func = InterfaceFunction {
            name: "balance_of",
            params: vec![(ParamName::new("account"), parse_quote!(Address))],
            return_type: parse_quote!(bool), // Wrong return type
            is_view: true,
            gas: None,
            call_type_path: quote::quote!(ITIP20::balanceOfCall),
        };
        let fields = vec![create_field(
            "balances",
            parse_quote!(Mapping<Address, U256>),
            vec![parse_quote!(#[map = "balance_of"])],
        )];

        let field_match = find_field_getter(&func, &fields);
        assert!(
            matches!(field_match, GetterInfo::NoMatch),
            "Expected NoMatch due to return type mismatch (bool vs U256)"
        );
    }

    #[test]
    fn test_nested_mapping_type_mismatch() {
        use crate::interface::ParamName;
        // key1 mismatch
        let func = InterfaceFunction {
            name: "allowance",
            params: vec![
                (ParamName::new("owner"), parse_quote!(U256)), // Wrong type
                (ParamName::new("spender"), parse_quote!(Address)),
            ],
            return_type: parse_quote!(U256),
            is_view: true,
            gas: None,
            call_type_path: quote::quote!(ITIP20::allowanceCall),
        };
        let fields = vec![create_field(
            "allowances",
            parse_quote!(Mapping<Address, Mapping<Address, U256>>),
            vec![parse_quote!(#[map = "allowance"])],
        )];

        let field_match = find_field_getter(&func, &fields);
        assert!(
            matches!(field_match, GetterInfo::NoMatch),
            "Expected NoMatch due to first key type mismatch"
        );

        // key2 mismatch
        let func = InterfaceFunction {
            name: "allowance",
            params: vec![
                (ParamName::new("owner"), parse_quote!(Address)),
                (ParamName::new("spender"), parse_quote!(U256)), // Wrong type
            ],
            return_type: parse_quote!(U256),
            is_view: true,
            gas: None,
            call_type_path: quote::quote!(ITIP20::allowanceCall),
        };
        let fields = vec![create_field(
            "allowances",
            parse_quote!(Mapping<Address, Mapping<Address, U256>>),
            vec![parse_quote!(#[map = "allowance"])],
        )];

        let field_match = find_field_getter(&func, &fields);
        assert!(
            matches!(field_match, GetterInfo::NoMatch),
            "Expected NoMatch due to second key type mismatch"
        );

        // return mismatch
        let func = InterfaceFunction {
            name: "allowance",
            params: vec![
                (ParamName::new("owner"), parse_quote!(Address)),
                (ParamName::new("spender"), parse_quote!(Address)),
            ],
            return_type: parse_quote!(bool), // Wrong return type
            is_view: true,
            gas: None,
            call_type_path: quote::quote!(ITIP20::allowanceCall),
        };
        let fields = vec![create_field(
            "allowances",
            parse_quote!(Mapping<Address, Mapping<Address, U256>>),
            vec![parse_quote!(#[map = "allowance"])],
        )];

        let field_match = find_field_getter(&func, &fields);
        assert!(
            matches!(field_match, GetterInfo::NoMatch),
            "Expected NoMatch due to return type mismatch (bool vs U256)"
        );
    }
}

#[cfg(test)]
mod tests_trait {
    use super::*;
    use crate::{FieldInfo, interface::InterfaceFunction};
    use syn::parse_quote;

    #[test]
    fn test_generate_trait_with_direct_match() {
        let struct_name: Ident = parse_quote!(TIP20Token);
        let interface_ident: Ident = parse_quote!(ITIP20);

        let func = InterfaceFunction {
            name: "name",
            params: vec![],
            return_type: parse_quote!(String),
            is_view: true,
            gas: None,
            call_type_path: quote!(ITIP20::nameCall),
        };

        let field = FieldInfo {
            name: parse_quote!(name),
            ty: parse_quote!(String),
            slot: None,
            base_slot: None,
            slot_count: None,
            map: None,
            effective_name: std::cell::OnceCell::new(),
        };

        let interface = crate::interface::Interface {
            functions: vec![func],
            events: vec![],
            errors: vec![],
        };

        let interface_data = vec![(interface_ident, interface)];

        let trait_code = gen_traits_and_impls(&struct_name, &interface_data, &[field]);
        let trait_str = trait_code.to_string();

        assert!(trait_str.contains("trait _TIP20TokenStorage"));
        // Single interface uses simpler naming
        assert!(trait_str.contains("trait TIP20TokenCall"));
        assert!(trait_str.contains("fn name"));
        assert!(trait_str.contains("impl"));
        assert!(trait_str.contains("sload_name"));
    }

    #[test]
    fn test_generate_trait_with_no_match() {
        let struct_name: Ident = parse_quote!(TIP20Token);
        let interface_ident: Ident = parse_quote!(ITIP20);

        let func = InterfaceFunction {
            name: "transfer",
            params: vec![],
            return_type: parse_quote!(bool),
            is_view: false,
            gas: None,
            call_type_path: quote!(ITIP20::transferCall),
        };

        let interface = crate::interface::Interface {
            functions: vec![func],
            events: vec![],
            errors: vec![],
        };

        let interface_data = vec![(interface_ident, interface)];

        let trait_code = gen_traits_and_impls(&struct_name, &interface_data, &[]);
        let trait_str = trait_code.to_string();

        assert!(trait_str.contains("fn transfer"));
        assert!(!trait_str.contains("unimplemented"),);
    }
}
