//! Trait generation for contract macro.
//!
//! This module generates custom traits, with a default implementation for getter functions,
//! that allow for easy call interactions with the contract.

use crate::{FieldInfo, interface::InterfaceFunction, utils::extract_mapping_types};
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

// TODO(rusowsky): match based on actual param types, not just on compatibility based on number of fields
/// Matches a function to a field based on type compatibility.
fn match_by_type<'a>(func: &'a InterfaceFunction, field: &'a FieldInfo) -> GetterInfo<'a> {
    match (func.params.len(), extract_mapping_types(&field.ty)) {
        (0, None) => GetterInfo::Direct { field },
        (1, Some((_, value))) if extract_mapping_types(value).is_none() => GetterInfo::Mapping {
            field,
            key_param: func.params[0].0,
        },
        (2, Some((_, value))) if extract_mapping_types(value).is_some() => {
            GetterInfo::NestedMapping {
                field,
                key1_param: func.params[0].0,
                key2_param: func.params[1].0,
            }
        }
        _ => GetterInfo::NoMatch,
    }
}

/// Generates storage trait, storage impl, and interface trait with default methods.
pub(crate) fn gen_trait_and_impl<'a>(
    ident: &Ident,
    _interface_types: &[Type],
    match_results: &[GetterFn<'a>],
) -> TokenStream {
    let s_name = format_ident!("_{}Storage", ident);
    let c_name = format_ident!("{}Call", ident);

    let storage_trait = gen_storage_trait(&s_name, match_results);
    let storage_impl = gen_storage_impl(ident, &s_name, match_results);
    let call_trait = gen_call_trait(&c_name, &s_name, match_results);

    quote! {
        #storage_trait
        #storage_impl
        #call_trait
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
            let getter_name = format_ident!("_get_{}", field.name);
            if gen_sig {
                quote! { fn #getter_name(&mut self) -> crate::error::Result<#return_type>; }
            } else {
                quote! {
                    fn #getter_name(&mut self) -> crate::error::Result<#return_type> {
                        self.#getter_name()
                    }
                }
            }
        }
        GetterInfo::Mapping { field, key_param } => {
            let getter_name = format_ident!("_get_{}", field.name);
            let (key, ty) = (format_ident!("{}", key_param), &func.params[0].1);
            if gen_sig {
                quote! { fn #getter_name(&mut self, #key: #ty) -> crate::error::Result<#return_type>; }
            } else {
                quote! {
                    fn #getter_name(&mut self, #key: #ty) -> crate::error::Result<#return_type> {
                        self.#getter_name(#key)
                    }
                }
            }
        }
        GetterInfo::NestedMapping {
            field,
            key1_param,
            key2_param,
        } => {
            let getter_name = format_ident!("_get_{}", field.name);
            let (key1, ty1) = (format_ident!("{}", key1_param), &func.params[0].1);
            let (key2, ty2) = (format_ident!("{}", key2_param), &func.params[1].1);
            if gen_sig {
                quote! { fn #getter_name(&mut self, #key1: #ty1, #key2: #ty2) -> crate::error::Result<#return_type>; }
            } else {
                quote! {
                    fn #getter_name(&mut self, #key1: #ty1, #key2: #ty2) -> crate::error::Result<#return_type> {
                        self.#getter_name(#key1, #key2)
                    }
                }
            }
        }
        GetterInfo::NoMatch => unreachable!("`GetterInfo::NoMatch` should be filtered out"),
    }
}

/// Generates the call trait with default implementations for getter methods.
fn gen_call_trait(
    trait_name: &Ident,
    storage_trait_name: &Ident,
    match_results: &[GetterFn<'_>],
) -> TokenStream {
    let interface_methods: Vec<TokenStream> = match_results
        .iter()
        .map(|result| gen_call_trait_method(result))
        .collect();

    quote! {
        /// Auto-generated trait for contract call implementation.
        ///
        /// Getter methods have default implementations.
        pub trait #trait_name: #storage_trait_name {
            #(#interface_methods)*
        }
    }
}

// TODO(rusowsky): flatten call so that we users can pass params directly.
/// Generates a call method defined in the contract's interface.
fn gen_call_trait_method(result: &GetterFn<'_>) -> TokenStream {
    if let GetterInfo::NoMatch = &result.field_match {
        return gen_call_sig(result);
    }

    let func = &result.function;
    let method_name = format_ident!("{}", func.name);
    let return_type = &func.return_type;
    let call_type = &func.call_type_path;
    let has_params = !func.params.is_empty();

    // Generate default impl for getter methods
    let body = gen_default_getter(result);
    match func.is_view {
        true if has_params => quote! {
            fn #method_name(&mut self, call: #call_type) -> crate::error::Result<#return_type> {
                #body
            }
        },
        true => quote! {
            fn #method_name(&mut self) -> crate::error::Result<#return_type> {
                #body
            }
        },
        false if has_params => quote! {
            fn #method_name(&mut self, msg_sender: &::alloy::primitives::Address, call: #call_type) -> crate::error::Result<#return_type> {
                #body
            }
        },
        false => quote! {
            fn #method_name(&mut self, msg_sender: &::alloy::primitives::Address) -> crate::error::Result<#return_type> {
                #body
            }
        },
    }
}

/// Generates the default method body that calls storage operations.
fn gen_default_getter(result: &GetterFn<'_>) -> TokenStream {
    match &result.field_match {
        GetterInfo::Direct { field } => {
            let getter_name = format_ident!("_get_{}", field.name);
            quote! { self.#getter_name() }
        }
        GetterInfo::Mapping { field, key_param } => {
            let getter_name = format_ident!("_get_{}", field.name);
            let key_field = format_ident!("{}", key_param);
            quote! { self.#getter_name(call.#key_field) }
        }
        GetterInfo::NestedMapping {
            field,
            key1_param,
            key2_param,
        } => {
            let getter_name = format_ident!("_get_{}", field.name);
            let key1_field = format_ident!("{}", key1_param);
            let key2_field = format_ident!("{}", key2_param);
            quote! { self.#getter_name(call.#key1_field, call.#key2_field) }
        }
        GetterInfo::NoMatch => unreachable!("NoMatch should not generate default body"),
    }
}

/// Generates a trait method signature (no implementation).
fn gen_call_sig(result: &GetterFn<'_>) -> TokenStream {
    let func = &result.function;
    let method_name = format_ident!("{}", func.name);
    let return_type = &func.return_type;
    let call_type = &func.call_type_path;
    let has_params = !func.params.is_empty();

    match func.is_view {
        true if has_params => quote! {
            fn #method_name(&mut self, call: #call_type) -> crate::error::Result<#return_type>;
        },
        true => quote! {
            fn #method_name(&mut self) -> crate::error::Result<#return_type>;
        },
        false if has_params => quote! {
            fn #method_name(&mut self, msg_sender: ::alloy::primitives::Address, call: #call_type) -> crate::error::Result<#return_type>;
        },
        false => quote! {
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
        let (slot, map) = extract_attributes(&attrs).expect("invalid attribute");
        let field_name = syn::Ident::new(name, proc_macro2::Span::call_site());
        FieldInfo {
            name: field_name,
            ty,
            slot,
            map,
            effective_name: std::cell::OnceCell::new(),
        }
    }

    fn create_function(name: &'static str, params: Vec<(&'static str, Type)>) -> InterfaceFunction {
        InterfaceFunction {
            name,
            params,
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote::quote!(ITIP20::testCall),
        }
    }

    #[test]
    fn test_direct_field_getter() {
        let func = create_function("name", vec![]);
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
}

#[cfg(test)]
mod tests_trait {
    use super::*;
    use crate::{FieldInfo, interface::InterfaceFunction};
    use syn::parse_quote;

    fn create_match_result<'a>(
        function: &'a InterfaceFunction,
        field_match: GetterInfo<'a>,
    ) -> GetterFn<'a> {
        GetterFn {
            function,
            field_match,
        }
    }

    #[test]
    fn test_generate_trait_with_direct_match() {
        let struct_name: Ident = parse_quote!(TIP20Token);
        let interface_type: Type = parse_quote!(ITIP20);

        let func = InterfaceFunction {
            name: "name",
            params: vec![],
            return_type: parse_quote!(String),
            is_view: true,
            call_type_path: quote!(ITIP20::nameCall),
        };

        let field = FieldInfo {
            name: parse_quote!(name),
            ty: parse_quote!(String),
            slot: None,
            map: None,
            effective_name: std::cell::OnceCell::new(),
        };

        let matches = vec![create_match_result(
            &func,
            GetterInfo::Direct { field: &field },
        )];

        let trait_code = gen_trait_and_impl(&struct_name, &interface_type, &matches);
        let trait_str = trait_code.to_string();

        assert!(trait_str.contains("trait _TIP20TokenStorage"));
        assert!(trait_str.contains("trait TIP20TokenCall"));
        assert!(trait_str.contains("fn name"));
        assert!(trait_str.contains("impl"));
        assert!(trait_str.contains("_get_name"));
    }

    #[test]
    fn test_generate_trait_with_no_match() {
        let struct_name: Ident = parse_quote!(TIP20Token);
        let interface_type: Type = parse_quote!(ITIP20);

        let func = InterfaceFunction {
            name: "transfer",
            params: vec![],
            return_type: parse_quote!(bool),
            is_view: false,
            call_type_path: quote!(ITIP20::transferCall),
        };

        let matches = vec![create_match_result(&func, GetterInfo::NoMatch)];

        let trait_code = gen_trait_and_impl(&struct_name, &interface_type, &matches);
        let trait_str = trait_code.to_string();

        assert!(trait_str.contains("fn transfer"));
        assert!(!trait_str.contains("unimplemented"),);
    }
}
