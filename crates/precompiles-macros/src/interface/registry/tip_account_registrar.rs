use crate::{
    Type,
    interface::{InterfaceError, InterfaceEvent, InterfaceFunction},
};
use quote::quote;
use syn::parse_quote;

pub(crate) fn get_functions(interface_type: &Type) -> Vec<InterfaceFunction> {
    vec![
        InterfaceFunction {
            name: "delegate_to_default",
            params: vec![
                ("hash", parse_quote!(B256)),
                ("signature", parse_quote!(Bytes)),
            ],
            return_type: parse_quote!(Address),
            is_view: false,
            call_type_path: quote!(#interface_type::delegateToDefaultCall),
        },
        InterfaceFunction {
            name: "get_delegation_message",
            params: vec![],
            return_type: parse_quote!(String),
            is_view: true,
            call_type_path: quote!(#interface_type::getDelegationMessageCall),
        },
    ]
}

pub(crate) fn get_events(_interface_type: &Type) -> Vec<InterfaceEvent> {
    vec![]
}

pub(crate) fn get_errors(interface_type: &Type) -> Vec<InterfaceError> {
    vec![
        InterfaceError {
            name: "invalid_signature",
            params: vec![],
            error_type_path: quote!(#interface_type::InvalidSignature),
        },
        InterfaceError {
            name: "code_not_empty",
            params: vec![],
            error_type_path: quote!(#interface_type::CodeNotEmpty),
        },
        InterfaceError {
            name: "nonce_not_zero",
            params: vec![],
            error_type_path: quote!(#interface_type::NonceNotZero),
        },
    ]
}
