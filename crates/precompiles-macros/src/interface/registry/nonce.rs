use crate::{
    Type,
    interface::{InterfaceError, InterfaceEvent, InterfaceFunction},
};
use quote::quote;
use syn::parse_quote;

pub(crate) fn get_functions(interface_type: &Type) -> Vec<InterfaceFunction> {
    vec![
        InterfaceFunction {
            name: "get_nonce",
            params: vec![
                ("account", parse_quote!(Address)),
                ("nonce_key", parse_quote!(U256)),
            ],
            return_type: parse_quote!(u64),
            is_view: true,
            call_type_path: quote!(#interface_type::getNonceCall),
        },
        InterfaceFunction {
            name: "get_active_nonce_key_count",
            params: vec![("account", parse_quote!(Address))],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::getActiveNonceKeyCountCall),
        },
    ]
}

pub(crate) fn get_events(interface_type: &Type) -> Vec<InterfaceEvent> {
    vec![
        InterfaceEvent {
            name: "nonce_incremented",
            params: vec![
                ("account", parse_quote!(Address), true),
                ("nonce_key", parse_quote!(U256), true),
                ("new_nonce", parse_quote!(u64), false),
            ],
            event_type_path: quote!(#interface_type::NonceIncremented),
        },
        InterfaceEvent {
            name: "active_key_count_changed",
            params: vec![
                ("account", parse_quote!(Address), true),
                ("new_count", parse_quote!(U256), false),
            ],
            event_type_path: quote!(#interface_type::ActiveKeyCountChanged),
        },
    ]
}

pub(crate) fn get_errors(interface_type: &Type) -> Vec<InterfaceError> {
    vec![
        InterfaceError {
            name: "protocol_nonce_not_supported",
            params: vec![],
            error_type_path: quote!(#interface_type::ProtocolNonceNotSupported),
        },
        InterfaceError {
            name: "invalid_nonce_key",
            params: vec![],
            error_type_path: quote!(#interface_type::InvalidNonceKey),
        },
        InterfaceError {
            name: "nonce_overflow",
            params: vec![],
            error_type_path: quote!(#interface_type::NonceOverflow),
        },
    ]
}
