use crate::{
    Type,
    interface::{InterfaceError, InterfaceEvent, InterfaceFunction},
};
use quote::quote;
use syn::parse_quote;

pub(crate) fn get_functions(interface_type: &Type) -> Vec<InterfaceFunction> {
    vec![
        // View functions
        InterfaceFunction {
            name: "policy_id_counter",
            params: vec![],
            return_type: parse_quote!(u64),
            is_view: true,
            call_type_path: quote!(#interface_type::policyIdCounterCall),
        },
        InterfaceFunction {
            name: "policy_data",
            params: vec![("policy_id", parse_quote!(u64))],
            return_type: parse_quote!((#interface_type::PolicyType, Address)),
            is_view: true,
            call_type_path: quote!(#interface_type::policyDataCall),
        },
        InterfaceFunction {
            name: "is_authorized",
            params: vec![
                ("policy_id", parse_quote!(u64)),
                ("user", parse_quote!(Address)),
            ],
            return_type: parse_quote!(bool),
            is_view: true,
            call_type_path: quote!(#interface_type::isAuthorizedCall),
        },
        // State-changing functions (non-void returns)
        InterfaceFunction {
            name: "create_policy",
            params: vec![
                ("admin", parse_quote!(Address)),
                ("policy_type", parse_quote!(#interface_type::PolicyType)),
            ],
            return_type: parse_quote!(u64),
            is_view: false,
            call_type_path: quote!(#interface_type::createPolicyCall),
        },
        InterfaceFunction {
            name: "create_policy_with_accounts",
            params: vec![
                ("admin", parse_quote!(Address)),
                ("policy_type", parse_quote!(#interface_type::PolicyType)),
                ("accounts", parse_quote!(Vec<Address>)),
            ],
            return_type: parse_quote!(u64),
            is_view: false,
            call_type_path: quote!(#interface_type::createPolicyWithAccountsCall),
        },
        // State-changing functions (void)
        InterfaceFunction {
            name: "set_policy_admin",
            params: vec![
                ("policy_id", parse_quote!(u64)),
                ("admin", parse_quote!(Address)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::setPolicyAdminCall),
        },
        InterfaceFunction {
            name: "modify_policy_whitelist",
            params: vec![
                ("policy_id", parse_quote!(u64)),
                ("account", parse_quote!(Address)),
                ("allowed", parse_quote!(bool)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::modifyPolicyWhitelistCall),
        },
        InterfaceFunction {
            name: "modify_policy_blacklist",
            params: vec![
                ("policy_id", parse_quote!(u64)),
                ("account", parse_quote!(Address)),
                ("restricted", parse_quote!(bool)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::modifyPolicyBlacklistCall),
        },
    ]
}

pub(crate) fn get_events(interface_type: &Type) -> Vec<InterfaceEvent> {
    vec![
        InterfaceEvent {
            name: "policy_admin_updated",
            params: vec![
                ("policy_id", parse_quote!(u64), true),
                ("updater", parse_quote!(Address), true),
                ("admin", parse_quote!(Address), true),
            ],
            event_type_path: quote!(#interface_type::PolicyAdminUpdated),
        },
        InterfaceEvent {
            name: "policy_created",
            params: vec![
                ("policy_id", parse_quote!(u64), true),
                ("updater", parse_quote!(Address), true),
                (
                    "policy_type",
                    parse_quote!(#interface_type::PolicyType),
                    false,
                ),
            ],
            event_type_path: quote!(#interface_type::PolicyCreated),
        },
        InterfaceEvent {
            name: "whitelist_updated",
            params: vec![
                ("policy_id", parse_quote!(u64), true),
                ("updater", parse_quote!(Address), true),
                ("account", parse_quote!(Address), true),
                ("allowed", parse_quote!(bool), false),
            ],
            event_type_path: quote!(#interface_type::WhitelistUpdated),
        },
        InterfaceEvent {
            name: "blacklist_updated",
            params: vec![
                ("policy_id", parse_quote!(u64), true),
                ("updater", parse_quote!(Address), true),
                ("account", parse_quote!(Address), true),
                ("restricted", parse_quote!(bool), false),
            ],
            event_type_path: quote!(#interface_type::BlacklistUpdated),
        },
    ]
}

pub(crate) fn get_errors(interface_type: &Type) -> Vec<InterfaceError> {
    vec![
        InterfaceError {
            name: "unauthorized",
            params: vec![],
            error_type_path: quote!(#interface_type::Unauthorized),
        },
        InterfaceError {
            name: "incompatible_policy_type",
            params: vec![],
            error_type_path: quote!(#interface_type::IncompatiblePolicyType),
        },
        InterfaceError {
            name: "self_owned_policy_must_be_whitelist",
            params: vec![],
            error_type_path: quote!(#interface_type::SelfOwnedPolicyMustBeWhitelist),
        },
    ]
}
