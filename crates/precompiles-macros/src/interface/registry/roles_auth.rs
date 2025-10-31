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
            name: "has_role",
            params: vec![
                ("account", parse_quote!(Address)),
                ("role", parse_quote!(B256)),
            ],
            return_type: parse_quote!(bool),
            is_view: true,
            call_type_path: quote!(#interface_type::hasRoleCall),
        },
        InterfaceFunction {
            name: "get_role_admin",
            params: vec![("role", parse_quote!(B256))],
            return_type: parse_quote!(B256),
            is_view: true,
            call_type_path: quote!(#interface_type::getRoleAdminCall),
        },
        // Mutating functions (void)
        InterfaceFunction {
            name: "grant_role",
            params: vec![
                ("role", parse_quote!(B256)),
                ("account", parse_quote!(Address)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::grantRoleCall),
        },
        InterfaceFunction {
            name: "revoke_role",
            params: vec![
                ("role", parse_quote!(B256)),
                ("account", parse_quote!(Address)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::revokeRoleCall),
        },
        InterfaceFunction {
            name: "renounce_role",
            params: vec![("role", parse_quote!(B256))],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::renounceRoleCall),
        },
        InterfaceFunction {
            name: "set_role_admin",
            params: vec![
                ("role", parse_quote!(B256)),
                ("admin_role", parse_quote!(B256)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::setRoleAdminCall),
        },
    ]
}

pub(crate) fn get_events(interface_type: &Type) -> Vec<InterfaceEvent> {
    vec![
        InterfaceEvent {
            name: "role_membership_updated",
            params: vec![
                ("role", parse_quote!(B256), true),
                ("account", parse_quote!(Address), true),
                ("sender", parse_quote!(Address), true),
                ("has_role", parse_quote!(bool), false),
            ],
            event_type_path: quote!(#interface_type::RoleMembershipUpdated),
        },
        InterfaceEvent {
            name: "role_admin_updated",
            params: vec![
                ("role", parse_quote!(B256), true),
                ("new_admin_role", parse_quote!(B256), true),
                ("sender", parse_quote!(Address), true),
            ],
            event_type_path: quote!(#interface_type::RoleAdminUpdated),
        },
    ]
}

pub(crate) fn get_errors(interface_type: &Type) -> Vec<InterfaceError> {
    vec![InterfaceError {
        name: "unauthorized",
        params: vec![],
        error_type_path: quote!(#interface_type::Unauthorized),
    }]
}
