//! Interface parsing and function extraction for contract macro.
//!
//! This module handles parsing the `#[contract(InterfaceName)]` attribute and
//! extracting interface function signatures for trait generation.

use crate::utils;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{Ident, Type};

/// Represents a single function from a sol! interface.
#[derive(Debug, Clone)]
pub(crate) struct InterfaceFunction {
    /// Function name, normalized to snake_case
    pub name: &'static str,
    /// Function parameters as (name, type) pairs
    pub params: Vec<(&'static str, Type)>,
    /// Return type of the function
    pub return_type: Type,
    /// Whether this is a view function
    pub is_view: bool,
    /// Path to the Call struct for this function
    pub call_type_path: TokenStream,
}

/// Classification of function types for dispatcher routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FunctionKind {
    /// View function with no parameters
    Metadata,
    /// View function with parameters
    View,
    /// Mutating function returning
    Mutate,
    /// Mutating function returning
    MutateVoid,
}

impl InterfaceFunction {
    pub(crate) fn kind(&self) -> FunctionKind {
        match self.is_view {
            true if self.params.is_empty() => FunctionKind::Metadata,
            true => FunctionKind::View,
            false if utils::is_unit(&self.return_type) => FunctionKind::MutateVoid,
            false => FunctionKind::Mutate,
        }
    }
}

// TODO(rusowsky): Implement automatic method discovery from sol! generated interfaces.
pub(crate) fn parse_interface(interface_type: &Type) -> syn::Result<Vec<InterfaceFunction>> {
    let interface_ident = extract_interface_ident(interface_type)?;
    get_interface_functions(&interface_ident, interface_type)
}

/// Extracts the identifier from an interface type path.
///
/// Handles simple paths like `ITIP20` and qualified paths like `crate::ITIP20`.
fn extract_interface_ident(ty: &Type) -> syn::Result<Ident> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        return Ok(segment.ident.clone());
    }
    Err(syn::Error::new_spanned(
        ty,
        "Interface type must be a simple path or qualified path",
    ))
}

// TODO(rusowsky): Implement automatic method discovery from sol! generated interfaces.
fn get_interface_functions(
    interface_ident: &Ident,
    interface_type: &Type,
) -> syn::Result<Vec<InterfaceFunction>> {
    let interface_name = interface_ident.to_string();
    match interface_name.as_str() {
        "ITIP20" => Ok(get_itip20_functions(interface_type)),
        "ITestToken" => Ok(get_itest_token_functions(interface_type)),
        "IMetadata" => Ok(get_imetadata_functions(interface_type)),
        _ => {
            eprintln!(
                "Warning: Interface '{interface_name}' not in registry. No trait methods will be generated."
            );
            Ok(Vec::new())
        }
    }
}

// TODO(rusowsky): Implement automatic method discovery from sol! generated interfaces.
fn get_itip20_functions(interface_type: &Type) -> Vec<InterfaceFunction> {
    use syn::parse_quote;

    vec![
        // Metadata functions (view, no parameters)
        InterfaceFunction {
            name: "name",
            params: vec![],
            return_type: parse_quote!(String),
            is_view: true,
            call_type_path: quote!(#interface_type::nameCall),
        },
        InterfaceFunction {
            name: "symbol",
            params: vec![],
            return_type: parse_quote!(String),
            is_view: true,
            call_type_path: quote!(#interface_type::symbolCall),
        },
        InterfaceFunction {
            name: "decimals",
            params: vec![],
            return_type: parse_quote!(u8),
            is_view: true,
            call_type_path: quote!(#interface_type::decimalsCall),
        },
        InterfaceFunction {
            name: "currency",
            params: vec![],
            return_type: parse_quote!(String),
            is_view: true,
            call_type_path: quote!(#interface_type::currencyCall),
        },
        InterfaceFunction {
            name: "total_supply",
            params: vec![],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::totalSupplyCall),
        },
        InterfaceFunction {
            name: "supply_cap",
            params: vec![],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::supplyCapCall),
        },
        InterfaceFunction {
            name: "transfer_policy_id",
            params: vec![],
            return_type: parse_quote!(u64),
            is_view: true,
            call_type_path: quote!(#interface_type::transferPolicyIdCall),
        },
        InterfaceFunction {
            name: "paused",
            params: vec![],
            return_type: parse_quote!(bool),
            is_view: true,
            call_type_path: quote!(#interface_type::pausedCall),
        },
        InterfaceFunction {
            name: "quote_token",
            params: vec![],
            return_type: parse_quote!(Address),
            is_view: true,
            call_type_path: quote!(#interface_type::quoteTokenCall),
        },
        InterfaceFunction {
            name: "next_quote_token",
            params: vec![],
            return_type: parse_quote!(Address),
            is_view: true,
            call_type_path: quote!(#interface_type::nextQuoteTokenCall),
        },
        // View functions with parameters
        InterfaceFunction {
            name: "balance_of",
            params: vec![("account", parse_quote!(Address))],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::balanceOfCall),
        },
        InterfaceFunction {
            name: "allowance",
            params: vec![
                ("owner", parse_quote!(Address)),
                ("spender", parse_quote!(Address)),
            ],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::allowanceCall),
        },
        // Mutating functions (non-void)
        InterfaceFunction {
            name: "transfer",
            params: vec![
                ("to", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
            ],
            return_type: parse_quote!(bool),
            is_view: false,
            call_type_path: quote!(#interface_type::transferCall),
        },
        InterfaceFunction {
            name: "transfer_from",
            params: vec![
                ("from", parse_quote!(Address)),
                ("to", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
            ],
            return_type: parse_quote!(bool),
            is_view: false,
            call_type_path: quote!(#interface_type::transferFromCall),
        },
        InterfaceFunction {
            name: "approve",
            params: vec![
                ("spender", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
            ],
            return_type: parse_quote!(bool),
            is_view: false,
            call_type_path: quote!(#interface_type::approveCall),
        },
        InterfaceFunction {
            name: "transfer_from_with_memo",
            params: vec![
                ("from", parse_quote!(Address)),
                ("to", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
                ("memo", parse_quote!(B256)),
            ],
            return_type: parse_quote!(bool),
            is_view: false,
            call_type_path: quote!(#interface_type::transferFromWithMemoCall),
        },
        // Mutating functions (void)
        InterfaceFunction {
            name: "mint",
            params: vec![
                ("to", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::mintCall),
        },
        InterfaceFunction {
            name: "burn",
            params: vec![("amount", parse_quote!(U256))],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::burnCall),
        },
        InterfaceFunction {
            name: "mint_with_memo",
            params: vec![
                ("to", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
                ("memo", parse_quote!(B256)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::mintWithMemoCall),
        },
        InterfaceFunction {
            name: "burn_with_memo",
            params: vec![("amount", parse_quote!(U256)), ("memo", parse_quote!(B256))],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::burnWithMemoCall),
        },
        InterfaceFunction {
            name: "burn_blocked",
            params: vec![
                ("from", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::burnBlockedCall),
        },
        InterfaceFunction {
            name: "transfer_with_memo",
            params: vec![
                ("to", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
                ("memo", parse_quote!(B256)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::transferWithMemoCall),
        },
        // Admin functions (void)
        InterfaceFunction {
            name: "change_transfer_policy_id",
            params: vec![("new_policy_id", parse_quote!(u64))],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::changeTransferPolicyIdCall),
        },
        InterfaceFunction {
            name: "set_supply_cap",
            params: vec![("new_supply_cap", parse_quote!(U256))],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::setSupplyCapCall),
        },
        InterfaceFunction {
            name: "pause",
            params: vec![],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::pauseCall),
        },
        InterfaceFunction {
            name: "unpause",
            params: vec![],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::unpauseCall),
        },
        InterfaceFunction {
            name: "update_quote_token",
            params: vec![("new_quote_token", parse_quote!(Address))],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::updateQuoteTokenCall),
        },
        InterfaceFunction {
            name: "finalize_quote_token_update",
            params: vec![],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::finalizeQuoteTokenUpdateCall),
        },
    ]
}

// Test interface for E2E dispatcher tests
fn get_itest_token_functions(interface_type: &Type) -> Vec<InterfaceFunction> {
    use syn::parse_quote;

    vec![
        // Metadata functions (view, no parameters)
        InterfaceFunction {
            name: "name",
            params: vec![],
            return_type: parse_quote!(String),
            is_view: true,
            call_type_path: quote!(#interface_type::nameCall),
        },
        InterfaceFunction {
            name: "symbol",
            params: vec![],
            return_type: parse_quote!(String),
            is_view: true,
            call_type_path: quote!(#interface_type::symbolCall),
        },
        InterfaceFunction {
            name: "decimals",
            params: vec![],
            return_type: parse_quote!(u8),
            is_view: true,
            call_type_path: quote!(#interface_type::decimalsCall),
        },
        // View functions (with parameters)
        InterfaceFunction {
            name: "balance_of",
            params: vec![("account", parse_quote!(Address))],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::balanceOfCall),
        },
        InterfaceFunction {
            name: "allowance",
            params: vec![
                ("owner", parse_quote!(Address)),
                ("spender", parse_quote!(Address)),
            ],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::allowanceCall),
        },
        // Mutating functions (non-void)
        InterfaceFunction {
            name: "transfer",
            params: vec![
                ("to", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
            ],
            return_type: parse_quote!(bool),
            is_view: false,
            call_type_path: quote!(#interface_type::transferCall),
        },
        InterfaceFunction {
            name: "approve",
            params: vec![
                ("spender", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
            ],
            return_type: parse_quote!(bool),
            is_view: false,
            call_type_path: quote!(#interface_type::approveCall),
        },
        // Mutating functions (void)
        InterfaceFunction {
            name: "mint",
            params: vec![
                ("to", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::mintCall),
        },
        InterfaceFunction {
            name: "burn",
            params: vec![("amount", parse_quote!(U256))],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::burnCall),
        },
    ]
}

// Test interface for multi-interface testing
fn get_imetadata_functions(interface_type: &Type) -> Vec<InterfaceFunction> {
    use syn::parse_quote;

    vec![
        InterfaceFunction {
            name: "version",
            params: vec![],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::versionCall),
        },
        InterfaceFunction {
            name: "owner",
            params: vec![],
            return_type: parse_quote!(Address),
            is_view: true,
            call_type_path: quote!(#interface_type::ownerCall),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_extract_interface_ident() {
        let ty: Type = parse_quote!(ITIP20);
        let ident = extract_interface_ident(&ty).unwrap();
        assert_eq!(ident.to_string(), "ITIP20");

        let ty: Type = parse_quote!(crate::ITIP20);
        let ident = extract_interface_ident(&ty).unwrap();
        assert_eq!(ident.to_string(), "ITIP20");
    }

    #[test]
    fn test_parse_interface_itip20() {
        let ty: Type = parse_quote!(ITIP20);
        let functions = parse_interface(&ty).unwrap();

        // Should have 28 functions
        assert_eq!(functions.len(), 28);

        // Check a few specific functions
        let name_fn = functions.iter().find(|f| f.name == "name");
        assert!(name_fn.is_some());
        assert!(name_fn.unwrap().is_view);
        assert!(name_fn.unwrap().params.is_empty());

        let balance_of_fn = functions.iter().find(|f| f.name == "balance_of");
        assert!(balance_of_fn.is_some());
        assert_eq!(balance_of_fn.unwrap().params.len(), 1);
    }

    #[test]
    fn test_parse_unknown_interface() {
        let ty: Type = parse_quote!(UnknownInterface);
        let functions = parse_interface(&ty).unwrap();

        // Should return empty vec for unknown interfaces
        assert!(functions.is_empty());
    }

    #[test]
    fn test_fn_kind() {
        let new_fn = |name: &'static str,
                      params: Vec<(&'static str, Type)>,
                      return_type: Type,
                      is_view: bool|
         -> InterfaceFunction {
            InterfaceFunction {
                name,
                params,
                return_type,
                is_view,
                call_type_path: quote::quote!(ITIP20::testCall),
            }
        };

        let func = new_fn("name", vec![], parse_quote!(String), true);
        assert_eq!(func.kind(), FunctionKind::Metadata);

        let func = new_fn(
            "balance_of",
            vec![("account", parse_quote!(Address))],
            parse_quote!(U256),
            true,
        );
        assert_eq!(func.kind(), FunctionKind::View);

        let func = new_fn(
            "transfer",
            vec![
                ("to", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
            ],
            parse_quote!(bool),
            false,
        );
        assert_eq!(func.kind(), FunctionKind::Mutate);

        let func = new_fn(
            "mint",
            vec![
                ("to", parse_quote!(Address)),
                ("amount", parse_quote!(U256)),
            ],
            parse_quote!(()),
            false,
        );
        assert_eq!(func.kind(), FunctionKind::MutateVoid);
    }
}
