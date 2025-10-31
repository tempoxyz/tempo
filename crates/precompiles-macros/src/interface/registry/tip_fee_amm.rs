use crate::{
    Type,
    interface::{InterfaceError, InterfaceEvent, InterfaceFunction},
};
use quote::quote;
use syn::parse_quote;

pub(crate) fn get_functions(interface_type: &Type) -> Vec<InterfaceFunction> {
    vec![
        // Pure functions
        InterfaceFunction {
            name: "get_pool_id",
            params: vec![
                ("user_token", parse_quote!(Address)),
                ("validator_token", parse_quote!(Address)),
            ],
            return_type: parse_quote!(B256),
            is_view: true,
            call_type_path: quote!(#interface_type::getPoolIdCall),
        },
        InterfaceFunction {
            name: "calculate_liquidity",
            params: vec![("x", parse_quote!(U256)), ("y", parse_quote!(U256))],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::calculateLiquidityCall),
        },
        // View functions returning structs
        InterfaceFunction {
            name: "get_pool",
            params: vec![
                ("user_token", parse_quote!(Address)),
                ("validator_token", parse_quote!(Address)),
            ],
            return_type: parse_quote!(#interface_type::Pool),
            is_view: true,
            call_type_path: quote!(#interface_type::getPoolCall),
        },
        InterfaceFunction {
            name: "pools",
            params: vec![("pool_id", parse_quote!(B256))],
            return_type: parse_quote!(#interface_type::Pool),
            is_view: true,
            call_type_path: quote!(#interface_type::poolsCall),
        },
        // View functions returning primitives
        InterfaceFunction {
            name: "total_supply",
            params: vec![("pool_id", parse_quote!(B256))],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::totalSupplyCall),
        },
        InterfaceFunction {
            name: "liquidity_balances",
            params: vec![
                ("pool_id", parse_quote!(B256)),
                ("user", parse_quote!(Address)),
            ],
            return_type: parse_quote!(U256),
            is_view: true,
            call_type_path: quote!(#interface_type::liquidityBalancesCall),
        },
        // Mutating functions (non-void returns)
        InterfaceFunction {
            name: "mint",
            params: vec![
                ("user_token", parse_quote!(Address)),
                ("validator_token", parse_quote!(Address)),
                ("amount_user_token", parse_quote!(U256)),
                ("amount_validator_token", parse_quote!(U256)),
                ("to", parse_quote!(Address)),
            ],
            return_type: parse_quote!(U256),
            is_view: false,
            call_type_path: quote!(#interface_type::mintCall),
        },
        InterfaceFunction {
            name: "burn",
            params: vec![
                ("user_token", parse_quote!(Address)),
                ("validator_token", parse_quote!(Address)),
                ("liquidity", parse_quote!(U256)),
                ("to", parse_quote!(Address)),
            ],
            return_type: parse_quote!((U256, U256)),
            is_view: false,
            call_type_path: quote!(#interface_type::burnCall),
        },
        InterfaceFunction {
            name: "rebalance_swap",
            params: vec![
                ("user_token", parse_quote!(Address)),
                ("validator_token", parse_quote!(Address)),
                ("amount_out", parse_quote!(U256)),
                ("to", parse_quote!(Address)),
            ],
            return_type: parse_quote!(U256),
            is_view: false,
            call_type_path: quote!(#interface_type::rebalanceSwapCall),
        },
    ]
}

pub(crate) fn get_events(interface_type: &Type) -> Vec<InterfaceEvent> {
    vec![
        InterfaceEvent {
            name: "mint",
            params: vec![
                ("sender", parse_quote!(Address), true),
                ("user_token", parse_quote!(Address), true),
                ("validator_token", parse_quote!(Address), true),
                ("amount_user_token", parse_quote!(U256), false),
                ("amount_validator_token", parse_quote!(U256), false),
                ("liquidity", parse_quote!(U256), false),
            ],
            event_type_path: quote!(#interface_type::Mint),
        },
        InterfaceEvent {
            name: "burn",
            params: vec![
                ("sender", parse_quote!(Address), true),
                ("user_token", parse_quote!(Address), true),
                ("validator_token", parse_quote!(Address), true),
                ("amount_user_token", parse_quote!(U256), false),
                ("amount_validator_token", parse_quote!(U256), false),
                ("liquidity", parse_quote!(U256), false),
                ("to", parse_quote!(Address), false),
            ],
            event_type_path: quote!(#interface_type::Burn),
        },
        InterfaceEvent {
            name: "rebalance_swap",
            params: vec![
                ("user_token", parse_quote!(Address), true),
                ("validator_token", parse_quote!(Address), true),
                ("swapper", parse_quote!(Address), true),
                ("amount_in", parse_quote!(U256), false),
                ("amount_out", parse_quote!(U256), false),
            ],
            event_type_path: quote!(#interface_type::RebalanceSwap),
        },
        InterfaceEvent {
            name: "fee_swap",
            params: vec![
                ("user_token", parse_quote!(Address), true),
                ("validator_token", parse_quote!(Address), true),
                ("amount_in", parse_quote!(U256), false),
                ("amount_out", parse_quote!(U256), false),
            ],
            event_type_path: quote!(#interface_type::FeeSwap),
        },
    ]
}

pub(crate) fn get_errors(interface_type: &Type) -> Vec<InterfaceError> {
    vec![
        InterfaceError {
            name: "identical_addresses",
            params: vec![],
            error_type_path: quote!(#interface_type::IdenticalAddresses),
        },
        InterfaceError {
            name: "zero_address",
            params: vec![],
            error_type_path: quote!(#interface_type::ZeroAddress),
        },
        InterfaceError {
            name: "pool_exists",
            params: vec![],
            error_type_path: quote!(#interface_type::PoolExists),
        },
        InterfaceError {
            name: "pool_does_not_exist",
            params: vec![],
            error_type_path: quote!(#interface_type::PoolDoesNotExist),
        },
        InterfaceError {
            name: "invalid_token",
            params: vec![],
            error_type_path: quote!(#interface_type::InvalidToken),
        },
        InterfaceError {
            name: "insufficient_liquidity",
            params: vec![],
            error_type_path: quote!(#interface_type::InsufficientLiquidity),
        },
        InterfaceError {
            name: "only_protocol",
            params: vec![],
            error_type_path: quote!(#interface_type::OnlyProtocol),
        },
        InterfaceError {
            name: "insufficient_pool_balance",
            params: vec![],
            error_type_path: quote!(#interface_type::InsufficientPoolBalance),
        },
        InterfaceError {
            name: "insufficient_reserves",
            params: vec![],
            error_type_path: quote!(#interface_type::InsufficientReserves),
        },
        InterfaceError {
            name: "insufficient_liquidity_balance",
            params: vec![],
            error_type_path: quote!(#interface_type::InsufficientLiquidityBalance),
        },
        InterfaceError {
            name: "must_deposit_lower_balance_token",
            params: vec![],
            error_type_path: quote!(#interface_type::MustDepositLowerBalanceToken),
        },
        InterfaceError {
            name: "invalid_amount",
            params: vec![],
            error_type_path: quote!(#interface_type::InvalidAmount),
        },
        InterfaceError {
            name: "invalid_rebalance_state",
            params: vec![],
            error_type_path: quote!(#interface_type::InvalidRebalanceState),
        },
        InterfaceError {
            name: "invalid_rebalance_direction",
            params: vec![],
            error_type_path: quote!(#interface_type::InvalidRebalanceDirection),
        },
        InterfaceError {
            name: "invalid_new_reserves",
            params: vec![],
            error_type_path: quote!(#interface_type::InvalidNewReserves),
        },
        InterfaceError {
            name: "cannot_support_pending_swaps",
            params: vec![],
            error_type_path: quote!(#interface_type::CannotSupportPendingSwaps),
        },
        InterfaceError {
            name: "division_by_zero",
            params: vec![],
            error_type_path: quote!(#interface_type::DivisionByZero),
        },
        InterfaceError {
            name: "invalid_swap_calculation",
            params: vec![],
            error_type_path: quote!(#interface_type::InvalidSwapCalculation),
        },
        InterfaceError {
            name: "insufficient_liquidity_for_pending",
            params: vec![],
            error_type_path: quote!(#interface_type::InsufficientLiquidityForPending),
        },
        InterfaceError {
            name: "token_transfer_failed",
            params: vec![],
            error_type_path: quote!(#interface_type::TokenTransferFailed),
        },
        InterfaceError {
            name: "internal_error",
            params: vec![],
            error_type_path: quote!(#interface_type::InternalError),
        },
    ]
}
