use crate::{
    Type,
    interface::{InterfaceError, InterfaceEvent, InterfaceFunction},
};
use quote::quote;
use syn::parse_quote;

pub(crate) fn get_functions(interface_type: &Type) -> Vec<InterfaceFunction> {
    vec![
        // Core trading functions (non-void returns)
        InterfaceFunction {
            name: "create_pair",
            params: vec![("base", parse_quote!(Address))],
            return_type: parse_quote!(B256),
            is_view: false,
            call_type_path: quote!(#interface_type::createPairCall),
        },
        InterfaceFunction {
            name: "place",
            params: vec![
                ("token", parse_quote!(Address)),
                ("amount", parse_quote!(u128)),
                ("is_bid", parse_quote!(bool)),
                ("tick", parse_quote!(i16)),
            ],
            return_type: parse_quote!(u128),
            is_view: false,
            call_type_path: quote!(#interface_type::placeCall),
        },
        InterfaceFunction {
            name: "place_flip",
            params: vec![
                ("token", parse_quote!(Address)),
                ("amount", parse_quote!(u128)),
                ("is_bid", parse_quote!(bool)),
                ("tick", parse_quote!(i16)),
                ("flip_tick", parse_quote!(i16)),
            ],
            return_type: parse_quote!(u128),
            is_view: false,
            call_type_path: quote!(#interface_type::placeFlipCall),
        },
        // Swap functions (non-void returns)
        InterfaceFunction {
            name: "swap_exact_amount_in",
            params: vec![
                ("token_in", parse_quote!(Address)),
                ("token_out", parse_quote!(Address)),
                ("amount_in", parse_quote!(u128)),
                ("min_amount_out", parse_quote!(u128)),
            ],
            return_type: parse_quote!(u128),
            is_view: false,
            call_type_path: quote!(#interface_type::swapExactAmountInCall),
        },
        InterfaceFunction {
            name: "swap_exact_amount_out",
            params: vec![
                ("token_in", parse_quote!(Address)),
                ("token_out", parse_quote!(Address)),
                ("amount_out", parse_quote!(u128)),
                ("max_amount_in", parse_quote!(u128)),
            ],
            return_type: parse_quote!(u128),
            is_view: false,
            call_type_path: quote!(#interface_type::swapExactAmountOutCall),
        },
        // View swap quote functions
        InterfaceFunction {
            name: "quote_swap_exact_amount_in",
            params: vec![
                ("token_in", parse_quote!(Address)),
                ("token_out", parse_quote!(Address)),
                ("amount_in", parse_quote!(u128)),
            ],
            return_type: parse_quote!(u128),
            is_view: true,
            call_type_path: quote!(#interface_type::quoteSwapExactAmountInCall),
        },
        InterfaceFunction {
            name: "quote_swap_exact_amount_out",
            params: vec![
                ("token_in", parse_quote!(Address)),
                ("token_out", parse_quote!(Address)),
                ("amount_out", parse_quote!(u128)),
            ],
            return_type: parse_quote!(u128),
            is_view: true,
            call_type_path: quote!(#interface_type::quoteSwapExactAmountOutCall),
        },
        // Balance management view functions
        InterfaceFunction {
            name: "balance_of",
            params: vec![
                ("user", parse_quote!(Address)),
                ("token", parse_quote!(Address)),
            ],
            return_type: parse_quote!(u128),
            is_view: true,
            call_type_path: quote!(#interface_type::balanceOfCall),
        },
        // View functions returning structs
        InterfaceFunction {
            name: "get_order",
            params: vec![("order_id", parse_quote!(u128))],
            return_type: parse_quote!(#interface_type::Order),
            is_view: true,
            call_type_path: quote!(#interface_type::getOrderCall),
        },
        InterfaceFunction {
            name: "get_price_level",
            params: vec![
                ("base", parse_quote!(Address)),
                ("tick", parse_quote!(i16)),
                ("is_bid", parse_quote!(bool)),
            ],
            return_type: parse_quote!(#interface_type::PriceLevel),
            is_view: true,
            call_type_path: quote!(#interface_type::getPriceLevelCall),
        },
        InterfaceFunction {
            name: "books",
            params: vec![("pair_key", parse_quote!(B256))],
            return_type: parse_quote!(#interface_type::Orderbook),
            is_view: true,
            call_type_path: quote!(#interface_type::booksCall),
        },
        // Simple view functions
        InterfaceFunction {
            name: "pair_key",
            params: vec![
                ("token_a", parse_quote!(Address)),
                ("token_b", parse_quote!(Address)),
            ],
            return_type: parse_quote!(B256),
            is_view: true,
            call_type_path: quote!(#interface_type::pairKeyCall),
        },
        InterfaceFunction {
            name: "active_order_id",
            params: vec![],
            return_type: parse_quote!(u128),
            is_view: true,
            call_type_path: quote!(#interface_type::activeOrderIdCall),
        },
        InterfaceFunction {
            name: "pending_order_id",
            params: vec![],
            return_type: parse_quote!(u128),
            is_view: true,
            call_type_path: quote!(#interface_type::pendingOrderIdCall),
        },
        // Mutating functions (void)
        InterfaceFunction {
            name: "cancel",
            params: vec![("order_id", parse_quote!(u128))],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::cancelCall),
        },
        InterfaceFunction {
            name: "execute_block",
            params: vec![],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::executeBlockCall),
        },
        InterfaceFunction {
            name: "withdraw",
            params: vec![
                ("token", parse_quote!(Address)),
                ("amount", parse_quote!(u128)),
            ],
            return_type: parse_quote!(()),
            is_view: false,
            call_type_path: quote!(#interface_type::withdrawCall),
        },
    ]
}

pub(crate) fn get_events(interface_type: &Type) -> Vec<InterfaceEvent> {
    vec![
        InterfaceEvent {
            name: "pair_created",
            params: vec![
                ("key", parse_quote!(B256), true),
                ("base", parse_quote!(Address), true),
                ("quote", parse_quote!(Address), true),
            ],
            event_type_path: quote!(#interface_type::PairCreated),
        },
        InterfaceEvent {
            name: "order_placed",
            params: vec![
                ("order_id", parse_quote!(u128), true),
                ("maker", parse_quote!(Address), true),
                ("token", parse_quote!(Address), true),
                ("amount", parse_quote!(u128), false),
                ("is_bid", parse_quote!(bool), false),
                ("tick", parse_quote!(i16), false),
            ],
            event_type_path: quote!(#interface_type::OrderPlaced),
        },
        InterfaceEvent {
            name: "flip_order_placed",
            params: vec![
                ("order_id", parse_quote!(u128), true),
                ("maker", parse_quote!(Address), true),
                ("token", parse_quote!(Address), true),
                ("amount", parse_quote!(u128), false),
                ("is_bid", parse_quote!(bool), false),
                ("tick", parse_quote!(i16), false),
                ("flip_tick", parse_quote!(i16), false),
            ],
            event_type_path: quote!(#interface_type::FlipOrderPlaced),
        },
        InterfaceEvent {
            name: "order_filled",
            params: vec![
                ("order_id", parse_quote!(u128), true),
                ("maker", parse_quote!(Address), true),
                ("amount_filled", parse_quote!(u128), false),
                ("partial_fill", parse_quote!(bool), false),
            ],
            event_type_path: quote!(#interface_type::OrderFilled),
        },
        InterfaceEvent {
            name: "order_cancelled",
            params: vec![("order_id", parse_quote!(u128), true)],
            event_type_path: quote!(#interface_type::OrderCancelled),
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
            name: "pair_does_not_exist",
            params: vec![],
            error_type_path: quote!(#interface_type::PairDoesNotExist),
        },
        InterfaceError {
            name: "pair_already_exists",
            params: vec![],
            error_type_path: quote!(#interface_type::PairAlreadyExists),
        },
        InterfaceError {
            name: "order_does_not_exist",
            params: vec![],
            error_type_path: quote!(#interface_type::OrderDoesNotExist),
        },
        InterfaceError {
            name: "identical_tokens",
            params: vec![],
            error_type_path: quote!(#interface_type::IdenticalTokens),
        },
        InterfaceError {
            name: "tick_out_of_bounds",
            params: vec![("tick", parse_quote!(i16))],
            error_type_path: quote!(#interface_type::TickOutOfBounds),
        },
        InterfaceError {
            name: "invalid_tick",
            params: vec![],
            error_type_path: quote!(#interface_type::InvalidTick),
        },
        InterfaceError {
            name: "invalid_flip_tick",
            params: vec![],
            error_type_path: quote!(#interface_type::InvalidFlipTick),
        },
        InterfaceError {
            name: "insufficient_balance",
            params: vec![],
            error_type_path: quote!(#interface_type::InsufficientBalance),
        },
        InterfaceError {
            name: "insufficient_liquidity",
            params: vec![],
            error_type_path: quote!(#interface_type::InsufficientLiquidity),
        },
        InterfaceError {
            name: "insufficient_output",
            params: vec![],
            error_type_path: quote!(#interface_type::InsufficientOutput),
        },
        InterfaceError {
            name: "max_input_exceeded",
            params: vec![],
            error_type_path: quote!(#interface_type::MaxInputExceeded),
        },
    ]
}
