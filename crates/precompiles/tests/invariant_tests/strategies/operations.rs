use proptest::{prelude::*, strategy::BoxedStrategy};
use proptest_state_machine::ReferenceStateMachine;
use tempo_precompiles::stablecoin_dex::{
    MIN_ORDER_AMOUNT, TICK_SPACING,
    orderbook::{MAX_TICK, MIN_TICK},
};

pub(crate) const NUM_USERS: usize = 3;

const MAX_AMOUNT: u128 = 1_000_000_000; // $1,000 USD
const NUM_VALID_TICKS: i16 = (MAX_TICK - MIN_TICK) / TICK_SPACING + 1; // 401

#[derive(Clone, Debug)]
pub(crate) enum DexTransition {
    PlaceBid {
        user_idx: usize,
        amount: u128,
        tick: i16,
    },
    PlaceAsk {
        user_idx: usize,
        amount: u128,
        tick: i16,
    },
    PlaceFlipBid {
        user_idx: usize,
        amount: u128,
        tick: i16,
        flip_tick: i16,
    },
    PlaceFlipAsk {
        user_idx: usize,
        amount: u128,
        tick: i16,
        flip_tick: i16,
    },
    Cancel {
        order_idx: usize,
    },
    SwapExactIn {
        user_idx: usize,
        amount: u128,
        buy_base: bool,
    },
    SwapExactOut {
        user_idx: usize,
        amount: u128,
        buy_base: bool,
    },
    Withdraw {
        user_idx: usize,
        amount: u128,
        withdraw_base: bool,
    },
}

/// Reference model for state-aware transition generation
#[derive(Clone, Debug)]
pub(crate) struct DexRefState {
    pub(crate) order_ids: Vec<u128>,
    pub(crate) order_makers: Vec<usize>,
    pub(crate) order_is_bid: Vec<bool>,
    pub(crate) order_is_flip: Vec<bool>,
    pub(crate) order_ticks: Vec<i16>,
    pub(crate) partially_filled: Vec<bool>,
    pub(crate) has_bids: bool,
    pub(crate) has_asks: bool,
    pub(crate) internal_balances: [u128; NUM_USERS],
    pub(crate) next_order_id: u128,
}

fn arb_valid_tick() -> impl Strategy<Value = i16> {
    (0..NUM_VALID_TICKS).prop_map(|idx| MIN_TICK + idx * TICK_SPACING)
}

fn arb_tick_pair_ascending() -> impl Strategy<Value = (i16, i16)> {
    (0..NUM_VALID_TICKS, 0..NUM_VALID_TICKS)
        .prop_filter("ticks must differ", |(a, b)| a != b)
        .prop_map(|(a, b)| {
            let (lo, hi) = if a < b { (a, b) } else { (b, a) };
            (MIN_TICK + lo * TICK_SPACING, MIN_TICK + hi * TICK_SPACING)
        })
}

impl ReferenceStateMachine for DexRefState {
    type State = Self;
    type Transition = DexTransition;

    fn init_state() -> BoxedStrategy<Self::State> {
        Just(Self {
            order_ids: Vec::new(),
            order_makers: Vec::new(),
            order_is_bid: Vec::new(),
            order_is_flip: Vec::new(),
            order_ticks: Vec::new(),
            partially_filled: Vec::new(),
            has_bids: false,
            has_asks: false,
            internal_balances: [0; NUM_USERS],
            next_order_id: 1,
        })
        .boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        let arb_amount = MIN_ORDER_AMOUNT..=MAX_AMOUNT;
        let arb_user = 0..NUM_USERS;

        let place_bid =
            (arb_user.clone(), arb_amount.clone(), arb_valid_tick()).prop_map(|(u, a, t)| {
                DexTransition::PlaceBid {
                    user_idx: u,
                    amount: a,
                    tick: t,
                }
            });

        let place_ask =
            (arb_user.clone(), arb_amount.clone(), arb_valid_tick()).prop_map(|(u, a, t)| {
                DexTransition::PlaceAsk {
                    user_idx: u,
                    amount: a,
                    tick: t,
                }
            });

        let place_flip_bid = (
            arb_user.clone(),
            arb_amount.clone(),
            arb_tick_pair_ascending(),
        )
            .prop_map(|(u, a, (tick, flip_tick))| DexTransition::PlaceFlipBid {
                user_idx: u,
                amount: a,
                tick,
                flip_tick,
            });

        let place_flip_ask = (
            arb_user.clone(),
            arb_amount.clone(),
            arb_tick_pair_ascending(),
        )
            .prop_map(|(u, a, (tick, flip_tick))| DexTransition::PlaceFlipAsk {
                user_idx: u,
                amount: a,
                tick: flip_tick,
                flip_tick: tick,
            });

        let has_orders = !state.order_ids.is_empty();
        let has_liquidity = state.has_bids || state.has_asks;
        let has_partially_filled = state.partially_filled.iter().any(|&f| f);
        let has_flip_orders = state.order_is_flip.iter().any(|&f| f);
        let has_internal_balance = state.internal_balances.iter().any(|&b| b > 0);

        let mut options: Vec<(u32, BoxedStrategy<DexTransition>)> = vec![
            (20, place_bid.boxed()),
            (20, place_ask.boxed()),
            (8, place_flip_bid.boxed()),
            (7, place_flip_ask.boxed()),
        ];

        if has_orders {
            let num_orders = state.order_ids.len();
            let cancel = (0..num_orders)
                .prop_map(|idx| DexTransition::Cancel { order_idx: idx })
                .boxed();
            let cancel_weight = if has_partially_filled { 18 } else { 10 }; // refund rounding edge cases
            options.push((cancel_weight, cancel));
        }

        if has_liquidity {
            let swap_in = (arb_user.clone(), arb_amount.clone(), proptest::bool::ANY)
                .prop_map(|(u, a, buy)| DexTransition::SwapExactIn {
                    user_idx: u,
                    amount: a,
                    buy_base: buy,
                })
                .boxed();
            let swap_out = (arb_user.clone(), arb_amount.clone(), proptest::bool::ANY)
                .prop_map(|(u, a, buy)| DexTransition::SwapExactOut {
                    user_idx: u,
                    amount: a,
                    buy_base: buy,
                })
                .boxed();
            let swap_in_weight = if has_flip_orders { 20 } else { 12 }; // trigger flip creation path
            options.push((swap_in_weight, swap_in));
            options.push((5, swap_out));
        }

        if has_internal_balance {
            let withdraw = (arb_user, arb_amount, proptest::bool::ANY)
                .prop_map(|(u, a, base)| DexTransition::Withdraw {
                    user_idx: u,
                    amount: a,
                    withdraw_base: base,
                })
                .boxed();
            options.push((5, withdraw));
        }

        let strategies: Vec<BoxedStrategy<DexTransition>> = options
            .into_iter()
            .flat_map(|(weight, strat)| std::iter::repeat_n(strat, weight as usize))
            .collect();

        proptest::sample::select(strategies)
            .prop_flat_map(|s| s)
            .boxed()
    }

    fn preconditions(state: &Self::State, transition: &Self::Transition) -> bool {
        match transition {
            DexTransition::Cancel { order_idx } => *order_idx < state.order_ids.len(),
            DexTransition::SwapExactIn { .. } | DexTransition::SwapExactOut { .. } => {
                state.has_bids || state.has_asks
            }
            DexTransition::Withdraw { user_idx, .. } => {
                state.internal_balances[*user_idx % NUM_USERS] > 0
            }
            _ => true,
        }
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            DexTransition::PlaceBid { user_idx, tick, .. } => {
                state.order_ids.push(state.next_order_id);
                state.order_makers.push(*user_idx);
                state.order_is_bid.push(true);
                state.order_is_flip.push(false);
                state.order_ticks.push(*tick);
                state.partially_filled.push(false);
                state.has_bids = true;
                state.next_order_id += 1;
            }
            DexTransition::PlaceAsk { user_idx, tick, .. } => {
                state.order_ids.push(state.next_order_id);
                state.order_makers.push(*user_idx);
                state.order_is_bid.push(false);
                state.order_is_flip.push(false);
                state.order_ticks.push(*tick);
                state.partially_filled.push(false);
                state.has_asks = true;
                state.next_order_id += 1;
            }
            DexTransition::PlaceFlipBid { user_idx, tick, .. } => {
                state.order_ids.push(state.next_order_id);
                state.order_makers.push(*user_idx);
                state.order_is_bid.push(true);
                state.order_is_flip.push(true);
                state.order_ticks.push(*tick);
                state.partially_filled.push(false);
                state.has_bids = true;
                state.next_order_id += 1;
            }
            DexTransition::PlaceFlipAsk { user_idx, tick, .. } => {
                state.order_ids.push(state.next_order_id);
                state.order_makers.push(*user_idx);
                state.order_is_bid.push(false);
                state.order_is_flip.push(true);
                state.order_ticks.push(*tick);
                state.partially_filled.push(false);
                state.has_asks = true;
                state.next_order_id += 1;
            }
            DexTransition::Cancel { order_idx } => {
                if *order_idx < state.order_ids.len() {
                    state.order_ids.remove(*order_idx);
                    state.order_makers.remove(*order_idx);
                    state.order_is_bid.remove(*order_idx);
                    state.order_is_flip.remove(*order_idx);
                    state.order_ticks.remove(*order_idx);
                    state.partially_filled.remove(*order_idx);
                    state.has_bids = state.order_is_bid.iter().any(|&b| b);
                    state.has_asks = state.order_is_bid.iter().any(|&b| !b);
                }
            }
            DexTransition::SwapExactIn { .. } | DexTransition::SwapExactOut { .. } => {
                if !state.order_ids.is_empty() {
                    state.partially_filled[0] = true;
                }
                for balance in &mut state.internal_balances {
                    *balance = balance.saturating_add(MIN_ORDER_AMOUNT);
                }
            }
            DexTransition::Withdraw {
                user_idx, amount, ..
            } => {
                let idx = *user_idx % NUM_USERS;
                state.internal_balances[idx] = state.internal_balances[idx].saturating_sub(*amount);
            }
        }
        state
    }
}
