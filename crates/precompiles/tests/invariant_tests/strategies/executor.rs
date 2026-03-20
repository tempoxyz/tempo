use std::cell::RefCell;

use alloy::primitives::{Address, B256, U256};
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    stablecoin_dex::{StablecoinDEX, orderbook::compute_book_key},
    storage::{ContractStorage, Handler, StorageCtx, hashmap::HashMapStorageProvider},
    test_util::TIP20Setup,
};

use super::operations::{DexRefState, DexTransition, NUM_USERS};
use crate::invariant_tests::framework::{
    context::InvariantContext, registry::all_invariants, result::InvariantResult,
};

enum TransitionResult {
    OrderCreated(u128),
    OrderCancelled(usize),
    SwapExecuted,
    None,
}

pub(crate) struct DexTestState {
    storage: RefCell<HashMapStorageProvider>,
    users: [Address; NUM_USERS],
    base_token: Address,
    quote_token: Address,
    book_key: B256,
    created_order_ids: Vec<u128>,
    pub(crate) control_book_key: B256, // CTRL/PathUSD pair
    pub(crate) swap_count: u64,
}

impl DexTestState {
    fn with_storage<R>(&self, f: impl FnOnce() -> R) -> R {
        StorageCtx::enter(&mut *self.storage.borrow_mut(), f)
    }
}

pub(crate) struct DexStateMachineTest;

impl StateMachineTest for DexStateMachineTest {
    type SystemUnderTest = DexTestState;
    type Reference = DexRefState;

    fn init_test(
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) -> Self::SystemUnderTest {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);

        let (users, base_token, quote_token, book_key, control_book_key) =
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinDEX::new();
                exchange.initialize().expect("DEX init failed");

                let admin = Address::random();
                let users: [Address; NUM_USERS] =
                    [Address::random(), Address::random(), Address::random()];

                let large_amount = U256::from(u128::MAX / 4);
                let mut quote_setup = TIP20Setup::path_usd(admin).with_issuer(admin);
                let mut base_setup = TIP20Setup::create("BASE", "BASE", admin).with_issuer(admin);

                for &user in &users {
                    quote_setup = quote_setup.with_mint(user, large_amount).with_approval(
                        user,
                        exchange.address(),
                        large_amount,
                    );
                    base_setup = base_setup.with_mint(user, large_amount).with_approval(
                        user,
                        exchange.address(),
                        large_amount,
                    );
                }

                let quote = quote_setup.apply().expect("quote token setup failed");
                let base = base_setup.apply().expect("base token setup failed");
                let base_token = base.address();
                let quote_token = quote.address();
                let book_key = exchange
                    .create_pair(base_token)
                    .expect("create_pair failed");
                debug_assert_eq!(book_key, compute_book_key(base_token, quote_token));

                // Control pair
                let ctrl = TIP20Setup::create("CTRL", "CTRL", admin)
                    .with_issuer(admin)
                    .apply()
                    .expect("control token setup failed");
                let control_book_key = exchange
                    .create_pair(ctrl.address())
                    .expect("control create_pair failed");

                (users, base_token, quote_token, book_key, control_book_key)
            });

        DexTestState {
            storage: RefCell::new(storage),
            users,
            base_token,
            quote_token,
            book_key,
            created_order_ids: Vec::new(),
            control_book_key,
            swap_count: 0,
        }
    }

    fn apply(
        mut state: Self::SystemUnderTest,
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        transition: <Self::Reference as ReferenceStateMachine>::Transition,
    ) -> Self::SystemUnderTest {
        let users = state.users;
        let base_token = state.base_token;
        let quote_token = state.quote_token;

        let result: TransitionResult = StorageCtx::enter(state.storage.get_mut(), || {
            let mut exchange = StablecoinDEX::new();
            let guard = exchange.storage_mut().checkpoint();

            let result = match transition {
                DexTransition::PlaceBid {
                    user_idx,
                    amount,
                    tick,
                } => {
                    let user = users[user_idx % NUM_USERS];
                    match exchange.place(user, base_token, amount, true, tick) {
                        Ok(id) => TransitionResult::OrderCreated(id),
                        Err(_) => return TransitionResult::None,
                    }
                }
                DexTransition::PlaceAsk {
                    user_idx,
                    amount,
                    tick,
                } => {
                    let user = users[user_idx % NUM_USERS];
                    match exchange.place(user, base_token, amount, false, tick) {
                        Ok(id) => TransitionResult::OrderCreated(id),
                        Err(_) => return TransitionResult::None,
                    }
                }
                DexTransition::PlaceFlipBid {
                    user_idx,
                    amount,
                    tick,
                    flip_tick,
                } => {
                    let user = users[user_idx % NUM_USERS];
                    match exchange
                        .place_flip(user, base_token, amount, true, tick, flip_tick, false)
                    {
                        Ok(id) => TransitionResult::OrderCreated(id),
                        Err(_) => return TransitionResult::None,
                    }
                }
                DexTransition::PlaceFlipAsk {
                    user_idx,
                    amount,
                    tick,
                    flip_tick,
                } => {
                    let user = users[user_idx % NUM_USERS];
                    match exchange
                        .place_flip(user, base_token, amount, false, tick, flip_tick, false)
                    {
                        Ok(id) => TransitionResult::OrderCreated(id),
                        Err(_) => return TransitionResult::None,
                    }
                }
                DexTransition::Cancel { order_idx } => {
                    if order_idx < state.created_order_ids.len() {
                        let order_id = state.created_order_ids[order_idx];
                        if let Ok(order) = exchange.orders[order_id].read() {
                            if !order.maker().is_zero()
                                && exchange.cancel(order.maker(), order_id).is_ok()
                            {
                                TransitionResult::OrderCancelled(order_idx)
                            } else {
                                return TransitionResult::None;
                            }
                        } else {
                            return TransitionResult::None;
                        }
                    } else {
                        return TransitionResult::None;
                    }
                }
                DexTransition::SwapExactIn {
                    user_idx,
                    amount,
                    buy_base,
                } => {
                    let user = users[user_idx % NUM_USERS];
                    let (token_in, token_out) = if buy_base {
                        (quote_token, base_token)
                    } else {
                        (base_token, quote_token)
                    };
                    if exchange
                        .swap_exact_amount_in(user, token_in, token_out, amount, 0)
                        .is_err()
                    {
                        return TransitionResult::None;
                    }
                    TransitionResult::SwapExecuted
                }
                DexTransition::SwapExactOut {
                    user_idx,
                    amount,
                    buy_base,
                } => {
                    let user = users[user_idx % NUM_USERS];
                    let (token_in, token_out) = if buy_base {
                        (quote_token, base_token)
                    } else {
                        (base_token, quote_token)
                    };
                    if exchange
                        .swap_exact_amount_out(user, token_in, token_out, amount, u128::MAX)
                        .is_err()
                    {
                        return TransitionResult::None;
                    }
                    TransitionResult::SwapExecuted
                }
                DexTransition::Withdraw {
                    user_idx,
                    amount,
                    withdraw_base,
                } => {
                    let user = users[user_idx % NUM_USERS];
                    let token = if withdraw_base {
                        base_token
                    } else {
                        quote_token
                    };
                    if exchange.withdraw(user, token, amount).is_err() {
                        return TransitionResult::None;
                    }
                    TransitionResult::None
                }
            };

            guard.commit(); // only reached on success
            result
        });

        match result {
            TransitionResult::OrderCreated(id) => state.created_order_ids.push(id),
            TransitionResult::OrderCancelled(idx) => {
                state.created_order_ids.remove(idx);
            }
            TransitionResult::SwapExecuted => {
                state.swap_count += 1;
            }
            TransitionResult::None => {}
        }

        state
    }

    fn check_invariants(
        state: &Self::SystemUnderTest,
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) {
        state.with_storage(|| {
            let exchange = StablecoinDEX::new();
            let ctx = InvariantContext {
                exchange: &exchange,
                created_order_ids: &state.created_order_ids,
                users: &state.users,
                base_token: state.base_token,
                quote_token: state.quote_token,
                book_key: state.book_key,
                control_book_key: state.control_book_key,
                swap_count: state.swap_count,
            };

            for invariant in all_invariants() {
                let result =
                    (invariant.check)(&ctx).unwrap_or_else(|e| panic!("{}: {e}", invariant.name));

                if let InvariantResult::Violated { message } = result {
                    panic!("{}: {message}", invariant.name);
                }
            }
        });
    }
}
