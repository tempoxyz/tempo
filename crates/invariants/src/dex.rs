//! The stablecoin DEX's custody: the TIP-20 balances it holds against what
//! it owes, its users' internal balances and its live orders' escrow.
//!
//! The DEX is a protected custody address (no privileged burn can take from
//! it). An order's escrow is what cancelling it refunds: an ask's remaining
//! base, a bid's remaining base priced at its tick and rounded up (the DEX
//! refunds a cancelled bid exactly that, "the exact escrowed amount").
//! Settlement rounds against the taker, so the holdings cover every claim.
//! Users and orders need not all be known: claims are summed over the
//! observed subset, which only makes the check weaker.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, sol};

use crate::tip20::ITIP20;
use invariants_core::{check, ensure};

use crate::{Check, ObserveError, Views, Violation, decode, judge};

pub const DEX_CUSTODY: &str = "TEMPO-DEX10";

pub static CHECKS: &[Check<Books>] = &[
    // The DEX holds, of each token, at least its users' internal balances of it plus its live
    // orders' escrow in it.
    check! {
        id: DEX_CUSTODY,
        over: |books: &Books| books.holdings.keys(),
        judge: |b, token| {
            let token = **token;
            let held = b.holdings[&token];
            let internal: U256 = b
                .internal
                .iter()
                .filter(|((_, t), _)| *t == token)
                .map(|(_, v)| *v)
                .sum();
            let orders: Vec<&Escrow> = b.escrow.iter().filter(|e| e.token == token).collect();
            let escrowed: U256 = orders.iter().map(|e| e.amount).sum();
            let owed = internal + escrowed;
            ensure!(
                owed <= held,
                "holds {held}, owes {owed} (internal balances {internal}, escrow of {} live orders {escrowed}); short {}",
                orders.len(),
                owed - held
            )
        },
    },
];

/// The violations of [`CHECKS`] in `books`.
pub fn check(books: &Books) -> Vec<Violation> {
    judge(CHECKS, books)
}

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[allow(clippy::too_many_arguments)]
    interface IStablecoinDex {
        struct Order {
            uint128 orderId;
            address maker;
            bytes32 bookKey;
            bool isBid;
            int16 tick;
            uint128 amount;
            uint128 remaining;
            uint128 prev;
            uint128 next;
            bool isFlip;
            int16 flipTick;
        }
        struct Orderbook {
            address base;
            address quote;
            int16 bestBidTick;
            int16 bestAskTick;
        }
        function balanceOf(address user, address token) external view returns (uint128);
        function getOrder(uint128 orderId) external view returns (Order memory);
        function books(bytes32 pairKey) external view returns (Orderbook memory);
        event OrderPlaced(uint128 indexed orderId, address indexed maker, address indexed token, uint128 amount, bool isBid, int16 tick, bool isFlipOrder, int16 flipTick);
        event OrderFilled(uint128 indexed orderId, address indexed maker, address indexed taker, uint128 amountFilled, bool partialFill);
        event OrderFlipped(uint128 indexed orderId, address indexed maker, address indexed token, uint128 amount, bool isBid, int16 tick, int16 flipTick);
        event OrderCancelled(uint128 indexed orderId);
    }
}

pub use IStablecoinDex::{OrderCancelled, OrderFilled, OrderFlipped, OrderPlaced};

/// The DEX's price scale: a tick's price is `PRICE_SCALE + tick`.
pub const PRICE_SCALE: u32 = 100_000;

/// One live order and the escrow it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escrow {
    pub order: u128,
    pub token: Address,
    pub amount: U256,
}

/// The DEX's books over the observed tokens, users and orders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Books {
    /// Its own balance of each token.
    pub holdings: BTreeMap<Address, U256>,
    /// Internal balances, keyed `(user, token)`.
    pub internal: BTreeMap<(Address, Address), U256>,
    pub escrow: Vec<Escrow>,
}

/// `remaining` base at `tick`, in quote, rounded up (the DEX's
/// `base_to_quote(.., Up)`).
pub fn bid_escrow(remaining: u128, tick: i16) -> U256 {
    let price = U256::from((PRICE_SCALE as i32 + i32::from(tick)).max(0) as u32);
    (U256::from(remaining) * price).div_ceil(U256::from(PRICE_SCALE))
}

/// Reads the DEX at `dex`: its balance of every token in `tokens` and of
/// every live order's book, the internal balances of `users` in each, and
/// the orders `orders` that are still live (a deleted one reads as absent).
pub fn observe<V: Views>(
    views: &mut V,
    dex: Address,
    tokens: &[Address],
    users: &[Address],
    orders: &[u128],
) -> Result<Books, ObserveError<V::Error>> {
    // Live orders in one batch; a deleted order's read reverts and fails the
    // batch, so then one call each, skipping the reverted ones.
    let get = |id: u128| -> (Address, Bytes) {
        let call = IStablecoinDex::getOrderCall { orderId: id };
        (dex, call.abi_encode().into())
    };
    let batch: Vec<(Address, Bytes)> = orders.iter().map(|&id| get(id)).collect();
    let outputs: Vec<Option<Bytes>> = match views.call(&batch) {
        Ok(out) => out,
        Err(_) => orders
            .iter()
            .map(|&id| {
                views
                    .call(&[get(id)])
                    .ok()
                    .and_then(|o| o.into_iter().next().flatten())
            })
            .collect(),
    };
    let mut live = Vec::new();
    for output in outputs.into_iter().flatten() {
        let order = decode::<IStablecoinDex::getOrderCall, _>(dex, Some(Some(output)))?;
        if order.maker != Address::ZERO {
            live.push(order);
        }
    }
    let mut keys: Vec<B256> = live.iter().map(|o| o.bookKey).collect();
    keys.sort();
    keys.dedup();
    let calls: Vec<(Address, Bytes)> = keys
        .iter()
        .map(|&pair_key| {
            let c = IStablecoinDex::booksCall { pairKey: pair_key };
            (dex, c.abi_encode().into())
        })
        .collect();
    let mut out = views.call(&calls).map_err(ObserveError::Views)?.into_iter();
    let mut book = BTreeMap::new();
    for &key in &keys {
        book.insert(
            key,
            decode::<IStablecoinDex::booksCall, _>(dex, out.next())?,
        );
    }

    let mut all: Vec<Address> = tokens.to_vec();
    all.extend(book.values().flat_map(|b| [b.base, b.quote]));
    all.sort();
    all.dedup();
    let mut calls: Vec<(Address, Bytes)> = Vec::new();
    for &token in &all {
        let c = ITIP20::balanceOfCall { account: dex };
        calls.push((token, c.abi_encode().into()));
    }
    for &user in users {
        for &token in &all {
            let c = IStablecoinDex::balanceOfCall { user, token };
            calls.push((dex, c.abi_encode().into()));
        }
    }
    let mut out = views.call(&calls).map_err(ObserveError::Views)?.into_iter();
    let mut holdings = BTreeMap::new();
    for &token in &all {
        holdings.insert(
            token,
            decode::<ITIP20::balanceOfCall, _>(token, out.next())?,
        );
    }
    let mut internal = BTreeMap::new();
    for &user in users {
        for &token in &all {
            let v = decode::<IStablecoinDex::balanceOfCall, _>(dex, out.next())?;
            internal.insert((user, token), U256::from(v));
        }
    }
    let escrow = live
        .iter()
        .map(|o| {
            let b = &book[&o.bookKey];
            if o.isBid {
                Escrow {
                    order: o.orderId,
                    token: b.quote,
                    amount: bid_escrow(o.remaining, o.tick),
                }
            } else {
                Escrow {
                    order: o.orderId,
                    token: b.base,
                    amount: U256::from(o.remaining),
                }
            }
        })
        .collect();
    Ok(Books {
        holdings,
        internal,
        escrow,
    })
}
