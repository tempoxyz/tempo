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
use alloy_sol_types::SolCall;

use tempo_contracts::precompiles::ITIP20;

use crate::{Observe, ObserveError, Views, decode};

pub use tempo_contracts::precompiles::{
    IStablecoinDEX::{self, OrderCancelled, OrderFilled, OrderFlipped, OrderPlaced},
    PRICE_SCALE,
};

mod checks;

pub use checks::{CHECKS, CUSTODY_STEP, DEX_CUSTODY, STEP_CHECKS, VIEW};

/// One live order and the escrow it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escrow {
    pub order: u128,
    pub token: Address,
    pub amount: U256,
}

impl Escrow {
    /// `remaining` base at `tick`, in quote, rounded up (the DEX's
    /// `base_to_quote(.., Up)`).
    fn bid(remaining: u128, tick: i16) -> U256 {
        let price = U256::from((PRICE_SCALE as i32 + i32::from(tick)).max(0) as u32);
        (U256::from(remaining) * price).div_ceil(U256::from(PRICE_SCALE))
    }
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

impl Books {
    /// What the DEX owes in `token`: its users' internal balances and its live orders' escrow.
    pub fn owed(&self, token: Address) -> (U256, U256) {
        let internal = self
            .internal
            .iter()
            .filter(|((_, t), _)| *t == token)
            .map(|(_, v)| *v)
            .sum();
        let escrowed = self
            .escrow
            .iter()
            .filter(|e| e.token == token)
            .map(|e| e.amount)
            .sum();
        (internal, escrowed)
    }
}

impl Observe for Books {
    type At<'a> = At<'a>;

    /// Reads the DEX at `dex`: its balance of every token in `tokens` and of
    /// every live order's book, the internal balances of `users` in each, and
    /// the orders `orders` that are still live (a deleted one reads as absent).
    fn observe<V: Views>(views: &mut V, at: Self::At<'_>) -> Result<Self, ObserveError<V::Error>> {
        let At {
            dex,
            tokens,
            users,
            orders,
        } = at;
        // Live orders in one batch; a deleted order's read reverts and fails the
        // batch, so then one call each, skipping the reverted ones.
        let get = |id: u128| -> (Address, Bytes) {
            let call = IStablecoinDEX::getOrderCall { orderId: id };
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
            let order = decode::<IStablecoinDEX::getOrderCall, _>(dex, Some(Some(output)))?;
            if !order.maker.is_zero() {
                live.push(order);
            }
        }
        let mut keys: Vec<B256> = live.iter().map(|o| o.bookKey).collect();
        keys.sort();
        keys.dedup();
        let calls: Vec<(Address, Bytes)> = keys
            .iter()
            .map(|&pair_key| {
                let c = IStablecoinDEX::booksCall { pairKey: pair_key };
                (dex, c.abi_encode().into())
            })
            .collect();
        let mut out = views.call(&calls).map_err(ObserveError::Views)?.into_iter();
        let mut book = BTreeMap::new();
        for &key in &keys {
            book.insert(
                key,
                decode::<IStablecoinDEX::booksCall, _>(dex, out.next())?,
            );
        }

        let mut all: Vec<Address> = tokens.to_vec();
        all.extend(book.values().flat_map(|b| [b.base, b.quote]));
        all.sort();
        all.dedup();
        let mut calls: Vec<(Address, Bytes)> = Vec::with_capacity(all.len() * (1 + users.len()));
        for &token in &all {
            let c = ITIP20::balanceOfCall { account: dex };
            calls.push((token, c.abi_encode().into()));
        }
        for &user in users {
            for &token in &all {
                let c = IStablecoinDEX::balanceOfCall { user, token };
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
                let v = decode::<IStablecoinDEX::balanceOfCall, _>(dex, out.next())?;
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
                        amount: Escrow::bid(o.remaining, o.tick),
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
        Ok(Self {
            holdings,
            internal,
            escrow,
        })
    }
}

/// The DEX and the tokens, users and orders to read of it.
#[derive(Debug, Clone, Copy)]
pub struct At<'a> {
    pub dex: Address,
    pub tokens: &'a [Address],
    pub users: &'a [Address],
    pub orders: &'a [u128],
}
