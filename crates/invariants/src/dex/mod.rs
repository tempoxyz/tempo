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

use alloy_primitives::{Address, B256, U256};

use tempo_contracts::precompiles::ITIP20;

use crate::{
    Batch, Observe, ObserveError, Views,
    model::{Reader, Scope},
    view,
};

pub use tempo_contracts::precompiles::{
    IStablecoinDEX::{self, OrderCancelled, OrderFilled, OrderFlipped, OrderPlaced},
    PRICE_SCALE, STABLECOIN_DEX_ADDRESS,
};

mod checks;

pub use checks::{CHECKS, CUSTODY_STEP, DEX_CUSTODY, STEP_CHECKS, VIEW};

/// How many of the newest orders the books are read over.
const MAX_ORDERS: u128 = 256;

/// Checks the DEX's books, over its newest orders, when the scope selects them.
pub(crate) fn check<R: Reader>(reader: &mut R, scope: &Scope<'_>) {
    let dex = STABLECOIN_DEX_ADDRESS;
    if !(scope.selected)(&dex) {
        return;
    }
    // Order IDs start at 1.
    let next = view(reader.after(), dex, IStablecoinDEX::nextOrderIdCall {}).unwrap_or(0);
    let orders: Vec<u128> = (next.saturating_sub(MAX_ORDERS).max(1)..next).collect();
    let at = At {
        dex,
        tokens: scope.tokens,
        users: scope.holders,
        orders: &orders,
    };
    reader.check::<Books>(at, dex, VIEW);
}

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
        // A deleted order's read reverts, so only the orders that returned are live.
        let mut batch = Batch::default();
        let reads: Vec<_> = orders
            .iter()
            .map(|&id| batch.push(None, dex, &IStablecoinDEX::getOrderCall { orderId: id }))
            .collect();
        let answers = batch.run(views)?;
        let mut live = Vec::new();
        for read in &reads {
            if !answers
                .outcome(read)
                .is_some_and(|outcome| outcome.succeeded())
            {
                continue;
            }
            let order = answers.decode(read)?;
            if !order.maker.is_zero() {
                live.push(order);
            }
        }
        let mut keys: Vec<B256> = live.iter().map(|o| o.bookKey).collect();
        keys.sort();
        keys.dedup();
        let mut batch = Batch::default();
        let reads: Vec<_> = keys
            .iter()
            .map(|&pair_key| {
                batch.push(None, dex, &IStablecoinDEX::booksCall { pairKey: pair_key })
            })
            .collect();
        let answers = batch.run(views)?;
        let mut book = BTreeMap::new();
        for (&key, read) in keys.iter().zip(&reads) {
            book.insert(key, answers.decode(read)?);
        }

        let mut all: Vec<Address> = tokens.to_vec();
        all.extend(book.values().flat_map(|b| [b.base, b.quote]));
        all.sort();
        all.dedup();
        let mut batch = Batch::default();
        let held: Vec<_> = all
            .iter()
            .map(|&token| batch.push(None, token, &ITIP20::balanceOfCall { account: dex }))
            .collect();
        let owed: Vec<_> = users
            .iter()
            .flat_map(|&user| all.iter().map(move |&token| (user, token)))
            .map(|(user, token)| {
                let read = batch.push(None, dex, &IStablecoinDEX::balanceOfCall { user, token });
                ((user, token), read)
            })
            .collect();
        let answers = batch.run(views)?;
        let mut holdings = BTreeMap::new();
        for (&token, read) in all.iter().zip(&held) {
            holdings.insert(token, answers.decode(read)?);
        }
        let mut internal = BTreeMap::new();
        for (key, read) in &owed {
            internal.insert(*key, U256::from(answers.decode(read)?));
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
