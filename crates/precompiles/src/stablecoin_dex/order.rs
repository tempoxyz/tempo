//! Limit order type for the stablecoin DEX.
//!
//! This module defines the core `Order` type used in the stablecoin DEX orderbook.
//! Orders support price-time priority matching, partial fills, and flip orders that
//! automatically place opposite-side orders when filled.

use crate::{
    error::{Result as StorageResult, TempoPrecompileError},
    stablecoin_dex::{IStablecoinDEX, error::OrderError},
    storage::{
        FromWord, Handler, Layout, LayoutCtx, Mapping, StorableType, StorageCtx, StorageKey,
        packing,
    },
};
use alloy::primitives::{Address, B256, U256};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles_macros::Storable;

/// Represents an order in the stablecoin DEX orderbook.
///
/// This struct matches the Solidity reference implementation in StablecoinDEX.sol.
///
/// # Order Types
/// - **Regular orders**: Orders with `is_flip = false`
/// - **Flip orders**: Orders with `is_flip = true` that automatically create
///   a new order on the opposite side when fully filled
///
/// # Order Lifecycle
/// 1. Order is placed via `place()` or `placeFlip()` and immediately added to the orderbook
/// 2. Orders can be filled (fully or partially) by swaps
/// 3. Flip orders automatically create a new order on the opposite side when fully filled
/// 4. Orders can be cancelled, removing them from the book and refunding escrow
///
/// # Price-Time Priority
/// Orders are sorted by price (tick), then by insertion time.
/// The doubly linked list maintains insertion order - orders are added at the tail,
/// so traversing from head to tail gives price-time priority.
///
/// # Onchain Storage
/// Orders are stored onchain in doubly linked lists organized by tick.
/// Each tick maintains a FIFO queue of orders using `prev` and `next` pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
pub struct Order {
    /// Unique identifier for this order
    pub order_id: u128,
    /// Address of the user who placed this order
    pub maker: Address,
    /// Orderbook key (identifies the trading pair)
    pub book_key: B256,
    /// Whether this is a bid (true) or ask (false) order
    pub is_bid: bool,
    /// Price tick
    pub tick: i16,
    /// Original order amount
    pub amount: u128,
    /// Remaining amount to be filled
    pub remaining: u128,
    /// Previous order ID in the doubly linked list (0 if head)
    pub prev: u128,
    /// Next order ID in the doubly linked list (0 if tail)
    pub next: u128,
    /// Whether this is a flip order
    pub is_flip: bool,
    /// Tick to flip to when fully filled (for flip orders, 0 for regular orders).
    /// Pre-T5: for bid flips `flip_tick > tick`; for ask flips `flip_tick < tick`.
    /// T5+ (TIP-1030): for bid flips `flip_tick >= tick`; for ask flips `flip_tick <= tick`.
    pub flip_tick: i16,
}

/// Version-aware storage wrapper for DEX orders.
///
/// The wrapper intentionally hides the raw mapping so all order reads, writes, and linked-list
/// pointer mutations pass through a single version discriminator. Legacy orders use storage
/// version 0. Starting at T6, new writes use storage version 1, which stores the version byte in
/// the high byte of slot 0 and synthesizes `order_id` from the mapping key.
#[derive(Debug, Clone)]
pub struct Orders {
    base_slot: U256,
    address: Address,
    legacy: Mapping<u128, Order>,
}

impl StorableType for Orders {
    const LAYOUT: Layout = Layout::Slots(1);

    type Handler = Self;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        Self {
            base_slot: slot,
            address,
            legacy: Mapping::new(slot, address),
        }
    }
}

impl Orders {
    const VERSION_LEGACY: u8 = 0;
    const VERSION_1: u8 = 1;

    const VERSION_1_MAKER_OFFSET: usize = 0;
    const VERSION_1_IS_BID_OFFSET: usize = 20;
    const VERSION_1_TICK_OFFSET: usize = 21;
    const VERSION_1_IS_FLIP_OFFSET: usize = 23;
    const VERSION_1_FLIP_TICK_OFFSET: usize = 24;
    const VERSION_1_DISCRIMINATOR_OFFSET: usize = 31;

    const VERSION_1_BOOK_KEY_SLOT: u64 = 1;
    const VERSION_1_AMOUNTS_SLOT: u64 = 2;
    const VERSION_1_LINKS_SLOT: u64 = 3;
    const LEGACY_EXTRA_SLOT_START: u64 = 4;
    const LEGACY_EXTRA_SLOT_END: u64 = 5;

    const VERSION_1_AMOUNT_OFFSET: usize = 0;
    const VERSION_1_REMAINING_OFFSET: usize = 16;
    const VERSION_1_PREV_OFFSET: usize = 0;
    const VERSION_1_NEXT_OFFSET: usize = 16;

    fn order_base_slot(&self, order_id: u128) -> U256 {
        order_id.mapping_slot(self.base_slot)
    }

    fn slot(base_slot: U256, offset: u64) -> U256 {
        base_slot + U256::from(offset)
    }

    fn load_slot(&self, base_slot: U256, offset: u64) -> StorageResult<U256> {
        StorageCtx.sload(self.address, Self::slot(base_slot, offset))
    }

    fn store_slot(&mut self, base_slot: U256, offset: u64, value: U256) -> StorageResult<()> {
        StorageCtx.sstore(self.address, Self::slot(base_slot, offset), value)
    }

    fn version_from_header(header: U256) -> StorageResult<u8> {
        packing::extract_from_word(header, Self::VERSION_1_DISCRIMINATOR_OFFSET, 1)
    }

    fn versioned_layout_active() -> bool {
        StorageCtx.spec().is_t6()
    }

    /// Returns the stored order-layout version for an order ID.
    pub fn version(&self, order_id: u128) -> StorageResult<u8> {
        if !Self::versioned_layout_active() {
            return Ok(Self::VERSION_LEGACY);
        }

        let base_slot = self.order_base_slot(order_id);
        let header = self.load_slot(base_slot, 0)?;
        Self::version_from_header(header)
    }

    /// Reads an order from storage, using legacy layout before T6 and versioned dispatch on T6+.
    pub fn read(&self, order_id: u128) -> StorageResult<Order> {
        if !Self::versioned_layout_active() {
            return self.legacy[order_id].read();
        }

        let base_slot = self.order_base_slot(order_id);
        let header = self.load_slot(base_slot, 0)?;

        match Self::version_from_header(header)? {
            Self::VERSION_LEGACY => self.legacy[order_id].read(),
            Self::VERSION_1 => self.read_version_1(order_id, base_slot, header),
            version => Err(TempoPrecompileError::Fatal(format!(
                "unknown StablecoinDEX order storage version {version}"
            ))),
        }
    }

    /// Writes an order using legacy layout before T6 and version 1 on T6+.
    pub fn write(&mut self, order_id: u128, order: Order) -> StorageResult<()> {
        debug_assert_eq!(order_id, order.order_id());

        if !Self::versioned_layout_active() {
            return self.legacy[order_id].write(order);
        }

        let base_slot = self.order_base_slot(order_id);
        self.store_slot(base_slot, 0, Self::encode_version_1_header(&order)?)?;
        self.store_slot(
            base_slot,
            Self::VERSION_1_BOOK_KEY_SLOT,
            order.book_key.to_word(),
        )?;
        self.store_slot(
            base_slot,
            Self::VERSION_1_AMOUNTS_SLOT,
            Self::encode_version_1_amounts(&order)?,
        )?;
        self.store_slot(
            base_slot,
            Self::VERSION_1_LINKS_SLOT,
            Self::encode_version_1_links(&order)?,
        )
    }

    /// Deletes an order according to its storage layout.
    pub fn delete(&mut self, order_id: u128) -> StorageResult<()> {
        if !Self::versioned_layout_active() {
            return self.legacy[order_id].delete();
        }

        match self.version(order_id)? {
            Self::VERSION_LEGACY => self.legacy[order_id].delete(),
            Self::VERSION_1 => {
                let base_slot = self.order_base_slot(order_id);
                for offset in 0..=Self::VERSION_1_LINKS_SLOT {
                    self.store_slot(base_slot, offset, U256::ZERO)?;
                }
                Ok(())
            }
            version => Err(TempoPrecompileError::Fatal(format!(
                "unknown StablecoinDEX order storage version {version}"
            ))),
        }
    }

    /// Updates the remaining amount without exposing the underlying layout.
    pub fn set_remaining(&mut self, order_id: u128, remaining: u128) -> StorageResult<()> {
        if !Self::versioned_layout_active() {
            return self.legacy[order_id].remaining.write(remaining);
        }

        match self.version(order_id)? {
            Self::VERSION_LEGACY => self.legacy[order_id].remaining.write(remaining),
            Self::VERSION_1 => self.update_packed_slot(
                order_id,
                Self::VERSION_1_AMOUNTS_SLOT,
                Self::VERSION_1_REMAINING_OFFSET,
                &remaining,
            ),
            version => Err(TempoPrecompileError::Fatal(format!(
                "unknown StablecoinDEX order storage version {version}"
            ))),
        }
    }

    /// Updates the previous linked-list pointer without exposing the underlying layout.
    pub fn set_prev(&mut self, order_id: u128, prev: u128) -> StorageResult<()> {
        if !Self::versioned_layout_active() {
            return self.legacy[order_id].prev.write(prev);
        }

        match self.version(order_id)? {
            Self::VERSION_LEGACY => self.legacy[order_id].prev.write(prev),
            Self::VERSION_1 => self.update_packed_slot(
                order_id,
                Self::VERSION_1_LINKS_SLOT,
                Self::VERSION_1_PREV_OFFSET,
                &prev,
            ),
            version => Err(TempoPrecompileError::Fatal(format!(
                "unknown StablecoinDEX order storage version {version}"
            ))),
        }
    }

    /// Updates the next linked-list pointer without exposing the underlying layout.
    pub fn set_next(&mut self, order_id: u128, next: u128) -> StorageResult<()> {
        if !Self::versioned_layout_active() {
            return self.legacy[order_id].next.write(next);
        }

        match self.version(order_id)? {
            Self::VERSION_LEGACY => self.legacy[order_id].next.write(next),
            Self::VERSION_1 => self.update_packed_slot(
                order_id,
                Self::VERSION_1_LINKS_SLOT,
                Self::VERSION_1_NEXT_OFFSET,
                &next,
            ),
            version => Err(TempoPrecompileError::Fatal(format!(
                "unknown StablecoinDEX order storage version {version}"
            ))),
        }
    }

    #[cfg(test)]
    pub(crate) fn write_legacy(&mut self, order_id: u128, order: Order) -> StorageResult<()> {
        self.legacy[order_id].write(order)
    }

    pub(crate) fn clear_legacy_extra_slots(&mut self, order_id: u128) -> StorageResult<()> {
        let base_slot = self.order_base_slot(order_id);
        for offset in Self::LEGACY_EXTRA_SLOT_START..=Self::LEGACY_EXTRA_SLOT_END {
            self.store_slot(base_slot, offset, U256::ZERO)?;
        }
        Ok(())
    }

    fn read_version_1(
        &self,
        order_id: u128,
        base_slot: U256,
        header: U256,
    ) -> StorageResult<Order> {
        let amounts = self.load_slot(base_slot, Self::VERSION_1_AMOUNTS_SLOT)?;
        let links = self.load_slot(base_slot, Self::VERSION_1_LINKS_SLOT)?;

        Ok(Order {
            order_id,
            maker: packing::extract_from_word(header, Self::VERSION_1_MAKER_OFFSET, 20)?,
            book_key: B256::from_word(self.load_slot(base_slot, Self::VERSION_1_BOOK_KEY_SLOT)?)?,
            is_bid: packing::extract_from_word(header, Self::VERSION_1_IS_BID_OFFSET, 1)?,
            tick: packing::extract_from_word(header, Self::VERSION_1_TICK_OFFSET, 2)?,
            amount: packing::extract_from_word(amounts, Self::VERSION_1_AMOUNT_OFFSET, 16)?,
            remaining: packing::extract_from_word(amounts, Self::VERSION_1_REMAINING_OFFSET, 16)?,
            prev: packing::extract_from_word(links, Self::VERSION_1_PREV_OFFSET, 16)?,
            next: packing::extract_from_word(links, Self::VERSION_1_NEXT_OFFSET, 16)?,
            is_flip: packing::extract_from_word(header, Self::VERSION_1_IS_FLIP_OFFSET, 1)?,
            flip_tick: packing::extract_from_word(header, Self::VERSION_1_FLIP_TICK_OFFSET, 2)?,
        })
    }

    fn encode_version_1_header(order: &Order) -> StorageResult<U256> {
        let mut header = U256::ZERO;
        header = packing::insert_into_word(header, &order.maker, Self::VERSION_1_MAKER_OFFSET, 20)?;
        header =
            packing::insert_into_word(header, &order.is_bid, Self::VERSION_1_IS_BID_OFFSET, 1)?;
        header = packing::insert_into_word(header, &order.tick, Self::VERSION_1_TICK_OFFSET, 2)?;
        header =
            packing::insert_into_word(header, &order.is_flip, Self::VERSION_1_IS_FLIP_OFFSET, 1)?;
        header = packing::insert_into_word(
            header,
            &order.flip_tick,
            Self::VERSION_1_FLIP_TICK_OFFSET,
            2,
        )?;
        packing::insert_into_word(
            header,
            &Self::VERSION_1,
            Self::VERSION_1_DISCRIMINATOR_OFFSET,
            1,
        )
    }

    fn encode_version_1_amounts(order: &Order) -> StorageResult<U256> {
        let mut amounts = U256::ZERO;
        amounts =
            packing::insert_into_word(amounts, &order.amount, Self::VERSION_1_AMOUNT_OFFSET, 16)?;
        packing::insert_into_word(
            amounts,
            &order.remaining,
            Self::VERSION_1_REMAINING_OFFSET,
            16,
        )
    }

    fn encode_version_1_links(order: &Order) -> StorageResult<U256> {
        let mut links = U256::ZERO;
        links = packing::insert_into_word(links, &order.prev, Self::VERSION_1_PREV_OFFSET, 16)?;
        packing::insert_into_word(links, &order.next, Self::VERSION_1_NEXT_OFFSET, 16)
    }

    fn update_packed_slot<T>(
        &mut self,
        order_id: u128,
        slot_offset: u64,
        byte_offset: usize,
        value: &T,
    ) -> StorageResult<()>
    where
        T: FromWord + StorableType,
    {
        let base_slot = self.order_base_slot(order_id);
        let slot = self.load_slot(base_slot, slot_offset)?;
        let updated = packing::insert_into_word(slot, value, byte_offset, T::BYTES)?;
        self.store_slot(base_slot, slot_offset, updated)
    }
}

impl Order {
    /// Creates a new [`Order`] with `prev` and `next` initialized to 0.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        order_id: u128,
        maker: Address,
        book_key: B256,
        amount: u128,
        tick: i16,
        is_bid: bool,
        is_flip: bool,
        flip_tick: i16,
    ) -> Self {
        Self {
            order_id,
            maker,
            book_key,
            is_bid,
            tick,
            amount,
            remaining: amount,
            prev: 0,
            next: 0,
            is_flip,
            flip_tick,
        }
    }

    /// Creates a new bid order
    pub fn new_bid(
        order_id: u128,
        maker: Address,
        book_key: B256,
        amount: u128,
        tick: i16,
    ) -> Self {
        Self::new(order_id, maker, book_key, amount, tick, true, false, 0)
    }

    /// Creates a new ask order
    pub fn new_ask(
        order_id: u128,
        maker: Address,
        book_key: B256,
        amount: u128,
        tick: i16,
    ) -> Self {
        Self::new(order_id, maker, book_key, amount, tick, false, false, 0)
    }

    /// Creates a new flip order with `prev` and `next` initialized to 0.
    /// The orderbook sets linked-list pointers when inserting.
    ///
    /// The `hardfork` parameter controls flip-tick validation:
    /// - Pre-T5: for bid flips `flip_tick > tick`; for ask flips `flip_tick < tick`.
    /// - T5+ (TIP-1030): for bid flips `flip_tick >= tick`; for ask flips `flip_tick <= tick`.
    ///
    /// # Errors
    /// - `InvalidBidFlipTick` - `is_bid` is true and `flip_tick < tick`
    /// - `InvalidAskFlipTick` - `is_bid` is false and `flip_tick > tick`
    #[allow(clippy::too_many_arguments)]
    pub fn new_flip(
        order_id: u128,
        maker: Address,
        book_key: B256,
        amount: u128,
        tick: i16,
        is_bid: bool,
        flip_tick: i16,
        hardfork: TempoHardfork,
    ) -> Result<Self, OrderError> {
        // TIP-1030 (T5+) relaxes the constraint to allow `flip_tick == tick`.
        let t5_active = hardfork.is_t5();
        let invalid = if is_bid {
            flip_tick < tick || (!t5_active && flip_tick == tick)
        } else {
            flip_tick > tick || (!t5_active && flip_tick == tick)
        };

        if invalid {
            return Err(if is_bid {
                OrderError::InvalidBidFlipTick { tick, flip_tick }
            } else {
                OrderError::InvalidAskFlipTick { tick, flip_tick }
            });
        }

        Ok(Self::new(
            order_id, maker, book_key, amount, tick, is_bid, true, flip_tick,
        ))
    }

    /// Returns the order ID.
    pub fn order_id(&self) -> u128 {
        self.order_id
    }

    /// Returns the maker address.
    pub fn maker(&self) -> Address {
        self.maker
    }

    /// Returns the orderbook key.
    pub fn book_key(&self) -> B256 {
        self.book_key
    }

    /// Returns whether this is a bid order.
    pub fn is_bid(&self) -> bool {
        self.is_bid
    }

    /// Returns the original amount.
    pub fn amount(&self) -> u128 {
        self.amount
    }

    /// Returns the remaining amount.
    pub fn remaining(&self) -> u128 {
        self.remaining
    }

    /// Returns a mutable reference to the remaining amount.
    fn remaining_mut(&mut self) -> &mut u128 {
        &mut self.remaining
    }

    /// Returns the tick price.
    pub fn tick(&self) -> i16 {
        self.tick
    }

    /// Returns true if this is an ask order (selling base token).
    pub fn is_ask(&self) -> bool {
        !self.is_bid
    }

    /// Returns true if this is a flip order.
    pub fn is_flip(&self) -> bool {
        self.is_flip
    }

    /// Returns the flip tick.
    ///
    /// For non-flip orders, this is always 0.
    /// For flip orders, this can be any valid tick value including 0 (peg price).
    pub fn flip_tick(&self) -> i16 {
        self.flip_tick
    }

    /// Returns the previous order ID in the doubly linked list (0 if head).
    pub fn prev(&self) -> u128 {
        self.prev
    }

    /// Returns the next order ID in the doubly linked list (0 if tail).
    pub fn next(&self) -> u128 {
        self.next
    }

    /// Sets the previous order ID in the doubly linked list.
    pub fn set_prev(&mut self, prev_id: u128) {
        self.prev = prev_id;
    }

    /// Sets the next order ID in the doubly linked list.
    pub fn set_next(&mut self, next_id: u128) {
        self.next = next_id;
    }

    /// Returns true if the order is completely filled (no remaining amount).
    pub fn is_fully_filled(&self) -> bool {
        self.remaining == 0
    }

    /// Fills the order by the specified amount, reducing `remaining` accordingly.
    ///
    /// # Errors
    /// - `FillAmountExceedsRemaining` — `fill_amount` is greater than `remaining`
    pub fn fill(&mut self, fill_amount: u128) -> Result<(), OrderError> {
        if fill_amount > self.remaining {
            return Err(OrderError::FillAmountExceedsRemaining {
                requested: fill_amount,
                available: self.remaining,
            });
        }
        *self.remaining_mut() = self.remaining.saturating_sub(fill_amount);
        Ok(())
    }

    /// Creates a flipped order from a fully filled flip order.
    ///
    /// When a flip order is completely filled, it creates a new order on the opposite side:
    /// - Sides are swapped (bid -> ask, ask -> bid)
    /// - New price = original flip_tick
    /// - New flip_tick = original tick
    /// - Amount is the same as original
    /// - Linked list pointers are reset to 0 (will be set by orderbook on insertion)
    pub(crate) fn create_flipped_order(&self, new_order_id: u128) -> Self {
        debug_assert!(self.is_flip());

        // Create flipped order
        Self {
            order_id: new_order_id,
            maker: self.maker,
            book_key: self.book_key,
            is_bid: !self.is_bid,   // Flip the side
            tick: self.flip_tick,   // Old flip_tick becomes new tick
            amount: self.amount,    // Same as original
            remaining: self.amount, // Reset remaining to original amount
            prev: 0,                // Reset linked list pointers
            next: 0,
            is_flip: true,        // Keep as flip order
            flip_tick: self.tick, // Old tick becomes new flip_tick
        }
    }
}

impl From<Order> for IStablecoinDEX::Order {
    fn from(value: Order) -> Self {
        Self {
            orderId: value.order_id,
            maker: value.maker,
            bookKey: value.book_key,
            isBid: value.is_bid,
            tick: value.tick,
            amount: value.amount,
            remaining: value.remaining,
            prev: value.prev,
            next: value.next,
            isFlip: value.is_flip,
            flipTick: value.flip_tick,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        stablecoin_dex::StablecoinDEX,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };

    use super::*;
    use alloy::primitives::{address, b256};

    const TEST_MAKER: Address = address!("0x1111111111111111111111111111111111111111");
    const TEST_BOOK_KEY: B256 =
        b256!("0x0000000000000000000000000000000000000000000000000000000000000001");

    #[test]
    fn test_new_bid_order() {
        let order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        assert_eq!(order.order_id(), 1);
        assert_eq!(order.maker(), TEST_MAKER);
        assert_eq!(order.book_key(), TEST_BOOK_KEY);
        assert!(order.is_bid());
        assert_eq!(order.amount(), 1000);
        assert_eq!(order.remaining(), 1000);
        assert!(order.is_bid());
        assert!(!order.is_ask());
        assert_eq!(order.tick(), 5);
        assert!(!order.is_flip());
        assert_eq!(order.flip_tick(), 0);
    }

    #[test]
    fn test_new_ask_order() {
        let order = Order::new_ask(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        assert_eq!(order.order_id(), 1);
        assert!(!order.is_bid());
        assert!(!order.is_bid());
        assert!(order.is_ask());
        assert!(!order.is_flip());
    }

    #[test]
    fn test_new_flip_order_bid() {
        let order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            true,
            10,
            TempoHardfork::T4,
        )
        .unwrap();

        assert!(order.is_flip());
        assert_eq!(order.flip_tick(), 10);
        assert_eq!(order.tick(), 5);
        assert!(order.is_bid());
    }

    #[test]
    fn test_new_flip_order_ask() {
        let order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            false,
            2,
            TempoHardfork::T4,
        )
        .unwrap();

        assert!(order.is_flip());
        assert_eq!(order.flip_tick(), 2);
        assert_eq!(order.tick(), 5);
        assert!(!order.is_bid());
        assert!(order.is_ask());
    }

    #[test]
    fn test_new_flip_order_bid_invalid_flip_tick() {
        let result = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            true,
            3,
            TempoHardfork::T4,
        );

        assert!(matches!(result, Err(OrderError::InvalidBidFlipTick { .. })));
    }

    #[test]
    fn test_new_flip_order_ask_invalid_flip_tick() {
        let result = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            false,
            7,
            TempoHardfork::T4,
        );

        assert!(matches!(result, Err(OrderError::InvalidAskFlipTick { .. })));
    }

    #[test]
    fn test_new_flip_order_bid_same_tick_rejected() {
        // Pre-T5: same-tick bid flip is rejected
        let result = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            true,
            5,
            TempoHardfork::T4,
        );
        assert!(matches!(result, Err(OrderError::InvalidBidFlipTick { .. })));
    }

    #[test]
    fn test_new_flip_order_ask_same_tick_rejected() {
        // Pre-T5: same-tick ask flip is rejected
        let result = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            false,
            5,
            TempoHardfork::T4,
        );
        assert!(matches!(result, Err(OrderError::InvalidAskFlipTick { .. })));
    }

    #[test]
    fn test_new_flip_order_bid_same_tick_accepted() {
        // TIP-1030 (T5+): same-tick bid flip is accepted
        let order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            true,
            5,
            TempoHardfork::T5,
        )
        .unwrap();
        assert!(order.is_flip());
        assert_eq!(order.tick(), 5);
        assert_eq!(order.flip_tick(), 5);
        assert!(order.is_bid());
    }

    #[test]
    fn test_new_flip_t5_still_rejects_wrong_side() {
        // TIP-1030 (T5+): flip_tick < tick still rejected for bids
        let result = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            true,
            3,
            TempoHardfork::T5,
        );
        assert!(matches!(result, Err(OrderError::InvalidBidFlipTick { .. })));

        // TIP-1030 (T5+): flip_tick > tick still rejected for asks
        let result = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            false,
            7,
            TempoHardfork::T5,
        );
        assert!(matches!(result, Err(OrderError::InvalidAskFlipTick { .. })));
    }

    #[test]
    fn test_new_flip_order_ask_same_tick_accepted() {
        // TIP-1030 (T5+): same-tick ask flip is accepted
        let order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            false,
            5,
            TempoHardfork::T5,
        )
        .unwrap();
        assert!(order.is_flip());
        assert_eq!(order.tick(), 5);
        assert_eq!(order.flip_tick(), 5);
        assert!(order.is_ask());
    }

    #[test]
    fn test_fill_bid_order_partial() {
        let mut order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        assert!(!order.is_fully_filled());

        order.fill(400).unwrap();

        assert_eq!(order.remaining(), 600);
        assert_eq!(order.amount(), 1000);
        assert!(!order.is_fully_filled());
    }

    #[test]
    fn test_fill_ask_order_complete() {
        let mut order = Order::new_ask(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        order.fill(1000).unwrap();

        assert_eq!(order.remaining(), 0);
        assert_eq!(order.amount(), 1000);
        assert!(order.is_fully_filled());
    }

    #[test]
    fn test_fill_order_overfill() {
        let mut order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        let result = order.fill(1001);
        assert!(matches!(
            result,
            Err(OrderError::FillAmountExceedsRemaining { .. })
        ));
    }

    #[test]
    fn test_create_flipped_order_bid_to_ask() {
        let mut order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            true,
            10,
            TempoHardfork::T4,
        )
        .unwrap();

        // Fully fill the order
        order.fill(1000).unwrap();
        assert!(order.is_fully_filled());

        // Create flipped order
        let flipped = order.create_flipped_order(2);

        assert_eq!(flipped.order_id(), 2);
        assert_eq!(flipped.maker(), order.maker());
        assert_eq!(flipped.book_key(), order.book_key());
        assert_eq!(flipped.amount(), 1000); // Same as original
        assert_eq!(flipped.remaining(), 1000); // Reset to full amount
        assert!(!flipped.is_bid()); // Flipped from bid to ask
        assert!(flipped.is_ask());
        assert_eq!(flipped.tick(), 10); // Old flip_tick
        assert_eq!(flipped.flip_tick(), 5); // Old tick
        assert!(flipped.is_flip());
    }

    #[test]
    fn test_create_flipped_order_ask_to_bid() {
        let mut order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            10,
            false,
            5,
            TempoHardfork::T4,
        )
        .unwrap();

        order.fill(1000).unwrap();
        let flipped = order.create_flipped_order(2);

        assert!(flipped.is_bid()); // Flipped from ask to bid
        assert!(!flipped.is_ask());
        assert_eq!(flipped.tick(), 5); // Old flip_tick
        assert_eq!(flipped.flip_tick(), 10); // Old tick
    }

    #[test]
    fn test_multiple_fills() {
        let mut order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        // Multiple partial fills
        order.fill(300).unwrap();
        assert_eq!(order.remaining(), 700);

        order.fill(200).unwrap();
        assert_eq!(order.remaining(), 500);

        order.fill(500).unwrap();
        assert_eq!(order.remaining(), 0);
        assert!(order.is_fully_filled());
    }

    #[test]
    fn test_multiple_flips() {
        // Test that an order can flip multiple times
        let mut order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            true,
            10,
            TempoHardfork::T4,
        )
        .unwrap();

        // First flip: bid -> ask
        order.fill(1000).unwrap();
        let mut flipped1 = order.create_flipped_order(2);

        assert!(!flipped1.is_bid());
        assert!(flipped1.is_ask());
        assert_eq!(flipped1.tick(), 10);
        assert_eq!(flipped1.flip_tick(), 5);

        // Second flip: ask -> bid
        flipped1.fill(1000).unwrap();
        let flipped2 = flipped1.create_flipped_order(3);

        assert!(flipped2.is_bid());
        assert!(!flipped2.is_ask());
        assert_eq!(flipped2.tick(), 5);
        assert_eq!(flipped2.flip_tick(), 10);
    }

    #[test]
    fn test_tick_price_encoding() {
        // Tick represents price offset from peg

        let order_above = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 2);
        assert_eq!(order_above.tick(), 2);

        let order_below = Order::new_ask(2, TEST_MAKER, TEST_BOOK_KEY, 1000, -2);
        assert_eq!(order_below.tick(), -2);

        let order_par = Order::new_bid(3, TEST_MAKER, TEST_BOOK_KEY, 1000, 0);
        assert_eq!(order_par.tick(), 0);
    }

    #[test]
    fn test_linked_list_pointers_initialization() {
        let order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);
        // Linked list pointers should be initialized to 0
        assert_eq!(order.prev(), 0);
        assert_eq!(order.next(), 0);
    }

    #[test]
    fn test_set_linked_list_pointers() {
        let mut order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        // Set prev and next pointers
        order.set_prev(42);
        order.set_next(43);

        assert_eq!(order.prev(), 42);
        assert_eq!(order.next(), 43);
    }

    #[test]
    fn test_flipped_order_resets_linked_list_pointers() {
        let mut order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            5,
            true,
            10,
            TempoHardfork::T4,
        )
        .unwrap();

        // Set linked list pointers on original order
        order.set_prev(100);
        order.set_next(200);

        // Fill the order
        order.fill(1000).unwrap();

        // Create flipped order
        let flipped = order.create_flipped_order(2);

        // Flipped order should have reset pointers
        assert_eq!(flipped.prev(), 0);
        assert_eq!(flipped.next(), 0);
    }

    #[test]
    fn test_store_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let id = 42;
            let order = Order::new_flip(
                id,
                TEST_MAKER,
                TEST_BOOK_KEY,
                1000,
                5,
                true,
                10,
                TempoHardfork::T4,
            )
            .unwrap();
            exchange.orders.write(id, order)?;

            assert_eq!(exchange.orders.version(id)?, 1);

            let loaded_order = exchange.orders.read(id)?;
            assert_eq!(loaded_order.order_id(), 42);
            assert_eq!(loaded_order.maker(), TEST_MAKER);
            assert_eq!(loaded_order.book_key(), TEST_BOOK_KEY);
            assert_eq!(loaded_order.amount(), 1000);
            assert_eq!(loaded_order.remaining(), 1000);
            assert_eq!(loaded_order.tick(), 5);
            assert!(loaded_order.is_bid());
            assert!(loaded_order.is_flip());
            assert_eq!(loaded_order.flip_tick(), 10);
            assert_eq!(loaded_order.prev(), 0);
            assert_eq!(loaded_order.next(), 0);

            Ok(())
        })
    }

    #[test]
    fn test_write_before_t6_uses_legacy_layout() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let id = 42;
            let order = Order::new_flip(
                id,
                TEST_MAKER,
                TEST_BOOK_KEY,
                1000,
                5,
                true,
                10,
                TempoHardfork::T5,
            )
            .unwrap();
            exchange.orders.write(id, order)?;

            assert_eq!(exchange.orders.version(id)?, 0);

            let loaded_order = exchange.orders.read(id)?;
            assert_eq!(loaded_order.order_id(), id);
            assert_eq!(loaded_order.maker(), TEST_MAKER);
            assert_eq!(loaded_order.book_key(), TEST_BOOK_KEY);
            assert_eq!(loaded_order.amount(), 1000);
            assert_eq!(loaded_order.remaining(), 1000);
            assert_eq!(loaded_order.tick(), 5);
            assert!(loaded_order.is_bid());
            assert!(loaded_order.is_flip());
            assert_eq!(loaded_order.flip_tick(), 10);

            Ok(())
        })
    }

    #[test]
    fn test_delete_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let id = 42;
            let order = Order::new_flip(
                id,
                TEST_MAKER,
                TEST_BOOK_KEY,
                1000,
                5,
                true,
                10,
                TempoHardfork::T4,
            )
            .unwrap();
            exchange.orders.write(id, order)?;
            exchange.orders.delete(id)?;

            let deleted_order = exchange.orders.read(id)?;
            assert_eq!(deleted_order.order_id(), 0);
            assert_eq!(deleted_order.maker(), Address::ZERO);
            assert_eq!(deleted_order.book_key(), B256::ZERO);
            assert_eq!(deleted_order.amount(), 0);
            assert_eq!(deleted_order.remaining(), 0);
            assert_eq!(deleted_order.tick(), 0);
            assert!(!deleted_order.is_bid());
            assert!(!deleted_order.is_flip());
            assert_eq!(deleted_order.flip_tick(), 0);
            assert_eq!(deleted_order.prev(), 0);
            assert_eq!(deleted_order.next(), 0);

            Ok(())
        })
    }

    #[test]
    fn test_read_legacy_order_has_zero_version_byte() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let id = 42;
            let order = Order::new_flip(
                id,
                TEST_MAKER,
                TEST_BOOK_KEY,
                1000,
                5,
                true,
                10,
                TempoHardfork::T4,
            )
            .unwrap();
            exchange.orders.write_legacy(id, order)?;

            assert_eq!(exchange.orders.version(id)?, 0);

            let loaded_order = exchange.orders.read(id)?;
            assert_eq!(loaded_order.order_id(), id);
            assert_eq!(loaded_order.maker(), TEST_MAKER);
            assert_eq!(loaded_order.book_key(), TEST_BOOK_KEY);
            assert_eq!(loaded_order.amount(), 1000);
            assert_eq!(loaded_order.remaining(), 1000);
            assert_eq!(loaded_order.prev(), 0);
            assert_eq!(loaded_order.next(), 0);
            assert!(loaded_order.is_flip());
            assert_eq!(loaded_order.flip_tick(), 10);

            Ok(())
        })
    }

    #[test]
    fn test_rewrite_legacy_flip_order_upgrades_to_version_1() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let id = 42;
            let mut legacy_order = Order::new_flip(
                id,
                TEST_MAKER,
                TEST_BOOK_KEY,
                1000,
                5,
                true,
                10,
                TempoHardfork::T4,
            )
            .unwrap();
            exchange.orders.write_legacy(id, legacy_order)?;
            assert_eq!(exchange.orders.version(id)?, 0);

            legacy_order.fill(1000)?;
            let flipped = legacy_order.create_flipped_order(id);
            exchange.orders.write(id, flipped)?;

            assert_eq!(exchange.orders.version(id)?, 1);
            let loaded_order = exchange.orders.read(id)?;
            assert_eq!(loaded_order.order_id(), id);
            assert!(!loaded_order.is_bid());
            assert!(loaded_order.is_flip());
            assert_eq!(loaded_order.tick(), 10);
            assert_eq!(loaded_order.flip_tick(), 5);
            assert_eq!(loaded_order.remaining(), 1000);

            Ok(())
        })
    }

    #[test]
    fn test_update_version_1_order_links_and_remaining() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let id = 42;
            let order = Order::new_bid(id, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);
            exchange.orders.write(id, order)?;

            exchange.orders.set_remaining(id, 600)?;
            exchange.orders.set_prev(id, 10)?;
            exchange.orders.set_next(id, 11)?;

            let loaded_order = exchange.orders.read(id)?;
            assert_eq!(loaded_order.remaining(), 600);
            assert_eq!(loaded_order.prev(), 10);
            assert_eq!(loaded_order.next(), 11);

            Ok(())
        })
    }

    #[test]
    fn test_update_mixed_version_order_links() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let mut legacy_order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);
            legacy_order.set_next(2);
            exchange.orders.write_legacy(1, legacy_order)?;

            let mut version_1_order = Order::new_bid(2, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);
            version_1_order.set_prev(1);
            exchange.orders.write(2, version_1_order)?;

            assert_eq!(exchange.orders.version(1)?, 0);
            assert_eq!(exchange.orders.version(2)?, 1);

            exchange.orders.set_next(1, 0)?;
            exchange.orders.set_prev(2, 0)?;

            assert_eq!(exchange.orders.read(1)?.next(), 0);
            assert_eq!(exchange.orders.read(2)?.prev(), 0);

            Ok(())
        })
    }
}
