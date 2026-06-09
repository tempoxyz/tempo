//! Limit order type for the stablecoin DEX.
//!
//! This module defines the core `Order` type used in the stablecoin DEX orderbook.
//! Orders support price-time priority matching, partial fills, and flip orders that
//! automatically place opposite-side orders when filled.

use crate::{
    error::{Result as StorageResult, TempoPrecompileError},
    stablecoin_dex::{IStablecoinDEX, error::OrderError},
    storage::{
        Handler, Layout, LayoutCtx, Storable, StorableType, StorageCtx, StorageKey, StorageOps,
        packing,
    },
};
use alloy::primitives::{Address, B256, FixedBytes, U256};
use std::ops::{Deref, DerefMut};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles_macros::Storable;

const ORDER_VERSION_V1: u8 = 1;

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
pub struct LegacyOrder {
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

pub type Order = LegacyOrder;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
#[repr(u8)]
enum OrderVersion {
    Legacy,
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoredOrder {
    order: Order,
    version: OrderVersion,
}

impl StoredOrder {
    fn new(order: Order, version: OrderVersion) -> Self {
        Self { order, version }
    }

    pub(crate) fn into_order(self) -> Order {
        self.order
    }
}

impl Deref for StoredOrder {
    type Target = Order;

    fn deref(&self) -> &Self::Target {
        &self.order
    }
}

impl DerefMut for StoredOrder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.order
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
struct V1Order {
    maker: Address,
    is_bid: bool,
    tick: i16,
    is_flip: bool,
    flip_tick: i16,
    _unused: FixedBytes<5>,
    version: OrderVersion,
    book_key: B256,
    amount: u128,
    remaining: u128,
    prev: u128,
    next: u128,
}

const _: () = {
    assert!(__packing_v1_order::MAKER_LOC.offset_slots == 0);
    assert!(__packing_v1_order::IS_BID_LOC.offset_slots == 0);
    assert!(__packing_v1_order::TICK_LOC.offset_slots == 0);
    assert!(__packing_v1_order::IS_FLIP_LOC.offset_slots == 0);
    assert!(__packing_v1_order::FLIP_TICK_LOC.offset_slots == 0);
    assert!(__packing_v1_order::BOOK_KEY_LOC.offset_bytes == 0);
    assert!(__packing_v1_order::BOOK_KEY_LOC.size == 32);
    assert!(
        __packing_v1_order::AMOUNT_LOC.offset_slots
            == __packing_v1_order::REMAINING_LOC.offset_slots
    );
    assert!(__packing_v1_order::PREV_LOC.offset_slots == __packing_v1_order::NEXT_LOC.offset_slots);
    assert!(__packing_v1_order::VERSION_LOC.offset_slots == 0);
    assert!(V1Order::SLOTS < LegacyOrder::SLOTS);
};

impl V1Order {
    fn new(order: Order) -> Self {
        Self {
            maker: order.maker,
            is_bid: order.is_bid,
            tick: order.tick,
            is_flip: order.is_flip,
            flip_tick: order.flip_tick,
            _unused: FixedBytes::<5>::ZERO,
            version: OrderVersion::V1,
            book_key: order.book_key,
            amount: order.amount,
            remaining: order.remaining,
            prev: order.prev,
            next: order.next,
        }
    }

    fn into_order(self, order_id: u128) -> Order {
        Order {
            order_id,
            maker: self.maker,
            book_key: self.book_key,
            is_bid: self.is_bid,
            tick: self.tick,
            amount: self.amount,
            remaining: self.remaining,
            prev: self.prev,
            next: self.next,
            is_flip: self.is_flip,
            flip_tick: self.flip_tick,
        }
    }
}

/// Storage wrapper for the DEX `orders` mapping.
///
/// It preserves the original mapping base slot and key type while returning handlers that retain
/// the `order_id` key. Version 1 order values no longer store `order_id`, so reads synthesize it
/// from this key.
#[derive(Debug)]
pub(crate) struct OrderStorage {
    base_slot: U256,
    address: Address,
}

impl OrderStorage {
    #[inline]
    fn new(base_slot: U256, address: Address) -> Self {
        Self { base_slot, address }
    }

    /// Returns a handler for `order_id`.
    pub(crate) fn at(&self, order_id: u128) -> OrderHandler {
        OrderHandler::new(
            order_id.mapping_slot(self.base_slot),
            order_id,
            self.address,
        )
    }
}

impl Clone for OrderStorage {
    fn clone(&self) -> Self {
        Self::new(self.base_slot, self.address)
    }
}

impl Default for OrderStorage {
    fn default() -> Self {
        Self::new(U256::ZERO, Address::ZERO)
    }
}

impl StorableType for OrderStorage {
    const LAYOUT: Layout = Layout::Slots(1);

    type Handler = Self;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        Self::new(slot, address)
    }
}

/// Version-aware storage handler for a single DEX order.
#[derive(Debug, Clone)]
pub struct OrderHandler {
    base_slot: U256,
    order_id: u128,
    address: Address,
}

impl OrderHandler {
    #[inline]
    fn new(base_slot: U256, order_id: u128, address: Address) -> Self {
        Self {
            base_slot,
            order_id,
            address,
        }
    }

    /// Returns the base storage slot for this order's mapping value.
    #[inline]
    pub const fn base_slot(&self) -> U256 {
        self.base_slot
    }

    /// Writes the order's remaining amount in the active storage version.
    pub fn write_remaining(&mut self, remaining: u128) -> StorageResult<()> {
        self.write_remaining_for_version(self.version()?, remaining)
    }

    /// Writes the order's remaining amount using a version learned from a prior read.
    pub(crate) fn write_remaining_for(
        &mut self,
        order: &StoredOrder,
        remaining: u128,
    ) -> StorageResult<()> {
        self.write_remaining_for_version(order.version, remaining)
    }

    /// Writes the previous linked-list pointer in the active storage version.
    pub(crate) fn write_prev(&mut self, prev: u128) -> StorageResult<()> {
        self.write_prev_for_version(self.version()?, prev)
    }

    /// Writes the previous linked-list pointer using a version learned from a prior read.
    pub(crate) fn write_prev_for(&mut self, order: &StoredOrder, prev: u128) -> StorageResult<()> {
        self.write_prev_for_version(order.version, prev)
    }

    /// Writes the next linked-list pointer in the active storage version.
    pub(crate) fn write_next(&mut self, next: u128) -> StorageResult<()> {
        self.write_next_for_version(self.version()?, next)
    }

    pub(crate) fn read_stored(&self) -> StorageResult<StoredOrder> {
        load_stored_order(self, self.base_slot, Some(self.order_id))
    }

    pub(crate) fn write_flip_rewrite_for(
        &mut self,
        previous: &StoredOrder,
        order: Order,
    ) -> StorageResult<()> {
        match previous.version {
            OrderVersion::Legacy => <Self as Handler<Order>>::write(self, order),
            OrderVersion::V1 => self.write_v1_flip_rewrite(previous, order),
        }
    }

    fn write_remaining_for_version(
        &mut self,
        version: OrderVersion,
        remaining: u128,
    ) -> StorageResult<()> {
        let loc = match version {
            OrderVersion::Legacy => __packing_legacy_order::REMAINING_LOC,
            OrderVersion::V1 => __packing_v1_order::REMAINING_LOC,
        };
        self.write_u128_field(loc, remaining)
    }

    fn write_prev_for_version(&mut self, version: OrderVersion, prev: u128) -> StorageResult<()> {
        let loc = match version {
            OrderVersion::Legacy => __packing_legacy_order::PREV_LOC,
            OrderVersion::V1 => __packing_v1_order::PREV_LOC,
        };
        self.write_u128_field(loc, prev)
    }

    fn write_next_for_version(&mut self, version: OrderVersion, next: u128) -> StorageResult<()> {
        let loc = match version {
            OrderVersion::Legacy => __packing_legacy_order::NEXT_LOC,
            OrderVersion::V1 => __packing_v1_order::NEXT_LOC,
        };
        self.write_u128_field(loc, next)
    }

    fn write_u128_field(&mut self, loc: packing::FieldLocation, value: u128) -> StorageResult<()> {
        <u128 as Storable>::store(
            &value,
            self,
            self.relative_slot(loc.offset_slots),
            LayoutCtx::packed(loc.offset_bytes),
        )
    }

    fn write_v1_flip_rewrite(&mut self, previous: &StoredOrder, order: Order) -> StorageResult<()> {
        debug_assert_eq!(previous.order_id(), order.order_id());
        debug_assert_eq!(previous.book_key(), order.book_key());

        if previous.book_key() != order.book_key() {
            return <Self as Handler<Order>>::write(self, order);
        }

        let mut slot0 = packing::PackedSlot(U256::ZERO);
        order.maker.store(
            &mut slot0,
            U256::ZERO,
            LayoutCtx::packed(__packing_v1_order::MAKER_LOC.offset_bytes),
        )?;
        order.is_bid.store(
            &mut slot0,
            U256::ZERO,
            LayoutCtx::packed(__packing_v1_order::IS_BID_LOC.offset_bytes),
        )?;
        order.tick.store(
            &mut slot0,
            U256::ZERO,
            LayoutCtx::packed(__packing_v1_order::TICK_LOC.offset_bytes),
        )?;
        order.is_flip.store(
            &mut slot0,
            U256::ZERO,
            LayoutCtx::packed(__packing_v1_order::IS_FLIP_LOC.offset_bytes),
        )?;
        order.flip_tick.store(
            &mut slot0,
            U256::ZERO,
            LayoutCtx::packed(__packing_v1_order::FLIP_TICK_LOC.offset_bytes),
        )?;
        OrderVersion::V1.store(
            &mut slot0,
            U256::ZERO,
            LayoutCtx::packed(__packing_v1_order::VERSION_LOC.offset_bytes),
        )?;
        self.store(self.base_slot, slot0.0)?;

        if previous.amount() != order.amount() || previous.remaining() != order.remaining() {
            let mut slot2 = packing::PackedSlot(U256::ZERO);
            order.amount.store(
                &mut slot2,
                U256::ZERO,
                LayoutCtx::packed(__packing_v1_order::AMOUNT_LOC.offset_bytes),
            )?;
            order.remaining.store(
                &mut slot2,
                U256::ZERO,
                LayoutCtx::packed(__packing_v1_order::REMAINING_LOC.offset_bytes),
            )?;
            self.store(
                self.relative_slot(__packing_v1_order::AMOUNT_LOC.offset_slots),
                slot2.0,
            )?;
        }

        if previous.prev() != order.prev() || previous.next() != order.next() {
            let mut slot3 = packing::PackedSlot(U256::ZERO);
            order.prev.store(
                &mut slot3,
                U256::ZERO,
                LayoutCtx::packed(__packing_v1_order::PREV_LOC.offset_bytes),
            )?;
            order.next.store(
                &mut slot3,
                U256::ZERO,
                LayoutCtx::packed(__packing_v1_order::NEXT_LOC.offset_bytes),
            )?;
            self.store(
                self.relative_slot(__packing_v1_order::PREV_LOC.offset_slots),
                slot3.0,
            )?;
        }

        Ok(())
    }

    fn version(&self) -> StorageResult<OrderVersion> {
        if !StorageCtx.spec().is_t7() {
            return Ok(OrderVersion::Legacy);
        }

        match order_version(self, self.base_slot)? {
            0 => Ok(OrderVersion::Legacy),
            1 => Ok(OrderVersion::V1),
            version => Err(unknown_order_version(version)),
        }
    }

    #[inline]
    fn relative_slot(&self, offset: usize) -> U256 {
        self.base_slot + U256::from(offset)
    }
}

impl StorageOps for OrderHandler {
    fn store(&mut self, slot: U256, value: U256) -> StorageResult<()> {
        StorageCtx.sstore(self.address, slot, value)
    }

    fn load(&self, slot: U256) -> StorageResult<U256> {
        StorageCtx.sload(self.address, slot)
    }
}

impl Handler<Order> for OrderHandler {
    fn read(&self) -> StorageResult<Order> {
        load_order(self, self.base_slot, Some(self.order_id))
    }

    fn write(&mut self, value: Order) -> StorageResult<()> {
        debug_assert_eq!(value.order_id, self.order_id);
        store_order(&value, self, self.base_slot)
    }

    fn delete(&mut self) -> StorageResult<()> {
        delete_order(self, self.base_slot)
    }

    fn t_read(&self) -> StorageResult<Order> {
        Err(TempoPrecompileError::Fatal(
            "transient order storage is unsupported".to_string(),
        ))
    }

    fn t_write(&mut self, _value: Order) -> StorageResult<()> {
        Err(TempoPrecompileError::Fatal(
            "transient order storage is unsupported".to_string(),
        ))
    }

    fn t_delete(&mut self) -> StorageResult<()> {
        Err(TempoPrecompileError::Fatal(
            "transient order storage is unsupported".to_string(),
        ))
    }
}

fn load_order<S: StorageOps>(
    storage: &S,
    base_slot: U256,
    order_id: Option<u128>,
) -> StorageResult<Order> {
    Ok(load_stored_order(storage, base_slot, order_id)?.into_order())
}

fn load_stored_order<S: StorageOps>(
    storage: &S,
    base_slot: U256,
    order_id: Option<u128>,
) -> StorageResult<StoredOrder> {
    if !StorageCtx.spec().is_t7() {
        return Ok(StoredOrder::new(
            load_order_legacy(storage, base_slot)?,
            OrderVersion::Legacy,
        ));
    }

    match order_version(storage, base_slot)? {
        0 => Ok(StoredOrder::new(
            load_order_legacy(storage, base_slot)?,
            OrderVersion::Legacy,
        )),
        1 => Ok(StoredOrder::new(
            load_order_v1(storage, base_slot, order_id.unwrap_or_default())?,
            OrderVersion::V1,
        )),
        version => Err(unknown_order_version(version)),
    }
}

fn load_order_legacy<S: StorageOps>(storage: &S, base_slot: U256) -> StorageResult<Order> {
    LegacyOrder::load(storage, base_slot, LayoutCtx::FULL)
}

fn load_order_v1<S: StorageOps>(
    storage: &S,
    base_slot: U256,
    order_id: u128,
) -> StorageResult<Order> {
    Ok(V1Order::load(storage, base_slot, LayoutCtx::FULL)?.into_order(order_id))
}

fn store_order<S: StorageOps>(
    order: &Order,
    storage: &mut S,
    base_slot: U256,
) -> StorageResult<()> {
    if !StorageCtx.spec().is_t7() {
        return order.store(storage, base_slot, LayoutCtx::FULL);
    }

    let current_slot0 = storage.load(base_slot)?;
    let current_version = order_version_from_word(current_slot0)?;
    if current_version != 0 && current_version != ORDER_VERSION_V1 {
        return Err(unknown_order_version(current_version));
    }

    // Migrate legacy
    V1Order::new(*order).store(storage, base_slot, LayoutCtx::FULL)?;

    if current_version == 0 && current_slot0 != U256::ZERO {
        // Delete unused legacy slot
        for offset in V1Order::SLOTS..LegacyOrder::SLOTS {
            storage.store(base_slot.wrapping_add(U256::from(offset)), U256::ZERO)?;
        }
    }

    Ok(())
}

fn delete_order<S: StorageOps>(storage: &mut S, base_slot: U256) -> StorageResult<()> {
    if !StorageCtx.spec().is_t7() {
        for offset in 0..LegacyOrder::SLOTS {
            storage.store(base_slot.wrapping_add(U256::from(offset)), U256::ZERO)?;
        }

        return Ok(());
    }

    let version = order_version(storage, base_slot)?;
    let slot_count = match version {
        0 => LegacyOrder::SLOTS,
        1 => V1Order::SLOTS,
        version => return Err(unknown_order_version(version)),
    };

    for offset in 0..slot_count {
        storage.store(base_slot.wrapping_add(U256::from(offset)), U256::ZERO)?;
    }

    Ok(())
}

fn order_version<S: StorageOps>(storage: &S, base_slot: U256) -> StorageResult<u8> {
    let slot0 = storage.load(base_slot)?;
    order_version_from_word(slot0)
}

fn order_version_from_word(slot0: U256) -> StorageResult<u8> {
    <u8 as Storable>::load(
        &packing::PackedSlot(slot0),
        U256::ZERO,
        LayoutCtx::packed(__packing_v1_order::VERSION_LOC.offset_bytes),
    )
}

fn unknown_order_version(version: u8) -> TempoPrecompileError {
    TempoPrecompileError::Fatal(format!(
        "unknown stablecoin DEX order storage version {version}"
    ))
}

impl LegacyOrder {
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
        storage::{ContractStorage, Handler, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20::{ITIP20, TIP20Token},
        tip403_registry::{ITIP403Registry, TIP403Registry},
    };

    use super::*;
    use alloy::primitives::{address, b256};
    use proptest::prelude::*;

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
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let exchange = StablecoinDEX::new();

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
            exchange.orders.at(id).write(order)?;

            let loaded_order = exchange.orders.at(id).read()?;
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
    fn test_t7_store_order_uses_v1_layout() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let exchange = StablecoinDEX::new();

            let id = 42;
            let mut order = Order::new_flip(
                id,
                TEST_MAKER,
                TEST_BOOK_KEY,
                1000,
                5,
                true,
                10,
                TempoHardfork::T7,
            )
            .unwrap();
            order.set_prev(7);
            order.set_next(9);

            exchange.orders.at(id).write(order)?;

            let base_slot = exchange.orders.at(id).base_slot();
            let slot0 = StorageCtx.sload(exchange.address(), base_slot)?;
            let version = order_version_from_word(slot0)?;
            assert_eq!(version, ORDER_VERSION_V1);

            let loaded_order = exchange.orders.at(id).read()?;
            assert_eq!(loaded_order, order);

            // New writes use only the v1 slots, not legacy-only slots 4 and 5.
            assert_eq!(
                StorageCtx.sload(
                    exchange.address(),
                    base_slot + U256::from(__packing_legacy_order::REMAINING_LOC.offset_slots),
                )?,
                U256::ZERO
            );
            assert_eq!(
                StorageCtx.sload(
                    exchange.address(),
                    base_slot + U256::from(__packing_legacy_order::NEXT_LOC.offset_slots),
                )?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_t6_store_order_uses_legacy_layout() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let exchange = StablecoinDEX::new();

            let id = 42;
            let mut order = Order::new_flip(
                id,
                TEST_MAKER,
                TEST_BOOK_KEY,
                1000,
                5,
                true,
                10,
                TempoHardfork::T7,
            )
            .unwrap();
            order.set_prev(7);
            order.set_next(9);

            exchange.orders.at(id).write(order)?;

            let base_slot = exchange.orders.at(id).base_slot();
            let version =
                order_version_from_word(StorageCtx.sload(exchange.address(), base_slot)?)?;
            assert_eq!(version, 0);
            assert_eq!(exchange.orders.at(id).read()?, order);
            let expected_remaining_slot =
                legacy_order_slot(order, __packing_legacy_order::REMAINING_LOC)?;
            let expected_next_slot = legacy_order_slot(order, __packing_legacy_order::NEXT_LOC)?;
            assert_eq!(
                StorageCtx.sload(
                    exchange.address(),
                    base_slot + U256::from(__packing_legacy_order::REMAINING_LOC.offset_slots),
                )?,
                expected_remaining_slot,
            );
            assert_eq!(
                StorageCtx.sload(
                    exchange.address(),
                    base_slot + U256::from(__packing_legacy_order::NEXT_LOC.offset_slots),
                )?,
                expected_next_slot,
            );

            Ok(())
        })
    }

    #[test]
    fn test_read_and_mutate_legacy_order_layout() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let exchange = StablecoinDEX::new();

            let id = 42;
            let mut order = Order::new_flip(
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
            order.set_prev(7);
            order.set_next(9);
            store_legacy_order(&mut exchange.orders.at(id), order)?;

            assert_eq!(exchange.orders.at(id).read()?, order);

            exchange.orders.at(id).write_remaining(600)?;
            exchange.orders.at(id).write_prev(11)?;
            exchange.orders.at(id).write_next(12)?;

            let loaded_order = exchange.orders.at(id).read()?;
            assert_eq!(loaded_order.order_id(), id);
            assert_eq!(loaded_order.remaining(), 600);
            assert_eq!(loaded_order.prev(), 11);
            assert_eq!(loaded_order.next(), 12);

            let version = order_version_from_word(
                StorageCtx.sload(exchange.address(), exchange.orders.at(id).base_slot())?,
            )?;
            assert_eq!(version, 0);

            Ok(())
        })
    }

    #[test]
    fn test_write_migrates_legacy_order_to_v1_layout() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let id = 42;
            let mut order = Order::new_flip(
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
            order.set_prev(7);
            order.set_next(9);
            exchange.next_order_id.write(id + 1)?;
            store_legacy_order(&mut exchange.orders.at(id), order)?;

            let base_slot = exchange.orders.at(id).base_slot();
            assert_eq!(
                order_version_from_word(StorageCtx.sload(exchange.address(), base_slot)?)?,
                0
            );
            let expected_remaining_slot =
                legacy_order_slot(order, __packing_legacy_order::REMAINING_LOC)?;
            let expected_next_slot = legacy_order_slot(order, __packing_legacy_order::NEXT_LOC)?;
            assert_eq!(
                StorageCtx.sload(
                    exchange.address(),
                    base_slot + U256::from(__packing_legacy_order::REMAINING_LOC.offset_slots),
                )?,
                expected_remaining_slot,
            );
            assert_eq!(
                StorageCtx.sload(
                    exchange.address(),
                    base_slot + U256::from(__packing_legacy_order::NEXT_LOC.offset_slots),
                )?,
                expected_next_slot,
            );

            let mut migrated_order = order;
            migrated_order.fill(250)?;
            migrated_order.set_prev(11);
            migrated_order.set_next(12);
            exchange.orders.at(id).write(migrated_order)?;

            assert_eq!(
                order_version_from_word(StorageCtx.sload(exchange.address(), base_slot)?)?,
                ORDER_VERSION_V1
            );
            assert_eq!(exchange.orders.at(id).read()?, migrated_order);
            assert_eq!(
                IStablecoinDEX::Order::from(exchange.get_order(id)?),
                migrated_order.into()
            );

            assert_eq!(
                StorageCtx.sload(
                    exchange.address(),
                    base_slot + U256::from(__packing_legacy_order::REMAINING_LOC.offset_slots),
                )?,
                U256::ZERO
            );
            assert_eq!(
                StorageCtx.sload(
                    exchange.address(),
                    base_slot + U256::from(__packing_legacy_order::NEXT_LOC.offset_slots),
                )?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_t7_fill_legacy_flip_order_migrates_without_corrupting_book() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();
            let amount = crate::stablecoin_dex::MIN_ORDER_AMOUNT;
            let tick = 100i16;
            let price = crate::stablecoin_dex::orderbook::tick_to_price(tick);
            let bid_escrow =
                amount * u128::from(price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);

            let base = TIP20Setup::create("BASE", "BASE", admin)
                .with_issuer(admin)
                .with_mint(bob, U256::from(amount * 2))
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;
            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(bid_escrow * 2))
                .with_approval(alice, exchange.address, U256::MAX)
                .apply()?;

            exchange.create_pair(base_token)?;
            let book_key =
                crate::stablecoin_dex::orderbook::compute_book_key(base_token, quote_token);

            let flip_id =
                exchange.place_flip(alice, base_token, amount, true, tick, tick, false)?;
            let resting_id = exchange.place(alice, base_token, amount, true, tick)?;

            let legacy_flip = exchange.orders.at(flip_id).read()?;
            store_legacy_order(&mut exchange.orders.at(flip_id), legacy_flip)?;
            assert_eq!(
                order_version(
                    &exchange.orders.at(flip_id),
                    exchange.orders.at(flip_id).base_slot()
                )?,
                0
            );

            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;

            let flipped = exchange.get_order(flip_id)?;
            assert!(!flipped.is_bid());
            assert_eq!(flipped.tick(), tick);
            assert_eq!(flipped.prev(), 0);
            assert_eq!(flipped.next(), 0);
            assert_eq!(
                order_version(
                    &exchange.orders.at(flip_id),
                    exchange.orders.at(flip_id).base_slot()
                )?,
                ORDER_VERSION_V1
            );

            let resting = exchange.get_order(resting_id)?;
            assert_eq!(resting.prev(), 0);
            assert_eq!(resting.next(), 0);

            let bid_level = exchange.books[book_key]
                .tick_level_handler(tick, true)
                .read()?;
            assert_eq!(bid_level.head, resting_id);
            assert_eq!(bid_level.tail, resting_id);
            assert_eq!(bid_level.total_liquidity, amount);

            let ask_level = exchange.books[book_key]
                .tick_level_handler(tick, false)
                .read()?;
            assert_eq!(ask_level.head, flip_id);
            assert_eq!(ask_level.tail, flip_id);
            assert_eq!(ask_level.total_liquidity, amount);

            Ok(())
        })
    }

    #[test]
    fn test_t7_legacy_flip_rewrite_gets_fresh_destination_priority() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let carol = Address::random();
            let admin = Address::random();
            let amount = crate::stablecoin_dex::MIN_ORDER_AMOUNT;
            let tick = 100i16;
            let flip_tick = 200i16;
            let bid_price = crate::stablecoin_dex::orderbook::tick_to_price(tick);
            let ask_price = crate::stablecoin_dex::orderbook::tick_to_price(flip_tick);
            let bid_escrow =
                amount * u128::from(bid_price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);
            let ask_quote =
                amount * u128::from(ask_price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);

            let base = TIP20Setup::create("BASE", "BASE", admin)
                .with_issuer(admin)
                .with_mint(bob, U256::from(amount * 2))
                .with_mint(carol, U256::from(amount))
                .with_approval(bob, exchange.address, U256::MAX)
                .with_approval(carol, exchange.address, U256::MAX)
                .apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;
            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(bid_escrow * 2))
                .with_mint(bob, U256::from(ask_quote))
                .with_approval(alice, exchange.address, U256::MAX)
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;

            exchange.create_pair(base_token)?;
            let book_key =
                crate::stablecoin_dex::orderbook::compute_book_key(base_token, quote_token);

            let flip_id =
                exchange.place_flip(alice, base_token, amount, true, tick, flip_tick, false)?;
            let source_next_id = exchange.place(alice, base_token, amount, true, tick)?;
            let destination_tail_id =
                exchange.place(carol, base_token, amount, false, flip_tick)?;

            let legacy_flip = exchange.orders.at(flip_id).read()?;
            store_legacy_order(&mut exchange.orders.at(flip_id), legacy_flip)?;
            assert_eq!(
                order_version(
                    &exchange.orders.at(flip_id),
                    exchange.orders.at(flip_id).base_slot()
                )?,
                0
            );

            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;

            let source_level = exchange.books[book_key]
                .tick_level_handler(tick, true)
                .read()?;
            assert_eq!(source_level.head, source_next_id);
            assert_eq!(source_level.tail, source_next_id);
            assert_eq!(source_level.total_liquidity, amount);

            let destination_level = exchange.books[book_key]
                .tick_level_handler(flip_tick, false)
                .read()?;
            assert_eq!(destination_level.head, destination_tail_id);
            assert_eq!(destination_level.tail, flip_id);
            assert_eq!(destination_level.total_liquidity, amount * 2);

            let destination_tail = exchange.get_order(destination_tail_id)?;
            assert_eq!(destination_tail.next(), flip_id);

            let flipped = exchange.get_order(flip_id)?;
            assert!(!flipped.is_bid());
            assert_eq!(flipped.tick(), flip_tick);
            assert_eq!(flipped.prev(), destination_tail_id);
            assert_eq!(flipped.next(), 0);
            assert_eq!(
                order_version(
                    &exchange.orders.at(flip_id),
                    exchange.orders.at(flip_id).base_slot()
                )?,
                ORDER_VERSION_V1
            );

            Ok(())
        })
    }

    #[test]
    fn test_t7_cancel_migrated_legacy_flip_cleans_destination_queue() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let carol = Address::random();
            let admin = Address::random();
            let amount = crate::stablecoin_dex::MIN_ORDER_AMOUNT;
            let tick = 100i16;
            let flip_tick = 200i16;
            let bid_price = crate::stablecoin_dex::orderbook::tick_to_price(tick);
            let ask_price = crate::stablecoin_dex::orderbook::tick_to_price(flip_tick);
            let bid_escrow =
                amount * u128::from(bid_price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);
            let ask_quote =
                amount * u128::from(ask_price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);

            let base = TIP20Setup::create("BASE", "BASE", admin)
                .with_issuer(admin)
                .with_mint(bob, U256::from(amount * 2))
                .with_mint(carol, U256::from(amount))
                .with_approval(bob, exchange.address, U256::MAX)
                .with_approval(carol, exchange.address, U256::MAX)
                .apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;
            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(bid_escrow * 2))
                .with_mint(bob, U256::from(ask_quote))
                .with_approval(alice, exchange.address, U256::MAX)
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;

            exchange.create_pair(base_token)?;
            let book_key =
                crate::stablecoin_dex::orderbook::compute_book_key(base_token, quote_token);

            let flip_id =
                exchange.place_flip(alice, base_token, amount, true, tick, flip_tick, false)?;
            let source_next_id = exchange.place(alice, base_token, amount, true, tick)?;
            let destination_tail_id =
                exchange.place(carol, base_token, amount, false, flip_tick)?;

            let legacy_flip = exchange.orders.at(flip_id).read()?;
            store_legacy_order(&mut exchange.orders.at(flip_id), legacy_flip)?;

            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;
            exchange.cancel(alice, flip_id)?;

            assert!(exchange.get_order(flip_id).is_err());
            assert_eq!(exchange.balance_of(alice, base_token)?, amount);

            let source_level = exchange.books[book_key]
                .tick_level_handler(tick, true)
                .read()?;
            assert_eq!(source_level.head, source_next_id);
            assert_eq!(source_level.tail, source_next_id);
            assert_eq!(source_level.total_liquidity, amount);

            let destination_level = exchange.books[book_key]
                .tick_level_handler(flip_tick, false)
                .read()?;
            assert_eq!(destination_level.head, destination_tail_id);
            assert_eq!(destination_level.tail, destination_tail_id);
            assert_eq!(destination_level.total_liquidity, amount);

            let destination_tail = exchange.get_order(destination_tail_id)?;
            assert_eq!(destination_tail.prev(), 0);
            assert_eq!(destination_tail.next(), 0);

            Ok(())
        })
    }

    #[test]
    fn test_t7_cancel_stale_migrated_legacy_flip() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let carol = Address::random();
            let admin = Address::random();
            let amount = crate::stablecoin_dex::MIN_ORDER_AMOUNT;
            let tick = 100i16;
            let flip_tick = 200i16;
            let bid_price = crate::stablecoin_dex::orderbook::tick_to_price(tick);
            let ask_price = crate::stablecoin_dex::orderbook::tick_to_price(flip_tick);
            let bid_escrow =
                amount * u128::from(bid_price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);
            let ask_quote =
                amount * u128::from(ask_price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);

            let base = TIP20Setup::create("BASE", "BASE", admin)
                .with_issuer(admin)
                .with_mint(bob, U256::from(amount * 2))
                .with_mint(carol, U256::from(amount))
                .with_approval(bob, exchange.address, U256::MAX)
                .with_approval(carol, exchange.address, U256::MAX)
                .apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;
            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(bid_escrow * 2))
                .with_mint(bob, U256::from(ask_quote))
                .with_approval(alice, exchange.address, U256::MAX)
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;

            exchange.create_pair(base_token)?;
            let book_key =
                crate::stablecoin_dex::orderbook::compute_book_key(base_token, quote_token);

            let flip_id =
                exchange.place_flip(alice, base_token, amount, true, tick, flip_tick, false)?;
            let source_next_id = exchange.place(alice, base_token, amount, true, tick)?;
            let destination_tail_id =
                exchange.place(carol, base_token, amount, false, flip_tick)?;

            let legacy_flip = exchange.orders.at(flip_id).read()?;
            store_legacy_order(&mut exchange.orders.at(flip_id), legacy_flip)?;

            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;

            let mut registry = TIP403Registry::new();
            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;
            let mut base = TIP20Token::from_address(base_token)?;
            base.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy_id,
                },
            )?;
            registry.modify_policy_blacklist(
                admin,
                ITIP403Registry::modifyPolicyBlacklistCall {
                    policyId: policy_id,
                    account: alice,
                    restricted: true,
                },
            )?;

            exchange.cancel_stale_order(flip_id)?;

            assert!(exchange.get_order(flip_id).is_err());
            assert_eq!(exchange.balance_of(alice, base_token)?, amount);

            let source_level = exchange.books[book_key]
                .tick_level_handler(tick, true)
                .read()?;
            assert_eq!(source_level.head, source_next_id);
            assert_eq!(source_level.tail, source_next_id);
            assert_eq!(source_level.total_liquidity, amount);

            let destination_level = exchange.books[book_key]
                .tick_level_handler(flip_tick, false)
                .read()?;
            assert_eq!(destination_level.head, destination_tail_id);
            assert_eq!(destination_level.tail, destination_tail_id);
            assert_eq!(destination_level.total_liquidity, amount);

            let destination_tail = exchange.get_order(destination_tail_id)?;
            assert_eq!(destination_tail.prev(), 0);
            assert_eq!(destination_tail.next(), 0);

            Ok(())
        })
    }

    #[test]
    fn test_t7_migrated_legacy_flip_can_partially_fill_then_flip_again() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();
            let amount = crate::stablecoin_dex::MIN_ORDER_AMOUNT;
            let partial = amount / 2;
            let tick = 100i16;
            let price = crate::stablecoin_dex::orderbook::tick_to_price(tick);
            let quote_amount =
                amount * u128::from(price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);

            let base = TIP20Setup::create("BASE", "BASE", admin)
                .with_issuer(admin)
                .with_mint(bob, U256::from(amount))
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;
            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(quote_amount))
                .with_mint(bob, U256::from(quote_amount))
                .with_approval(alice, exchange.address, U256::MAX)
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;

            exchange.create_pair(base_token)?;
            let book_key =
                crate::stablecoin_dex::orderbook::compute_book_key(base_token, quote_token);

            let flip_id =
                exchange.place_flip(alice, base_token, amount, true, tick, tick, false)?;
            let legacy_flip = exchange.orders.at(flip_id).read()?;
            store_legacy_order(&mut exchange.orders.at(flip_id), legacy_flip)?;

            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;

            let ask_after_migration = exchange.get_order(flip_id)?;
            assert!(!ask_after_migration.is_bid());
            assert_eq!(ask_after_migration.remaining(), amount);
            assert_eq!(
                order_version(
                    &exchange.orders.at(flip_id),
                    exchange.orders.at(flip_id).base_slot()
                )?,
                ORDER_VERSION_V1
            );

            exchange.swap_exact_amount_out(bob, quote_token, base_token, partial, u128::MAX)?;

            let partially_filled_ask = exchange.get_order(flip_id)?;
            assert!(!partially_filled_ask.is_bid());
            assert_eq!(partially_filled_ask.remaining(), amount - partial);

            exchange.swap_exact_amount_out(
                bob,
                quote_token,
                base_token,
                amount - partial,
                u128::MAX,
            )?;

            let flipped_back = exchange.get_order(flip_id)?;
            assert!(flipped_back.is_bid());
            assert_eq!(flipped_back.tick(), tick);
            assert_eq!(flipped_back.flip_tick(), tick);
            assert_eq!(flipped_back.amount(), amount);
            assert_eq!(flipped_back.remaining(), amount);
            assert_eq!(flipped_back.prev(), 0);
            assert_eq!(flipped_back.next(), 0);
            assert_eq!(
                order_version(
                    &exchange.orders.at(flip_id),
                    exchange.orders.at(flip_id).base_slot()
                )?,
                ORDER_VERSION_V1
            );

            let bid_level = exchange.books[book_key]
                .tick_level_handler(tick, true)
                .read()?;
            assert_eq!(bid_level.head, flip_id);
            assert_eq!(bid_level.tail, flip_id);
            assert_eq!(bid_level.total_liquidity, amount);

            let ask_level = exchange.books[book_key]
                .tick_level_handler(tick, false)
                .read()?;
            assert_eq!(ask_level.head, 0);
            assert_eq!(ask_level.tail, 0);
            assert_eq!(ask_level.total_liquidity, 0);

            Ok(())
        })
    }

    #[test]
    fn test_t7_fill_legacy_head_updates_v1_neighbor() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let carol = Address::random();
            let admin = Address::random();
            let amount = crate::stablecoin_dex::MIN_ORDER_AMOUNT;
            let tick = 100i16;
            let price = crate::stablecoin_dex::orderbook::tick_to_price(tick);
            let quote_amount =
                amount * u128::from(price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);

            let base = TIP20Setup::create("BASE", "BASE", admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(amount))
                .with_mint(bob, U256::from(amount))
                .with_approval(alice, exchange.address, U256::MAX)
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;
            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(carol, U256::from(quote_amount))
                .with_approval(carol, exchange.address, U256::MAX)
                .apply()?;

            exchange.create_pair(base_token)?;
            let book_key =
                crate::stablecoin_dex::orderbook::compute_book_key(base_token, quote_token);

            let legacy_head_id = exchange.place(alice, base_token, amount, false, tick)?;
            let v1_tail_id = exchange.place(bob, base_token, amount, false, tick)?;
            let legacy_head = exchange.orders.at(legacy_head_id).read()?;
            store_legacy_order(&mut exchange.orders.at(legacy_head_id), legacy_head)?;

            assert_eq!(
                order_version(
                    &exchange.orders.at(legacy_head_id),
                    exchange.orders.at(legacy_head_id).base_slot()
                )?,
                0
            );
            assert_eq!(
                order_version(
                    &exchange.orders.at(v1_tail_id),
                    exchange.orders.at(v1_tail_id).base_slot()
                )?,
                ORDER_VERSION_V1
            );

            exchange.swap_exact_amount_out(carol, quote_token, base_token, amount, u128::MAX)?;

            assert!(exchange.get_order(legacy_head_id).is_err());

            let v1_tail = exchange.get_order(v1_tail_id)?;
            assert_eq!(v1_tail.prev(), 0);
            assert_eq!(v1_tail.next(), 0);
            assert_eq!(
                order_version(
                    &exchange.orders.at(v1_tail_id),
                    exchange.orders.at(v1_tail_id).base_slot()
                )?,
                ORDER_VERSION_V1
            );

            let ask_level = exchange.books[book_key]
                .tick_level_handler(tick, false)
                .read()?;
            assert_eq!(ask_level.head, v1_tail_id);
            assert_eq!(ask_level.tail, v1_tail_id);
            assert_eq!(ask_level.total_liquidity, amount);

            Ok(())
        })
    }

    #[test]
    fn test_t7_legacy_flip_failure_deletes_filled_record() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();
            let amount = crate::stablecoin_dex::MIN_ORDER_AMOUNT;
            let tick = 100i16;
            let flip_tick = 200i16;
            let price = crate::stablecoin_dex::orderbook::tick_to_price(tick);
            let bid_escrow =
                amount * u128::from(price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);

            let base = TIP20Setup::create("BASE", "BASE", admin)
                .with_issuer(admin)
                .with_mint(bob, U256::from(amount * 2))
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;
            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(bid_escrow * 2))
                .with_approval(alice, exchange.address, U256::MAX)
                .apply()?;

            exchange.create_pair(base_token)?;
            let book_key =
                crate::stablecoin_dex::orderbook::compute_book_key(base_token, quote_token);

            let flip_id =
                exchange.place_flip(alice, base_token, amount, true, tick, flip_tick, false)?;
            let source_next_id = exchange.place(alice, base_token, amount, true, tick)?;

            let legacy_flip = exchange.orders.at(flip_id).read()?;
            store_legacy_order(&mut exchange.orders.at(flip_id), legacy_flip)?;

            let mut registry = TIP403Registry::new();
            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;
            let mut quote = TIP20Token::from_address(quote_token)?;
            quote.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy_id,
                },
            )?;
            registry.modify_policy_blacklist(
                admin,
                ITIP403Registry::modifyPolicyBlacklistCall {
                    policyId: policy_id,
                    account: alice,
                    restricted: true,
                },
            )?;

            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;

            assert!(exchange.get_order(flip_id).is_err());
            assert!(
                exchange.cancel(alice, flip_id).is_err(),
                "filled flip record must not remain cancellable after failed re-flip"
            );
            assert_eq!(
                exchange.balance_of(alice, base_token)?,
                amount,
                "maker keeps the legitimate proceeds from the filled bid"
            );
            assert_eq!(
                exchange.balance_of(alice, quote_token)?,
                0,
                "maker must not also recover the consumed bid escrow"
            );

            let source_next = exchange.get_order(source_next_id)?;
            assert_eq!(source_next.prev(), 0);
            assert_eq!(source_next.next(), 0);

            let bid_level = exchange.books[book_key]
                .tick_level_handler(tick, true)
                .read()?;
            assert_eq!(bid_level.head, source_next_id);
            assert_eq!(bid_level.tail, source_next_id);
            assert_eq!(bid_level.total_liquidity, amount);

            let ask_level = exchange.books[book_key]
                .tick_level_handler(flip_tick, false)
                .read()?;
            assert_eq!(ask_level.head, 0);
            assert_eq!(ask_level.tail, 0);
            assert_eq!(ask_level.total_liquidity, 0);

            Ok(())
        })
    }

    #[test]
    fn test_unknown_order_version_fails() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let exchange = StablecoinDEX::new();

            let id = 42;
            let base_slot = exchange.orders.at(id).base_slot();
            let mut slot0 = U256::ZERO;
            let mut packed_slot0 = packing::PackedSlot(slot0);
            <u8 as Storable>::store(
                &2,
                &mut packed_slot0,
                U256::ZERO,
                LayoutCtx::packed(__packing_v1_order::VERSION_LOC.offset_bytes),
            )?;
            slot0 = packed_slot0.0;
            StorageCtx.sstore(exchange.address(), base_slot, slot0)?;

            let order = Order::new_bid(id, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);
            assert!(exchange.orders.at(id).read().is_err());
            assert!(exchange.orders.at(id).write(order).is_err());
            assert!(exchange.orders.at(id).delete().is_err());

            Ok(())
        })
    }

    #[test]
    fn test_delete_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let exchange = StablecoinDEX::new();

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
            exchange.orders.at(id).write(order)?;
            exchange.orders.at(id).delete()?;

            let deleted_order = exchange.orders.at(id).read()?;
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn proptest_linked_list_equivalent_across_order_storage_versions(
            order_specs in prop::collection::vec(arb_order_spec(), 1..=12),
            update_seed in any::<usize>(),
            remove_seed in any::<usize>(),
            remaining_seed in any::<u128>(),
            mixed_offset in any::<bool>(),
        ) {
            let legacy = run_order_storage_linked_list_case(
                OrderLayoutCase::Legacy,
                &order_specs,
                update_seed,
                remove_seed,
                remaining_seed,
                mixed_offset,
            ).unwrap();
            let v1 = run_order_storage_linked_list_case(
                OrderLayoutCase::V1,
                &order_specs,
                update_seed,
                remove_seed,
                remaining_seed,
                mixed_offset,
            ).unwrap();
            let mixed = run_order_storage_linked_list_case(
                OrderLayoutCase::Mixed,
                &order_specs,
                update_seed,
                remove_seed,
                remaining_seed,
                mixed_offset,
            ).unwrap();

            prop_assert_eq!(&legacy, &v1);
            prop_assert_eq!(&legacy, &mixed);
        }
    }

    fn store_legacy_order(handler: &mut OrderHandler, order: Order) -> StorageResult<()> {
        order.store(handler, handler.base_slot(), LayoutCtx::FULL)
    }

    fn legacy_order_slot(order: Order, loc: packing::FieldLocation) -> StorageResult<U256> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let exchange = StablecoinDEX::new();
            store_legacy_order(&mut exchange.orders.at(order.order_id()), order)?;
            StorageCtx.sload(
                exchange.address(),
                exchange.orders.at(order.order_id()).base_slot() + U256::from(loc.offset_slots),
            )
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OrderLayoutCase {
        Legacy,
        V1,
        Mixed,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DexMigrationSnapshot {
        next_order_id: u128,
        active_orders: Vec<Option<Order>>,
        bid_level: crate::stablecoin_dex::orderbook::TickLevel,
        ask_level: crate::stablecoin_dex::orderbook::TickLevel,
        best_bid_tick: i16,
        best_ask_tick: i16,
        alice_internal_base: u128,
        alice_internal_quote: u128,
        bob_internal_base: u128,
        bob_internal_quote: u128,
        carol_internal_base: u128,
        carol_internal_quote: u128,
        alice_wallet_base: U256,
        alice_wallet_quote: U256,
        bob_wallet_base: U256,
        bob_wallet_quote: U256,
        carol_wallet_base: U256,
        carol_wallet_quote: U256,
    }

    #[test]
    fn test_t7_dex_sequence_equivalent_across_order_storage_versions() -> eyre::Result<()> {
        let v1 = run_dex_migration_sequence_case(0)?;
        for legacy_mask in 1..(1u8 << 3) {
            assert_eq!(
                v1,
                run_dex_migration_sequence_case(legacy_mask)?,
                "legacy mask {legacy_mask:03b}"
            );
        }

        Ok(())
    }

    fn run_dex_migration_sequence_case(legacy_mask: u8) -> eyre::Result<DexMigrationSnapshot> {
        use crate::stablecoin_dex::{
            MIN_ORDER_AMOUNT,
            orderbook::{RoundingDirection, base_to_quote, compute_book_key},
        };

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let admin = address!("0x1000000000000000000000000000000000000001");
            let alice = address!("0x1000000000000000000000000000000000000002");
            let bob = address!("0x1000000000000000000000000000000000000003");
            let carol = address!("0x1000000000000000000000000000000000000004");
            let amount = MIN_ORDER_AMOUNT;
            let partial = amount / 2;
            let tick = 100i16;
            let flip_tick = 200i16;
            let bid_escrow = base_to_quote(amount, tick, RoundingDirection::Up)
                .ok_or(TempoPrecompileError::under_overflow())?;
            let ask_quote = base_to_quote(amount, flip_tick, RoundingDirection::Up)
                .ok_or(TempoPrecompileError::under_overflow())?;

            let base = TIP20Setup::create("BASE", "BASE", admin)
                .with_salt(b256!(
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                ))
                .with_issuer(admin)
                .with_mint(bob, U256::from(amount))
                .with_mint(carol, U256::from(amount))
                .with_approval(bob, exchange.address, U256::MAX)
                .with_approval(carol, exchange.address, U256::MAX)
                .apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;
            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(bid_escrow * 2))
                .with_mint(bob, U256::from(ask_quote * 2))
                .with_approval(alice, exchange.address, U256::MAX)
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;

            exchange.create_pair(base_token)?;
            let book_key = compute_book_key(base_token, quote_token);

            let flip_id =
                exchange.place_flip(alice, base_token, amount, true, tick, flip_tick, false)?;
            let resting_bid_id = exchange.place(alice, base_token, amount, true, tick)?;
            let destination_tail_id =
                exchange.place(carol, base_token, amount, false, flip_tick)?;

            rewrite_initial_orders_for_layout(
                &mut exchange,
                legacy_mask,
                &[flip_id, resting_bid_id, destination_tail_id],
            )?;
            assert_initial_versions_for_mask(&exchange, legacy_mask, 3)?;

            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;
            exchange.cancel(carol, destination_tail_id)?;
            exchange.swap_exact_amount_out(bob, quote_token, base_token, partial, u128::MAX)?;
            exchange.swap_exact_amount_out(
                bob,
                quote_token,
                base_token,
                amount - partial,
                u128::MAX,
            )?;
            exchange.cancel(alice, resting_bid_id)?;

            let next_order_id = exchange.next_order_id()?;
            let active_orders = (1..next_order_id)
                .map(|id| exchange.get_order(id).ok())
                .collect();
            let bid_level = exchange.books[book_key]
                .tick_level_handler(tick, true)
                .read()?;
            let ask_level = exchange.books[book_key]
                .tick_level_handler(flip_tick, false)
                .read()?;
            let book = exchange.books[book_key].read()?;
            let base_tip20 = TIP20Token::from_address(base_token)?;
            let quote_tip20 = TIP20Token::from_address(quote_token)?;

            Ok(DexMigrationSnapshot {
                next_order_id,
                active_orders,
                bid_level,
                ask_level,
                best_bid_tick: book.best_bid_tick,
                best_ask_tick: book.best_ask_tick,
                alice_internal_base: exchange.balance_of(alice, base_token)?,
                alice_internal_quote: exchange.balance_of(alice, quote_token)?,
                bob_internal_base: exchange.balance_of(bob, base_token)?,
                bob_internal_quote: exchange.balance_of(bob, quote_token)?,
                carol_internal_base: exchange.balance_of(carol, base_token)?,
                carol_internal_quote: exchange.balance_of(carol, quote_token)?,
                alice_wallet_base: base_tip20
                    .balance_of(ITIP20::balanceOfCall { account: alice })?,
                alice_wallet_quote: quote_tip20
                    .balance_of(ITIP20::balanceOfCall { account: alice })?,
                bob_wallet_base: base_tip20.balance_of(ITIP20::balanceOfCall { account: bob })?,
                bob_wallet_quote: quote_tip20.balance_of(ITIP20::balanceOfCall { account: bob })?,
                carol_wallet_base: base_tip20
                    .balance_of(ITIP20::balanceOfCall { account: carol })?,
                carol_wallet_quote: quote_tip20
                    .balance_of(ITIP20::balanceOfCall { account: carol })?,
            })
        })
    }

    fn rewrite_initial_orders_for_layout(
        exchange: &mut StablecoinDEX,
        legacy_mask: u8,
        order_ids: &[u128],
    ) -> StorageResult<()> {
        for (index, order_id) in order_ids.iter().copied().enumerate() {
            if legacy_mask & (1 << index) != 0 {
                let order = exchange.orders.at(order_id).read()?;
                store_legacy_order(&mut exchange.orders.at(order_id), order)?;
            }
        }
        Ok(())
    }

    fn assert_initial_versions_for_mask(
        exchange: &StablecoinDEX,
        legacy_mask: u8,
        len: usize,
    ) -> eyre::Result<()> {
        for index in 0..len {
            let id = index as u128 + 1;
            let version =
                order_version(&exchange.orders.at(id), exchange.orders.at(id).base_slot())?;
            assert_eq!(version == 0, legacy_mask & (1 << index) != 0);
        }
        Ok(())
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OrderSpec {
        maker: Address,
        book_key: B256,
        is_bid: bool,
        tick: i16,
        amount: u128,
        remaining: u128,
        is_flip: bool,
        flip_tick: i16,
    }

    fn arb_address() -> impl Strategy<Value = Address> {
        any::<[u8; 20]>()
            .prop_filter("maker must be nonzero", |bytes| {
                bytes.iter().any(|byte| *byte != 0)
            })
            .prop_map(Address::from)
    }

    fn arb_b256() -> impl Strategy<Value = B256> {
        any::<[u8; 32]>().prop_map(B256::from)
    }

    prop_compose! {
        fn arb_order_spec()(
            maker in arb_address(),
            book_key in arb_b256(),
            is_bid in any::<bool>(),
            tick in any::<i16>(),
            amount_seed in any::<u128>(),
            remaining_seed in any::<u128>(),
            is_flip in any::<bool>(),
            flip_tick in any::<i16>(),
        ) -> OrderSpec {
            let amount = amount_seed.max(1);
            let remaining = (remaining_seed % amount) + 1;
            OrderSpec {
                maker,
                book_key,
                is_bid,
                tick,
                amount,
                remaining,
                is_flip,
                flip_tick,
            }
        }
    }

    fn run_order_storage_linked_list_case(
        layout: OrderLayoutCase,
        order_specs: &[OrderSpec],
        update_seed: usize,
        remove_seed: usize,
        remaining_seed: u128,
        mixed_offset: bool,
    ) -> eyre::Result<Vec<IStablecoinDEX::Order>> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            let mut expected_ids: Vec<u128> = (1..=order_specs.len() as u128).collect();

            exchange
                .next_order_id
                .write(order_specs.len() as u128 + 1)?;

            for (index, order_spec) in order_specs.iter().enumerate() {
                let id = index as u128 + 1;
                let order = test_linked_order(id, order_spec, order_specs.len());
                store_order_for_layout(&mut exchange, layout, mixed_offset, index, order)?;
            }

            assert_initial_versions(&exchange, layout, mixed_offset, order_specs.len())?;
            assert_linked_list_integrity(&exchange, &expected_ids)?;

            let update_index = update_seed % expected_ids.len();
            let update_id = expected_ids[update_index];
            let amount = order_specs[update_index].amount;
            let remaining = (remaining_seed % amount) + 1;
            exchange.orders.at(update_id).write_remaining(remaining)?;

            if expected_ids.len() > 1 {
                let remove_index = remove_seed % expected_ids.len();
                let remove_id = expected_ids[remove_index];
                let prev = if remove_index == 0 {
                    0
                } else {
                    expected_ids[remove_index - 1]
                };
                let next = if remove_index + 1 == expected_ids.len() {
                    0
                } else {
                    expected_ids[remove_index + 1]
                };

                if prev != 0 {
                    exchange.orders.at(prev).write_next(next)?;
                }
                if next != 0 {
                    exchange.orders.at(next).write_prev(prev)?;
                }
                exchange.orders.at(remove_id).delete()?;
                expected_ids.remove(remove_index);

                assert!(exchange.get_order(remove_id).is_err());
            }

            assert_linked_list_integrity(&exchange, &expected_ids)?;
            expected_ids
                .iter()
                .map(|id| exchange.get_order(*id).map(Into::into).map_err(Into::into))
                .collect()
        })
    }

    fn test_linked_order(id: u128, spec: &OrderSpec, len: usize) -> Order {
        let prev = if id == 1 { 0 } else { id - 1 };
        let next = if id == len as u128 { 0 } else { id + 1 };

        Order {
            order_id: id,
            maker: spec.maker,
            book_key: spec.book_key,
            is_bid: spec.is_bid,
            tick: spec.tick,
            amount: spec.amount,
            remaining: spec.remaining,
            prev,
            next,
            is_flip: spec.is_flip,
            flip_tick: spec.flip_tick,
        }
    }

    fn store_order_for_layout(
        exchange: &mut StablecoinDEX,
        layout: OrderLayoutCase,
        mixed_offset: bool,
        index: usize,
        order: Order,
    ) -> StorageResult<()> {
        if should_store_legacy(layout, mixed_offset, index) {
            store_legacy_order(&mut exchange.orders.at(order.order_id()), order)
        } else {
            exchange.orders.at(order.order_id()).write(order)
        }
    }

    fn should_store_legacy(layout: OrderLayoutCase, mixed_offset: bool, index: usize) -> bool {
        match layout {
            OrderLayoutCase::Legacy => true,
            OrderLayoutCase::V1 => false,
            OrderLayoutCase::Mixed => (index + usize::from(mixed_offset)).is_multiple_of(2),
        }
    }

    fn assert_initial_versions(
        exchange: &StablecoinDEX,
        layout: OrderLayoutCase,
        mixed_offset: bool,
        len: usize,
    ) -> eyre::Result<()> {
        let mut saw_legacy = false;
        let mut saw_v1 = false;

        for index in 0..len {
            let id = index as u128 + 1;
            let version =
                order_version(&exchange.orders.at(id), exchange.orders.at(id).base_slot())?;
            let expect_legacy = should_store_legacy(layout, mixed_offset, index);
            assert_eq!(version == 0, expect_legacy);
            saw_legacy |= version == 0;
            saw_v1 |= version == ORDER_VERSION_V1;
        }

        match layout {
            OrderLayoutCase::Legacy => {
                assert!(saw_legacy);
                assert!(!saw_v1);
            }
            OrderLayoutCase::V1 => {
                assert!(!saw_legacy);
                assert!(saw_v1);
            }
            OrderLayoutCase::Mixed if len > 1 => {
                assert!(saw_legacy);
                assert!(saw_v1);
            }
            OrderLayoutCase::Mixed => {
                assert!(saw_legacy || saw_v1);
            }
        }

        Ok(())
    }

    fn assert_linked_list_integrity(
        exchange: &StablecoinDEX,
        expected_ids: &[u128],
    ) -> eyre::Result<()> {
        if expected_ids.is_empty() {
            return Ok(());
        }

        for (index, id) in expected_ids.iter().copied().enumerate() {
            let order = exchange.get_order(id)?;
            let expected_prev = if index == 0 {
                0
            } else {
                expected_ids[index - 1]
            };
            let expected_next = if index + 1 == expected_ids.len() {
                0
            } else {
                expected_ids[index + 1]
            };

            assert_eq!(order.prev(), expected_prev);
            assert_eq!(order.next(), expected_next);
        }

        let mut traversed = Vec::new();
        let mut cursor = expected_ids[0];
        while cursor != 0 {
            assert!(
                !traversed.contains(&cursor),
                "linked list cycle at {cursor}"
            );
            traversed.push(cursor);
            cursor = exchange.get_order(cursor)?.next();
        }

        assert_eq!(traversed, expected_ids);
        Ok(())
    }
}
