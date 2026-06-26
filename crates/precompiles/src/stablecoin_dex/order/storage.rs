//! Versioned storage for stablecoin DEX orders.
//!
//! The DEX business logic uses [`Order`] as its canonical order model. This module translates
//! between that logical type and the physical records stored onchain in the `orders` mapping.
//!
//! Two physical layouts are supported:
//!
//! - [`LegacyOrder`]: the original layout, identical to [`Order`]. Existing records may still be
//!   present in chain state and must remain readable.
//! - [`V1Order`]: the T8+ (TIP-1062) compact layout. It removes fields that can be derived from the
//!   mapping key and packs fields more tightly to reduce storage footprint.
//!
//! [`OrderHandler`] detects the record version on read, exposes field-level handlers for mutable
//! linked-list fields, and lazily migrates legacy records to V1 when they are rewritten.

use super::{__packing_legacy_order, LegacyOrder, ORDER_VERSION_V1, Order};
use crate::{
    error::{Result as StorageResult, TempoPrecompileError},
    storage::{
        Handler, HandlerCache, Layout, LayoutCtx, Slot, Storable, StorableType, StorageCtx,
        StorageKey, StorageOps, packing,
    },
};
use alloy::primitives::{Address, B256, FixedBytes, U256};
use std::{
    cell::Cell,
    ops::{Index, IndexMut},
};
use tempo_precompiles_macros::Storable;

/// Physical storage layout version for an order record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
#[repr(u8)]
pub(crate) enum OrderVersion {
    /// Original physical layout, identical to the canonical [`Order`] / [`LegacyOrder`] shape.
    Legacy,
    /// T8+ (TIP-1062): Optimized physical layout represented by [`V1Order`].
    V1,
}

impl TryFrom<U256> for OrderVersion {
    type Error = TempoPrecompileError;

    /// Decodes the packed version byte from order slot 0.
    fn try_from(slot0: U256) -> Result<Self, Self::Error> {
        let version = <u8 as Storable>::load(
            &packing::PackedSlot(slot0),
            U256::ZERO,
            LayoutCtx::packed(__packing_v1_order::VERSION_LOC.offset_bytes),
        )?;

        match version {
            0 => Ok(Self::Legacy),
            ORDER_VERSION_V1 => Ok(Self::V1),
            version => Err(TempoPrecompileError::Fatal(format!(
                "unknown stablecoin DEX order storage version {version}"
            ))),
        }
    }
}

/// Compact TIP-1062 physical order layout.
///
/// V1 omits `order_id`; reads synthesize it from the `orders` mapping key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
struct V1Order {
    /// Address of the user who placed the order.
    maker: Address,
    /// Whether this order is a bid (`true`) or ask (`false`).
    is_bid: bool,
    /// Price tick for the order's current side.
    tick: i16,
    /// Whether the order should create an opposite-side order when fully filled.
    is_flip: bool,
    /// Destination tick for a fully filled flip order.
    flip_tick: i16,
    /// Reserved bytes in packed slot 0. Kept zeroed for deterministic encoding and future use.
    _unused: FixedBytes<5>,
    /// Physical layout marker stored in packed slot 0.
    version: OrderVersion,
    /// Orderbook key identifying the trading pair.
    book_key: B256,
    /// Original order amount.
    amount: u128,
    /// Remaining unfilled amount.
    remaining: u128,
    /// Previous order ID in the tick-level FIFO linked list.
    prev: u128,
    /// Next order ID in the tick-level FIFO linked list.
    next: u128,
}

impl V1Order {
    /// Converts the logical order into the compact V1 physical layout.
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

    /// Converts V1 storage back into the logical order, restoring `order_id` from the mapping key.
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

/// Version-aware storage handler for a single DEX order.
#[derive(Debug, Clone)]
pub(crate) struct OrderHandler {
    /// Base storage slot for this order's mapping value.
    base_slot: U256,
    /// Mapping key for this order. V1 storage omits `order_id`, so reads restore it from here.
    order_id: u128,
    /// Contract address whose storage contains the order mapping.
    address: Address,
    /// Cached physical layout version for this record.
    pub(crate) version: Cell<Option<OrderVersion>>,
}

impl OrderHandler {
    #[inline]
    fn new(base_slot: U256, order_id: u128, address: Address) -> Self {
        Self {
            base_slot,
            order_id,
            address,
            version: Cell::new(None),
        }
    }

    /// Returns a storage handler for the order's maker address.
    pub(crate) fn maker(&self) -> StorageResult<Slot<Address>> {
        let loc = match self.version()? {
            OrderVersion::Legacy => __packing_legacy_order::MAKER_LOC,
            OrderVersion::V1 => __packing_v1_order::MAKER_LOC,
        };

        Ok(Slot::new_at_loc(self.base_slot, loc, self.address))
    }

    /// Returns a storage handler for the order's remaining amount.
    pub(crate) fn remaining(&self) -> StorageResult<Slot<u128>> {
        self.u128_field(
            __packing_legacy_order::REMAINING_LOC,
            __packing_v1_order::REMAINING_LOC,
        )
    }

    /// Returns a storage handler for the previous linked-list pointer.
    pub(crate) fn prev(&self) -> StorageResult<Slot<u128>> {
        self.u128_field(
            __packing_legacy_order::PREV_LOC,
            __packing_v1_order::PREV_LOC,
        )
    }

    /// Returns a storage handler for the next linked-list pointer.
    pub(crate) fn next(&self) -> StorageResult<Slot<u128>> {
        self.u128_field(
            __packing_legacy_order::NEXT_LOC,
            __packing_v1_order::NEXT_LOC,
        )
    }

    /// Selects the version-specific location for a mutable `u128` field.
    fn u128_field(
        &self,
        legacy: packing::FieldLocation,
        v1: packing::FieldLocation,
    ) -> StorageResult<Slot<u128>> {
        let loc = match self.version()? {
            OrderVersion::Legacy => legacy,
            OrderVersion::V1 => v1,
        };

        Ok(Slot::new_at_loc(self.base_slot, loc, self.address))
    }

    /// Returns the cached physical storage version, detecting and caching it if needed.
    pub(crate) fn version(&self) -> StorageResult<OrderVersion> {
        if !StorageCtx.spec().is_t8() {
            return Ok(OrderVersion::Legacy);
        }

        if let Some(version) = self.version.get() {
            return Ok(version);
        }

        let version = OrderVersion::try_from(self.load(self.base_slot)?)?;
        self.version.set(Some(version));
        Ok(version)
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
    /// Reads the order using the cached or detected physical layout version.
    fn read(&self) -> StorageResult<Order> {
        match self.version()? {
            OrderVersion::Legacy => LegacyOrder::load(self, self.base_slot, LayoutCtx::FULL),
            OrderVersion::V1 => V1Order::load(self, self.base_slot, LayoutCtx::FULL)
                .map(|res| res.into_order(self.order_id)),
        }
    }

    /// Writes the order, migrating T8 records to V1 and updating the cached version.
    fn write(&mut self, value: Order) -> StorageResult<()> {
        debug_assert_eq!(value.order_id, self.order_id);

        if !StorageCtx.spec().is_t8() {
            value.store(self, self.base_slot, LayoutCtx::FULL)?;
            self.version.set(Some(OrderVersion::Legacy));
            return Ok(());
        }

        match self.version.get() {
            Some(OrderVersion::Legacy) => {
                V1Order::new(value).store(self, self.base_slot, LayoutCtx::FULL)?;
                for offset in V1Order::SLOTS..LegacyOrder::SLOTS {
                    self.store(self.base_slot.wrapping_add(U256::from(offset)), U256::ZERO)?;
                }
            }
            Some(OrderVersion::V1) => {
                V1Order::new(value).store(self, self.base_slot, LayoutCtx::FULL)?;
            }
            None => {
                let current_slot0 = self.load(self.base_slot)?;
                let current_version = OrderVersion::try_from(current_slot0)?;

                V1Order::new(value).store(self, self.base_slot, LayoutCtx::FULL)?;
                if matches!(current_version, OrderVersion::Legacy) && !current_slot0.is_zero() {
                    for offset in V1Order::SLOTS..LegacyOrder::SLOTS {
                        self.store(self.base_slot.wrapping_add(U256::from(offset)), U256::ZERO)?;
                    }
                }
            }
        }

        self.version.set(Some(OrderVersion::V1));
        Ok(())
    }

    /// Deletes the physical slots for the cached or detected order layout.
    fn delete(&mut self) -> StorageResult<()> {
        let slot_count = match self.version()? {
            OrderVersion::Legacy => LegacyOrder::SLOTS,
            OrderVersion::V1 => V1Order::SLOTS,
        };

        for offset in 0..slot_count {
            self.store(self.base_slot.wrapping_add(U256::from(offset)), U256::ZERO)?;
        }

        self.version.set(None);
        Ok(())
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

/// Specialized `Mapping<u128, Order>` wrapper for DEX `orders`, whose handlers retain the order ID.
///
/// It preserves the original mapping base slot and key type while returning handlers that retain
/// the `order_id` key. Version 1 order values no longer store `order_id`, so reads synthesize it
/// from this key.
#[derive(Debug)]
pub(crate) struct OrderMapping {
    /// Base slot of the `orders` mapping.
    base_slot: U256,
    /// Contract address whose storage contains the mapping.
    address: Address,
    /// Per-order handler cache keyed by order ID.
    cache: HandlerCache<u128, OrderHandler>,
}

impl OrderMapping {
    #[inline]
    fn new(base_slot: U256, address: Address) -> Self {
        Self {
            base_slot,
            address,
            cache: HandlerCache::new(),
        }
    }

    /// Returns a cached handler for `order_id`.
    pub(crate) fn at(&self, order_id: u128) -> &OrderHandler {
        let (base_slot, address) = (self.base_slot, self.address);
        self.cache.get_or_insert(&order_id, || {
            OrderHandler::new(order_id.mapping_slot(base_slot), order_id, address)
        })
    }

    /// Returns a mutable cached handler for `order_id`.
    pub(crate) fn at_mut(&mut self, order_id: u128) -> &mut OrderHandler {
        let (base_slot, address) = (self.base_slot, self.address);
        self.cache.get_or_insert_mut(&order_id, || {
            OrderHandler::new(order_id.mapping_slot(base_slot), order_id, address)
        })
    }
}

impl Index<u128> for OrderMapping {
    type Output = OrderHandler;

    /// Returns a cached order handler by order ID.
    fn index(&self, order_id: u128) -> &Self::Output {
        self.at(order_id)
    }
}

impl IndexMut<u128> for OrderMapping {
    /// Returns a mutable cached order handler by order ID.
    fn index_mut(&mut self, order_id: u128) -> &mut Self::Output {
        self.at_mut(order_id)
    }
}

impl Clone for OrderMapping {
    fn clone(&self) -> Self {
        Self::new(self.base_slot, self.address)
    }
}

impl Default for OrderMapping {
    fn default() -> Self {
        Self::new(U256::ZERO, Address::ZERO)
    }
}

impl StorableType for OrderMapping {
    const LAYOUT: Layout = Layout::Slots(1);

    type Handler = Self;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        Self::new(slot, address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        stablecoin_dex::{IStablecoinDEX, StablecoinDEX},
        storage::{ContractStorage, Handler, StorageCtx, hashmap::HashMapStorageProvider},
        storage_credits::StorageCredits,
        test_util::TIP20Setup,
        tip20::{ITIP20, TIP20Token},
        tip403_registry::{ITIP403Registry, TIP403Registry},
    };
    use alloy::primitives::{address, b256};
    use proptest::prelude::*;
    use tempo_chainspec::hardfork::TempoHardfork;

    const TEST_MAKER: Address = address!("0x1111111111111111111111111111111111111111");
    const TEST_BOOK_KEY: B256 =
        b256!("0x0000000000000000000000000000000000000000000000000000000000000001");
    #[test]
    fn test_store_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
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
            exchange.orders[id].write(order)?;

            let loaded_order = exchange.orders[id].read()?;
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
    fn test_t8_store_order_uses_v1_layout() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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
                TempoHardfork::T8,
            )
            .unwrap();
            order.set_prev(7);
            order.set_next(9);

            exchange.orders[id].write(order)?;

            let base_slot = exchange.orders[id].base_slot;
            assert_eq!(exchange.orders[id].version()?, OrderVersion::V1);

            let loaded_order = exchange.orders[id].read()?;
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
    fn test_cached_version_field_write_skips_version_sload() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let id = 42;
            let order = Order::new_bid(id, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);
            exchange.orders[id].write(order)?;

            let uncached_exchange = StablecoinDEX::new();
            StorageCtx.reset_counters();
            uncached_exchange.orders[id].remaining()?.write(900)?;
            assert_eq!(StorageCtx.counter_sload(), 2);

            StorageCtx.reset_counters();
            exchange.orders[id].remaining()?.write(800)?;
            assert_eq!(StorageCtx.counter_sload(), 1);

            let loaded = exchange.orders[id].read()?;
            assert_eq!(loaded.remaining(), 800);

            Ok(())
        })
    }

    #[test]
    fn test_t6_store_order_uses_legacy_layout() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
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
                TempoHardfork::T8,
            )
            .unwrap();
            order.set_prev(7);
            order.set_next(9);

            exchange.orders[id].write(order)?;

            let base_slot = exchange.orders[id].base_slot;
            assert_eq!(exchange.orders[id].version()?, OrderVersion::Legacy);
            assert_eq!(exchange.orders[id].read()?, order);
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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
            store_legacy_order(&exchange.orders[id], order)?;

            assert_eq!(exchange.orders[id].read()?, order);

            exchange.orders[id].remaining()?.write(600)?;
            exchange.orders[id].prev()?.write(11)?;
            exchange.orders[id].next()?.write(12)?;

            let loaded_order = exchange.orders[id].read()?;
            assert_eq!(loaded_order.order_id(), id);
            assert_eq!(loaded_order.remaining(), 600);
            assert_eq!(loaded_order.prev(), 11);
            assert_eq!(loaded_order.next(), 12);

            assert_eq!(exchange.orders[id].version()?, OrderVersion::Legacy);

            Ok(())
        })
    }

    #[test]
    fn test_write_migrates_legacy_order_to_v1_layout() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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
            store_legacy_order(&exchange.orders[id], order)?;

            let base_slot = exchange.orders[id].base_slot;
            assert_eq!(exchange.orders[id].version()?, OrderVersion::Legacy);
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
            exchange.orders[id].write(migrated_order)?;

            assert_eq!(exchange.orders[id].version()?, OrderVersion::V1);
            assert_eq!(exchange.orders[id].read()?, migrated_order);
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

    fn store_legacy_order(handler: &OrderHandler, order: Order) -> StorageResult<()> {
        let mut storage = handler.clone();
        LegacyOrder::store(&order, &mut storage, handler.base_slot, LayoutCtx::FULL)?;
        handler.version.set(Some(OrderVersion::Legacy));
        for offset in LegacyOrder::SLOTS..V1Order::SLOTS {
            storage.store(
                handler.base_slot.wrapping_add(U256::from(offset)),
                U256::ZERO,
            )?;
        }
        Ok(())
    }

    fn legacy_order_slot(order: Order, loc: packing::FieldLocation) -> StorageResult<U256> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let exchange = StablecoinDEX::new();
            let handler = &exchange.orders[order.order_id()];
            let mut storage = handler.clone();
            LegacyOrder::store(&order, &mut storage, handler.base_slot, LayoutCtx::FULL)?;
            StorageCtx.sload(
                exchange.address(),
                handler.base_slot + U256::from(loc.offset_slots),
            )
        })
    }
    #[test]
    fn test_t8_fill_legacy_flip_order_migrates_without_corrupting_book() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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

            let legacy_flip = exchange.orders[flip_id].read()?;
            store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;
            assert_eq!(exchange.orders[flip_id].version()?, OrderVersion::Legacy);
            assert_eq!(exchange.storage_credits(alice)?, 0);
            let pooled_credits_before = StorageCredits::new().balance_of(exchange.address())?;

            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;

            assert!(
                exchange.storage_credits(alice)? > 0,
                "maker must receive TIP-1064 DEX storage credits for slots cleared by legacy -> V1 flip rewrite"
            );
            assert!(
                StorageCredits::new().balance_of(exchange.address())? > pooled_credits_before,
                "legacy -> V1 flip rewrite must still mint DEX TIP-1060 credits for cleared physical slots"
            );

            let flipped = exchange.get_order(flip_id)?;
            assert!(!flipped.is_bid());
            assert_eq!(flipped.tick(), tick);
            assert_eq!(flipped.prev(), 0);
            assert_eq!(flipped.next(), 0);
            assert_eq!(exchange.orders[flip_id].version()?, OrderVersion::V1);

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
    fn test_flip_rewrite_does_not_spend_maker_storage_credits() -> eyre::Result<()> {
        for (placement_fork, rewrite_fork) in [
            (TempoHardfork::T7, TempoHardfork::T7),
            (TempoHardfork::T7, TempoHardfork::T8),
            (TempoHardfork::T8, TempoHardfork::T8),
        ] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, placement_fork);
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
                let bid_escrow =
                    amount * u128::from(bid_price) / u128::from(crate::stablecoin_dex::PRICE_SCALE);

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
                    .with_mint(alice, U256::from(bid_escrow * 3))
                    .with_approval(alice, exchange.address, U256::MAX)
                    .apply()?;

                exchange.create_pair(base_token)?;

                let flip_id =
                    exchange.place_flip(alice, base_token, amount, true, tick, flip_tick, false)?;
                let credit_order_id = exchange.place(alice, base_token, amount, true, tick)?;
                exchange.cancel(alice, credit_order_id)?;
                let credits_before = exchange.storage_credits(alice)?;
                assert!(
                    credits_before > 0,
                    "{placement_fork:?}->{rewrite_fork:?} setup must give maker credits"
                );

                StorageCtx.set_spec(rewrite_fork);

                let destination_tail =
                    exchange.place(carol, base_token, amount, false, flip_tick)?;
                exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;

                let flipped = exchange.get_order(flip_id)?;
                assert!(!flipped.is_bid());
                assert_eq!(flipped.prev(), destination_tail);
                assert!(
                    exchange.storage_credits(alice)? >= credits_before,
                    "{placement_fork:?}->{rewrite_fork:?} flip rewrite spent maker credits"
                );

                Ok::<(), TempoPrecompileError>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_t8_legacy_flip_rewrite_gets_fresh_destination_priority() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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

            let legacy_flip = exchange.orders[flip_id].read()?;
            store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;
            assert_eq!(exchange.orders[flip_id].version()?, OrderVersion::Legacy);

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
            assert_eq!(exchange.orders[flip_id].version()?, OrderVersion::V1);

            Ok(())
        })
    }

    #[test]
    fn test_t8_cancel_migrated_legacy_flip_cleans_destination_queue() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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

            let legacy_flip = exchange.orders[flip_id].read()?;
            store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;

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
    fn test_t8_cancel_stale_migrated_legacy_flip() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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

            let legacy_flip = exchange.orders[flip_id].read()?;
            store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;

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
    fn test_t8_migrated_legacy_flip_can_partially_fill_then_flip_again() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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
            let legacy_flip = exchange.orders[flip_id].read()?;
            store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;

            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;

            let ask_after_migration = exchange.get_order(flip_id)?;
            assert!(!ask_after_migration.is_bid());
            assert_eq!(ask_after_migration.remaining(), amount);
            assert_eq!(exchange.orders[flip_id].version()?, OrderVersion::V1);

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
            assert_eq!(exchange.orders[flip_id].version()?, OrderVersion::V1);

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
    fn test_t8_fill_legacy_head_updates_v1_neighbor() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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
            let legacy_head = exchange.orders[legacy_head_id].read()?;
            store_legacy_order(&exchange.orders[legacy_head_id], legacy_head)?;

            assert_eq!(
                exchange.orders[legacy_head_id].version()?,
                OrderVersion::Legacy
            );
            assert_eq!(exchange.orders[v1_tail_id].version()?, OrderVersion::V1);

            exchange.swap_exact_amount_out(carol, quote_token, base_token, amount, u128::MAX)?;

            assert!(exchange.get_order(legacy_head_id).is_err());

            let v1_tail = exchange.get_order(v1_tail_id)?;
            assert_eq!(v1_tail.prev(), 0);
            assert_eq!(v1_tail.next(), 0);
            assert_eq!(exchange.orders[v1_tail_id].version()?, OrderVersion::V1);

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
    fn test_t8_legacy_flip_failure_deletes_filled_record() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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

            let legacy_flip = exchange.orders[flip_id].read()?;
            store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;

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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let id = 42;
            let base_slot = exchange.orders[id].base_slot;
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
            assert!(exchange.orders[id].read().is_err());
            assert!(exchange.orders[id].write(order).is_err());
            assert!(exchange.orders[id].delete().is_err());

            Ok(())
        })
    }

    #[test]
    fn test_delete_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
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
            exchange.orders[id].write(order)?;
            exchange.orders[id].delete()?;

            let deleted_order = exchange.orders[id].read()?;
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
    fn test_t8_dex_sequence_equivalent_across_order_storage_versions() -> eyre::Result<()> {
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

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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
                let order = exchange.orders[order_id].read()?;
                store_legacy_order(&exchange.orders[order_id], order)?;
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
            let version = exchange.orders[id].version()?;
            assert_eq!(
                version == OrderVersion::Legacy,
                legacy_mask & (1 << index) != 0
            );
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
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
            exchange.orders[update_id].remaining()?.write(remaining)?;

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
                    exchange.orders[prev].next()?.write(next)?;
                }
                if next != 0 {
                    exchange.orders[next].prev()?.write(prev)?;
                }
                exchange.orders[remove_id].delete()?;
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
            store_legacy_order(&exchange.orders[order.order_id()], order)
        } else {
            exchange.orders[order.order_id()].write(order)
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
            let version = exchange.orders[id].version()?;
            let expect_legacy = should_store_legacy(layout, mixed_offset, index);
            assert_eq!(version == OrderVersion::Legacy, expect_legacy);
            saw_legacy |= version == OrderVersion::Legacy;
            saw_v1 |= version == OrderVersion::V1;
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
