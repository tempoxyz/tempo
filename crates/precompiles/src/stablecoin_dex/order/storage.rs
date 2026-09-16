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

use super::{__packing_legacy_order, LegacyOrder, ORDER_VERSION_V1, ORDER_VERSION_V2, Order};
use crate::{
    STABLECOIN_DEX_ADDRESS,
    error::{Result as StorageResult, TempoPrecompileError},
    stablecoin_dex::{self, StablecoinDEX, orderbook::BookId},
    storage::{
        Handler, HandlerCache, Layout, LayoutCtx, Slot, Storable, StorableType, StorageCtx,
        StorageKey, StorageOps, packing,
    },
};
use alloy::primitives::{Address, B256, FixedBytes, U256};
use std::ops::{Index, IndexMut};
use tempo_precompiles_macros::Storable;

/// Physical storage layout version for an order record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
#[repr(u8)]
pub(crate) enum OrderVersion {
    /// Original physical layout, identical to the canonical [`Order`] / [`LegacyOrder`] shape.
    Legacy,
    /// T8+ (TIP-1062): Optimized physical layout represented by [`V1Order`].
    V1,
    /// T8+ (TIP-1087): V1 prefix plus compact book index represented by [`V2Order`].
    V2,
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
            ORDER_VERSION_V2 => Ok(Self::V2),
            version => Err(TempoPrecompileError::Fatal(format!(
                "unknown stablecoin DEX order storage version {version}"
            ))),
        }
    }
}

struct OrderFlags;

impl OrderFlags {
    const IS_BID: u8 = 1 << 0;
    const IS_FLIP: u8 = 1 << 1;

    /// Packs logical order flags into a metadata byte.
    #[inline]
    fn pack(is_bid: bool, is_flip: bool) -> u8 {
        (u8::from(is_bid) * Self::IS_BID) | (u8::from(is_flip) * Self::IS_FLIP)
    }

    /// Returns whether the metadata marks the order as a bid (`true`) or ask (`false`).
    #[inline]
    fn is_bid(metadata: u8) -> bool {
        metadata & Self::IS_BID != 0
    }

    /// Returns whether the metadata marks the order as a flip order.
    #[inline]
    fn is_flip(metadata: u8) -> bool {
        metadata & Self::IS_FLIP != 0
    }
}

/// Compact TIP-1062 physical order layout.
///
/// V1 omits `order_id` by synthesizing it from the `orders` mapping key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
struct V1Order {
    /// Address of the user who placed the order.
    maker: Address,
    /// Packed order metadata. Bit 0 stores `is_bid`; bit 1 stores `is_flip`.
    metadata: u8,
    /// Price tick for the order's current side.
    tick: i16,
    /// Destination tick for a fully filled flip order.
    flip_tick: i16,
    /// Reserved bytes in packed slot 0. Kept zeroed for deterministic encoding and future use.
    _unused: FixedBytes<6>,
    /// Physical layout marker stored in packed slot 0.
    version: OrderVersion,
    /// Original order amount.
    amount: u128,
    /// Remaining unfilled amount.
    remaining: u128,
    /// Previous order ID in the tick-level FIFO linked list.
    prev: u128,
    /// Next order ID in the tick-level FIFO linked list.
    next: u128,
    /// Orderbook key identifying the trading pair.
    book_key: B256,
}

impl V1Order {
    /// Converts the logical order into the compact V1 physical layout.
    fn new(order: Order) -> Self {
        Self {
            maker: order.maker,
            tick: order.tick,
            metadata: OrderFlags::pack(order.is_bid, order.is_flip),
            flip_tick: order.flip_tick,
            _unused: FixedBytes::<6>::ZERO,
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
            is_bid: OrderFlags::is_bid(self.metadata),
            tick: self.tick,
            amount: self.amount,
            remaining: self.remaining,
            prev: self.prev,
            next: self.next,
            is_flip: OrderFlags::is_flip(self.metadata),
            flip_tick: self.flip_tick,
        }
    }
}

/// Compact TIP-1087 physical order layout.
///
/// V2 replaces V1's repeated `book_key` slot with a compact index into the DEX `book_keys` vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
struct V2Order {
    /// Address of the user who placed the order.
    maker: Address,
    /// Packed order metadata. Bit 0 stores `is_bid`; bit 1 stores `is_flip`.
    metadata: u8,
    /// Price tick for the order's current side.
    tick: i16,
    /// Destination tick for a fully filled flip order.
    flip_tick: i16,
    /// Index into the DEX `book_keys` vector.
    book_index: u32,
    /// Reserved bytes in packed slot 0.
    _unused: FixedBytes<2>,
    /// Physical layout marker stored in packed slot 0.
    version: OrderVersion,
    /// Original order amount.
    amount: u128,
    /// Remaining unfilled amount.
    remaining: u128,
    /// Previous order ID in the tick-level FIFO linked list.
    prev: u128,
    /// Next order ID in the tick-level FIFO linked list.
    next: u128,
}

impl V2Order {
    /// Converts the logical order into the compact V2 physical layout.
    fn new(order: Order, book_index: u32) -> Self {
        Self {
            maker: order.maker,
            metadata: OrderFlags::pack(order.is_bid, order.is_flip),
            tick: order.tick,
            flip_tick: order.flip_tick,
            book_index,
            _unused: FixedBytes::<2>::ZERO,
            version: OrderVersion::V2,
            amount: order.amount,
            remaining: order.remaining,
            prev: order.prev,
            next: order.next,
        }
    }

    /// Converts V2 storage back into the logical order, restoring `order_id` and `book_key`.
    fn into_order(self, order_id: u128, book_key: B256) -> Order {
        Order {
            order_id,
            maker: self.maker,
            book_key,
            is_bid: OrderFlags::is_bid(self.metadata),
            tick: self.tick,
            amount: self.amount,
            remaining: self.remaining,
            prev: self.prev,
            next: self.next,
            is_flip: OrderFlags::is_flip(self.metadata),
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

    /// Returns the order's maker address.
    pub(crate) fn maker(&self) -> StorageResult<Address> {
        let (version, slot0) = self.version_and_slot()?;
        let loc = match version {
            OrderVersion::Legacy => __packing_legacy_order::MAKER_LOC,
            OrderVersion::V1 | OrderVersion::V2 => __packing_v1_order::MAKER_LOC,
        };

        // T8+ version detection loads slot 0. We reuse it when the maker is stored there.
        if let Some(slot0) = slot0
            && loc.offset_slots == 0
        {
            Address::load(
                &packing::PackedSlot(slot0),
                U256::ZERO,
                LayoutCtx::packed(loc.offset_bytes),
            )
        } else {
            Slot::new_at_loc(self.base_slot, loc, self.address).read()
        }
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
        compact: packing::FieldLocation,
    ) -> StorageResult<Slot<u128>> {
        let loc = match self.version()? {
            OrderVersion::Legacy => legacy,
            OrderVersion::V1 | OrderVersion::V2 => compact,
        };

        Ok(Slot::new_at_loc(self.base_slot, loc, self.address))
    }

    /// Returns the physical storage version and the loaded base slot, when read.
    pub(crate) fn version_and_slot(&self) -> StorageResult<(OrderVersion, Option<U256>)> {
        if !StorageCtx.spec().is_t8() {
            return Ok((OrderVersion::Legacy, None));
        }

        let slot0 = self.load(self.base_slot)?;
        Ok((OrderVersion::try_from(slot0)?, Some(slot0)))
    }

    /// Returns the physical storage version.
    pub(crate) fn version(&self) -> StorageResult<OrderVersion> {
        self.version_and_slot().map(|(version, _)| version)
    }

    /// Reads this order using a known owning book key, skipping V2 index resolution.
    pub(crate) fn read_in_book(&self, book_key: B256) -> StorageResult<Order> {
        self.read_with_book_key(Some(book_key))
    }

    /// Reads this order, skipping V2 index resolution when a book key is provided.
    fn read_with_book_key(&self, known_book: Option<B256>) -> StorageResult<Order> {
        match self.version()? {
            OrderVersion::Legacy => LegacyOrder::load(self, self.base_slot, LayoutCtx::FULL),
            OrderVersion::V1 => V1Order::load(self, self.base_slot, LayoutCtx::FULL)
                .map(|res| res.into_order(self.order_id)),
            OrderVersion::V2 => {
                let order = V2Order::load(self, self.base_slot, LayoutCtx::FULL)?;
                let book_key = match known_book {
                    None => StablecoinDEX::new().book_key_for_index(order.book_index)?,
                    Some(book_key) => book_key,
                };
                Ok(order.into_order(self.order_id, book_key))
            }
        }
    }

    /// Writes this order using a known owning book ID, skipping index resolution.
    pub(crate) fn write_in_book(&mut self, value: Order, book_id: BookId) -> StorageResult<()> {
        self.write_with_book_id(value, Some(book_id))
    }

    /// Writes this order, skipping V2 index resolution when a book ID is provided.
    fn write_with_book_id(&mut self, value: Order, known_id: Option<BookId>) -> StorageResult<()> {
        debug_assert_eq!(value.order_id, self.order_id);

        if !StorageCtx.spec().is_t8() {
            return value.store(self, self.base_slot, LayoutCtx::FULL);
        }

        let (old_version, slot0) = self.version_and_slot()?;
        let old_slots = match old_version {
            OrderVersion::Legacy => LegacyOrder::SLOTS,
            OrderVersion::V1 => V1Order::SLOTS,
            OrderVersion::V2 => V2Order::SLOTS,
        };

        // If known, use the book ID. Otherwise resolve it from storage.
        let book_index = match known_id {
            None => StablecoinDEX::new().book_key_index(value.book_key)?,
            Some(id) => id.index(),
        };

        let new_slots = if let Some(book_index) = book_index {
            V2Order::new(value, book_index).store(self, self.base_slot, LayoutCtx::FULL)?;
            V2Order::SLOTS
        } else {
            V1Order::new(value).store(self, self.base_slot, LayoutCtx::FULL)?;
            V1Order::SLOTS
        };

        if slot0.is_none_or(|val| !val.is_zero()) {
            for offset in new_slots..old_slots {
                self.store(self.base_slot.wrapping_add(U256::from(offset)), U256::ZERO)?;
            }
        }
        Ok(())
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
        self.read_with_book_key(None)
    }

    /// Writes the order, migrating T8 records to V1/V2.
    fn write(&mut self, value: Order) -> StorageResult<()> {
        self.write_with_book_id(value, None)
    }

    /// Deletes the physical slots for the cached or detected order layout.
    fn delete(&mut self) -> StorageResult<()> {
        let slot_count = match self.version()? {
            OrderVersion::Legacy => LegacyOrder::SLOTS,
            OrderVersion::V1 => V1Order::SLOTS,
            OrderVersion::V2 => V2Order::SLOTS,
        };

        for offset in 0..slot_count {
            self.store(self.base_slot.wrapping_add(U256::from(offset)), U256::ZERO)?;
        }

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

/// Specialized `Mapping<u128, Order>` wrapper for stablecoin DEX `orders`.
///
/// Unlike generic storage mappings, this wrapper is tied to the stablecoin DEX storage layout and
/// address. Handlers retain the `order_id` key because V1 order values no longer store it, so reads
/// synthesize it from this key.
#[derive(Debug)]
pub(crate) struct OrderMapping {
    /// Per-order handler cache keyed by order ID.
    cache: HandlerCache<u128, OrderHandler>,
}

impl OrderMapping {
    #[inline]
    fn new() -> Self {
        Self {
            cache: HandlerCache::new(),
        }
    }

    #[inline]
    fn base_slot() -> U256 {
        stablecoin_dex::slots::ORDERS
    }

    /// Returns a cached handler for `order_id`.
    pub(crate) fn at(&self, order_id: u128) -> &OrderHandler {
        self.cache.get_or_insert(&order_id, || {
            OrderHandler::new(
                order_id.mapping_slot(Self::base_slot()),
                order_id,
                STABLECOIN_DEX_ADDRESS,
            )
        })
    }

    /// Returns a mutable cached handler for `order_id`.
    pub(crate) fn at_mut(&mut self, order_id: u128) -> &mut OrderHandler {
        self.cache.get_or_insert_mut(&order_id, || {
            OrderHandler::new(
                order_id.mapping_slot(Self::base_slot()),
                order_id,
                STABLECOIN_DEX_ADDRESS,
            )
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
        Self::new()
    }
}

impl Default for OrderMapping {
    fn default() -> Self {
        Self::new()
    }
}

impl StorableType for OrderMapping {
    const LAYOUT: Layout = Layout::Slots(1);

    type Handler = Self;

    fn handle(_slot: U256, _ctx: LayoutCtx, _address: Address) -> Self::Handler {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        stablecoin_dex::{
            IStablecoinDEX, MIN_ORDER_AMOUNT, StablecoinDEX, StablecoinDEXError,
            orderbook::{Orderbook, RoundingDirection, base_to_quote},
        },
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
    const TEST_BASE: Address = address!("0x2222222222222222222222222222222222222222");
    const TEST_QUOTE: Address = address!("0x3333333333333333333333333333333333333333");
    const TEST_BOOK_KEY: B256 =
        b256!("0x0000000000000000000000000000000000000000000000000000000000000001");

    #[derive(Default)]
    struct DexTestSetup {
        alice: Address,
        bob: Address,
        carol: Address,
        admin: Address,
        amount: u128,
        tick: i16,
        quote: Address,
        pairs: [(Address, B256); 2],
    }

    impl DexTestSetup {
        fn new(amount: u128, tick: i16) -> Self {
            Self {
                alice: Address::random(),
                bob: Address::random(),
                carol: Address::random(),
                admin: Address::random(),
                amount,
                tick,
                ..Default::default()
            }
        }

        fn hardfork_for(version: OrderVersion) -> TempoHardfork {
            match version {
                OrderVersion::Legacy => TempoHardfork::T7,
                OrderVersion::V1 | OrderVersion::V2 => TempoHardfork::T8,
            }
        }

        fn pair_index(version: OrderVersion) -> usize {
            match version {
                OrderVersion::Legacy | OrderVersion::V1 => 0,
                OrderVersion::V2 => 1,
            }
        }

        fn pair(&self, version: OrderVersion) -> (Address, B256) {
            self.pairs[Self::pair_index(version)]
        }

        fn create_pair(
            &mut self,
            exchange: &mut StablecoinDEX,
            version: OrderVersion,
        ) -> StorageResult<()> {
            let name = match version {
                OrderVersion::Legacy | OrderVersion::V1 => "BASE_V1",
                OrderVersion::V2 => "BASE_V2",
            };
            let salt = match version {
                OrderVersion::Legacy | OrderVersion::V1 => {
                    b256!("0x1111111111111111111111111111111111111111111111111111111111111111")
                }
                OrderVersion::V2 => {
                    b256!("0x2222222222222222222222222222222222222222222222222222222222222222")
                }
            };
            let base = TIP20Setup::create(name, name, self.admin)
                .with_salt(salt)
                .with_issuer(self.admin)
                .with_mint(self.alice, U256::from(self.amount * 3))
                .with_mint(self.bob, U256::from(self.amount * 3))
                .with_mint(self.carol, U256::from(self.amount * 3))
                .apply()?;
            self.quote = base.quote_token()?;

            // Ensure orderbook is created with/out its ID depending on the version
            let prev_spec = StorageCtx.spec();
            let pair_creation_hardfork = match version {
                OrderVersion::Legacy | OrderVersion::V1 => TempoHardfork::T7,
                OrderVersion::V2 => TempoHardfork::T8,
            };
            StorageCtx.set_spec(pair_creation_hardfork);
            exchange.create_pair(base.address())?;
            StorageCtx.set_spec(prev_spec);

            let book_key = stablecoin_dex::orderbook::compute_book_key(base.address(), self.quote);
            self.pairs[Self::pair_index(version)] = (base.address(), book_key);

            Ok(())
        }

        fn setup(mut self, spec: TempoHardfork) -> (Self, HashMapStorageProvider) {
            let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinDEX::new();
                exchange.initialize()?;

                let price = stablecoin_dex::orderbook::tick_to_price(self.tick);
                let quote_amount =
                    self.amount * u128::from(price) / u128::from(stablecoin_dex::PRICE_SCALE);

                TIP20Setup::path_usd(self.admin)
                    .with_issuer(self.admin)
                    .with_mint(self.alice, U256::from(quote_amount * 3))
                    .with_mint(self.bob, U256::from(quote_amount * 3))
                    .with_mint(self.carol, U256::from(quote_amount * 3))
                    .with_approval(self.alice, exchange.address, U256::MAX)
                    .with_approval(self.bob, exchange.address, U256::MAX)
                    .with_approval(self.carol, exchange.address, U256::MAX)
                    .apply()?;

                // `V1Order`s require orderbooks WITHOUT `OrderbookId`
                self.create_pair(&mut exchange, OrderVersion::V1)?;

                // `V2Order`s require orderbooks WITH `OrderbookId`
                self.create_pair(&mut exchange, OrderVersion::V2)?;

                TIP20Setup::config(self.quote)
                    .with_mint(self.alice, U256::from(quote_amount * 3))
                    .with_mint(self.bob, U256::from(quote_amount * 3))
                    .with_mint(self.carol, U256::from(quote_amount * 3))
                    .with_approval(self.alice, exchange.address, U256::MAX)
                    .with_approval(self.bob, exchange.address, U256::MAX)
                    .with_approval(self.carol, exchange.address, U256::MAX)
                    .apply()?;

                Ok::<_, TempoPrecompileError>(())
            })
            .unwrap();

            (self, storage)
        }
    }

    #[test]
    fn test_v1_order_layout_matches_tip_1062() {
        assert_eq!(__packing_v1_order::MAKER_LOC.offset_slots, 0);
        assert_eq!(__packing_v1_order::METADATA_LOC.offset_slots, 0);
        assert_eq!(__packing_v1_order::METADATA_LOC.size, 1);
        assert_eq!(__packing_v1_order::TICK_LOC.offset_slots, 0);
        assert_eq!(__packing_v1_order::FLIP_TICK_LOC.offset_slots, 0);
        assert_eq!(__packing_v1_order::VERSION_LOC.offset_slots, 0);
        assert_eq!(__packing_v1_order::BOOK_KEY_LOC.offset_bytes, 0);
        assert_eq!(__packing_v1_order::BOOK_KEY_LOC.size, 32);
        assert_eq!(
            __packing_v1_order::AMOUNT_LOC.offset_slots,
            __packing_v1_order::REMAINING_LOC.offset_slots
        );
        assert_eq!(
            __packing_v1_order::PREV_LOC.offset_slots,
            __packing_v1_order::NEXT_LOC.offset_slots
        );
        assert_eq!(V1Order::SLOTS, 4);
        assert_eq!(LegacyOrder::SLOTS, 6);
    }

    #[test]
    fn test_v2_order_layout_matches_tip_1087() {
        assert_eq!(__packing_v2_order::MAKER_LOC.offset_slots, 0);
        assert_eq!(__packing_v2_order::METADATA_LOC.offset_slots, 0);
        assert_eq!(__packing_v2_order::METADATA_LOC.size, 1);
        assert_eq!(__packing_v2_order::TICK_LOC.offset_slots, 0);
        assert_eq!(__packing_v2_order::FLIP_TICK_LOC.offset_slots, 0);
        assert_eq!(__packing_v2_order::BOOK_INDEX_LOC.offset_slots, 0);
        assert_eq!(__packing_v2_order::BOOK_INDEX_LOC.size, 4);
        assert_eq!(__packing_v2_order::VERSION_LOC.offset_slots, 0);
        assert_eq!(
            __packing_v2_order::AMOUNT_LOC.offset_slots,
            __packing_v2_order::REMAINING_LOC.offset_slots
        );
        assert_eq!(
            __packing_v2_order::PREV_LOC.offset_slots,
            __packing_v2_order::NEXT_LOC.offset_slots
        );
        assert_eq!(V2Order::SLOTS, 3);
        assert_eq!(V1Order::SLOTS, 4);
    }

    #[test]
    fn test_store_order_uses_expected_layout() -> eyre::Result<()> {
        let (amount, tick, flip_tick) = (MIN_ORDER_AMOUNT, 5i16, 10i16);
        let (test, mut storage) = DexTestSetup::new(amount, 100).setup(TempoHardfork::T7);

        for (i, version) in [OrderVersion::Legacy, OrderVersion::V1, OrderVersion::V2]
            .into_iter()
            .enumerate()
        {
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                StorageCtx.set_spec(DexTestSetup::hardfork_for(version));

                let mut exchange = StablecoinDEX::new();
                let (_, book_key) = test.pair(version);
                let id = 10 + i as u128;

                let mut order = Order::new_flip(
                    id,
                    TEST_MAKER,
                    book_key,
                    amount,
                    tick,
                    true,
                    flip_tick,
                    StorageCtx.spec(),
                )?;
                order.set_prev(id - 1);
                order.set_next(id + 1);

                exchange.orders[id].write(order)?;

                let base_slot = exchange.orders[id].base_slot;
                assert_eq!(exchange.orders[id].version()?, version);
                assert_eq!(exchange.orders[id].read()?, order);

                let assert_slot_value = |loc: packing::FieldLocation, expected: U256| {
                    let value = StorageCtx
                        .sload(exchange.address(), base_slot + U256::from(loc.offset_slots))
                        .expect("SLOAD failed");
                    assert_eq!(value, expected);
                };

                match version {
                    OrderVersion::Legacy => {
                        let remaining_sload =
                            legacy_order_slot(order, __packing_legacy_order::REMAINING_LOC)?;
                        let next_sload =
                            legacy_order_slot(order, __packing_legacy_order::NEXT_LOC)?;

                        assert_slot_value(__packing_legacy_order::REMAINING_LOC, remaining_sload);
                        assert_slot_value(__packing_legacy_order::NEXT_LOC, next_sload);
                    }
                    OrderVersion::V1 => {
                        // `V1Order` writes do not use legacy-only slots 4 and 5.
                        assert_slot_value(__packing_legacy_order::REMAINING_LOC, U256::ZERO);
                        assert_slot_value(__packing_legacy_order::NEXT_LOC, U256::ZERO);
                    }
                    OrderVersion::V2 => {
                        // `V2Order` writes do not use legacy-only slots 4 and 5.
                        assert_slot_value(__packing_legacy_order::REMAINING_LOC, U256::ZERO);
                        assert_slot_value(__packing_legacy_order::NEXT_LOC, U256::ZERO);
                        // `V2Order` writes do not use `V1Order` slots 3.
                        assert_slot_value(__packing_v1_order::BOOK_KEY_LOC, U256::ZERO);
                    }
                }
                Ok(())
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_can_delete_any_order_layout() -> eyre::Result<()> {
        let (amount, tick, flip_tick) = (MIN_ORDER_AMOUNT, 5i16, 10i16);
        let (test, mut storage) = DexTestSetup::new(amount, 100).setup(TempoHardfork::T8);

        for (i, version) in [OrderVersion::Legacy, OrderVersion::V1, OrderVersion::V2]
            .into_iter()
            .enumerate()
        {
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                let mut exchange = StablecoinDEX::new();
                let (_, book_key) = test.pair(version);

                // Create 2 orders of each version
                StorageCtx.set_spec(DexTestSetup::hardfork_for(version));
                for n in [10, 20] {
                    let id = n + i as u128;

                    let order = Order::new_flip(
                        id,
                        TEST_MAKER,
                        book_key,
                        amount,
                        tick,
                        true,
                        flip_tick,
                        StorageCtx.spec(),
                    )?;
                    exchange.orders[id].write(order)?;
                    assert_eq!(exchange.orders[id].version()?, version);
                    assert_eq!(exchange.orders[id].read()?, order);
                }

                // Verify orders are properly deleted regardless of hardfork
                for (n, hardfork) in [(10, TempoHardfork::T7), (20, TempoHardfork::T8)] {
                    StorageCtx.set_spec(hardfork);
                    let id = n + i as u128;

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
                }

                Ok(())
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_t8_can_read_and_mutate_any_order_layout() -> eyre::Result<()> {
        let (amount, tick, flip_tick) = (MIN_ORDER_AMOUNT, 5i16, 10i16);
        let (test, mut storage) = DexTestSetup::new(amount, 100).setup(TempoHardfork::T8);

        for (i, version) in [OrderVersion::Legacy, OrderVersion::V1, OrderVersion::V2]
            .into_iter()
            .enumerate()
        {
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                let mut exchange = StablecoinDEX::new();
                let (_, book_key) = test.pair(version);
                let id = 10 + i as u128;

                let mut order = Order::new_flip(
                    id,
                    TEST_MAKER,
                    book_key,
                    amount,
                    tick,
                    true,
                    flip_tick,
                    StorageCtx.spec(),
                )?;
                order.set_prev(id - 1);
                order.set_next(id + 1);

                if version == OrderVersion::Legacy {
                    store_legacy_order(&exchange.orders[id], order)?;
                } else {
                    exchange.orders[id].write(order)?;
                }

                assert_eq!(exchange.orders[id].version()?, version);
                assert_eq!(exchange.orders[id].read()?, order);

                exchange.orders[id].remaining()?.write(600)?;
                exchange.orders[id].prev()?.write(11)?;
                exchange.orders[id].next()?.write(12)?;

                let loaded_order = exchange.orders[id].read()?;
                assert_eq!(loaded_order.order_id(), id);
                assert_eq!(loaded_order.book_key(), book_key);
                assert_eq!(loaded_order.remaining(), 600);
                assert_eq!(loaded_order.prev(), 11);
                assert_eq!(loaded_order.next(), 12);
                assert_eq!(exchange.orders[id].version()?, version);

                Ok(())
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_t8_write_migrates_legacy_order_layout() -> eyre::Result<()> {
        let (amount, tick, flip_tick) = (MIN_ORDER_AMOUNT, 5i16, 10i16);
        let (test, mut storage) = DexTestSetup::new(amount, 100).setup(TempoHardfork::T7);

        for (i, version) in [OrderVersion::V1, OrderVersion::V2].into_iter().enumerate() {
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                StorageCtx.set_spec(TempoHardfork::T8);
                let mut exchange = StablecoinDEX::new();
                let (_, book_key) = test.pair(version);
                let id = 10 + i as u128;

                let mut order = Order::new_flip(
                    id,
                    TEST_MAKER,
                    book_key,
                    amount,
                    tick,
                    true,
                    flip_tick,
                    StorageCtx.spec(),
                )?;
                order.set_prev(id - 1);
                order.set_next(id + 1);
                exchange.next_order_id.write(id + 1)?;
                store_legacy_order(&exchange.orders[id], order)?;

                let base_slot = exchange.orders[id].base_slot;
                let assert_slot_value = |loc: packing::FieldLocation, expected: U256| {
                    let value = StorageCtx
                        .sload(
                            STABLECOIN_DEX_ADDRESS,
                            base_slot + U256::from(loc.offset_slots),
                        )
                        .expect("SLOAD failed");
                    assert_eq!(value, expected);
                };

                assert_eq!(exchange.orders[id].version()?, OrderVersion::Legacy);
                // Legacy orders use legacy-only slots 4 and 5.
                let remaining_sload =
                    legacy_order_slot(order, __packing_legacy_order::REMAINING_LOC)?;
                let next_sload = legacy_order_slot(order, __packing_legacy_order::NEXT_LOC)?;
                assert_slot_value(__packing_legacy_order::REMAINING_LOC, remaining_sload);
                assert_slot_value(__packing_legacy_order::NEXT_LOC, next_sload);

                let mut migrated_order = order;
                migrated_order.fill(250).unwrap();
                migrated_order.set_prev(11);
                migrated_order.set_next(12);
                exchange.orders[id].write(migrated_order)?;

                assert_eq!(exchange.orders[id].version()?, version);
                assert_eq!(exchange.orders[id].read()?, migrated_order);
                assert_eq!(
                    IStablecoinDEX::Order::from(exchange.get_order(id)?),
                    migrated_order.into()
                );

                // Migrating to compact layouts clears legacy-only slots 4 and 5.
                assert_slot_value(__packing_legacy_order::REMAINING_LOC, U256::ZERO);
                assert_slot_value(__packing_legacy_order::NEXT_LOC, U256::ZERO);

                if matches!(version, OrderVersion::V2) {
                    // `V2Order` migrations also clear the `V1Order` book key slot.
                    assert_slot_value(__packing_v1_order::BOOK_KEY_LOC, U256::ZERO);
                }

                Ok(())
            })?;
        }

        Ok(())
    }

    fn store_legacy_order(handler: &OrderHandler, order: Order) -> StorageResult<()> {
        let mut storage = handler.clone();
        LegacyOrder::store(&order, &mut storage, handler.base_slot, LayoutCtx::FULL)
    }

    fn store_versioned_order(
        exchange: &mut StablecoinDEX,
        version: OrderVersion,
        order: Order,
    ) -> StorageResult<()> {
        match version {
            OrderVersion::Legacy => store_legacy_order(&exchange.orders[order.order_id()], order),
            OrderVersion::V1 => {
                let handler = &exchange.orders[order.order_id()];
                let mut storage = handler.clone();
                V1Order::new(order).store(&mut storage, handler.base_slot, LayoutCtx::FULL)
            }
            OrderVersion::V2 => {
                let book_index = ensure_test_book_index(exchange, order.book_key)?;
                let handler = &exchange.orders[order.order_id()];
                let mut storage = handler.clone();
                V2Order::new(order, book_index).store(
                    &mut storage,
                    handler.base_slot,
                    LayoutCtx::FULL,
                )
            }
        }
    }

    fn ensure_test_book_index(exchange: &mut StablecoinDEX, book_key: B256) -> StorageResult<u32> {
        match exchange.book_key_index(book_key) {
            Ok(Some(index)) => Ok(index),
            Ok(None) => {
                let index = exchange.book_keys.len()? as u32;
                exchange.book_keys.push(book_key)?;
                exchange.set_book_index(index)?;
                Ok(index)
            }
            Err(TempoPrecompileError::StablecoinDEX(StablecoinDEXError::PairDoesNotExist(_))) => {
                let index = exchange.book_keys.len()? as u32;
                exchange.books[book_key]
                    .write(Orderbook::new_with_index(TEST_BASE, TEST_QUOTE, index))?;
                exchange.book_keys.push(book_key)?;
                Ok(index)
            }
            Err(err) => Err(err),
        }
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
        let (amount, tick) = (MIN_ORDER_AMOUNT, 100i16);
        let (test, mut storage) = DexTestSetup::new(amount, tick).setup(TempoHardfork::T8);

        for version in [OrderVersion::V1, OrderVersion::V2] {
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinDEX::new();
                let (base_token, book_key) = test.pair(version);

                let flip_id =
                    exchange.place_flip(test.alice, base_token, amount, true, tick, tick, false)?;
                let resting_id = exchange.place(test.alice, base_token, amount, true, tick)?;

                let legacy_flip = exchange.orders[flip_id].read()?;
                store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;
                assert_eq!(exchange.orders[flip_id].version()?, OrderVersion::Legacy);
                assert_eq!(exchange.storage_credits(test.alice)?, 0);
                let pooled_credits_before = StorageCredits::new().balance_of(exchange.address())?;

                exchange.swap_exact_amount_in(test.bob, base_token, test.quote, amount, 0)?;

                assert!(
                    exchange.storage_credits(test.alice)? > 0,
                    "maker must receive TIP-1064 DEX storage credits for slots cleared by legacy -> V1/V2 flip rewrite"
                );
                assert!(
                    StorageCredits::new().balance_of(exchange.address())? > pooled_credits_before,
                    "legacy -> V1/V2 flip rewrite must still mint DEX TIP-1060 credits for cleared physical slots"
                );

                let flipped = exchange.get_order(flip_id)?;
                assert!(!flipped.is_bid());
                assert_eq!(flipped.tick(), tick);
                assert_eq!(flipped.prev(), 0);
                assert_eq!(flipped.next(), 0);
                assert_eq!(exchange.orders[flip_id].version()?, version);

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

                Ok::<_, TempoPrecompileError>(())
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_flip_rewrite_does_not_spend_maker_storage_credits() -> eyre::Result<()> {
        let (amount, tick, flip_tick) = (MIN_ORDER_AMOUNT, 100i16, 200i16);

        for (placement_fork, version) in [
            (TempoHardfork::T7, OrderVersion::Legacy),
            (TempoHardfork::T7, OrderVersion::V1),
            (TempoHardfork::T7, OrderVersion::V2),
            (TempoHardfork::T8, OrderVersion::V1),
            (TempoHardfork::T8, OrderVersion::V2),
        ] {
            let (test, mut storage) = DexTestSetup::new(amount, tick).setup(placement_fork);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinDEX::new();
                let (base_token, _) = test.pair(version);

                let flip_id = exchange
                    .place_flip(test.alice, base_token, amount, true, tick, flip_tick, false)?;
                let credit_order_id = exchange.place(test.alice, base_token, amount, true, tick)?;
                exchange.cancel(test.alice, credit_order_id)?;

                let credits_before = exchange.storage_credits(test.alice)?;
                assert!(
                    credits_before > 0,
                    "{placement_fork:?} setup must give maker credits"
                );

                let rewrite_fork = DexTestSetup::hardfork_for(version);
                StorageCtx.set_spec(rewrite_fork);

                let destination_tail =
                    exchange.place(test.carol, base_token, amount, false, flip_tick)?;
                exchange.swap_exact_amount_in(test.bob, base_token, test.quote, amount, 0)?;

                let flipped = exchange.get_order(flip_id)?;
                assert!(!flipped.is_bid());
                assert_eq!(flipped.prev(), destination_tail);
                assert!(
                    exchange.storage_credits(test.alice)? >= credits_before,
                    "{placement_fork:?}->{rewrite_fork:?} flip rewrite spent maker credits"
                );

                Ok::<(), TempoPrecompileError>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_t8_legacy_flip_rewrite_gets_fresh_destination_priority() -> eyre::Result<()> {
        let (amount, tick, flip_tick) = (MIN_ORDER_AMOUNT, 100i16, 200i16);
        let (test, mut storage) = DexTestSetup::new(amount, tick).setup(TempoHardfork::T8);

        for version in [OrderVersion::V1, OrderVersion::V2] {
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinDEX::new();
                let (base_token, book_key) = test.pair(version);

                let flip_id = exchange
                    .place_flip(test.alice, base_token, amount, true, tick, flip_tick, false)?;
                let source_next_id = exchange.place(test.alice, base_token, amount, true, tick)?;
                let destination_tail_id =
                    exchange.place(test.carol, base_token, amount, false, flip_tick)?;

                let legacy_flip = exchange.orders[flip_id].read()?;
                store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;
                assert_eq!(exchange.orders[flip_id].version()?, OrderVersion::Legacy);

                exchange.swap_exact_amount_in(test.bob, base_token, test.quote, amount, 0)?;

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
                assert_eq!(exchange.orders[flip_id].version()?, version);

                Ok::<_, TempoPrecompileError>(())
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_t8_cancel_migrated_legacy_flip_cleans_destination_queue() -> eyre::Result<()> {
        let (amount, tick, flip_tick) = (MIN_ORDER_AMOUNT, 100i16, 200i16);
        let (test, mut storage) = DexTestSetup::new(amount, tick).setup(TempoHardfork::T8);

        for version in [OrderVersion::V1, OrderVersion::V2] {
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                let mut exchange = StablecoinDEX::new();
                let (base_token, book_key) = test.pair(version);

                let flip_id = exchange
                    .place_flip(test.alice, base_token, amount, true, tick, flip_tick, false)?;
                let source_next_id = exchange.place(test.alice, base_token, amount, true, tick)?;
                let destination_tail_id =
                    exchange.place(test.carol, base_token, amount, false, flip_tick)?;

                let legacy_flip = exchange.orders[flip_id].read()?;
                store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;

                exchange.swap_exact_amount_in(test.bob, base_token, test.quote, amount, 0)?;
                assert_eq!(exchange.orders[flip_id].version()?, version);

                exchange.cancel(test.alice, flip_id)?;

                assert!(exchange.get_order(flip_id).is_err());
                assert_eq!(exchange.balance_of(test.alice, base_token)?, amount);

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
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_t8_cancel_stale_migrated_legacy_flip() -> eyre::Result<()> {
        let (amount, tick, flip_tick) = (MIN_ORDER_AMOUNT, 100i16, 200i16);
        let (test, mut storage) = DexTestSetup::new(amount, tick).setup(TempoHardfork::T8);

        for version in [OrderVersion::V1, OrderVersion::V2] {
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                let mut exchange = StablecoinDEX::new();
                let (base_token, book_key) = test.pair(version);

                let flip_id = exchange
                    .place_flip(test.alice, base_token, amount, true, tick, flip_tick, false)?;
                let source_next_id = exchange.place(test.alice, base_token, amount, true, tick)?;
                let destination_tail_id =
                    exchange.place(test.carol, base_token, amount, false, flip_tick)?;

                let legacy_flip = exchange.orders[flip_id].read()?;
                store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;

                exchange.swap_exact_amount_in(test.bob, base_token, test.quote, amount, 0)?;
                assert_eq!(exchange.orders[flip_id].version()?, version);

                let mut registry = TIP403Registry::new();
                let policy_id = registry.create_policy(
                    test.admin,
                    ITIP403Registry::createPolicyCall {
                        admin: test.admin,
                        policyType: ITIP403Registry::PolicyType::BLACKLIST,
                    },
                )?;
                let mut base = TIP20Token::from_address(base_token)?;
                base.change_transfer_policy_id(
                    test.admin,
                    ITIP20::changeTransferPolicyIdCall {
                        newPolicyId: policy_id,
                    },
                )?;
                registry.modify_policy_blacklist(
                    test.admin,
                    ITIP403Registry::modifyPolicyBlacklistCall {
                        policyId: policy_id,
                        account: test.alice,
                        restricted: true,
                    },
                )?;

                exchange.cancel_stale_order(flip_id)?;

                assert!(exchange.get_order(flip_id).is_err());
                assert_eq!(exchange.balance_of(test.alice, base_token)?, amount);

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
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_t8_migrated_legacy_flip_can_partially_fill_then_flip_again() -> eyre::Result<()> {
        let (amount, tick) = (MIN_ORDER_AMOUNT, 100i16);
        let partial = amount / 2;
        let (test, mut storage) = DexTestSetup::new(amount, tick).setup(TempoHardfork::T8);

        for version in [OrderVersion::V1, OrderVersion::V2] {
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                let mut exchange = StablecoinDEX::new();
                let (base_token, book_key) = test.pair(version);

                let flip_id =
                    exchange.place_flip(test.alice, base_token, amount, true, tick, tick, false)?;
                let legacy_flip = exchange.orders[flip_id].read()?;
                store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;

                exchange.swap_exact_amount_in(test.bob, base_token, test.quote, amount, 0)?;

                let ask_after_migration = exchange.get_order(flip_id)?;
                assert!(!ask_after_migration.is_bid());
                assert_eq!(ask_after_migration.remaining(), amount);
                assert_eq!(exchange.orders[flip_id].version()?, version);

                exchange.swap_exact_amount_out(
                    test.bob,
                    test.quote,
                    base_token,
                    partial,
                    u128::MAX,
                )?;
                let partially_filled_ask = exchange.get_order(flip_id)?;
                assert!(!partially_filled_ask.is_bid());
                assert_eq!(partially_filled_ask.remaining(), amount - partial);

                exchange.swap_exact_amount_out(
                    test.bob,
                    test.quote,
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
                assert_eq!(exchange.orders[flip_id].version()?, version);

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
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_t8_fill_legacy_head_updates_v1_and_v2_neighbors() -> eyre::Result<()> {
        let (amount, tick) = (MIN_ORDER_AMOUNT, 100i16);
        let (test, mut storage) = DexTestSetup::new(amount, tick).setup(TempoHardfork::T7);

        for version in [OrderVersion::V1, OrderVersion::V2] {
            StorageCtx::enter(&mut storage, || {
                StorageCtx.set_spec(TempoHardfork::T8);
                let mut exchange = StablecoinDEX::new();
                let (base_token, book_key) = test.pair(version);
                let legacy_head_id = exchange.place(test.alice, base_token, amount, false, tick)?;
                let new_tail_id = exchange.place(test.bob, base_token, amount, false, tick)?;
                let legacy_head = exchange.orders[legacy_head_id].read()?;
                store_legacy_order(&exchange.orders[legacy_head_id], legacy_head)?;

                assert_eq!(
                    exchange.orders[legacy_head_id].version()?,
                    OrderVersion::Legacy
                );
                assert_eq!(exchange.orders[new_tail_id].version()?, version);

                exchange.swap_exact_amount_out(
                    test.carol,
                    test.quote,
                    base_token,
                    amount,
                    u128::MAX,
                )?;

                assert!(exchange.get_order(legacy_head_id).is_err());

                let new_tail = exchange.get_order(new_tail_id)?;
                assert_eq!(new_tail.prev(), 0);
                assert_eq!(new_tail.next(), 0);
                assert_eq!(exchange.orders[new_tail_id].version()?, version);

                let ask_level = exchange.books[book_key]
                    .tick_level_handler(tick, false)
                    .read()?;
                assert_eq!(ask_level.head, new_tail_id);
                assert_eq!(ask_level.tail, new_tail_id);
                assert_eq!(ask_level.total_liquidity, amount);

                Ok::<_, TempoPrecompileError>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_t8_legacy_flip_failure_deletes_filled_record() -> eyre::Result<()> {
        let (amount, tick, flip_tick) = (MIN_ORDER_AMOUNT, 100i16, 200i16);

        for version in [OrderVersion::V1, OrderVersion::V2] {
            let (test, mut storage) = DexTestSetup::new(amount, tick).setup(TempoHardfork::T8);

            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                let mut exchange = StablecoinDEX::new();
                let (base_token, book_key) = test.pair(version);

                let flip_id = exchange
                    .place_flip(test.alice, base_token, amount, true, tick, flip_tick, false)?;
                let source_next_id = exchange.place(test.alice, base_token, amount, true, tick)?;

                let legacy_flip = exchange.orders[flip_id].read()?;
                store_legacy_order(&exchange.orders[flip_id], legacy_flip)?;

                let mut registry = TIP403Registry::new();
                let policy_id = registry.create_policy(
                    test.admin,
                    ITIP403Registry::createPolicyCall {
                        admin: test.admin,
                        policyType: ITIP403Registry::PolicyType::BLACKLIST,
                    },
                )?;
                let mut quote = TIP20Token::from_address(test.quote)?;
                quote.change_transfer_policy_id(
                    test.admin,
                    ITIP20::changeTransferPolicyIdCall {
                        newPolicyId: policy_id,
                    },
                )?;
                registry.modify_policy_blacklist(
                    test.admin,
                    ITIP403Registry::modifyPolicyBlacklistCall {
                        policyId: policy_id,
                        account: test.alice,
                        restricted: true,
                    },
                )?;

                exchange.swap_exact_amount_in(test.bob, base_token, test.quote, amount, 0)?;

                assert!(exchange.get_order(flip_id).is_err());
                assert!(
                    exchange.cancel(test.alice, flip_id).is_err(),
                    "filled flip record must not remain cancellable after failed re-flip"
                );
                assert_eq!(
                    exchange.balance_of(test.alice, base_token)?,
                    amount,
                    "maker keeps the legitimate proceeds from the filled bid"
                );
                assert_eq!(
                    exchange.balance_of(test.alice, test.quote)?,
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
            })?;
        }

        Ok(())
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
                &3,
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
            let v2 = run_order_storage_linked_list_case(
                OrderLayoutCase::V2,
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
            prop_assert_eq!(&legacy, &v2);
            prop_assert_eq!(&legacy, &mixed);
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OrderLayoutCase {
        Legacy,
        V1,
        V2,
        Mixed,
    }

    impl OrderLayoutCase {
        fn version_at(self, index: usize, mixed_offset: bool) -> OrderVersion {
            match self {
                Self::Legacy => OrderVersion::Legacy,
                Self::V1 => OrderVersion::V1,
                Self::V2 => OrderVersion::V2,
                Self::Mixed => match (index + usize::from(mixed_offset)) % 3 {
                    0 => OrderVersion::Legacy,
                    1 => OrderVersion::V1,
                    _ => OrderVersion::V2,
                },
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DexMigrationSnapshot {
        next_order_id: u128,
        active_orders: Vec<Option<Order>>,
        bid_level: stablecoin_dex::orderbook::TickLevel,
        ask_level: stablecoin_dex::orderbook::TickLevel,
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
        let v1 = run_dex_migration_sequence_case(OrderVersion::V1, 0)?;
        let v2 = run_dex_migration_sequence_case(OrderVersion::V2, 0)?;

        let without_order_book_keys = |snapshot: &DexMigrationSnapshot| {
            let mut normalized = snapshot.clone();
            for order in normalized.active_orders.iter_mut().flatten() {
                order.book_key = B256::ZERO;
            }
            normalized
        };
        assert_eq!(without_order_book_keys(&v1), without_order_book_keys(&v2));

        for legacy_mask in 1..(1u8 << 3) {
            assert_eq!(
                v1,
                run_dex_migration_sequence_case(OrderVersion::V1, legacy_mask)?,
                "v1 legacy mask {legacy_mask:03b}"
            );
            assert_eq!(
                v2,
                run_dex_migration_sequence_case(OrderVersion::V2, legacy_mask)?,
                "v2 legacy mask {legacy_mask:03b}"
            );
        }

        Ok(())
    }

    fn run_dex_migration_sequence_case(
        version: OrderVersion,
        legacy_mask: u8,
    ) -> eyre::Result<DexMigrationSnapshot> {
        let amount = MIN_ORDER_AMOUNT;
        let partial = amount / 2;
        let tick = 100i16;
        let flip_tick = 200i16;
        let ask_quote = base_to_quote(amount, flip_tick, RoundingDirection::Up)
            .ok_or(TempoPrecompileError::under_overflow())?;

        let test = DexTestSetup {
            admin: address!("0x1000000000000000000000000000000000000001"),
            alice: address!("0x1000000000000000000000000000000000000002"),
            bob: address!("0x1000000000000000000000000000000000000003"),
            carol: address!("0x1000000000000000000000000000000000000004"),
            ..DexTestSetup::new(amount, tick)
        };
        let (test, mut storage) = test.setup(TempoHardfork::T8);

        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            let (base_token, book_key) = test.pair(version);
            let quote_token = test.quote;

            TIP20Setup::config(quote_token)
                .with_mint(test.bob, U256::from(ask_quote * 2))
                .apply()?;

            let flip_id = exchange
                .place_flip(test.alice, base_token, amount, true, tick, flip_tick, false)?;
            let resting_bid_id = exchange.place(test.alice, base_token, amount, true, tick)?;
            let destination_tail_id =
                exchange.place(test.carol, base_token, amount, false, flip_tick)?;

            rewrite_initial_orders_for_layout(
                &mut exchange,
                legacy_mask,
                &[flip_id, resting_bid_id, destination_tail_id],
            )?;
            assert_initial_versions_for_mask(&exchange, version, legacy_mask, 3)?;

            exchange.swap_exact_amount_in(test.bob, base_token, quote_token, amount, 0)?;
            exchange.cancel(test.carol, destination_tail_id)?;
            exchange.swap_exact_amount_out(
                test.bob,
                quote_token,
                base_token,
                partial,
                u128::MAX,
            )?;
            exchange.swap_exact_amount_out(
                test.bob,
                quote_token,
                base_token,
                amount - partial,
                u128::MAX,
            )?;
            exchange.cancel(test.alice, resting_bid_id)?;

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
                alice_internal_base: exchange.balance_of(test.alice, base_token)?,
                alice_internal_quote: exchange.balance_of(test.alice, quote_token)?,
                bob_internal_base: exchange.balance_of(test.bob, base_token)?,
                bob_internal_quote: exchange.balance_of(test.bob, quote_token)?,
                carol_internal_base: exchange.balance_of(test.carol, base_token)?,
                carol_internal_quote: exchange.balance_of(test.carol, quote_token)?,
                alice_wallet_base: base_tip20.balance_of(ITIP20::balanceOfCall {
                    account: test.alice,
                })?,
                alice_wallet_quote: quote_tip20.balance_of(ITIP20::balanceOfCall {
                    account: test.alice,
                })?,
                bob_wallet_base: base_tip20
                    .balance_of(ITIP20::balanceOfCall { account: test.bob })?,
                bob_wallet_quote: quote_tip20
                    .balance_of(ITIP20::balanceOfCall { account: test.bob })?,
                carol_wallet_base: base_tip20.balance_of(ITIP20::balanceOfCall {
                    account: test.carol,
                })?,
                carol_wallet_quote: quote_tip20.balance_of(ITIP20::balanceOfCall {
                    account: test.carol,
                })?,
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
        expected_compact: OrderVersion,
        legacy_mask: u8,
        len: usize,
    ) -> eyre::Result<()> {
        debug_assert!(matches!(
            expected_compact,
            OrderVersion::V1 | OrderVersion::V2
        ));

        assert_order_versions(
            exchange,
            (0..len).map(|index| {
                if legacy_mask & (1 << index) != 0 {
                    OrderVersion::Legacy
                } else {
                    expected_compact
                }
            }),
        )?;
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
        store_versioned_order(exchange, layout.version_at(index, mixed_offset), order)
    }

    fn assert_order_versions(
        exchange: &StablecoinDEX,
        expected: impl IntoIterator<Item = OrderVersion>,
    ) -> eyre::Result<Vec<OrderVersion>> {
        let expected = expected.into_iter().collect::<Vec<_>>();
        let actual = (0..expected.len())
            .map(|index| exchange.orders[index as u128 + 1].version())
            .collect::<StorageResult<Vec<_>>>()?;
        assert_eq!(actual, expected);
        Ok(actual)
    }

    fn assert_initial_versions(
        exchange: &StablecoinDEX,
        layout: OrderLayoutCase,
        mixed_offset: bool,
        len: usize,
    ) -> eyre::Result<()> {
        let actual = assert_order_versions(
            exchange,
            (0..len).map(|index| layout.version_at(index, mixed_offset)),
        )?;

        if matches!(layout, OrderLayoutCase::Mixed) && len >= 3 {
            assert!(actual.contains(&OrderVersion::Legacy));
            assert!(actual.contains(&OrderVersion::V1));
            assert!(actual.contains(&OrderVersion::V2));
        } else if matches!(layout, OrderLayoutCase::V1 | OrderLayoutCase::V2) {
            let is_compact = |v: OrderVersion| !matches!(v, OrderVersion::Legacy);
            assert!(actual.iter().copied().all(is_compact));
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
