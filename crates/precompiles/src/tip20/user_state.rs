//! TIP-20 per-account balance state.
//!
//! Before T6, balance slots store the legacy `U256` amount directly, without packing.
//! At T6, the same storage slot is interpreted as a packed [`UserState`] containing a `u128` amount
//! and a cached reward opt-in flag.
//!
//! The manual [`Storable`] impl is necessary to preserve backwards compatibility, and optimally
//! handle [`StorageOps`] across all hardforks.

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        Handler, Layout, LayoutCtx, Slot, Storable, StorableType, StorageCtx, StorageOps,
        packing::PackedSlot,
    },
    tip20::{U128_MAX, rewards::RewardFlag},
};
use alloy::primitives::{Address, U256};
use tempo_precompiles_macros::StorableLayout;

#[derive(Debug, Clone, StorableLayout, Copy, PartialEq)]
pub struct UserState {
    pub(super) amount: u128,
    /// (T6+) Cached reward opt-in status. Tracks `reward_recipient`, which remains the source of truth.
    pub(super) flag: RewardFlag,
}

impl UserState {
    pub(super) fn new(amount: U256, flag: RewardFlag) -> Result<Self> {
        let amount = u128::try_from(amount).map_err(|_| TempoPrecompileError::under_overflow())?;
        Ok(Self { amount, flag })
    }

    pub fn amount(&self) -> U256 {
        U256::from(self.amount)
    }

    pub(super) fn checked_add(&self, amount: U256) -> Result<U256> {
        self.amount()
            .checked_add(amount)
            .ok_or(TempoPrecompileError::under_overflow())
    }

    pub(super) fn checked_sub(&self, amount: U256) -> Result<U256> {
        self.amount()
            .checked_sub(amount)
            .ok_or(TempoPrecompileError::under_overflow())
    }

    pub(super) fn checked_mul(&self, amount: U256) -> Result<U256> {
        self.amount()
            .checked_mul(amount)
            .ok_or(TempoPrecompileError::under_overflow())
    }
}

impl StorableType for UserState {
    const LAYOUT: Layout = Layout::Slots(__packing_user_state::SLOT_COUNT);

    type Handler = UserStateHandler;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        UserStateHandler::new(slot, address)
    }
}

#[derive(Debug, Clone)]
pub struct UserStateHandler {
    address: Address,
    base_slot: U256,
    pub amount: Slot<u128>,
    pub flag: Slot<RewardFlag>,
}

impl UserStateHandler {
    pub fn new(base_slot: U256, address: Address) -> Self {
        Self {
            address,
            base_slot,
            amount: Slot::new_at_loc(base_slot, __packing_user_state::AMOUNT_LOC, address),
            flag: Slot::new_at_loc(base_slot, __packing_user_state::FLAG_LOC, address),
        }
    }

    pub fn base_slot(&self) -> U256 {
        self.base_slot
    }

    fn as_slot(&self) -> Slot<UserState> {
        Slot::new(self.base_slot, self.address)
    }
}

impl Handler<UserState> for UserStateHandler {
    fn read(&self) -> Result<UserState> {
        self.as_slot().read()
    }

    fn write(&mut self, value: UserState) -> Result<()> {
        self.as_slot().write(value)
    }

    fn delete(&mut self) -> Result<()> {
        self.as_slot().delete()
    }

    fn t_read(&self) -> Result<UserState> {
        self.as_slot().t_read()
    }

    fn t_write(&mut self, value: UserState) -> Result<()> {
        self.as_slot().t_write(value)
    }

    fn t_delete(&mut self) -> Result<()> {
        self.as_slot().t_delete()
    }
}

impl Storable for UserState {
    fn load<S: StorageOps>(storage: &S, slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert!(
            ctx.is_full(),
            "UserState can only be loaded from a full slot"
        );

        if !StorageCtx.spec().is_t6() {
            let amount = u128::try_from(storage.load(slot)?)
                .map_err(|_| TempoPrecompileError::under_overflow())?;
            return Ok(Self {
                amount,
                flag: RewardFlag::Uninitialized,
            });
        }

        let packed = PackedSlot(storage.load(slot)?);
        Ok(Self {
            amount: u128::load(
                &packed,
                slot + __packing_user_state::AMOUNT,
                LayoutCtx::packed(__packing_user_state::AMOUNT_OFFSET),
            )?,
            flag: RewardFlag::load(
                &packed,
                slot + __packing_user_state::FLAG,
                LayoutCtx::packed(__packing_user_state::FLAG_OFFSET),
            )?,
        })
    }

    fn store<S: StorageOps>(&self, storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert!(ctx.is_full(), "UserState can only be stored in a full slot");

        if !StorageCtx.spec().is_t6() {
            return storage.store(slot, U256::from(self.amount));
        }

        let mut packed = PackedSlot(U256::ZERO);
        self.amount.store(
            &mut packed,
            slot + __packing_user_state::AMOUNT,
            LayoutCtx::packed(__packing_user_state::AMOUNT_OFFSET),
        )?;
        self.flag.store(
            &mut packed,
            slot + __packing_user_state::FLAG,
            LayoutCtx::packed(__packing_user_state::FLAG_OFFSET),
        )?;
        storage.store(slot, packed.0)
    }
}

/// Decodes the token balance amount from a raw TIP-20 `balances[account]` storage word.
///
/// T6 packs [`UserState`] into the legacy balance slot with the amount in the low 128 bits and
/// reward metadata in the high bits. Use this helper when reading balance slots through raw storage
/// APIs instead of typed storage handlers.
#[inline]
pub fn decode_tip20_balance(slot_value: U256) -> U256 {
    slot_value & U128_MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_tip20_balance_masks_user_state_cache() {
        let balance = U256::from(1000u64);
        let packed = U256::MAX ^ (decode_tip20_balance(U256::MAX) ^ balance);
        assert_eq!(decode_tip20_balance(packed), balance);

        let packed = U256::MAX;
        assert_eq!(decode_tip20_balance(packed), U128_MAX);
    }
}
