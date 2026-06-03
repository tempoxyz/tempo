//! TIP-20 per-account balance state.
//!
//! Before T6, balance slots store the legacy `U256` amount directly, without packing.
//! At T6, the same storage slot is interpreted as a packed [`UserState`] containing a `u128`
//! amount and a cached reward opt-in flag.
//!
//! The custom [`Storable`] impl preserves pre-T6 storage compatibility and delegates T6+ packing to
//! a derived storage type.

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        Layout, LayoutCtx, Slot, Storable, StorableType, StorageCtx, StorageOps,
        packing::{self, PackedSlot},
    },
    tip20::U128_MAX,
};
use alloy::{
    primitives::{Address, U256},
    sol_types::PanicKind,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles_macros::Storable;

// NOTE: `RewardFlag` derives `Storable`, so the cached flag occupies 1 byte in storage despite
// only needing 2 bits (as per the spec). If the balance slot needs to pack more metadata in the
// future, `UserState` should not derive `StorableLayout` and switch to a manual bit-level layout.
#[derive(Default, Debug, Clone, Storable, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RewardFlag {
    #[default]
    Uninitialized,
    OptedOut,
    OptedIn,
}

impl RewardFlag {
    pub fn is_opted_out(&self) -> bool {
        matches!(self, Self::OptedOut)
    }

    pub fn is_opted_in(&self) -> bool {
        matches!(self, Self::OptedIn)
    }

    pub fn is_uninitialized(&self) -> bool {
        matches!(self, Self::Uninitialized)
    }

    pub fn from_delegate(delegate: Address) -> Self {
        if delegate.is_zero() {
            Self::OptedOut
        } else {
            Self::OptedIn
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UserState {
    pub(super) amount: u128,
    /// (T6+) Canonical reward opt-in status for initialized balances.
    pub(super) flag: RewardFlag,
}

const REWARD_FLAG_OFFSET_BYTES: usize = 16;
const USER_STATE_AMOUNT_BYTES: usize = 16;
const REWARD_FLAG_BYTES: usize = 1;

// NOTE: derived storage layout is byte-granular, matching the `RewardFlag` byte above.
// This keeps generated T6+ packing correct, but cannot represent future sub-byte fields.
#[derive(Debug, Clone, Storable, Copy, PartialEq)]
struct PackedUserState {
    amount: u128,
    flag: RewardFlag,
}

impl From<PackedUserState> for UserState {
    fn from(value: PackedUserState) -> Self {
        Self {
            amount: value.amount,
            flag: value.flag,
        }
    }
}

impl From<UserState> for PackedUserState {
    fn from(value: UserState) -> Self {
        Self {
            amount: value.amount,
            flag: value.flag,
        }
    }
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

    pub(crate) fn incremented(&self, amount: U256, flag: RewardFlag) -> Result<Self> {
        Self::new(self.checked_add(amount)?, flag)
    }

    pub(crate) fn decremented(&self, amount: U256, flag: RewardFlag) -> Result<Self> {
        Self::new(self.checked_sub(amount)?, flag)
    }

    pub(crate) fn from_storage_word(value: U256, spec: TempoHardfork) -> Result<Self> {
        if !spec.is_t6() {
            let amount =
                u128::try_from(value).map_err(|_| TempoPrecompileError::under_overflow())?;
            return Ok(Self {
                amount,
                flag: RewardFlag::Uninitialized,
            });
        }

        let packed = PackedSlot(value);
        match PackedUserState::load(&packed, U256::ZERO, LayoutCtx::FULL) {
            Ok(value) => Ok(value.into()),
            Err(TempoPrecompileError::Panic(PanicKind::EnumConversionError)) => {
                Err(TempoPrecompileError::Fatal(
                    "invalid T6 TIP-20 packed user state: reward flag discriminant".into(),
                ))
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn storage_word_for_spec(&self, spec: TempoHardfork) -> Result<U256> {
        if !spec.is_t6() {
            return Ok(U256::from(self.amount));
        }

        let value =
            packing::insert_into_word(U256::ZERO, &self.amount, 0, USER_STATE_AMOUNT_BYTES)?;
        packing::insert_into_word(
            value,
            &(self.flag as u8),
            REWARD_FLAG_OFFSET_BYTES,
            REWARD_FLAG_BYTES,
        )
    }
}

impl StorableType for UserState {
    const LAYOUT: Layout = PackedUserState::LAYOUT;

    type Handler = Slot<Self>;

    fn handle(slot: U256, ctx: LayoutCtx, address: Address) -> Self::Handler {
        Slot::new_with_ctx(slot, ctx, address)
    }
}

impl Slot<UserState> {
    pub fn base_slot(&self) -> U256 {
        self.slot()
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used once TIP-20 transfers emit balance actions")
    )]
    pub(super) fn increment_balance(&mut self, delta: U256, flag: RewardFlag) -> Result<UserState> {
        debug_assert!(self.offset().is_none(), "`UserState` requires a full slot");
        let mut storage = StorageCtx;
        storage.tip20_balance_sinc(self.address(), self.slot(), delta, flag)
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used once TIP-20 transfers emit balance actions")
    )]
    pub(super) fn decrement_balance(&mut self, delta: U256, flag: RewardFlag) -> Result<UserState> {
        debug_assert!(self.offset().is_none(), "`UserState` requires a full slot");
        let mut storage = StorageCtx;
        storage.tip20_balance_sdec(self.address(), self.slot(), delta, flag)
    }
}

impl Storable for UserState {
    fn load<S: StorageOps>(storage: &S, slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert!(ctx.is_full(), "`UserState` is only loadable as a full slot");

        Self::from_storage_word(storage.load(slot)?, StorageCtx.spec())
    }

    fn store<S: StorageOps>(&self, storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert!(ctx.is_full(), "`UserState` is only storable as a full slot");

        storage.store(slot, self.storage_word_for_spec(StorageCtx.spec())?)
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
    use crate::storage::{Handler, hashmap::HashMapStorageProvider};
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn reward_flag_from_delegate() {
        assert_eq!(
            RewardFlag::from_delegate(Address::ZERO),
            RewardFlag::OptedOut
        );
        assert_eq!(
            RewardFlag::from_delegate(Address::random()),
            RewardFlag::OptedIn
        );
    }

    #[test]
    fn decode_tip20_balance_masks_user_state_cache() {
        let balance = U256::from(1000u64);
        let packed = U256::MAX ^ (decode_tip20_balance(U256::MAX) ^ balance);
        assert_eq!(decode_tip20_balance(packed), balance);

        let packed = U256::MAX;
        assert_eq!(decode_tip20_balance(packed), U128_MAX);
    }

    #[test]
    fn pre_t6_balance_helpers_update_legacy_amount_word() {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let slot = U256::from(42);
        let address = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut balance = Slot::<UserState>::new(slot, address);
            balance
                .write(UserState::new(U256::from(10), RewardFlag::OptedOut).unwrap())
                .unwrap();
            assert_eq!(StorageCtx.sload(address, slot).unwrap(), U256::from(10));

            let state = balance
                .increment_balance(U256::from(5), RewardFlag::OptedIn)
                .unwrap();
            assert_eq!(state.amount(), U256::from(15));
            assert_eq!(state.flag, RewardFlag::OptedIn);
            assert_eq!(StorageCtx.sload(address, slot).unwrap(), U256::from(15));
            assert_eq!(balance.read().unwrap().flag, RewardFlag::Uninitialized);

            let state = balance
                .decrement_balance(U256::from(4), RewardFlag::OptedOut)
                .unwrap();
            assert_eq!(state.amount(), U256::from(11));
            assert_eq!(state.flag, RewardFlag::OptedOut);
            assert_eq!(StorageCtx.sload(address, slot).unwrap(), U256::from(11));
            assert_eq!(balance.read().unwrap().flag, RewardFlag::Uninitialized);
        });
    }

    #[test]
    fn t6_balance_helpers_update_packed_user_state() {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let slot = U256::from(42);
        let address = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut balance = Slot::<UserState>::new(slot, address);
            balance
                .write(UserState::new(U256::from(10), RewardFlag::OptedOut).unwrap())
                .unwrap();

            let raw = StorageCtx.sload(address, slot).unwrap();
            assert_eq!(decode_tip20_balance(raw), U256::from(10));
            assert_ne!(raw, U256::from(10));

            let state = balance
                .increment_balance(U256::from(5), RewardFlag::OptedIn)
                .unwrap();
            assert_eq!(state.amount(), U256::from(15));
            assert_eq!(state.flag, RewardFlag::OptedIn);
            let raw = StorageCtx.sload(address, slot).unwrap();
            assert_eq!(decode_tip20_balance(raw), U256::from(15));
            assert_eq!(
                UserState::from_storage_word(raw, TempoHardfork::T6)
                    .unwrap()
                    .flag,
                RewardFlag::OptedIn
            );

            let state = balance
                .decrement_balance(U256::from(4), RewardFlag::OptedOut)
                .unwrap();
            assert_eq!(state.amount(), U256::from(11));
            assert_eq!(state.flag, RewardFlag::OptedOut);
            let raw = StorageCtx.sload(address, slot).unwrap();
            assert_eq!(decode_tip20_balance(raw), U256::from(11));
            assert_eq!(
                UserState::from_storage_word(raw, TempoHardfork::T6)
                    .unwrap()
                    .flag,
                RewardFlag::OptedOut
            );
        });
    }

    #[test]
    fn balance_helpers_fail_on_underflow_and_overflow() {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let slot = U256::from(42);
        let address = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut balance = Slot::<UserState>::new(slot, address);
            assert!(matches!(
                balance.decrement_balance(U256::ONE, RewardFlag::OptedOut),
                Err(TempoPrecompileError::Panic(_))
            ));

            balance
                .write(UserState::new(U128_MAX, RewardFlag::OptedIn).unwrap())
                .unwrap();
            assert!(matches!(
                balance.increment_balance(U256::ONE, RewardFlag::OptedIn),
                Err(TempoPrecompileError::Panic(_))
            ));
        });
    }

    #[test]
    fn t6_user_state_load_fails_fatally_on_invalid_reward_flag() {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let slot = U256::from(42);
        let address = Address::random();

        StorageCtx::enter(&mut storage, || {
            Slot::<u128>::new_with_ctx(slot, LayoutCtx::packed(0), address)
                .write(100)
                .unwrap();
            Slot::<u8>::new_with_ctx(slot, LayoutCtx::packed(16), address)
                .write(3)
                .unwrap();

            assert_eq!(
                Slot::<UserState>::new(slot, address).read().unwrap_err(),
                TempoPrecompileError::Fatal(
                    "invalid T6 TIP-20 packed user state: reward flag discriminant".into()
                )
            );
        });
    }
}
