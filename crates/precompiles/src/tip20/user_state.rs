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
    storage::{Layout, LayoutCtx, Slot, Storable, StorableType, StorageCtx, StorageOps},
    tip20::U128_MAX,
};
use alloy::{
    primitives::{Address, U256},
    sol_types::PanicKind,
};
use tempo_precompiles_macros::Storable;

// NOTE: `RewardFlag` derives `Storable`, so the cached flag occupies 1 byte in storage despite
// only needing 2 bits (as per the spec). If the balance slot needs to pack more metadata in the
// future, `UserState` should not derive `StorableLayout` and switch to a manual bit-level layout.
#[derive(Default, Debug, Clone, Storable, Copy, PartialEq)]
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
    /// (T7+) Canonical reward opt-in status for initialized balances. Always `OptedOut`, effectively disabled.
    pub(super) flag: RewardFlag,
}

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
        Ok(Self {
            amount: u128::try_from(amount).map_err(|_| TempoPrecompileError::under_overflow())?,
            flag,
        })
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
}

impl Storable for UserState {
    fn load<S: StorageOps>(storage: &S, slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert!(ctx.is_full(), "`UserState` is only loadable as a full slot");

        if !StorageCtx.spec().is_t6() {
            let amount = u128::try_from(storage.load(slot)?)
                .map_err(|_| TempoPrecompileError::under_overflow())?;
            return Ok(Self {
                amount,
                flag: RewardFlag::Uninitialized,
            });
        }

        match PackedUserState::load(storage, slot, ctx) {
            Ok(value) => Ok(value.into()),
            Err(TempoPrecompileError::Panic(PanicKind::EnumConversionError)) => {
                Err(TempoPrecompileError::Fatal(
                    "invalid T6 TIP-20 packed user state: reward flag discriminant".into(),
                ))
            }
            Err(err) => Err(err),
        }
    }

    fn store<S: StorageOps>(&self, storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert!(ctx.is_full(), "`UserState` is only storable as a full slot");

        if !StorageCtx.spec().is_t6() {
            return storage.store(slot, U256::from(self.amount));
        }

        PackedUserState::from(*self).store(storage, slot, ctx)
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
    use crate::storage::{Handler, StorageCtx, hashmap::HashMapStorageProvider};
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
    fn t7_user_state_uses_legacy_balance_layout() {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        let slot = U256::from(42);
        let address = Address::random();

        StorageCtx::enter(&mut storage, || {
            Slot::<U256>::new(slot, address)
                .write(U256::from(100))
                .unwrap();

            let mut state = Slot::<UserState>::new(slot, address);
            assert_eq!(
                state.read().unwrap(),
                UserState {
                    amount: 100,
                    flag: RewardFlag::Uninitialized,
                }
            );

            state
                .write(UserState {
                    amount: 100,
                    flag: RewardFlag::OptedOut,
                })
                .unwrap();
            assert_eq!(state.read().unwrap().flag, RewardFlag::OptedOut);
            assert_eq!(
                decode_tip20_balance(Slot::<U256>::new(slot, address).read().unwrap()),
                U256::from(100)
            );
        });
    }
}
