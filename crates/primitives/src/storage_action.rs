//! Storage actions Tempo's precompiles record during execution, such as for replaying a block's
//! state access or following its fee hooks.

use alloy_primitives::{Address, U256};
use tempo_contracts::precompiles::TIP_FEE_MANAGER_ADDRESS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StorageAction {
    /// Records an SLOAD opcode.
    Sload(Address, U256, U256),
    /// Records whether a fee-token balance covers the maximum transaction fee.
    ///
    /// Fields: token address, balance slot, observed balance, required fee, and affordability.
    FeeTokenBalanceCheck(Address, U256, U256, U256, bool),
    /// Records an SSTORE opcode.
    ///
    /// `address` - Account address
    /// `key` - Storage slot key
    /// `sload_value` - Slot value before store
    /// `value` - New value to store
    Sstore(Address, U256, U256, U256),
    /// Records an increment of a storage slot by delta.
    ///
    /// If the slot **was** zero before incrementing,
    /// [`Self::Sload`] and [`Self::Sstore`] are recorded instead.
    ///
    /// `address` - Account address
    /// `key` - Storage slot key
    /// `sload_value` - Slot value before increment
    /// `delta` - Amount to increment by
    Sinc(Address, U256, U256, U256),
    /// Records a decrement of a storage slot by delta.
    ///
    /// If the slot **became** zero as a result of decrementing,
    /// [`Self::Sload`] and [`Self::Sstore`] are recorded instead.
    ///
    /// `address` - Account address
    /// `key` - Storage slot key
    /// `sload_value` - Slot value before decrement
    /// `delta` - Amount to decrement by
    Sdec(Address, U256, U256, U256),
    /// Records a FeeAMM pool fee swap over a packed pool slot.
    ///
    /// `key` - Storage slot key.
    /// `sload_value` - Packed pool slot value before the swap.
    /// `amount_in` - Amount of tokens to swap in.
    ///
    /// `amount_out` can be calculated using the fee AMM's `compute_amount_out`.
    FeeAmmSwap(U256, U256, U256),
    /// Records a liquidity check for a FeeAMM pool.
    ///
    /// `key` - Storage slot key.
    /// `sload_value` - Packed pool slot value before the liquidity check.
    /// `amount_out` - Amount of tokens to swap out.
    /// `has_enough_liquidity` - Whether the pool has enough liquidity.
    FeeAmmLiquidityCheck(U256, U256, U256, bool),
    /// Marks where a step of the transaction's fee lifecycle starts or ends. It changes no state.
    Marker(FeeHook),
}

/// Brackets a protocol fee hook. The actions between a hook's start marker and the next
/// [`Self::End`] are the hook's own. A hook that fails records no end marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FeeHook {
    /// Pre-tx fee hook starts, charging `amount` of `token` to `payer`. Emits no logs.
    PreTx {
        payer: Address,
        token: Address,
        amount: U256,
    },
    /// Post-tx fee hook starts, refunding `refund` of `amount`. Its fee transfer is log `log`.
    PostTx { refund: U256, log: usize },
    /// The fee hook the last marker started returned.
    End,
}

impl StorageAction {
    /// Returns the address of the storage action.
    pub fn address(&self) -> Address {
        match self {
            Self::Sload(address, ..)
            | Self::FeeTokenBalanceCheck(address, ..)
            | Self::Sstore(address, ..)
            | Self::Sinc(address, ..)
            | Self::Sdec(address, ..) => *address,
            Self::FeeAmmSwap(..) | Self::FeeAmmLiquidityCheck(..) | Self::Marker(_) => {
                TIP_FEE_MANAGER_ADDRESS
            }
        }
    }
}
