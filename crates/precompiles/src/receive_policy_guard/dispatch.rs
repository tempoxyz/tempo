//! ABI dispatch for the [`ReceivePolicyGuard`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch, mutate_void, receive_policy_guard::ReceivePolicyGuard,
    view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IReceivePolicyGuard;
impl Precompile for ReceivePolicyGuard {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IReceivePolicyGuard::IReceivePolicyGuardCalls {
                    balanceOf(call) => view(call, |c| self.balance_of(c.receipt)),
                    claim(call) => mutate_void(call, msg_sender, |s, c| self.claim(s, c.to, c.receipt)),
                    burnBlockedReceipt(call) => mutate_void(call, msg_sender, |s, c| {
                        self.burn_blocked_receipt(s, c.receipt)
                    })
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expect_precompile_revert,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{B256, Bytes, U256},
        sol_types::{SolCall, SolValue},
    };
    use tempo_contracts::precompiles::{
        IReceivePolicyGuard::{self, ClaimReceiptV1, IReceivePolicyGuardCalls, InboundKind},
        ITIP403Registry::BlockedReason,
        ReceivePolicyGuardError,
    };

    /// Every function declared on `IReceivePolicyGuard` must have a dispatch handler above.
    /// This guards against a selector silently falling through to "unknown function selector"
    /// if the interface gains a new function that isn't wired into the `dispatch!` match.
    #[test]
    fn test_receive_policy_guard_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut guard = ReceivePolicyGuard::new();

            let unsupported = check_selector_coverage(
                &mut guard,
                IReceivePolicyGuardCalls::SELECTORS,
                "IReceivePolicyGuard",
                IReceivePolicyGuardCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }

    #[test]
    fn test_balance_of_unknown_receipt_returns_zero_via_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut guard = ReceivePolicyGuard::new();

            // A well-formed but never-recorded receipt: nothing was ever blocked for it, so the
            // ABI round trip through `call()` should report a zero balance rather than error.
            let receipt = ClaimReceiptV1::new(
                Address::repeat_byte(0x10),
                Address::ZERO,
                Address::repeat_byte(0x11),
                Address::repeat_byte(0x12),
                1_000,
                1,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let call = IReceivePolicyGuard::balanceOfCall {
                receipt: receipt.abi_encode().into(),
            };

            let output = guard.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!output.is_revert());
            assert_eq!(
                IReceivePolicyGuard::balanceOfCall::abi_decode_returns(&output.bytes)?,
                U256::ZERO
            );
            Ok(())
        })
    }

    /// Malformed receipt bytes must decode-fail with `InvalidReceipt` all the way through the
    /// ABI dispatch boundary (selector routing + revert encoding), not just at the Rust level.
    #[test]
    fn test_claim_and_burn_with_malformed_receipt_revert_via_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut guard = ReceivePolicyGuard::new();

            let claim = IReceivePolicyGuard::claimCall {
                to: Address::repeat_byte(0x01),
                receipt: Bytes::new(),
            };
            let result = guard.call(&claim.abi_encode(), Address::repeat_byte(0x02));
            expect_precompile_revert(&result, ReceivePolicyGuardError::invalid_receipt());

            let burn = IReceivePolicyGuard::burnBlockedReceiptCall {
                receipt: Bytes::new(),
            };
            let result = guard.call(&burn.abi_encode(), Address::repeat_byte(0x02));
            expect_precompile_revert(&result, ReceivePolicyGuardError::invalid_receipt());
            Ok(())
        })
    }
}
