//! ABI dispatch for the [`TIP20ChannelReserve`] precompile.

use super::{CLOSE_GRACE_PERIOD, TIP20ChannelReserve, VOUCHER_TYPEHASH};
use crate::{
    Precompile, charge_input_cost, dispatch, metadata, mutate, mutate_void,
    preserve_storage_credits, view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ITIP20ChannelReserve;
impl Precompile for TIP20ChannelReserve {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                ITIP20ChannelReserve::ITIP20ChannelReserveCalls {
                    CLOSE_GRACE_PERIOD(_) => metadata::<ITIP20ChannelReserve::CLOSE_GRACE_PERIODCall>(|| {
                        Ok(CLOSE_GRACE_PERIOD)
                    }),
                    VOUCHER_TYPEHASH(_) => metadata::<ITIP20ChannelReserve::VOUCHER_TYPEHASHCall>(|| Ok(*VOUCHER_TYPEHASH)),
                    open(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.open(sender, c)
                    }),
                    settle(call) => mutate_void(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.settle(sender, c)
                    }),
                    topUp(call) => mutate_void(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.top_up(sender, c)
                    }),
                    close(call) => mutate_void(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.close(sender, c)
                    }),
                    requestClose(call) => mutate_void(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.request_close(sender, c)
                    }),
                    withdraw(call) => mutate_void(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.withdraw(sender, c)
                    }),
                    getChannel(call) => view(call, |c| self.get_channel(c)),
                    getChannelState(call) => view(call, |c| self.get_channel_state(c)),
                    getChannelStatesBatch(call) => view(call, |c| self.get_channel_states_batch(c)),
                    computeChannelId(call) => view(call, |c| self.compute_channel_id(c)),
                    getVoucherDigest(call) => view(call, |c| self.get_voucher_digest(c)),
                    domainSeparator(call) => view(call, |_| self.domain_separator()),
                    #[schedule(since = T7)]
                    storageCredits(call) => view(call, |c| self.storage_credits(c.payer))
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
        primitives::{B256, aliases::U96},
        sol_types::SolCall,
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        ITIP20ChannelReserve::{self, ChannelDescriptor, ITIP20ChannelReserveCalls},
        TIP20ChannelReserveError,
    };

    /// Every function declared on `ITIP20ChannelReserve` must have a dispatch handler above.
    /// This guards against a selector silently falling through to "unknown function selector"
    /// if the interface gains a new function that isn't wired into the `dispatch!` match.
    #[test]
    fn test_tip20_channel_reserve_selector_coverage() -> eyre::Result<()> {
        // `storageCredits` only exists since T7, so exercise the latest hardfork to make sure
        // every selector (including schedule-gated ones) is covered.
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        StorageCtx::enter(&mut storage, || {
            let mut reserve = TIP20ChannelReserve::new();

            let unsupported = check_selector_coverage(
                &mut reserve,
                ITIP20ChannelReserveCalls::SELECTORS,
                "ITIP20ChannelReserve",
                ITIP20ChannelReserveCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }

    fn descriptor() -> ChannelDescriptor {
        ChannelDescriptor {
            payer: Address::repeat_byte(0x11),
            payee: Address::repeat_byte(0x22),
            operator: Address::ZERO,
            token: Address::repeat_byte(0x33),
            salt: B256::repeat_byte(0x44),
            authorizedSigner: Address::ZERO,
            expiringNonceHash: B256::ZERO,
        }
    }

    #[test]
    fn test_get_channel_state_for_unknown_channel_returns_zero_state() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut reserve = TIP20ChannelReserve::new();

            let call = ITIP20ChannelReserve::getChannelStateCall {
                channelId: B256::repeat_byte(0x99),
            };
            let output = reserve.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!output.is_revert());

            let state =
                ITIP20ChannelReserve::getChannelStateCall::abi_decode_returns(&output.bytes)?;
            assert!(state.deposit.is_zero());
            assert!(state.settled.is_zero());
            assert_eq!(state.closeRequestedAt, 0);
            Ok(())
        })
    }

    /// Every mutating entrypoint keyed by a channel descriptor must revert with
    /// `ChannelNotFound` through the full ABI dispatch boundary when the channel was never
    /// opened, not just when called directly against the business-logic methods.
    #[test]
    fn test_mutating_calls_on_unknown_channel_revert_via_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut reserve = TIP20ChannelReserve::new();
            let caller = Address::repeat_byte(0x11);

            let request_close = ITIP20ChannelReserve::requestCloseCall {
                descriptor: descriptor(),
            };
            let result = reserve.call(&request_close.abi_encode(), caller);
            expect_precompile_revert(&result, TIP20ChannelReserveError::channel_not_found());

            let withdraw = ITIP20ChannelReserve::withdrawCall {
                descriptor: descriptor(),
            };
            let result = reserve.call(&withdraw.abi_encode(), caller);
            expect_precompile_revert(&result, TIP20ChannelReserveError::channel_not_found());

            let top_up = ITIP20ChannelReserve::topUpCall {
                descriptor: descriptor(),
                additionalDeposit: U96::from(1),
            };
            let result = reserve.call(&top_up.abi_encode(), caller);
            expect_precompile_revert(&result, TIP20ChannelReserveError::channel_not_found());
            Ok(())
        })
    }
}
