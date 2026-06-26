//! ABI dispatch for the [`TIP20ChannelReserve`] precompile.

use super::{CLOSE_GRACE_PERIOD, TIP20ChannelReserve, VOUCHER_TYPEHASH};
use crate::{
    Precompile, SelectorSchedule, charge_input_cost, dispatch_call, metadata, mutate, mutate_void,
    preserve_storage_credits, view,
};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::PrecompileResult;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    ITIP20ChannelReserve, ITIP20ChannelReserve::ITIP20ChannelReserveCalls,
};

const T7_ADDED: &[[u8; 4]] = &[ITIP20ChannelReserve::storageCreditsCall::SELECTOR];

impl Precompile for TIP20ChannelReserve {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[SelectorSchedule::new(TempoHardfork::T7).with_added(T7_ADDED)],
            ITIP20ChannelReserveCalls::abi_decode,
            |call| match call {
                ITIP20ChannelReserveCalls::CLOSE_GRACE_PERIOD(_) => {
                    metadata::<ITIP20ChannelReserve::CLOSE_GRACE_PERIODCall>(|| {
                        Ok(CLOSE_GRACE_PERIOD)
                    })
                }
                ITIP20ChannelReserveCalls::VOUCHER_TYPEHASH(_) => {
                    metadata::<ITIP20ChannelReserve::VOUCHER_TYPEHASHCall>(|| Ok(*VOUCHER_TYPEHASH))
                }
                ITIP20ChannelReserveCalls::open(call) => mutate(call, msg_sender, |sender, c| {
                    preserve_storage_credits(self.address)?;
                    self.open(sender, c)
                }),
                ITIP20ChannelReserveCalls::settle(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.settle(sender, c)
                    })
                }
                ITIP20ChannelReserveCalls::topUp(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.top_up(sender, c)
                    })
                }
                ITIP20ChannelReserveCalls::close(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.close(sender, c)
                    })
                }
                ITIP20ChannelReserveCalls::requestClose(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.request_close(sender, c)
                    })
                }
                ITIP20ChannelReserveCalls::withdraw(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.withdraw(sender, c)
                    })
                }
                ITIP20ChannelReserveCalls::getChannel(call) => view(call, |c| self.get_channel(c)),
                ITIP20ChannelReserveCalls::getChannelState(call) => {
                    view(call, |c| self.get_channel_state(c))
                }
                ITIP20ChannelReserveCalls::getChannelStatesBatch(call) => {
                    view(call, |c| self.get_channel_states_batch(c))
                }
                ITIP20ChannelReserveCalls::computeChannelId(call) => {
                    view(call, |c| self.compute_channel_id(c))
                }
                ITIP20ChannelReserveCalls::getVoucherDigest(call) => {
                    view(call, |c| self.get_voucher_digest(c))
                }
                ITIP20ChannelReserveCalls::domainSeparator(call) => {
                    view(call, |_| self.domain_separator())
                }
                ITIP20ChannelReserveCalls::storageCredits(call) => {
                    view(call, |c| self.storage_credits(c.payer))
                }
            },
        )
    }
}
