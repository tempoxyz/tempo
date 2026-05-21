//! ABI dispatch for the [`TIP20ChannelReserve`] precompile.

use super::{CLOSE_GRACE_PERIOD, TIP20ChannelReserve, VOUCHER_TYPEHASH};
use crate::{Precompile, charge_input_cost, dispatch_call, metadata, mutate, mutate_void, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{
    ITIP20ChannelReserve, ITIP20ChannelReserve::ITIP20ChannelReserveCalls,
};

impl Precompile for TIP20ChannelReserve {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
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
                ITIP20ChannelReserveCalls::open(call) => {
                    mutate(call, msg_sender, |sender, c| self.open(sender, c))
                }
                ITIP20ChannelReserveCalls::settle(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.settle(sender, c))
                }
                ITIP20ChannelReserveCalls::topUp(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.top_up(sender, c))
                }
                ITIP20ChannelReserveCalls::close(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.close(sender, c))
                }
                ITIP20ChannelReserveCalls::requestClose(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.request_close(sender, c))
                }
                ITIP20ChannelReserveCalls::withdraw(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.withdraw(sender, c))
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
            },
        )
    }
}
