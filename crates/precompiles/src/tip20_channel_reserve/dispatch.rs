//! ABI dispatch for the [`TIP20ChannelReserve`] precompile.

use super::{CLOSE_GRACE_PERIOD, TIP20ChannelReserve, VOUCHER_TYPEHASH};
use crate::{Precompile, charge_input_cost, dispatch, metadata, mutate, mutate_void, view};
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

        dispatch!(calldata => {
            ITIP20ChannelReserve::CLOSE_GRACE_PERIOD(_) => {
                metadata::<ITIP20ChannelReserve::CLOSE_GRACE_PERIODCall>(|| {
                    Ok(CLOSE_GRACE_PERIOD)
                })
            },
            ITIP20ChannelReserve::VOUCHER_TYPEHASH(_) => {
                metadata::<ITIP20ChannelReserve::VOUCHER_TYPEHASHCall>(|| Ok(*VOUCHER_TYPEHASH))
            },
            ITIP20ChannelReserve::open(call) => {
                mutate(call, msg_sender, |sender, c| self.open(sender, c))
            },
            ITIP20ChannelReserve::settle(call) => {
                mutate_void(call, msg_sender, |sender, c| self.settle(sender, c))
            },
            ITIP20ChannelReserve::topUp(call) => {
                mutate_void(call, msg_sender, |sender, c| self.top_up(sender, c))
            },
            ITIP20ChannelReserve::close(call) => {
                mutate_void(call, msg_sender, |sender, c| self.close(sender, c))
            },
            ITIP20ChannelReserve::requestClose(call) => {
                mutate_void(call, msg_sender, |sender, c| self.request_close(sender, c))
            },
            ITIP20ChannelReserve::withdraw(call) => {
                mutate_void(call, msg_sender, |sender, c| self.withdraw(sender, c))
            },
            ITIP20ChannelReserve::getChannel(call) => view(call, |c| self.get_channel(c)),
            ITIP20ChannelReserve::getChannelState(call) => {
                view(call, |c| self.get_channel_state(c))
            },
            ITIP20ChannelReserve::getChannelStatesBatch(call) => {
                view(call, |c| self.get_channel_states_batch(c))
            },
            ITIP20ChannelReserve::computeChannelId(call) => {
                view(call, |c| self.compute_channel_id(c))
            },
            ITIP20ChannelReserve::getVoucherDigest(call) => {
                view(call, |c| self.get_voucher_digest(c))
            },
            ITIP20ChannelReserve::domainSeparator(call) => {
                view(call, |_| self.domain_separator())
            },
        })
    }
}
