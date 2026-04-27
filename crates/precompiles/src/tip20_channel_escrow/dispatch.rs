//! ABI dispatch for the [`TIP20ChannelEscrow`] precompile.

use super::{TIP20ChannelEscrow, CLOSE_GRACE_PERIOD, VOUCHER_TYPEHASH};
use crate::{charge_input_cost, dispatch_call, metadata, mutate, mutate_void, view, Precompile};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{
    ITIP20ChannelEscrow, ITIP20ChannelEscrow::ITIP20ChannelEscrowCalls,
};

impl Precompile for TIP20ChannelEscrow {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            ITIP20ChannelEscrowCalls::abi_decode,
            |call| match call {
                ITIP20ChannelEscrowCalls::CLOSE_GRACE_PERIOD(_) => {
                    metadata::<ITIP20ChannelEscrow::CLOSE_GRACE_PERIODCall>(|| {
                        Ok(CLOSE_GRACE_PERIOD)
                    })
                }
                ITIP20ChannelEscrowCalls::VOUCHER_TYPEHASH(_) => {
                    metadata::<ITIP20ChannelEscrow::VOUCHER_TYPEHASHCall>(|| Ok(*VOUCHER_TYPEHASH))
                }
                ITIP20ChannelEscrowCalls::open(call) => {
                    mutate(call, msg_sender, |sender, c| self.open(sender, c))
                }
                ITIP20ChannelEscrowCalls::settle(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.settle(sender, c))
                }
                ITIP20ChannelEscrowCalls::topUp(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.top_up(sender, c))
                }
                ITIP20ChannelEscrowCalls::close(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.close(sender, c))
                }
                ITIP20ChannelEscrowCalls::requestClose(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.request_close(sender, c))
                }
                ITIP20ChannelEscrowCalls::withdraw(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.withdraw(sender, c))
                }
                ITIP20ChannelEscrowCalls::getChannel(call) => view(call, |c| self.get_channel(c)),
                ITIP20ChannelEscrowCalls::getChannelState(call) => {
                    view(call, |c| self.get_channel_state(c))
                }
                ITIP20ChannelEscrowCalls::getChannelStatesBatch(call) => {
                    view(call, |c| self.get_channel_states_batch(c))
                }
                ITIP20ChannelEscrowCalls::computeChannelId(call) => {
                    view(call, |c| self.compute_channel_id(c))
                }
                ITIP20ChannelEscrowCalls::getVoucherDigest(call) => {
                    view(call, |c| self.get_voucher_digest(c))
                }
                ITIP20ChannelEscrowCalls::domainSeparator(call) => {
                    view(call, |_| self.domain_separator())
                }
            },
        )
    }
}
