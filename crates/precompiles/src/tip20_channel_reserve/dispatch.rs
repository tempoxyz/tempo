//! ABI dispatch for the [`TIP20ChannelReserve`] precompile.

use super::{CLOSE_GRACE_PERIOD, TIP20ChannelReserve, VOUCHER_TYPEHASH};
use crate::{
    Precompile, charge_input_cost, dispatch, metadata, mutate, mutate_void,
    preserve_storage_credits, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
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
