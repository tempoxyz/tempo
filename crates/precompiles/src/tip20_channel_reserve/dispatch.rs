//! ABI dispatch for the [`TIP20ChannelReserve`] precompile.

use super::{CLOSE_GRACE_PERIOD, TIP20ChannelReserve, VOUCHER_TYPEHASH};
use crate::{Precompile, charge_input_cost, dispatch, mutate, preserve_storage_credits, view};
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
                    CLOSE_GRACE_PERIOD(call) => view(call, |_| Ok(CLOSE_GRACE_PERIOD)),
                    VOUCHER_TYPEHASH(call) => view(call, |_| Ok(VOUCHER_TYPEHASH)),
                    open(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.open(sender, c)
                    }),
                    settle(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.settle(sender, c)
                    }),
                    topUp(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.top_up(sender, c)
                    }),
                    close(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.close(sender, c)
                    }),
                    requestClose(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.request_close(sender, c)
                    }),
                    withdraw(call) => mutate(call, msg_sender, |sender, c| {
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
