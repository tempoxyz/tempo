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
                    CLOSE_GRACE_PERIOD(call) => view(self, call, |_, _| Ok(CLOSE_GRACE_PERIOD)),
                    VOUCHER_TYPEHASH(call) => view(self, call, |_, _| Ok(VOUCHER_TYPEHASH)),
                    open(call) => mutate(self, call, msg_sender, |this, sender, c| {
                        preserve_storage_credits(this.address)?;
                        this.open(sender, c)
                    }),
                    settle(call) => mutate(self, call, msg_sender, |this, sender, c| {
                        preserve_storage_credits(this.address)?;
                        this.settle(sender, c)
                    }),
                    topUp(call) => mutate(self, call, msg_sender, |this, sender, c| {
                        preserve_storage_credits(this.address)?;
                        this.top_up(sender, c)
                    }),
                    close(call) => mutate(self, call, msg_sender, |this, sender, c| {
                        preserve_storage_credits(this.address)?;
                        this.close(sender, c)
                    }),
                    requestClose(call) => mutate(self, call, msg_sender, |this, sender, c| {
                        preserve_storage_credits(this.address)?;
                        this.request_close(sender, c)
                    }),
                    withdraw(call) => mutate(self, call, msg_sender, |this, sender, c| {
                        preserve_storage_credits(this.address)?;
                        this.withdraw(sender, c)
                    }),
                    getChannel(call) => view(self, call, |this, c| this.get_channel(c)),
                    getChannelState(call) => view(self, call, |this, c| this.get_channel_state(c)),
                    getChannelStatesBatch(call) => view(self, call, |this, c| this.get_channel_states_batch(c)),
                    computeChannelId(call) => view(self, call, |this, c| this.compute_channel_id(c)),
                    getVoucherDigest(call) => view(self, call, |this, c| this.get_voucher_digest(c)),
                    domainSeparator(call) => view(self, call, |this, _| this.domain_separator()),
                    #[schedule(since = T7)]
                    storageCredits(call) => view(self, call, |this, c| this.storage_credits(c.payer))
                }
            }
        )
    }
}
