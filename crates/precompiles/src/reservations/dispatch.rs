//! ABI dispatch for the [`Reservations`] precompile.

use super::Reservations;
use crate::{Precompile, charge_input_cost, dispatch, mutate, view};
use alloy::primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::precompiles::IReservationCore;

impl Precompile for Reservations {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IReservationCore::IReservationCoreCalls {
                    approveHolder(call) => mutate(call, msg_sender, |sender, c| self.approve_holder(sender, c)),
                    setCaptureTolerance(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_capture_tolerance(sender, c)
                    }),
                    hold(call) => mutate(call, msg_sender, |sender, c| self.place(sender, sender, c.request)),
                    holdFrom(call) => mutate(call, msg_sender, |sender, c| {
                        self.place(sender, c.owner, c.request)
                    }),
                    pledge(call) => mutate(call, msg_sender, |sender, c| self.pledge(sender, c)),
                    pledgeFrom(call) => mutate(call, msg_sender, |sender, c| self.pledge_from(sender, c)),
                    lien(call) => mutate(call, msg_sender, |sender, c| self.lien(sender, c)),
                    adjust(call) => mutate(call, msg_sender, |sender, c| self.adjust(sender, c)),
                    capture(call) => mutate(call, msg_sender, |sender, c| self.capture(sender, c)),
                    release(call) => mutate(call, msg_sender, |sender, c| self.release(sender, c)),
                    releaseExpired(call) => mutate(call, msg_sender, |_, c| self.release_expired(c)),
                    charge(call) => mutate(call, msg_sender, |sender, c| self.charge(sender, c)),
                    refund(call) => mutate(call, msg_sender, |sender, c| self.refund(sender, c)),
                    getHold(call) => view(call, |c| self.get_hold(c.owner, c.placer, c.id)),
                    reserved(call) => view(call, |c| self.reserved_of(c.owner, c.token)),
                    available(call) => view(call, |c| self.available_of(c.owner, c.token)),
                    budget(call) => view(call, |c| self.budget(c.owner, c.holder, c.token)),
                    captureTolerance(call) => view(call, |c| {
                        self.capture_tolerance(c.owner, c.payee, c.token)
                    }),
                }
            }
        )
    }
}
