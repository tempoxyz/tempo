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
                    setDebtCap(call) => mutate(call, msg_sender, |sender, c| self.set_debt_cap(sender, c)),
                    setCaptureTolerance(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_capture_tolerance(sender, c)
                    }),
                    setOfflineCap(call) => mutate(call, msg_sender, |sender, c| self.set_offline_cap(sender, c)),
                    hold(call) => mutate(call, msg_sender, |sender, c| self.place(sender, sender, c.request)),
                    holdFrom(call) => mutate(call, msg_sender, |sender, c| {
                        self.place(sender, c.owner, c.request)
                    }),
                    adjust(call) => mutate(call, msg_sender, |sender, c| self.adjust(sender, c)),
                    capture(call) => mutate(call, msg_sender, |sender, c| self.capture(sender, c)),
                    release(call) => mutate(call, msg_sender, |sender, c| self.release(sender, c.owner, c.id)),
                    releaseExpired(call) => mutate(call, msg_sender, |_, c| {
                        self.release_expired(c.owner, c.id)
                    }),
                    refund(call) => mutate(call, msg_sender, |sender, c| self.refund(sender, c)),
                    charge(call) => mutate(call, msg_sender, |sender, c| self.charge(sender, c)),
                    lien(call) => mutate(call, msg_sender, |sender, c| self.lien(sender, c)),
                    pledge(call) => mutate(call, msg_sender, |sender, c| self.pledge(sender, c)),
                    releaseLien(call) => mutate(call, msg_sender, |sender, c| self.release_lien(sender, c.id)),
                    reduceLien(call) => mutate(call, msg_sender, |sender, c| self.reduce_lien(sender, c)),
                    seizeLien(call) => mutate(call, msg_sender, |sender, c| self.seize_lien(sender, c)),
                    releaseExpiredLien(call) => mutate(call, msg_sender, |_, c| {
                        self.release_expired_lien(c.authority, c.id)
                    }),
                    pledgeFrom(call) => mutate(call, msg_sender, |sender, c| self.pledge_from(sender, c)),
                    getHold(call) => view(call, |c| self.get_hold(c.owner, c.id)),
                    reserved(call) => view(call, |c| self.reserved_of(c.owner, c.token)),
                    available(call) => view(call, |c| self.available_of(c.owner, c.token)),
                    allowance(call) => view(call, |c| self.allowance(c.owner, c.holder, c.token)),
                    debtOf(call) => view(call, |c| self.debt_of(c.owner, c.token)),
                    debtCap(call) => view(call, |c| self.debt_cap(c.owner, c.creditor, c.token)),
                    captureTolerance(call) => view(call, |c| {
                        self.capture_tolerance(c.owner, c.payee, c.token)
                    }),
                    offlineCap(call) => view(call, |c| self.offline_cap(c.owner, c.payee, c.token)),
                    lienOf(call) => view(call, |c| self.lien_of(c.authority, c.id)),
                    liened(call) => view(call, |c| self.liened_of(c.owner, c.token)),
                }
            }
        )
    }
}
