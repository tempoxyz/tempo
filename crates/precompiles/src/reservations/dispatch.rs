//! ABI dispatch for the [`Reservations`] precompile.

use super::Reservations;
use crate::{Precompile, charge_input_cost, dispatch, mutate, view};
use alloy::primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::precompiles::IReservations;

impl Precompile for Reservations {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IReservations::IReservationsCalls {
                    hold(call) => mutate(call, msg_sender, |sender, c| self.hold(sender, c, false)),
                    holdStandIn(call) => mutate(call, msg_sender, |sender, c| {
                        let c = IReservations::holdCall {
                            token: c.token,
                            id: c.id,
                            amount: c.amount,
                            expiresAt: c.expiresAt,
                            payee: c.payee,
                        };
                        self.hold(sender, c, true)
                    }),
                    adjust(call) => mutate(call, msg_sender, |sender, c| self.adjust(sender, c)),
                    capture(call) => mutate(call, msg_sender, |sender, c| {
                        self.capture_part(sender, c.id, c.amount, true)
                    }),
                    captureFor(call) => mutate(call, msg_sender, |sender, c| {
                        self.capture_for_part(sender, c.owner, c.id, c.amount, true)
                    }),
                    capturePart(call) => mutate(call, msg_sender, |sender, c| {
                        self.capture_part(sender, c.id, c.amount, c.isFinal)
                    }),
                    captureForPart(call) => mutate(call, msg_sender, |sender, c| {
                        self.capture_for_part(sender, c.owner, c.id, c.amount, c.isFinal)
                    }),
                    charge(call) => mutate(call, msg_sender, |sender, c| self.charge(sender, c, false)),
                    chargeStandIn(call) => mutate(call, msg_sender, |sender, c| {
                        let c = IReservations::chargeCall {
                            token: c.token,
                            id: c.id,
                            amount: c.amount,
                            payee: c.payee,
                        };
                        self.charge(sender, c, true)
                    }),
                    release(call) => mutate(call, msg_sender, |sender, c| self.release(sender, c.id)),
                    setDebtCap(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_debt_cap(sender, c)
                    }),
                    setCaptureTolerance(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_capture_tolerance(sender, c)
                    }),
                    setOfflineCap(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_offline_cap(sender, c)
                    }),
                    releaseExpired(call) => mutate(call, msg_sender, |_, c| {
                        self.release_expired(c.owner, c.id)
                    }),
                    refund(call) => mutate(call, msg_sender, |sender, c| self.refund(sender, c)),
                    getHold(call) => view(call, |c| self.get_hold(c.owner, c.id)),
                    reserved(call) => view(call, |c| self.reserved_of(c.owner, c.token)),
                    available(call) => view(call, |c| self.available_of(c.owner, c.token)),
                    debtOf(call) => view(call, |c| self.debt_of(c.owner, c.token)),
                    debtCap(call) => view(call, |c| self.debt_cap(c.owner, c.creditor, c.token)),
                    captureTolerance(call) => view(call, |c| {
                        self.capture_tolerance(c.owner, c.payee, c.token)
                    }),
                    captured(call) => view(call, |c| self.captured(c.owner, c.id)),
                    offlineCap(call) => view(call, |c| {
                        self.offline_cap(c.owner, c.payee, c.token)
                    }),
                }
            }
        )
    }
}
