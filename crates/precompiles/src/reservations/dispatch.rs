//! ABI dispatch for the [`Reservations`] precompile.

use super::{Placement, Reservations};
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
                    hold(call) => mutate(call, msg_sender, |sender, c| self.hold(sender, c, Placement::Plain)),
                    holdStandIn(call) => mutate(call, msg_sender, |sender, c| {
                        let c = IReservations::holdCall {
                            token: c.token,
                            id: c.id,
                            amount: c.amount,
                            expiresAt: c.expiresAt,
                            payee: c.payee,
                        };
                        self.hold(sender, c, Placement::StandIn)
                    }),
                    holdCard(call) => mutate(call, msg_sender, |sender, c| {
                        let placement = Placement::Card {
                            issuer: c.issuer,
                            card: c.card,
                        };
                        let c = IReservations::holdCall {
                            token: c.token,
                            id: c.id,
                            amount: c.amount,
                            expiresAt: c.expiresAt,
                            payee: c.payee,
                        };
                        self.hold(sender, c, placement)
                    }),
                    holdCardForMerchant(call) => mutate(call, msg_sender, |sender, c| {
                        let placement = Placement::CardMerchant {
                            issuer: c.issuer,
                            card: c.card,
                            merchant: c.merchant,
                        };
                        let c = IReservations::holdCall {
                            token: c.token,
                            id: c.id,
                            amount: c.amount,
                            expiresAt: c.expiresAt,
                            payee: c.payee,
                        };
                        self.hold(sender, c, placement)
                    }),
                    holdCardStandIn(call) => mutate(call, msg_sender, |sender, c| {
                        let placement = Placement::CardStandIn {
                            issuer: c.issuer,
                            card: c.card,
                        };
                        let c = IReservations::holdCall {
                            token: c.token,
                            id: c.id,
                            amount: c.amount,
                            expiresAt: c.expiresAt,
                            payee: c.payee,
                        };
                        self.hold(sender, c, placement)
                    }),
                    holdWithLine(call) => mutate(call, msg_sender, |sender, c| {
                        let placement = Placement::Line {
                            part: c.linePart,
                            line: c.line,
                            lender: c.lender,
                        };
                        let c = IReservations::holdCall {
                            token: c.token,
                            id: c.id,
                            amount: c.amount,
                            expiresAt: c.expiresAt,
                            payee: c.payee,
                        };
                        self.hold(sender, c, placement)
                    }),
                    holdCardWithLine(call) => mutate(call, msg_sender, |sender, c| {
                        let placement = Placement::CardLine {
                            issuer: c.issuer,
                            card: c.card,
                            part: c.linePart,
                            line: c.line,
                            lender: c.lender,
                        };
                        let c = IReservations::holdCall {
                            token: c.token,
                            id: c.id,
                            amount: c.amount,
                            expiresAt: c.expiresAt,
                            payee: c.payee,
                        };
                        self.hold(sender, c, placement)
                    }),
                    holdForDispute(call) => mutate(call, msg_sender, |sender, c| {
                        let placement = Placement::Dispute {
                            owner: c.disputeOwner,
                            id: c.disputeId,
                        };
                        let c = IReservations::holdCall {
                            token: c.token,
                            id: c.id,
                            amount: c.amount,
                            expiresAt: c.expiresAt,
                            payee: c.payee,
                        };
                        self.hold(sender, c, placement)
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
                    openLine(call) => mutate(call, msg_sender, |sender, c| self.open_line(sender, c)),
                    offerCredit(call) => mutate(call, msg_sender, |sender, c| {
                        self.offer_credit(sender, c)
                    }),
                    grantCredit(call) => mutate(call, msg_sender, |sender, c| {
                        self.grant_credit(sender, c)
                    }),
                    repayCredit(call) => mutate(call, msg_sender, |sender, c| {
                        self.repay_credit(sender, c)
                    }),
                    openDispute(call) => mutate(call, msg_sender, |sender, c| {
                        self.open_dispute(sender, c)
                    }),
                    disputeStep(call) => mutate(call, msg_sender, |sender, c| {
                        self.dispute_step(sender, c)
                    }),
                    resolveDispute(call) => mutate(call, msg_sender, |sender, c| {
                        self.resolve_dispute(sender, c)
                    }),
                    lien(call) => mutate(call, msg_sender, |sender, c| self.lien(sender, c)),
                    releaseLien(call) => mutate(call, msg_sender, |sender, c| {
                        self.release_lien(sender, c.id)
                    }),
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
                    creditOf(call) => view(call, |c| self.credit_of(c.owner, c.lender, c.line)),
                    getLine(call) => view(call, |c| self.get_line(c.lender, c.line)),
                    creditOffer(call) => view(call, |c| {
                        self.credit_offer(c.lender, c.line, c.owner)
                    }),
                    disputeOf(call) => view(call, |c| self.dispute_of(c.owner, c.id)),
                    lienOf(call) => view(call, |c| self.lien_of(c.authority, c.id)),
                    liened(call) => view(call, |c| self.liened_of(c.owner, c.token)),
                }
            }
        )
    }
}
