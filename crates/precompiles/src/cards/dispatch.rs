//! ABI dispatch for the [`Cards`] precompile.

use super::Cards;
use crate::{Precompile, charge_input_cost, dispatch, mutate, view};
use alloy::primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::precompiles::ICards;

impl Precompile for Cards {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                ICards::ICardsCalls {
                    issueCard(call) => mutate(call, msg_sender, |sender, c| self.issue_card(sender, c)),
                    updateCard(call) => mutate(call, msg_sender, |sender, c| self.update_card(sender, c)),
                    replaceCard(call) => mutate(call, msg_sender, |sender, c| self.replace_card(sender, c)),
                    setTokenHash(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_token_hash(sender, c)
                    }),
                    setProgramTokens(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_program_tokens(sender, c)
                    }),
                    setCardStatus(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_card_status(sender, c)
                    }),
                    lowerCardLimit(call) => mutate(call, msg_sender, |sender, c| {
                        self.lower_card_limit(sender, c)
                    }),
                    closeAccount(call) => mutate(call, msg_sender, |sender, c| {
                        self.close_account(sender, c)
                    }),
                    sweep(call) => mutate(call, msg_sender, |_, c| self.sweep(c.owner, c.token)),
                    markDormant(call) => mutate(call, msg_sender, |sender, c| {
                        self.mark_dormant(sender, c.owner)
                    }),
                    reactivate(call) => mutate(call, msg_sender, |sender, _| self.reactivate(sender)),
                    touch(call) => mutate(call, msg_sender, |sender, _| self.touch(sender)),
                    escheat(call) => mutate(call, msg_sender, |sender, c| self.escheat(sender, c)),
                    payoutOf(call) => view(call, |c| self.payout_of(c.owner, c.token, c.via)),
                    setEstate(call) => mutate(call, msg_sender, |sender, c| self.set_estate(sender, c)),
                    settleEstate(call) => mutate(call, msg_sender, |sender, c| {
                        self.settle_estate(sender, c)
                    }),
                    setAuthority(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_authority(sender, c)
                    }),
                    setSpendWindow(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_spend_window(sender, c)
                    }),
                    setMerchantMandate(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_merchant_mandate(sender, c)
                    }),
                    spendWindow(call) => view(call, |c| self.spend_window(c.owner, c.issuer)),
                    merchantMandate(call) => view(call, |c| {
                        self.merchant_mandate(c.owner, c.issuer, c.merchant)
                    }),
                    getAccount(call) => view(call, |c| self.get_account(c.owner)),
                    authorityOf(call) => view(call, |c| self.authority_of(c.authority, c.role)),
                    getCard(call) => view(call, |c| self.get_card(c.payee, c.card)),
                    cardByToken(call) => view(call, |c| self.card_by_token(c.payee, c.tokenHash)),
                    programAllows(call) => view(call, |c| self.program_allows(c.payee, c.token)),
                }
            }
        )
    }
}
