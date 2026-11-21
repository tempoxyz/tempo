//! ABI dispatch for the [`PaymentCallRegistry`] precompile.

use super::PaymentCallRegistry;
use crate::{Precompile, charge_input_cost, dispatch, mutate, view};
use alloy::primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::precompiles::IPaymentCallRegistry;

impl Precompile for PaymentCallRegistry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IPaymentCallRegistry::IPaymentCallRegistryCalls {
                    proposeTemplate(call) => mutate(call, msg_sender, |sender, c| {
                        self.propose_template(sender, c)
                    }),
                    activateTemplate(call) => mutate(call, msg_sender, |sender, c| {
                        self.activate_template(sender, c.templateId)
                    }),
                    removeTemplate(call) => mutate(call, msg_sender, |sender, c| {
                        self.remove_template(sender, c.templateId)
                    }),
                    removeInstance(call) => mutate(call, msg_sender, |sender, c| {
                        self.remove_instance(sender, c.instance)
                    }),
                    registerInstance(call) => mutate(call, msg_sender, |_, c| {
                        self.register_instance(c.instance)
                    }),
                    governance(call) => view(call, |_| self.governance()),
                    version(call) => view(call, |_| self.version()),
                    templateCount(call) => view(call, |_| self.template_count()),
                    templateTimelock(call) => view(call, |_| self.template_timelock()),
                    instanceActivationDelay(call) => view(call, |_| {
                        self.instance_activation_delay()
                    }),
                    getTemplate(call) => view(call, |c| self.get_template(c.templateId)),
                    getInstance(call) => view(call, |c| self.get_instance(c.instance)),
                    paymentCallGasCap(call) => view(call, |c| {
                        self.payment_call_gas_cap(c.target, &c.input)
                    }),
                    maskedCodeHash(call) => view(call, |c| {
                        self.masked_code_hash(&c.code, &c.ranges)
                    })
                }
            }
        )
    }
}
