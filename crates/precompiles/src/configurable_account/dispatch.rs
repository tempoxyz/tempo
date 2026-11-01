//! ABI dispatch for the [`ConfigurableAccount`] precompile.

use super::ConfigurableAccount;
use crate::{Precompile, charge_input_cost, dispatch, mutate, view};
use alloy::primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::precompiles::IConfigurableAccount;

impl Precompile for ConfigurableAccount {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IConfigurableAccount::IConfigurableAccountCalls {
                    deriveAccount(call) => view(call, |c| {
                        self.derive_account(c.salt, c.threshold, &c.owners)
                    }),
                    getConfigCommitment(call) => view(call, |c| {
                        self.get_config_commitment(c.account)
                    }),
                    updateConfig(call) => mutate(call, msg_sender, |sender, c| {
                        self.update_config(sender, &c.current, c.threshold, c.owners)
                    }),
                    upgradeAccount(call) => mutate(call, msg_sender, |sender, c| {
                        self.upgrade_account(sender, c.threshold, c.owners)
                    }),
                }
            }
        )
    }
}
