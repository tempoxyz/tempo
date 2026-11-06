//! Zone rules for the upstream Tempo ConfigurableAccount precompile (TIP-1154).

use alloy_primitives::Address;
use alloy_sol_types::{SolCall, SolError};
use tempo_contracts::precompiles::IConfigurableAccount;
use tempo_precompiles::dispatch::selector_from_calldata;

use crate::execution::{CallCheck, CallRules};

/// Zones read configuration commitments from Tempo and never write one, so owner updates and
/// migrations revert with `UnsupportedOnZone()`; the read functions run unchanged.
pub(crate) struct ConfigurableAccountRules;

impl CallRules for ConfigurableAccountRules {
    fn admit(&self, data: &[u8], _caller: Address) -> CallCheck {
        match selector_from_calldata(data) {
            Some(
                IConfigurableAccount::updateConfigCall::SELECTOR
                | IConfigurableAccount::upgradeAccountCall::SELECTOR,
            ) => CallCheck::Revert(
                IConfigurableAccount::UnsupportedOnZone {}
                    .abi_encode()
                    .into(),
            ),
            _ => CallCheck::Continue,
        }
    }
}
