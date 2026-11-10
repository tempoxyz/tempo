//! Zone rules for the upstream Tempo ConfigurableAccount precompile (TIP-1154).

use alloy_primitives::Address;
use alloy_sol_types::{SolError, SolInterface};
use tempo_contracts::precompiles::IConfigurableAccount::{self, IConfigurableAccountCalls};
use tempo_precompiles::dispatch::abi_decoder_config_for_spec;

use crate::{
    execution::{CallCheck, CallRules},
    storage::StorageCtx,
};

/// Zones read configuration commitments from Tempo and never write one, so owner updates and
/// migrations revert with `UnsupportedOnZone()`. The read functions run unchanged.
pub(crate) struct ConfigurableAccountRules;

impl CallRules for ConfigurableAccountRules {
    fn admit(&self, data: &[u8], _caller: Address) -> CallCheck {
        let Ok(call) = IConfigurableAccountCalls::abi_decode_with_config(
            data,
            abi_decoder_config_for_spec(StorageCtx::default().spec()),
        ) else {
            // Preserve the upstream error and gas behavior for malformed or unknown calldata.
            return CallCheck::Continue;
        };

        // Intentionally exhaustive: an upstream ABI addition must be classified here.
        match call {
            IConfigurableAccountCalls::updateConfig(_)
            | IConfigurableAccountCalls::upgradeAccount(_) => CallCheck::Revert(
                IConfigurableAccount::UnsupportedOnZone {}
                    .abi_encode()
                    .into(),
            ),
            IConfigurableAccountCalls::deriveAccount(_)
            | IConfigurableAccountCalls::getConfigCommitment(_) => CallCheck::Continue,
        }
    }
}
