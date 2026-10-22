//! Zone rules for the upstream Tempo ConfigurableAccount precompile.

use alloy_primitives::Address;
use alloy_sol_types::{SolError, SolInterface};
use tempo_contracts::precompiles::IConfigurableAccount;
use tempo_precompiles::dispatch::abi_decoder_config_for_spec;

use crate::{
    execution::{CallCheck, CallRules},
    storage::StorageCtx,
};

/// Zone-specific rules applied before forwarding to upstream `ConfigurableAccount`.
///
/// Zones reject configuration updates and migrations until they sync configurations from Tempo
/// (TIP-1114 Zones).
#[derive(Clone)]
pub(crate) struct ConfigurableAccountRules;

impl CallRules for ConfigurableAccountRules {
    fn admit(&self, data: &[u8], _caller: Address) -> CallCheck {
        let Ok(call) = IConfigurableAccount::IConfigurableAccountCalls::abi_decode_with_config(
            data,
            abi_decoder_config_for_spec(StorageCtx::default().spec()),
        ) else {
            // Preserve the upstream error and gas behavior for malformed or unknown calldata.
            return CallCheck::Continue;
        };

        // Intentionally exhaustive: an upstream ABI addition must be classified here.
        match call {
            IConfigurableAccount::IConfigurableAccountCalls::updateConfig(_)
            | IConfigurableAccount::IConfigurableAccountCalls::upgradeAccount(_) => {
                CallCheck::Revert(
                    IConfigurableAccount::UnauthorizedConfigurableAccountCaller {}
                        .abi_encode()
                        .into(),
                )
            }
            IConfigurableAccount::IConfigurableAccountCalls::deriveAccount(_)
            | IConfigurableAccount::IConfigurableAccountCalls::getConfigCommitment(_) => {
                CallCheck::Continue
            }
        }
    }
}
