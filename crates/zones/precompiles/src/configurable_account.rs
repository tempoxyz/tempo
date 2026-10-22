//! Zone rules for the upstream Tempo ConfigurableAccount precompile.

use alloy_primitives::Address;
use alloy_sol_types::{SolError, SolInterface};
use tempo_contracts::{precompiles::IConfigurableAccount, zones::ConfigurableAccountsNotSupported};
use tempo_precompiles::dispatch::abi_decoder_config_for_spec;

use crate::{
    execution::{CallCheck, CallRules},
    storage::StorageCtx,
};

/// Rejects configurable account updates and migrations on Zones.
///
/// Owner rotations and EOA migrations on Tempo never reach Zone state, so Zones reject
/// configurable accounts until their commitments are synced from Tempo.
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
                CallCheck::Revert(ConfigurableAccountsNotSupported {}.abi_encode().into())
            }
            IConfigurableAccount::IConfigurableAccountCalls::deriveAccount(_)
            | IConfigurableAccount::IConfigurableAccountCalls::getConfigCommitment(_) => {
                CallCheck::Continue
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes};
    use alloy_sol_types::SolCall;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount::ConfigurableAccountOwner,
    };

    use crate::test_utils::{call_precompile, test_context_with_hardfork, test_precompiles};

    const CALLER: Address = Address::repeat_byte(0x55);

    fn call(data: &[u8]) -> revm::precompile::PrecompileOutput {
        let mut ctx = test_context_with_hardfork(TempoHardfork::T14);
        let mut precompiles =
            test_precompiles(&ctx, crate::L1State::new(Default::default(), Address::ZERO));
        call_precompile(
            &mut ctx,
            &mut precompiles,
            CALLER,
            data,
            u64::MAX,
            false,
            CONFIGURABLE_ACCOUNT_ADDRESS,
            CONFIGURABLE_ACCOUNT_ADDRESS,
        )
        .unwrap()
    }

    #[test]
    fn updates_and_migrations_revert() {
        let owners = vec![ConfigurableAccountOwner {
            owner: Address::repeat_byte(0x66),
            weight: 1,
        }];
        for data in [
            IConfigurableAccount::updateConfigCall {
                current: IConfigurableAccount::ConfigurableAccountConfig {
                    salt: B256::ZERO,
                    version: 1,
                    threshold: 1,
                    owners: owners.clone(),
                },
                threshold: 1,
                owners: owners.clone(),
            }
            .abi_encode(),
            IConfigurableAccount::upgradeAccountCall {
                threshold: 1,
                owners,
            }
            .abi_encode(),
        ] {
            let output = call(&data);
            assert!(output.is_revert());
            assert_eq!(
                output.bytes,
                Bytes::from(ConfigurableAccountsNotSupported {}.abi_encode())
            );
        }
    }

    #[test]
    fn views_are_forwarded() {
        let output =
            call(&IConfigurableAccount::getConfigCommitmentCall { account: CALLER }.abi_encode());
        assert!(!output.is_revert());
        assert_eq!(
            IConfigurableAccount::getConfigCommitmentCall::abi_decode_returns(&output.bytes)
                .unwrap(),
            B256::ZERO
        );
    }
}
