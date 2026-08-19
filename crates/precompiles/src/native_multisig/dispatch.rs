//! ABI dispatch for the [`NativeMultisig`] precompile.

use super::NativeMultisig;
use crate::{Precompile, charge_input_cost, dispatch, mutate_void, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::INativeMultisig;

impl Precompile for NativeMultisig {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                INativeMultisig::INativeMultisigCalls {
                    deriveAccount(call) => view(call, |c| {
                        self.derive_account(c.salt, c.threshold, c.owners)
                    }),
                    isMultisigAccount(call) => {
                        view(call, |c| self.is_multisig_account(c.account))
                    },
                    getConfig(call) => {
                        view(call, |c| self.get_multisig_config(c.account))
                    },
                    updateConfig(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.update_multisig_config(sender, c.threshold, c.owners)
                    })
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::sol_types::SolCall;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::INativeMultisig::INativeMultisigCalls;

    #[test]
    fn selectors_match_tip_1061() {
        assert_eq!(
            INativeMultisig::deriveAccountCall::SELECTOR,
            [0xce, 0x8e, 0x07, 0x1c]
        );
        assert_eq!(
            INativeMultisig::isMultisigAccountCall::SELECTOR,
            [0x9f, 0xbf, 0x02, 0x9a]
        );
        assert_eq!(
            INativeMultisig::getConfigCall::SELECTOR,
            [0xe4, 0x8a, 0x5f, 0x7b]
        );
        assert_eq!(
            INativeMultisig::updateConfigCall::SELECTOR,
            [0xe1, 0x75, 0xd4, 0x79]
        );
    }

    #[test]
    fn selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            let unsupported = check_selector_coverage(
                &mut multisig,
                INativeMultisigCalls::SELECTORS,
                "INativeMultisig",
                INativeMultisigCalls::name_by_selector,
            );
            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
