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
                    getConfigCommitment(call) => {
                        view(call, |c| self.get_config_commitment(c.account))
                    },
                    updateConfig(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.update_multisig_config(sender, c.current, c.threshold, c.owners)
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
            INativeMultisig::getConfigCommitmentCall::SELECTOR,
            [0x5b, 0xd9, 0x33, 0x59]
        );
        assert_eq!(
            INativeMultisig::updateConfigCall::SELECTOR,
            [0x64, 0x20, 0x36, 0x45]
        );
    }

    #[test]
    fn selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
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
