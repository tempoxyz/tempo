//! ABI dispatch for the storage credits precompile.

use crate::{
    Precompile, charge_input_cost, dispatch_call, mutate_void,
    tip1060_storage_credits::StorageCredits, view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IStorageCredits::IStorageCreditsCalls;

impl Precompile for StorageCredits {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            IStorageCreditsCalls::abi_decode,
            |call| match call {
                IStorageCreditsCalls::balanceOf(call) => view(call, |c| self.balance_of(c.account)),
                IStorageCreditsCalls::modeOf(call) => {
                    view(call, |c| self.mode_of(c.account).map(Into::into))
                }
                IStorageCreditsCalls::budgetOf(call) => view(call, |c| self.budget_of(c.account)),
                IStorageCreditsCalls::setMode(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.set_mode(sender, c.newMode)
                    })
                }
                IStorageCreditsCalls::setBudget(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.set_budget(sender, c.credits)
                    })
                }
            },
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

    #[test]
    fn test_storage_credits_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut storage_credits_precompile = StorageCredits::new();

            let unsupported = check_selector_coverage(
                &mut storage_credits_precompile,
                IStorageCreditsCalls::SELECTORS,
                "IStorageCredits",
                IStorageCreditsCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
