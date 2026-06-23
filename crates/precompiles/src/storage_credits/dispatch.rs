//! ABI dispatch for the storage credits precompile.

use crate::{
    Precompile, charge_input_cost, dispatch_call, mutate_void, storage_credits::StorageCredits,
    view,
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
    use alloy::sol_types::SolCall;
    use tempo_contracts::precompiles::{IStorageCredits, StorageCreditsError};

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

    #[test]
    fn test_storage_credits_set_budget_zero_stays_direct() -> eyre::Result<()> {
        let caller = Address::repeat_byte(0x11);
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut storage_credits_precompile = StorageCredits::new();

            let set_budget = IStorageCredits::setBudgetCall { credits: 7 };
            let output = storage_credits_precompile.call(&set_budget.abi_encode(), caller)?;
            assert!(!output.is_revert());

            let mode = storage_credits_precompile.call(
                &IStorageCredits::modeOfCall { account: caller }.abi_encode(),
                caller,
            )?;
            assert_eq!(
                IStorageCredits::modeOfCall::abi_decode_returns(&mode.bytes)?,
                IStorageCredits::Mode::Direct
            );

            let budget = storage_credits_precompile.call(
                &IStorageCredits::budgetOfCall { account: caller }.abi_encode(),
                caller,
            )?;
            assert_eq!(
                IStorageCredits::budgetOfCall::abi_decode_returns(&budget.bytes)?,
                7
            );

            let zero_budget = IStorageCredits::setBudgetCall { credits: 0 };
            let output = storage_credits_precompile.call(&zero_budget.abi_encode(), caller)?;
            assert!(!output.is_revert());

            let mode = storage_credits_precompile.call(
                &IStorageCredits::modeOfCall { account: caller }.abi_encode(),
                caller,
            )?;
            assert_eq!(
                IStorageCredits::modeOfCall::abi_decode_returns(&mode.bytes)?,
                IStorageCredits::Mode::Direct,
                "setBudget(0) keeps Direct selected with a zero spend budget"
            );

            let budget = storage_credits_precompile.call(
                &IStorageCredits::budgetOfCall { account: caller }.abi_encode(),
                caller,
            )?;
            assert_eq!(
                IStorageCredits::budgetOfCall::abi_decode_returns(&budget.bytes)?,
                0
            );

            Ok(())
        })
    }

    #[test]
    fn test_storage_credits_set_mode_rejects_reserved_mode() -> eyre::Result<()> {
        let caller = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut storage_credits_precompile = StorageCredits::new();
            let mut calldata = IStorageCredits::setModeCall {
                newMode: IStorageCredits::Mode::Refund,
            }
            .abi_encode();
            *calldata
                .last_mut()
                .expect("setMode ABI calldata must contain the enum word") = 3;

            let output = storage_credits_precompile.call(&calldata, caller)?;
            assert!(output.is_revert());
            assert_eq!(
                &output.bytes[..4],
                StorageCreditsError::invalid_mode().selector().as_slice()
            );

            Ok(())
        })
    }
}
