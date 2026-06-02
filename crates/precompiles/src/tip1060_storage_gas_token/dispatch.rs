//! ABI dispatch for the storage gas tokens precompile.

use crate::{
    Precompile, charge_input_cost, dispatch_call, mutate_void,
    tip1060_storage_gas_token::TIP1060StorageGasToken, view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ITIP1060StorageGasTokens::ITIP1060StorageGasTokensCalls;

impl Precompile for TIP1060StorageGasToken {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            ITIP1060StorageGasTokensCalls::abi_decode,
            |call| match call {
                ITIP1060StorageGasTokensCalls::balance(call) => view(call, |_| {
                    self.state_of(msg_sender).map(|state| state.balance)
                }),
                ITIP1060StorageGasTokensCalls::balanceOf(call) => view(call, |c| {
                    self.state_of(c.account).map(|state| state.balance)
                }),
                ITIP1060StorageGasTokensCalls::mode(call) => view(call, |_| {
                    self.state_of(msg_sender).map(|state| state.mode.into())
                }),
                ITIP1060StorageGasTokensCalls::modeOf(call) => view(call, |c| {
                    self.state_of(c.account).map(|state| state.mode.into())
                }),
                ITIP1060StorageGasTokensCalls::setMode(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.set_mode(sender, c.newMode)
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
    fn test_storage_gas_tokens_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut gas_token = TIP1060StorageGasToken::new();

            let unsupported = check_selector_coverage(
                &mut gas_token,
                ITIP1060StorageGasTokensCalls::SELECTORS,
                "ITIP1060StorageGasTokens",
                ITIP1060StorageGasTokensCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
