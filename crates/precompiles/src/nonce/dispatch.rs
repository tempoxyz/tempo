//! ABI dispatch for the [`NonceManager`] precompile.

use crate::{Precompile, charge_input_cost, dispatch, dispatch::tempo::view, nonce::NonceManager};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::INonce;
impl Precompile for NonceManager {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(calldata, |call| match call {
            INonce::INonceCalls { getNonce(call) => view(call, |c| self.get_nonce(c)) }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use tempo_contracts::precompiles::INonce::INonceCalls;
    #[test]
    fn test_nonce_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut nonce_manager = NonceManager::new();

            let unsupported = check_selector_coverage(
                &mut nonce_manager,
                INonceCalls::SELECTORS,
                "INonce",
                INonceCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
