//! ABI dispatch for the [`TIP1028Escrow`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch_call, mutate_void, tip1028_escrow::TIP1028Escrow, view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ITIP1028Escrow::ITIP1028EscrowCalls;

impl Precompile for TIP1028Escrow {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            ITIP1028EscrowCalls::abi_decode,
            |call| match call {
                ITIP1028EscrowCalls::blockedReceiptBalance(call) => {
                    view(call, |c| self.blocked_receipt_balance(c))
                }
                ITIP1028EscrowCalls::claimBlocked(call) => {
                    mutate_void(call, msg_sender, |s, c| self.claim_blocked(s, c))
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
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let mut escrow = TIP1028Escrow::new();
            let unsupported = check_selector_coverage(
                &mut escrow,
                ITIP1028EscrowCalls::SELECTORS,
                "ITIP1028Escrow",
                ITIP1028EscrowCalls::name_by_selector,
            );
            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
