use crate::{Precompile, input_cost, mutate_void};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::ITIP20RewardsRegistry;

use crate::{storage::PrecompileStorageProvider, tip20_rewards_registry::TIP20RewardsRegistry};

impl<'a, S: PrecompileStorageProvider> Precompile for TIP20RewardsRegistry<'a, S> {
    fn call(
        &mut self,
        calldata: &[u8],
        msg_sender: Address,
        _beneficiary: Address,
    ) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".to_string()))?;

        let result = match selector {
            ITIP20RewardsRegistry::finalizeStreamsCall::SELECTOR => {
                mutate_void::<ITIP20RewardsRegistry::finalizeStreamsCall>(
                    calldata,
                    msg_sender,
                    |sender, _call| self.finalize_streams(sender),
                )
            }
            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        };

        result.map(|mut res| {
            res.gas_used = self.storage.gas_used();
            res
        })
    }
}
