use crate::{Precompile, mutate_void};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::ITIP20RewardsRegistry;

use crate::{storage::PrecompileStorageProvider, tip20_rewards_registry::TIP20RewardsRegistry};

impl<'a, S: PrecompileStorageProvider> Precompile for TIP20RewardsRegistry<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".to_string()))?;

        match selector {
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
        }
    }
}
