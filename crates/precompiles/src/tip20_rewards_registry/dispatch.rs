use crate::{Precompile, view, mutate};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::storage::PrecompileStorageProvider;
use crate::tip20_rewards_registry::{ITIPRewardsRegistry, TIPRewardsRegistry};

impl<'a, S: PrecompileStorageProvider> Precompile for TIPRewardsRegistry<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".to_string()))?;

        match selector {
            ITIPRewardsRegistry::addStreamCall::SELECTOR => {
                mutate::<ITIPRewardsRegistry::addStreamCall>(calldata, msg_sender, |_, call| {
                    self.add_stream(call.token, call.endTime);
                    Ok(())
                })
            }
            ITIPRewardsRegistry::getTokensEndingAtCall::SELECTOR => {
                view::<ITIPRewardsRegistry::getTokensEndingAtCall>(calldata, |call| {
                    Ok(self.get_tokens_ending_at(call.timestamp))
                })
            }
            ITIPRewardsRegistry::finalizeStreamsCall::SELECTOR => {
                mutate::<ITIPRewardsRegistry::finalizeStreamsCall>(calldata, msg_sender, |sender, call| {
                    self.finalize_streams_checked(sender, call.timestamp)
                })
            }
            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        }
    }
}
