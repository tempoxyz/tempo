use crate::{Precompile, mutate, view};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::{
    storage::PrecompileStorageProvider,
    tip20_factory::{ITIP20Factory, TIP20Factory},
};

impl<'a, S: PrecompileStorageProvider> Precompile for TIP20Factory<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".to_string()))?;

        match selector {
            ITIP20Factory::tokenIdCounterCall::SELECTOR => {
                view::<ITIP20Factory::tokenIdCounterCall>(calldata, |_call| self.token_id_counter())
            }
            ITIP20Factory::createTokenCall::SELECTOR => {
                mutate::<ITIP20Factory::createTokenCall>(calldata, msg_sender, |s, call| {
                    self.create_token(s, call)
                })
            }
            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        }
    }
}
