use crate::{contracts::DefaultAccountRegistrar, precompiles::Precompile};
use alloy_primitives::Address;
use reth_evm::revm::precompile::PrecompileResult;

impl Precompile for DefaultAccountRegistrar {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        // Delegate to the contract implementation
        DefaultAccountRegistrar::call(self, calldata, msg_sender)
    }
}

