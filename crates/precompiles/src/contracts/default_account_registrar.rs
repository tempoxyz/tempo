use alloy_primitives::Address;
use reth_evm::revm::precompile::PrecompileResult;

use crate::{
    contracts::types::{DefaultAccountRegistrarError, IDefaultAccountRegistrar},
    precompiles::Precompile,
};

pub struct DefaultAccountRegistrar;

impl DefaultAccountRegistrar {
    pub fn new() -> Self {
        Self
    }

    pub fn delegate_to_default(
        &mut self,
        _msg_sender: &Address,
        call: IDefaultAccountRegistrar::delegateToDefaultCall,
    ) -> Result<Address, DefaultAccountRegistrarError> {
        let IDefaultAccountRegistrar::delegateToDefaultCall {
            hash: _hash,
            v: _v,
            r: _r,
            s: _s,
        } = call;

        // TODO: Implement actual ECDSA recovery and validation
        // For now, return a stub address
        Ok(Address::ZERO)
    }
}

impl Default for DefaultAccountRegistrar {
    fn default() -> Self {
        Self::new()
    }
}

impl Precompile for DefaultAccountRegistrar {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector = calldata.get(..4).and_then(|s| s.try_into().ok());

        match selector {
            Some(IDefaultAccountRegistrar::delegateToDefaultCall::SELECTOR) => {
                mutate::<IDefaultAccountRegistrar::delegateToDefaultCall, DefaultAccountRegistrarError>(
                    calldata,
                    msg_sender,
                    |sender, call| self.delegate_to_default(sender, call),
                )
            }
            _ => Err(reth_evm::revm::precompile::PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        }
    }
}

