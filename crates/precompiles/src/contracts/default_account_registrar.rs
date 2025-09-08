use alloy_primitives::Address;

use crate::contracts::types::{DefaultAccountRegistrarError, IDefaultAccountRegistrar};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{contracts::types::IDefaultAccountRegistrar, precompiles::Precompile};
    use alloy_primitives::{B256, U256};

    #[test]
    fn test_delegate_to_default_stub() {
        let mut registrar = DefaultAccountRegistrar::new();
        let sender = Address::ZERO;

        let call = IDefaultAccountRegistrar::delegateToDefaultCall {
            hash: B256::ZERO,
            v: 27,
            r: B256::ZERO,
            s: B256::ZERO,
        };

        let result = registrar.delegate_to_default(&sender, call);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Address::ZERO);
    }

    #[test]
    fn test_precompile_call_with_invalid_selector() {
        let mut registrar = DefaultAccountRegistrar::new();
        let invalid_calldata = [0xFF; 4];
        let sender = Address::ZERO;

        let result = registrar.call(&invalid_calldata, &sender);
        assert!(result.is_err());
    }
}
