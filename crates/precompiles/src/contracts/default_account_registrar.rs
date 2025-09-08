use alloy_primitives::{Address, B256, U256};
use reth_evm::revm::precompile::secp256k1::ecrecover;

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
        let IDefaultAccountRegistrar::delegateToDefaultCall { hash, signature } = call;

        // Signature should be 65 bytes: [r (32 bytes), s (32 bytes), v (1 byte)]
        if signature.len() != 65 {
            return Err(DefaultAccountRegistrarError::InvalidSignature(
                IDefaultAccountRegistrar::InvalidSignature {},
            ));
        }

        // Extract signature components
        // r: bytes 0-31 bytes
        // s: bytes 32-63 bytes
        // v: byte 64
        let sig: &[u8; 64] = signature[0..64].try_into().unwrap();
        let mut v = signature[64];
        if v >= 27 {
            v -= 27;
        }

        let msg = &hash;

        match ecrecover(sig.into(), v, msg) {
            Ok(recovered_addr) => Ok(Address::from_word(recovered_addr)),
            Err(_) => Err(DefaultAccountRegistrarError::InvalidSignature(
                IDefaultAccountRegistrar::InvalidSignature {},
            )),
        }
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
    use alloy_primitives::B256;

    #[test]
    fn test_delegate_to_default_stub() {
        let mut registrar = DefaultAccountRegistrar::new();
        let sender = Address::ZERO;

        let call = IDefaultAccountRegistrar::delegateToDefaultCall {
            hash: B256::ZERO,
            signature: vec![0u8; 65].into(), // 65 zero bytes
        };

        let result = registrar.delegate_to_default(&sender, call);
        // Should fail with invalid signature (all zeros)
        assert!(result.is_err());
    }

    #[test]
    fn test_precompile_call_with_invalid_selector() {
        let mut registrar = DefaultAccountRegistrar::new();
        let invalid_calldata = [0xFF; 4];
        let sender = Address::ZERO;

        let result = registrar.call(&invalid_calldata, &sender);
        assert!(result.is_err());
    }

    #[test]
    fn test_delegate_to_default() {
        use alloy_primitives::keccak256;
        use alloy_signer::{Signer, SignerSync};
        use alloy_signer_local::PrivateKeySigner;

        let mut registrar = DefaultAccountRegistrar::new();

        let signer = PrivateKeySigner::random();
        let expected_address = signer.address();

        let message = b"msg";
        let hash = keccak256(message);

        // Sign the hash directly (not with Ethereum message prefix)
        let signature = signer.sign_hash_sync(&hash).unwrap();
        let call = IDefaultAccountRegistrar::delegateToDefaultCall {
            hash,
            signature: signature.as_bytes().into(),
        };

        let result = registrar.delegate_to_default(&signer.address(), call);
        assert!(result.is_ok());

        let recovered_address = result.unwrap();
        assert_eq!(recovered_address, expected_address);
    }
}
