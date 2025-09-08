use alloy_primitives::{Address, keccak256};
use reth_evm::revm::{precompile::secp256k1::ecrecover, state::Bytecode};
use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;

pub const EIP_7702_DELEGATION_MSG: &str = "eip7702 account delegation";

use crate::contracts::{
    StorageProvider,
    types::{ITipAccountRegistrar, TipAccountRegistrarError},
};

pub struct TipAccountRegistrar<'a, S: StorageProvider> {
    storage: &'a mut S,
}

impl<'a, S: StorageProvider> TipAccountRegistrar<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self { storage }
    }

    pub fn get_delegation_message() -> &'static str {
        EIP_7702_DELEGATION_MSG
    }

    pub fn delegate_to_default(
        &mut self,
        call: ITipAccountRegistrar::delegateToDefaultCall,
    ) -> Result<Address, TipAccountRegistrarError> {
        let ITipAccountRegistrar::delegateToDefaultCall { hash, signature } = call;

        if signature.len() != 65 {
            return Err(TipAccountRegistrarError::InvalidSignature(
                ITipAccountRegistrar::InvalidSignature {},
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

        // Enforce that the signed message matches the delegation message
        let expected_hash = keccak256(EIP_7702_DELEGATION_MSG.as_bytes());
        if hash != expected_hash {
            return Err(TipAccountRegistrarError::InvalidSignature(
                ITipAccountRegistrar::InvalidSignature {},
            ));
        }

        let msg = &hash;

        let signer = match ecrecover(sig.into(), v, msg) {
            Ok(recovered_addr) => Address::from_word(recovered_addr),
            Err(_) => {
                return Err(TipAccountRegistrarError::InvalidSignature(
                    ITipAccountRegistrar::InvalidSignature {},
                ));
            }
        };

        let code = self
            .storage
            .get_code(signer)
            .expect("TODO: handle error")
            .unwrap_or_default();

        if code.is_empty() {
            // Delegate the account to the default 7702 implementation
            self.storage
                .set_code(signer, Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS))
                .expect("TODO: handle error");
        }

        Ok(signer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contracts::{HashMapStorageProvider, types::ITipAccountRegistrar},
        precompiles::Precompile,
    };

    #[test]
    fn test_precompile_call_with_invalid_selector() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registrar = TipAccountRegistrar::new(&mut storage);
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

        let mut storage = HashMapStorageProvider::new(1);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let signer = PrivateKeySigner::random();
        let expected_address = signer.address();

        let hash = keccak256(EIP_7702_DELEGATION_MSG.as_bytes());

        // Sign the hash directly (not with Ethereum message prefix)
        let signature = signer.sign_hash_sync(&hash).unwrap();
        let call = ITipAccountRegistrar::delegateToDefaultCall {
            hash,
            signature: signature.as_bytes().into(),
        };

        let result = registrar.delegate_to_default(call);
        assert!(result.is_ok());

        let recovered_address = result.unwrap();
        assert_eq!(recovered_address, expected_address);

        // Verify that the account was deployed with EIP-7702 delegation
        let code_after = storage
            .get_code(expected_address)
            .expect("Failed to get account code");
        assert_eq!(
            code_after,
            Some(Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS)),
        );
    }
}
