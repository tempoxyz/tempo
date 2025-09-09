use alloy_primitives::Address;
use reth_evm::revm::{precompile::secp256k1::ecrecover, state::Bytecode};
use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;

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

        let signer = match ecrecover(sig.into(), v, &hash) {
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
    use crate::contracts::{HashMapStorageProvider, types::ITipAccountRegistrar};
    use alloy_primitives::keccak256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    #[test]
    fn test_delegate_to_default() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let signer = PrivateKeySigner::random();
        let expected_address = signer.address();

        let hash = keccak256(b"test");
        let signature = signer.sign_hash_sync(&hash).unwrap();
        let call = ITipAccountRegistrar::delegateToDefaultCall {
            hash,
            signature: signature.as_bytes().into(),
        };

        let result = registrar.delegate_to_default(call);
        assert!(result.is_ok());

        let recovered_address = result.unwrap();
        assert_eq!(recovered_address, expected_address);

        let code_after = storage
            .get_code(expected_address)
            .expect("Failed to get account code");
        assert_eq!(
            code_after,
            Some(Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS)),
        );
    }

    #[test]
    fn test_malformed_signature() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        // Signature too short
        let hash = keccak256(b"test message");
        let call = ITipAccountRegistrar::delegateToDefaultCall {
            hash,
            signature: vec![0u8; 64].into(),
        };

        let result = registrar.delegate_to_default(call);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TipAccountRegistrarError::InvalidSignature(_)
        ));

        // Signature too long
        let call = ITipAccountRegistrar::delegateToDefaultCall {
            hash,
            signature: vec![0u8; 66].into(),
        };

        let result = registrar.delegate_to_default(call);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TipAccountRegistrarError::InvalidSignature(_)
        ));
    }

    #[test]
    fn test_invalid_signature() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let hash = keccak256(b"test message");

        // Create a signature with an invalid recovery value
        let mut invalid_signature = vec![0u8; 65];
        invalid_signature[64] = 30;

        let call = ITipAccountRegistrar::delegateToDefaultCall {
            hash,
            signature: invalid_signature.into(),
        };

        let result = registrar.delegate_to_default(call);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TipAccountRegistrarError::InvalidSignature(_)
        ));
    }
}
