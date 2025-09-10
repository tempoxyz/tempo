use alloy::eips::eip7702::constants::SECP256K1N_HALF;
use alloy_primitives::{Address, B512, U256};
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

    /// Validates an ECDSA signature, and deploys the default 7702 delegate code
    /// to the recovered signer's account. The account must have nonce = 0 and empty code.
    pub fn delegate_to_default(
        &mut self,
        call: ITipAccountRegistrar::delegateToDefaultCall,
    ) -> Result<Address, TipAccountRegistrarError> {
        let ITipAccountRegistrar::delegateToDefaultCall { hash, signature } = call;

        let (sig, v) = validate_signature(&signature)?;

        let signer = match ecrecover(&sig, v, &hash) {
            Ok(recovered_addr) => Address::from_word(recovered_addr),
            Err(_) => {
                return Err(TipAccountRegistrarError::InvalidSignature(
                    ITipAccountRegistrar::InvalidSignature {},
                ));
            }
        };

        let account_info = self
            .storage
            .get_account_info(signer)
            .expect("TODO: handle error");

        if account_info.nonce != 0 {
            return Err(TipAccountRegistrarError::NonceNotZero(
                ITipAccountRegistrar::NonceNotZero {},
            ));
        }

        let code = account_info.code.unwrap_or_default();

        if !code.is_empty() {
            return Err(TipAccountRegistrarError::CodeNotEmpty(
                ITipAccountRegistrar::CodeNotEmpty {},
            ));
        }

        // Delegate the account to the default 7702 implementation
        self.storage
            .set_code(signer, Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS))
            .expect("TODO: handle error");

        Ok(signer)
    }
}

/// Validates an ECDSA signature according to Ethereum standards.
/// Accepts recovery values `v ∈ {0, 1, 27, 28}` and enforces EIP-2 low-s requirement.
fn validate_signature(signature: &[u8]) -> Result<(B512, u8), TipAccountRegistrarError> {
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
    // Normalize v and bound-check
    v = match v {
        27 | 28 => v - 27,
        0 | 1 => v,
        _ => {
            return Err(TipAccountRegistrarError::InvalidSignature(
                ITipAccountRegistrar::InvalidSignature {},
            ));
        }
    };

    // Enforce EIP-2 low-s
    let s = U256::from_be_slice(&sig[32..64]);
    if s > SECP256K1N_HALF {
        return Err(TipAccountRegistrarError::InvalidSignature(
            ITipAccountRegistrar::InvalidSignature {},
        ));
    }

    Ok((sig.into(), v))
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

        let account_info_after = storage
            .get_account_info(expected_address)
            .expect("Failed to get account info");
        assert_eq!(
            account_info_after.code,
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

    #[test]
    fn test_nonce_gt_zero() {
        let mut storage = HashMapStorageProvider::new(1);
        let signer = PrivateKeySigner::random();
        let expected_address = signer.address();
        storage.set_nonce(expected_address, 1);

        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let hash = keccak256(b"test");
        let signature = signer.sign_hash_sync(&hash).unwrap();
        let call = ITipAccountRegistrar::delegateToDefaultCall {
            hash,
            signature: signature.as_bytes().into(),
        };

        let result = registrar.delegate_to_default(call);
        assert!(matches!(
            result.unwrap_err(),
            TipAccountRegistrarError::NonceNotZero(_)
        ));

        let account_info_after = storage
            .get_account_info(expected_address)
            .expect("Failed to get account info");
        assert_eq!(account_info_after.code, None);
    }
}
