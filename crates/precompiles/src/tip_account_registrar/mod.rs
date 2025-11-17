pub mod dispatch;

pub use tempo_contracts::precompiles::ITipAccountRegistrar;
use tempo_precompiles_macros::contract;

use crate::{error::Result, storage::PrecompileStorageProvider};
use alloy::{
    eips::eip7702::constants::SECP256K1N_HALF,
    primitives::{Address, B512, Bytes, U256},
};
use revm::{precompile::secp256k1::ecrecover, state::Bytecode};
use tempo_contracts::{
    DEFAULT_7702_DELEGATE_ADDRESS,
    precompiles::{TIP_ACCOUNT_REGISTRAR, TIPAccountRegistrarError},
};

#[contract]
pub struct TipAccountRegistrar {}

impl<'a, S: PrecompileStorageProvider> TipAccountRegistrar<'a, S> {
    /// Creates an instance of the precompile.
    ///
    /// Caution: This does not initialize the account, see [`Self::initialize`].
    pub fn new(storage: &'a mut S) -> Self {
        Self::_new(TIP_ACCOUNT_REGISTRAR, storage)
    }

    /// Initializes the TIP Account Registrar contract
    ///
    /// Ensures the [`TipAccountRegistrar`] account isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        self.storage.set_code(
            TIP_ACCOUNT_REGISTRAR,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    /// Pre-Moderato: Validates an ECDSA signature against a provided hash.
    /// **WARNING**: This version is vulnerable to signature forgery and is only
    /// kept for pre-Moderato compatibility. **Deprecated at Moderato hardfork**.
    pub fn delegate_to_default(
        &mut self,
        call: ITipAccountRegistrar::delegateToDefaultCall,
    ) -> Result<Address> {
        let ITipAccountRegistrar::delegateToDefaultCall { hash, signature } = call;

        // taken from precompile gas cost
        // https://github.com/bluealloy/revm/blob/a1fdb9d9e98f9dd14b7577edbad49c139ab53b16/crates/precompile/src/secp256k1.rs#L34
        self.storage.deduct_gas(3_000)?;
        let (sig, v) = validate_signature(&signature)?;

        let signer = match ecrecover(&sig, v, &hash) {
            Ok(recovered_addr) => Address::from_word(recovered_addr),
            Err(_) => {
                return Err(TIPAccountRegistrarError::invalid_signature().into());
            }
        };

        let account_info = self.storage.get_account_info(signer)?;

        if account_info.nonce != 0 {
            return Err(TIPAccountRegistrarError::nonce_not_zero().into());
        }

        if !account_info.is_empty_code_hash() {
            return Err(TIPAccountRegistrarError::code_not_empty().into());
        }

        // EIP-7702 gas cost
        // can be discussed to lower this down as this cost i think encompasses the bytes of authorization in EIP-7702 tx.
        let cost = if account_info.is_empty() {
            revm::primitives::eip7702::PER_EMPTY_ACCOUNT_COST
        } else {
            revm::primitives::eip7702::PER_AUTH_BASE_COST
        };
        self.storage.deduct_gas(cost)?;

        // Delegate the account to the default 7702 implementation
        self.storage
            .set_code(signer, Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS))?;

        Ok(signer)
    }

    /// Post-Moderato: Validates an ECDSA signature and deploys the default 7702 delegate code
    /// to the recovered signer's account. The account must have nonce = 0 and empty code.
    ///
    /// This version computes the hash internally from arbitrary message bytes to prevent signature forgery.
    pub fn delegate_to_default_v2(
        &mut self,
        call: ITipAccountRegistrar::delegateToDefaultV2Call,
    ) -> Result<Address> {
        let ITipAccountRegistrar::delegateToDefaultV2Call { message, signature } = call;

        // Compute the hash internally from the provided message
        let hash = alloy::primitives::keccak256(&message);

        // taken from precompile gas cost
        // https://github.com/bluealloy/revm/blob/a1fdb9d9e98f9dd14b7577edbad49c139ab53b16/crates/precompile/src/secp256k1.rs#L34
        self.storage.deduct_gas(3_000)?;
        let (sig, v) = validate_signature(&signature)?;

        let signer = match ecrecover(&sig, v, &hash) {
            Ok(recovered_addr) => Address::from_word(recovered_addr),
            Err(_) => {
                return Err(TIPAccountRegistrarError::invalid_signature().into());
            }
        };

        let account_info = self.storage.get_account_info(signer)?;

        if account_info.nonce != 0 {
            return Err(TIPAccountRegistrarError::nonce_not_zero().into());
        }

        if !account_info.is_empty_code_hash() {
            return Err(TIPAccountRegistrarError::code_not_empty().into());
        }

        // EIP-7702 gas cost
        // can be discussed to lower this down as this cost i think encompasses the bytes of authorization in EIP-7702 tx.
        let cost = if account_info.is_empty() {
            revm::primitives::eip7702::PER_EMPTY_ACCOUNT_COST
        } else {
            revm::primitives::eip7702::PER_AUTH_BASE_COST
        };
        self.storage.deduct_gas(cost)?;

        // Delegate the account to the default 7702 implementation
        self.storage
            .set_code(signer, Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS))?;

        Ok(signer)
    }
}

/// Validates an ECDSA signature according to Ethereum standards.
/// Accepts recovery values `v ∈ {0, 1, 27, 28}` and enforces EIP-2 low-s requirement.
fn validate_signature(signature: &[u8]) -> Result<(B512, u8)> {
    if signature.len() != 65 {
        return Err(TIPAccountRegistrarError::invalid_signature().into());
    }

    // Extract signature components
    // r: bytes 0-31 bytes
    // s: bytes 32-63 bytes
    // v: byte 64
    // SAFETY: This is safe to unwrap because we already validated length == 65
    let sig: &[u8; 64] = signature[0..64].try_into().unwrap();
    let mut v = signature[64];
    // Normalize v and bound-check
    v = match v {
        27 | 28 => v - 27,
        0 | 1 => v,
        _ => {
            return Err(TIPAccountRegistrarError::invalid_signature().into());
        }
    };

    // Enforce EIP-2 low-s
    let s = U256::from_be_slice(&sig[32..64]);
    if s > SECP256K1N_HALF {
        return Err(TIPAccountRegistrarError::invalid_signature().into());
    }

    Ok((sig.into(), v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TempoHardfork, error::TempoPrecompileError, storage::hashmap::HashMapStorageProvider,
    };
    use alloy::sol_types::SolCall;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_contracts::precompiles::TIPAccountRegistrarError;

    #[test]
    fn test_delegate_to_default_pre_moderato() {
        // Pre-Moderato: v1 function should work
        let mut storage = HashMapStorageProvider::new(1);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let signer = PrivateKeySigner::random();
        let expected_address = signer.address();

        let hash = alloy::primitives::keccak256(b"test");
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
    fn test_delegate_to_default_deprecated_post_moderato() {
        // Post-Moderato: v1 function should be deprecated
        use crate::Precompile;

        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let signer = PrivateKeySigner::random();
        let hash = alloy::primitives::keccak256(b"test");
        let signature = signer.sign_hash_sync(&hash).unwrap();

        // Encode the call
        let call = ITipAccountRegistrar::delegateToDefaultCall {
            hash,
            signature: signature.as_bytes().into(),
        };
        let calldata = call.abi_encode();

        // Should fail with UnknownFunctionSelector after Moderato
        let result = registrar.call(&calldata, signer.address());
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_signature() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let hash = alloy::primitives::keccak256(b"test");

        // Signature too short
        let call = ITipAccountRegistrar::delegateToDefaultCall {
            hash,
            signature: vec![0u8; 64].into(),
        };

        let result = registrar.delegate_to_default(call);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::TIPAccountRegistrarError(
                TIPAccountRegistrarError::InvalidSignature(_)
            )
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
            TempoPrecompileError::TIPAccountRegistrarError(
                TIPAccountRegistrarError::InvalidSignature(_)
            )
        ));
    }

    #[test]
    fn test_invalid_signature() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let hash = alloy::primitives::keccak256(b"test");

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
            TempoPrecompileError::TIPAccountRegistrarError(
                TIPAccountRegistrarError::InvalidSignature(_)
            )
        ));
    }

    #[test]
    fn test_nonce_gt_zero() {
        let mut storage = HashMapStorageProvider::new(1);
        let signer = PrivateKeySigner::random();
        let expected_address = signer.address();
        storage.set_nonce(expected_address, 1);

        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let hash = alloy::primitives::keccak256(b"test");
        let signature = signer.sign_hash_sync(&hash).unwrap();
        let call = ITipAccountRegistrar::delegateToDefaultCall {
            hash,
            signature: signature.as_bytes().into(),
        };

        let result = registrar.delegate_to_default(call);
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::TIPAccountRegistrarError(TIPAccountRegistrarError::NonceNotZero(
                _
            ))
        ));

        let account_info_after = storage
            .get_account_info(expected_address)
            .expect("Failed to get account info");
        assert!(account_info_after.is_empty_code_hash());
    }

    #[test]
    fn test_delegate_to_default_v2_with_arbitrary_message() {
        let mut storage = HashMapStorageProvider::new(1);

        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let signer = PrivateKeySigner::random();
        let expected_address = signer.address();

        // User can sign any arbitrary message
        let message = b"Hello, Tempo! I want to delegate my account.";

        // Compute the hash from the message
        let message_hash = alloy::primitives::keccak256(message);

        let signature = signer.sign_hash_sync(&message_hash).unwrap();

        let call = ITipAccountRegistrar::delegateToDefaultV2Call {
            message: message.to_vec().into(),
            signature: signature.as_bytes().into(),
        };

        let result = registrar.delegate_to_default_v2(call);
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
    fn test_delegate_to_default_v2_different_messages_different_signers() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let signer = PrivateKeySigner::random();
        let expected_address = signer.address();

        // Sign one message
        let message1 = b"Message 1";
        let hash1 = alloy::primitives::keccak256(message1);
        let signature1 = signer.sign_hash_sync(&hash1).unwrap();

        // Try to reuse the signature for a different message
        let message2 = b"Message 2";

        let call = ITipAccountRegistrar::delegateToDefaultV2Call {
            message: message2.to_vec().into(),
            signature: signature1.as_bytes().into(),
        };

        // The signature was for message1, not message2
        // ecrecover will succeed but recover a different (random) address
        let result = registrar.delegate_to_default_v2(call);

        // Either it fails (ecrecover error) OR recovers a different address
        match result {
            Ok(recovered_addr) => {
                // Should recover a different address than the actual signer
                assert_ne!(recovered_addr, expected_address);
            }
            Err(_) => {
                // Also acceptable - signature verification can fail
            }
        }
    }
}
