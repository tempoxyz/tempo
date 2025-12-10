pub mod dispatch;

pub use tempo_contracts::precompiles::ITipAccountRegistrar;
use tempo_precompiles_macros::contract;

use crate::error::Result;
use alloy::{
    eips::eip7702::constants::SECP256K1N_HALF,
    primitives::{Address, B512, U256},
};
use revm::{precompile::secp256k1::ecrecover, state::Bytecode};
use tempo_contracts::{
    DEFAULT_7702_DELEGATE_ADDRESS,
    precompiles::{TIP_ACCOUNT_REGISTRAR, TIPAccountRegistrarError},
};

#[contract]
pub struct TipAccountRegistrar {}

impl Default for TipAccountRegistrar {
    fn default() -> Self {
        Self::new()
    }
}

impl TipAccountRegistrar {
    /// Creates an instance of the precompile.
    ///
    /// Caution: This does not initialize the account, see [`Self::initialize`].
    pub fn new() -> Self {
        Self::__new(TIP_ACCOUNT_REGISTRAR)
    }

    /// Initializes the TIP Account Registrar contract
    ///
    /// Ensures the [`TipAccountRegistrar`] account isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Pre-Moderato: Validates an ECDSA signature against a provided hash.
    /// **WARNING**: This version is vulnerable to signature forgery and is only
    /// kept for pre-Moderato compatibility. **Deprecated at Moderato hardfork**.
    pub fn delegate_to_default_v1(
        &mut self,
        call: ITipAccountRegistrar::delegateToDefault_0Call,
    ) -> Result<Address> {
        let ITipAccountRegistrar::delegateToDefault_0Call { hash, signature } = call;

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

        // EIP-7702 gas cost
        // can be discussed to lower this down as this cost i think encompasses the bytes of authorization in EIP-7702 tx.
        let cost = self.storage.with_account_info(signer, |info| {
            if info.nonce != 0 {
                Err(TIPAccountRegistrarError::nonce_not_zero().into())
            } else if !info.is_empty_code_hash() {
                Err(TIPAccountRegistrarError::code_not_empty().into())
            } else if info.is_empty() {
                Ok(revm::primitives::eip7702::PER_EMPTY_ACCOUNT_COST)
            } else {
                Ok(revm::primitives::eip7702::PER_AUTH_BASE_COST)
            }
        })?;
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
        call: ITipAccountRegistrar::delegateToDefault_1Call,
    ) -> Result<Address> {
        let ITipAccountRegistrar::delegateToDefault_1Call { message, signature } = call;

        // Compute the hash internally from the provided message
        let hash = alloy::primitives::keccak256(&message);

        // Reuse v1 logic with the computed hash
        self.delegate_to_default_v1(ITipAccountRegistrar::delegateToDefault_0Call {
            hash,
            signature,
        })
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
        Precompile,
        error::TempoPrecompileError,
        storage::{StorageContext, hashmap::HashMapStorageProvider},
    };
    use alloy::sol_types::{SolCall, SolError};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{TIPAccountRegistrarError, UnknownFunctionSelector};

    #[test]
    fn delegate_to_default_v1_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageContext::enter(&mut storage, || {
            // Pre-Moderato: delegateToDefault(bytes32,bytes) should work
            let signer = PrivateKeySigner::random();
            let expected_address = signer.address();
            let hash = alloy::primitives::keccak256(b"test");

            let mut registrar = TipAccountRegistrar::new();

            let signature = signer.sign_hash_sync(&hash).unwrap();
            let call = ITipAccountRegistrar::delegateToDefault_0Call {
                hash,
                signature: signature.as_bytes().into(),
            };

            let result = registrar.delegate_to_default_v1(call);
            assert!(result.is_ok());

            let recovered_address = result.unwrap();
            assert_eq!(recovered_address, expected_address);

            let account_info_after = registrar
                .storage
                .get_account_info(expected_address)
                .expect("Failed to get account info");
            assert_eq!(
                account_info_after.code,
                Some(Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS)),
            );

            Ok(())
        })
    }

    #[test]
    fn delegate_to_default_v1_rejected_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        StorageContext::enter(&mut storage, || {
            // Post-Moderato: delegateToDefault(bytes32,bytes) should be rejected
            let hash = alloy::primitives::keccak256(b"test");
            let mut registrar = TipAccountRegistrar::new();

            let signer = PrivateKeySigner::random();
            let signature = signer.sign_hash_sync(&hash).unwrap();

            // Encode the call using the old signature
            let call = ITipAccountRegistrar::delegateToDefault_0Call {
                hash,
                signature: signature.as_bytes().into(),
            };
            let calldata = call.abi_encode();

            // Should fail with UnknownFunctionSelector after Moderato (ABI-encoded error)
            let result = registrar.call(&calldata, signer.address());
            assert!(result.is_ok());
            let output = result.unwrap();
            assert!(output.reverted);

            // Verify the error can be decoded as UnknownFunctionSelector
            let decoded_error = UnknownFunctionSelector::abi_decode(&output.bytes);
            assert!(
                decoded_error.is_ok(),
                "Should decode as UnknownFunctionSelector"
            );

            // Verify it contains the expected selector
            let error = decoded_error.unwrap();
            assert_eq!(
                error.selector.as_slice(),
                &ITipAccountRegistrar::delegateToDefault_0Call::SELECTOR
            );

            Ok(())
        })
    }

    #[test]
    fn delegate_to_default_v2_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        StorageContext::enter(&mut storage, || {
            // Post-Moderato: delegateToDefault(bytes,bytes) should work
            let signer = PrivateKeySigner::random();
            let expected_address = signer.address();

            let mut registrar = TipAccountRegistrar::new();

            let message = b"Hello, Tempo! I want to delegate my account.";
            let message_hash = alloy::primitives::keccak256(message);
            let signature = signer.sign_hash_sync(&message_hash).unwrap();

            let call = ITipAccountRegistrar::delegateToDefault_1Call {
                message: message.to_vec().into(),
                signature: signature.as_bytes().into(),
            };

            let result = registrar.delegate_to_default_v2(call);
            assert!(result.is_ok());

            let recovered_address = result.unwrap();
            assert_eq!(recovered_address, expected_address);

            let account_info_after = registrar
                .storage
                .get_account_info(expected_address)
                .expect("Failed to get account info");
            assert_eq!(
                account_info_after.code,
                Some(Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS)),
            );

            Ok(())
        })
    }

    #[test]
    fn delegate_to_default_v2_rejected_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        StorageContext::enter(&mut storage, || {
            // Pre-Moderato: delegateToDefault(bytes,bytes) should be rejected
            let mut registrar = TipAccountRegistrar::new();

            let signer = PrivateKeySigner::random();
            let message = b"Hello, Tempo!";
            let message_hash = alloy::primitives::keccak256(message);
            let signature = signer.sign_hash_sync(&message_hash).unwrap();

            // Encode the call using the new signature
            let call = ITipAccountRegistrar::delegateToDefault_1Call {
                message: message.to_vec().into(),
                signature: signature.as_bytes().into(),
            };
            let calldata = call.abi_encode();

            // Should fail with UnknownFunctionSelector pre-Moderato
            let result = registrar.call(&calldata, signer.address());
            assert!(matches!(
                result,
                Err(revm::precompile::PrecompileError::Other(ref msg)) if msg.contains("Unknown function selector")
            ));

            Ok(())
        })
    }

    #[test]
    fn malformed_signature_v1() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageContext::enter(&mut storage, || {
            let hash = alloy::primitives::keccak256(b"test");
            let mut registrar = TipAccountRegistrar::new();

            // Signature too short
            let call = ITipAccountRegistrar::delegateToDefault_0Call {
                hash,
                signature: vec![0u8; 64].into(),
            };

            let result = registrar.delegate_to_default_v1(call);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIPAccountRegistrarError(
                    TIPAccountRegistrarError::InvalidSignature(_)
                )
            ));

            // Signature too long
            let call = ITipAccountRegistrar::delegateToDefault_0Call {
                hash,
                signature: vec![0u8; 66].into(),
            };

            let result = registrar.delegate_to_default_v1(call);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIPAccountRegistrarError(
                    TIPAccountRegistrarError::InvalidSignature(_)
                )
            ));

            Ok(())
        })
    }

    #[test]
    fn invalid_signature_v1() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageContext::enter(&mut storage, || {
            let hash = alloy::primitives::keccak256(b"test");
            let mut registrar = TipAccountRegistrar::new();

            // Create a signature with an invalid recovery value
            let mut invalid_signature = vec![0u8; 65];
            invalid_signature[64] = 30;

            let call = ITipAccountRegistrar::delegateToDefault_0Call {
                hash,
                signature: invalid_signature.into(),
            };

            let result = registrar.delegate_to_default_v1(call);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIPAccountRegistrarError(
                    TIPAccountRegistrarError::InvalidSignature(_)
                )
            ));

            Ok(())
        })
    }

    #[test]
    fn nonce_gt_zero_v1() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageContext::enter(&mut storage, || {
            let signer = PrivateKeySigner::random();
            let expected_address = signer.address();
            let hash = alloy::primitives::keccak256(b"test");

            let mut registrar = TipAccountRegistrar::new();

            registrar.storage.set_nonce(expected_address, 1);
            let signature = signer.sign_hash_sync(&hash).unwrap();
            let call = ITipAccountRegistrar::delegateToDefault_0Call {
                hash,
                signature: signature.as_bytes().into(),
            };

            let result = registrar.delegate_to_default_v1(call);
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIPAccountRegistrarError(
                    TIPAccountRegistrarError::NonceNotZero(_)
                )
            ));

            let account_info_after = registrar
                .storage
                .get_account_info(expected_address)
                .expect("Failed to get account info");
            assert!(account_info_after.is_empty_code_hash());

            Ok(())
        })
    }

    #[test]
    fn delegate_to_default_v2_different_messages_different_signers() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        StorageContext::enter(&mut storage, || {
            let signer = PrivateKeySigner::random();
            let expected_address = signer.address();

            let mut registrar = TipAccountRegistrar::new();

            // Sign one message
            let message1 = b"Message 1";
            let hash1 = alloy::primitives::keccak256(message1);
            let signature1 = signer.sign_hash_sync(&hash1).unwrap();

            // Try to reuse the signature for a different message
            let message2 = b"Message 2";

            let call = ITipAccountRegistrar::delegateToDefault_1Call {
                message: message2.to_vec().into(),
                signature: signature1.as_bytes().into(),
            };

            // The signature was for message1, not message2
            // ecrecover will succeed but recover a different (random) address
            let result = registrar.delegate_to_default_v2(call);

            // Should succeed and recover a different address than the actual signer
            // This demonstrates the signature is valid but for a different message
            let recovered_addr = result.expect("ecrecover should succeed with valid signature");
            assert_ne!(
                recovered_addr, expected_address,
                "Should recover a different address when signature is for different message"
            );

            Ok(())
        })
    }
}
