pub mod dispatch;

use tempo_contracts::precompiles::{
    ERC1271_MAGIC_VALUE, IMultiSigSigner, MultiSigSignerError, MultiSigSignerEvent,
};
pub use tempo_contracts::precompiles::{
    IMultiSigSigner::{
        MultisigConfig, getConfigCall, initConfigCall, isValidSignatureWithKeyHashCall,
    },
    MULTISIG_SIGNER_ADDRESS,
};

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::{
    primitives::{Address, B256, FixedBytes},
    sol_types::SolValue,
};
use tempo_precompiles_macros::{Storable, contract};

/// Maximum number of owners in a multisig
pub const MAX_OWNERS: usize = 20;

/// Maximum signature data size (8KB)
pub const MAX_SIGNATURE_DATA: usize = 8192;

/// Multisig configuration stored on-chain
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct StoredMultisigConfig {
    /// Required number of signatures
    pub threshold: u8,
    /// Number of owners (actual addresses stored separately)
    pub owner_count: u8,
}

/// MultiSigSigner precompile for threshold-based multisig verification
#[contract(addr = MULTISIG_SIGNER_ADDRESS)]
pub struct MultiSigSigner {
    /// configs[account][keyHash] -> StoredMultisigConfig
    configs: Mapping<Address, Mapping<B256, StoredMultisigConfig>>,
    /// owners[account][keyHash][index] -> owner address
    owners: Mapping<Address, Mapping<B256, Mapping<u8, Address>>>,
}

impl MultiSigSigner {
    /// Initialize the multisig signer precompile
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Initialize a new multisig configuration
    /// Called by the account that wants to set up a multisig access key
    pub fn init_config(&mut self, msg_sender: Address, call: initConfigCall) -> Result<()> {
        let key_hash = call.keyHash;
        let threshold = call.threshold;
        let owners = &call.owners;

        // Validate threshold
        if threshold == 0 || threshold as usize > owners.len() {
            return Err(MultiSigSignerError::invalid_threshold().into());
        }

        // Validate owner count
        if owners.is_empty() || owners.len() > MAX_OWNERS {
            return Err(MultiSigSignerError::invalid_threshold().into());
        }

        // Check config doesn't already exist
        let existing = self.configs[msg_sender][key_hash].read()?;
        if existing.threshold > 0 {
            return Err(MultiSigSignerError::config_already_exists().into());
        }

        // Check for duplicate owners (they must be sorted and unique)
        for i in 1..owners.len() {
            if owners[i] <= owners[i - 1] {
                return Err(MultiSigSignerError::duplicate_owner().into());
            }
        }

        // Store the config
        let config = StoredMultisigConfig {
            threshold,
            owner_count: owners.len() as u8,
        };
        self.configs[msg_sender][key_hash].write(config)?;

        // Store owners
        for (i, owner) in owners.iter().enumerate() {
            self.owners[msg_sender][key_hash][i as u8].write(*owner)?;
        }

        // Emit event
        self.emit_event(MultiSigSignerEvent::ConfigInitialized(
            IMultiSigSigner::ConfigInitialized {
                account: msg_sender,
                keyHash: key_hash,
                threshold,
                owners: owners.clone(),
            },
        ))
    }

    /// Get configuration for an account and keyHash
    pub fn get_config(&self, call: getConfigCall) -> Result<MultisigConfig> {
        let config = self.configs[call.account][call.keyHash].read()?;

        if config.threshold == 0 {
            return Ok(MultisigConfig {
                threshold: 0,
                owners: vec![],
            });
        }

        // Load owners
        let mut owners = Vec::with_capacity(config.owner_count as usize);
        for i in 0..config.owner_count {
            let owner = self.owners[call.account][call.keyHash][i].read()?;
            owners.push(owner);
        }

        Ok(MultisigConfig {
            threshold: config.threshold,
            owners,
        })
    }

    /// Validate signatures for contract-based access keys
    ///
    /// Signature format: abi.encode(address[] signers, bytes[] signatures)
    /// Each signature is a 65-byte secp256k1 signature over the digest
    pub fn is_valid_signature_with_key_hash(
        &self,
        call: isValidSignatureWithKeyHashCall,
    ) -> Result<FixedBytes<4>> {
        let account = call.account;
        let digest = call.digest;
        let key_hash = call.keyHash;
        let signature_data = &call.signature;

        // Check signature data size
        if signature_data.len() > MAX_SIGNATURE_DATA {
            return Ok(FixedBytes::ZERO);
        }

        // Load config
        let config = self.configs[account][key_hash].read()?;
        if config.threshold == 0 {
            return Ok(FixedBytes::ZERO);
        }

        // Decode signature data: (address[] signers, bytes[] signatures)
        let (signers, signatures) =
            match <(Vec<Address>, Vec<alloy::primitives::Bytes>)>::abi_decode(signature_data) {
                Ok(d) => d,
                Err(_) => return Ok(FixedBytes::ZERO),
            };

        // Check we have enough signatures
        if signers.len() < config.threshold as usize {
            return Ok(FixedBytes::ZERO);
        }

        if signers.len() != signatures.len() {
            return Ok(FixedBytes::ZERO);
        }

        // Load all owners into a set for O(1) lookup
        let mut owner_set = std::collections::HashSet::new();
        for i in 0..config.owner_count {
            let owner = self.owners[account][key_hash][i].read()?;
            owner_set.insert(owner);
        }

        // Verify each signature
        // Signers must be in ascending order to prevent replay with reordered signatures
        let mut last_signer = Address::ZERO;

        for (signer, sig) in signers.iter().zip(signatures.iter()) {
            // Check ascending order
            if *signer <= last_signer && last_signer != Address::ZERO {
                return Ok(FixedBytes::ZERO);
            }
            last_signer = *signer;

            // Check signer is an owner
            if !owner_set.contains(signer) {
                return Ok(FixedBytes::ZERO);
            }

            // Verify signature (65 bytes: r[32] || s[32] || v[1])
            if sig.len() != 65 {
                return Ok(FixedBytes::ZERO);
            }

            // Recover signer from signature
            let recovered = recover_signer(&digest, sig);
            match recovered {
                Some(addr) if addr == *signer => {}
                _ => return Ok(FixedBytes::ZERO),
            }
        }

        // All signatures valid
        Ok(FixedBytes::from(ERC1271_MAGIC_VALUE))
    }
}

/// Recover signer address from a secp256k1 signature
fn recover_signer(digest: &B256, signature: &[u8]) -> Option<Address> {
    if signature.len() != 65 {
        return None;
    }

    // Parse as alloy Signature (65 bytes: r || s || v)
    let sig = alloy::primitives::Signature::try_from(signature).ok()?;

    sig.recover_address_from_prehash(digest).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::{
        primitives::U256,
        signers::{Signer, local::PrivateKeySigner},
    };

    fn create_test_signer() -> (PrivateKeySigner, Address) {
        let signer = PrivateKeySigner::random();
        let address = signer.address();
        (signer, address)
    }

    #[test]
    fn test_init_config() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let account = Address::random();
        let key_hash = B256::random();

        let (_, owner1) = create_test_signer();
        let (_, owner2) = create_test_signer();

        // Sort owners
        let mut owners = vec![owner1, owner2];
        owners.sort();

        StorageCtx::enter(&mut storage, || {
            let mut signer = MultiSigSigner::new();
            signer.initialize()?;

            // Init config
            let call = initConfigCall {
                keyHash: key_hash,
                threshold: 2,
                owners: owners.clone(),
            };
            signer.init_config(account, call)?;

            // Verify config
            let config = signer.get_config(getConfigCall {
                account,
                keyHash: key_hash,
            })?;

            assert_eq!(config.threshold, 2);
            assert_eq!(config.owners.len(), 2);
            assert_eq!(config.owners, owners);

            Ok(())
        })
    }

    #[test]
    fn test_init_config_already_exists() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let account = Address::random();
        let key_hash = B256::random();
        let owner = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut signer = MultiSigSigner::new();
            signer.initialize()?;

            let call = initConfigCall {
                keyHash: key_hash,
                threshold: 1,
                owners: vec![owner],
            };

            // First init should succeed
            signer.init_config(account, call.clone())?;

            // Second init should fail
            let result = signer.init_config(account, call);
            assert!(result.is_err());

            Ok(())
        })
    }

    #[tokio::test]
    async fn test_valid_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let account = Address::random();
        let key_hash = B256::random();
        let digest = B256::random();

        let (signer1, owner1) = create_test_signer();
        let (signer2, owner2) = create_test_signer();

        // Sort owners
        let mut owners = vec![owner1, owner2];
        owners.sort();

        // Determine which signer corresponds to which sorted owner
        let (signer_low, signer_high) = if owner1 < owner2 {
            (signer1, signer2)
        } else {
            (signer2, signer1)
        };

        StorageCtx::enter(&mut storage, || {
            let mut multisig = MultiSigSigner::new();
            multisig.initialize()?;

            let call = initConfigCall {
                keyHash: key_hash,
                threshold: 2,
                owners: owners.clone(),
            };
            multisig.init_config(account, call)?;

            Ok::<_, eyre::Error>(multisig)
        })?;

        // Sign the digest with both signers
        let sig1 = signer_low.sign_hash(&digest).await?;
        let sig2 = signer_high.sign_hash(&digest).await?;

        // Encode signatures
        let sig1_bytes: alloy::primitives::Bytes = sig1.as_bytes().to_vec().into();
        let sig2_bytes: alloy::primitives::Bytes = sig2.as_bytes().to_vec().into();

        let signature_data = (owners.clone(), vec![sig1_bytes, sig2_bytes]).abi_encode();

        StorageCtx::enter(&mut storage, || {
            let multisig = MultiSigSigner::new();

            let result =
                multisig.is_valid_signature_with_key_hash(isValidSignatureWithKeyHashCall {
                    account,
                    digest,
                    keyHash: key_hash,
                    signature: signature_data.into(),
                })?;

            assert_eq!(result.as_slice(), &ERC1271_MAGIC_VALUE);

            Ok(())
        })
    }
}
