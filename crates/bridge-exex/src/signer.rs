//! Signature generation for bridge attestations.

use alloy::{
    primitives::{keccak256, Address, Bytes, B256},
    signers::{local::PrivateKeySigner, Signer},
};
use eyre::Result;

/// Domain separator for deposit attestations (must match precompile)
pub const DEPOSIT_ATTESTATION_DOMAIN: &[u8] = b"TEMPO_BRIDGE_DEPOSIT_V2";

/// Compute the deposit type hash for domain separation
pub fn deposit_type_hash() -> B256 {
    keccak256(DEPOSIT_ATTESTATION_DOMAIN)
}

/// Compute the digest that validators sign for deposit attestations.
///
/// IMPORTANT: This must match `Bridge::compute_deposit_attestation_digest` in the precompile.
///
/// The `validator_set_hash` binds signatures to a specific validator set, preventing
/// threshold manipulation during validator set transitions.
pub fn compute_deposit_attestation_digest(
    tempo_chain_id: u64,
    bridge_address: Address,
    request_id: B256,
    origin_chain_id: u64,
    origin_escrow: Address,
    origin_token: Address,
    origin_tx_hash: B256,
    origin_log_index: u32,
    tempo_recipient: Address,
    amount: u64,
    origin_block_number: u64,
    validator_set_hash: B256,
) -> B256 {
    let mut buf = Vec::with_capacity(
        DEPOSIT_ATTESTATION_DOMAIN.len() + 8 + 20 + 32 + 8 + 20 + 20 + 32 + 4 + 20 + 8 + 8 + 32,
    );
    buf.extend_from_slice(DEPOSIT_ATTESTATION_DOMAIN);
    buf.extend_from_slice(&tempo_chain_id.to_be_bytes());
    buf.extend_from_slice(bridge_address.as_slice());
    buf.extend_from_slice(request_id.as_slice());
    buf.extend_from_slice(&origin_chain_id.to_be_bytes());
    buf.extend_from_slice(origin_escrow.as_slice());
    buf.extend_from_slice(origin_token.as_slice());
    buf.extend_from_slice(origin_tx_hash.as_slice());
    buf.extend_from_slice(&origin_log_index.to_be_bytes());
    buf.extend_from_slice(tempo_recipient.as_slice());
    buf.extend_from_slice(&amount.to_be_bytes());
    buf.extend_from_slice(&origin_block_number.to_be_bytes());
    buf.extend_from_slice(validator_set_hash.as_slice());
    keccak256(&buf)
}

/// Trait for signing bridge attestations.
///
/// This abstraction enables HSM/KMS integration by separating the signing
/// interface from the key storage implementation.
#[async_trait::async_trait]
pub trait AttestationSigner: Send + Sync {
    /// Get the signer's address
    fn address(&self) -> Address;

    /// Sign a deposit request ID (raw hash signing)
    async fn sign_deposit(&self, request_id: &B256) -> Result<Bytes>;

    /// Sign an arbitrary hash (for burn attestations)
    async fn sign_hash(&self, hash: &B256) -> Result<Bytes>;
}

/// Local signer using an in-memory private key.
pub struct LocalSigner {
    signer: PrivateKeySigner,
    address: Address,
}

impl LocalSigner {
    /// Create from private key bytes
    pub fn from_bytes(key_bytes: &[u8; 32]) -> Result<Self> {
        let signer = PrivateKeySigner::from_bytes(&(*key_bytes).into())?;
        let address = signer.address();
        Ok(Self { signer, address })
    }
}

#[async_trait::async_trait]
impl AttestationSigner for LocalSigner {
    fn address(&self) -> Address {
        self.address
    }

    async fn sign_deposit(&self, request_id: &B256) -> Result<Bytes> {
        let signature = self.signer.sign_hash(request_id).await?;
        Ok(Bytes::from(signature.as_bytes().to_vec()))
    }

    async fn sign_hash(&self, hash: &B256) -> Result<Bytes> {
        let signature = self.signer.sign_hash(hash).await?;
        Ok(Bytes::from(signature.as_bytes().to_vec()))
    }
}

#[cfg(feature = "kms")]
mod kms_impl {
    use super::*;
    use aws_sdk_kms::{
        primitives::Blob,
        types::{MessageType, SigningAlgorithmSpec},
        Client,
    };
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    pub struct KmsSigner {
        client: Client,
        key_id: String,
        address: Address,
    }

    impl KmsSigner {
        pub async fn new(key_id: String, address: Address, region: Option<String>) -> Result<Self> {
            let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
            if let Some(region) = region {
                config_loader =
                    config_loader.region(aws_sdk_kms::config::Region::new(region.clone()));
            }
            let config = config_loader.load().await;
            let client = Client::new(&config);
            Ok(Self {
                client,
                key_id,
                address,
            })
        }

        async fn sign_digest(&self, digest: &B256) -> Result<Bytes> {
            let response = self
                .client
                .sign()
                .key_id(&self.key_id)
                .message(Blob::new(digest.as_slice()))
                .message_type(MessageType::Digest)
                .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                .send()
                .await
                .map_err(|e| eyre::eyre!("KMS sign failed: {e}"))?;

            let sig_der = response
                .signature()
                .ok_or_else(|| eyre::eyre!("No signature in KMS response"))?;

            let sig = Signature::from_der(sig_der.as_ref())
                .map_err(|e| eyre::eyre!("Invalid DER signature: {e}"))?;
            let sig = sig.normalize_s().unwrap_or(sig);

            let recovery_id = self.recover_id(digest, &sig)?;

            let mut sig_bytes = [0u8; 65];
            sig_bytes[..32].copy_from_slice(sig.r().to_bytes().as_slice());
            sig_bytes[32..64].copy_from_slice(sig.s().to_bytes().as_slice());
            sig_bytes[64] = recovery_id.to_byte() + 27;

            Ok(Bytes::from(sig_bytes.to_vec()))
        }

        fn recover_id(&self, digest: &B256, sig: &Signature) -> Result<RecoveryId> {
            for v in 0u8..4 {
                let recovery_id = RecoveryId::from_byte(v).unwrap();
                if let Ok(recovered_key) =
                    VerifyingKey::recover_from_prehash(digest.as_slice(), sig, recovery_id)
                {
                    let recovered_addr =
                        alloy::signers::utils::public_key_to_address(&recovered_key);
                    if recovered_addr == self.address {
                        return Ok(recovery_id);
                    }
                }
            }
            Err(eyre::eyre!(
                "Failed to recover signing key matching address {}",
                self.address
            ))
        }
    }

    #[async_trait::async_trait]
    impl AttestationSigner for KmsSigner {
        fn address(&self) -> Address {
            self.address
        }

        async fn sign_deposit(&self, request_id: &B256) -> Result<Bytes> {
            self.sign_digest(request_id).await
        }

        async fn sign_hash(&self, hash: &B256) -> Result<Bytes> {
            self.sign_digest(hash).await
        }
    }
}

#[cfg(feature = "kms")]
pub use kms_impl::KmsSigner;

#[cfg(not(feature = "kms"))]
pub struct KmsSigner {
    key_id: String,
    address: Address,
}

#[cfg(not(feature = "kms"))]
impl KmsSigner {
    pub async fn new(key_id: String, address: Address, _region: Option<String>) -> Result<Self> {
        Ok(Self { key_id, address })
    }
}

#[cfg(not(feature = "kms"))]
#[async_trait::async_trait]
impl AttestationSigner for KmsSigner {
    fn address(&self) -> Address {
        self.address
    }

    async fn sign_deposit(&self, _request_id: &B256) -> Result<Bytes> {
        Err(eyre::eyre!(
            "KMS signing requires the 'kms' feature. Rebuild with --features kms"
        ))
    }

    async fn sign_hash(&self, _hash: &B256) -> Result<Bytes> {
        Err(eyre::eyre!(
            "KMS signing requires the 'kms' feature. Rebuild with --features kms"
        ))
    }
}

/// Bridge signer using validator's existing key
pub struct BridgeSigner {
    inner: Box<dyn AttestationSigner>,
}

impl BridgeSigner {
    /// Create from private key bytes (local key)
    pub fn from_local_key(key_bytes: &[u8; 32]) -> Result<Self> {
        let local = LocalSigner::from_bytes(key_bytes)?;
        Ok(Self {
            inner: Box::new(local),
        })
    }

    /// Create from private key bytes (alias for backward compatibility)
    pub fn from_bytes(key_bytes: &[u8; 32]) -> Result<Self> {
        Self::from_local_key(key_bytes)
    }

    /// Create from KMS configuration
    pub async fn from_kms(
        key_id: String,
        address: Address,
        region: Option<String>,
    ) -> Result<Self> {
        let kms = KmsSigner::new(key_id, address, region).await?;
        Ok(Self {
            inner: Box::new(kms),
        })
    }

    /// Get validator address
    pub fn address(&self) -> Address {
        self.inner.address()
    }

    /// Sign a deposit request ID
    pub async fn sign_deposit(&self, request_id: &B256) -> Result<Bytes> {
        self.inner.sign_deposit(request_id).await
    }

    /// Sign an arbitrary hash (for burn attestations)
    pub async fn sign_hash(&self, hash: &B256) -> Result<Bytes> {
        self.inner.sign_hash(hash).await
    }

    /// Compute deposit request ID (must match precompile)
    ///
    /// Domain separation includes:
    /// - Type hash: keccak256("TEMPO_BRIDGE_DEPOSIT_V1")
    /// - Tempo chain ID: prevents replay across different Tempo networks
    /// - Bridge address: binds signature to specific bridge contract
    pub fn compute_deposit_id(
        tempo_chain_id: u64,
        bridge_address: Address,
        origin_chain_id: u64,
        origin_token: Address,
        origin_tx_hash: B256,
        origin_log_index: u32,
        tempo_recipient: Address,
        amount: u64,
        origin_block_number: u64,
    ) -> B256 {
        let type_hash = deposit_type_hash();
        let mut data = Vec::with_capacity(32 + 8 + 20 + 8 + 20 + 32 + 4 + 20 + 8 + 8);
        data.extend_from_slice(type_hash.as_slice());
        data.extend_from_slice(&tempo_chain_id.to_be_bytes());
        data.extend_from_slice(bridge_address.as_slice());
        data.extend_from_slice(&origin_chain_id.to_be_bytes());
        data.extend_from_slice(origin_token.as_slice());
        data.extend_from_slice(origin_tx_hash.as_slice());
        data.extend_from_slice(&origin_log_index.to_be_bytes());
        data.extend_from_slice(tempo_recipient.as_slice());
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&origin_block_number.to_be_bytes());
        keccak256(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sign_deposit() {
        let key = [1u8; 32];
        let signer = BridgeSigner::from_bytes(&key).unwrap();

        let request_id = B256::repeat_byte(0x42);
        let sig = signer.sign_deposit(&request_id).await.unwrap();

        assert_eq!(sig.len(), 65);
    }

    #[tokio::test]
    async fn test_local_signer() {
        let key = [2u8; 32];
        let signer = LocalSigner::from_bytes(&key).unwrap();

        let request_id = B256::repeat_byte(0x43);
        let sig = signer.sign_deposit(&request_id).await.unwrap();

        assert_eq!(sig.len(), 65);
        assert_ne!(signer.address(), Address::ZERO);
    }

    #[tokio::test]
    #[cfg(not(feature = "kms"))]
    async fn test_kms_signer_requires_feature() {
        let signer = KmsSigner::new("test-key-id".to_string(), Address::ZERO, None)
            .await
            .unwrap();

        let request_id = B256::repeat_byte(0x44);
        let result = signer.sign_deposit(&request_id).await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("KMS signing requires the 'kms' feature"));
    }

    #[tokio::test]
    #[cfg(not(feature = "kms"))]
    async fn test_bridge_signer_from_kms() {
        let signer =
            BridgeSigner::from_kms("test-key".to_string(), Address::repeat_byte(0x01), None)
                .await
                .unwrap();

        assert_eq!(signer.address(), Address::repeat_byte(0x01));

        let request_id = B256::repeat_byte(0x45);
        let result = signer.sign_deposit(&request_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_local_signer_produces_low_s_signatures() {
        use alloy::primitives::U256;

        // Half of the secp256k1 curve order (n/2)
        let secp256k1_n_div_2 = U256::from_be_slice(&[
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46,
            0x68, 0x1B, 0x20, 0xA0,
        ]);

        // Test with multiple keys and messages to ensure low-s is consistent
        for i in 1u8..=10 {
            let key = [i; 32];
            let signer = LocalSigner::from_bytes(&key).unwrap();

            for j in 1u8..=5 {
                let hash = B256::repeat_byte(j);
                let sig = signer.sign_hash(&hash).await.unwrap();

                // Extract s value from signature (bytes 32..64)
                let s = U256::from_be_slice(&sig[32..64]);

                assert!(
                    s <= secp256k1_n_div_2,
                    "LocalSigner must produce low-s signatures. s={s}, n/2={secp256k1_n_div_2}"
                );
            }
        }
    }
}
