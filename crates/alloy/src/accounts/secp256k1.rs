//! Adapter for ordinary Alloy secp256k1 signers.

use std::sync::{Arc, RwLock};

use alloy_primitives::{Address, B256, ChainId, Signature};
use alloy_signer::{Signer, SignerSync};
use tempo_primitives::{SignatureType, transaction::PrimitiveSignature};

use super::TempoSigner;

/// Adapts any Alloy secp256k1 signer for Tempo primitive signatures.
#[derive(Debug)]
pub struct TempoSecp256k1Signer<S> {
    signer: Arc<S>,
    chain_id: Arc<RwLock<Option<ChainId>>>,
}

impl<S> TempoSecp256k1Signer<S> {
    /// Wrap an Alloy secp256k1 signer.
    pub fn new(signer: S) -> Self
    where
        S: Signer<Signature>,
    {
        let chain_id = signer.chain_id();
        Self {
            signer: Arc::new(signer),
            chain_id: Arc::new(RwLock::new(chain_id)),
        }
    }

    /// Borrow the underlying Alloy signer.
    pub fn inner(&self) -> &S {
        &self.signer
    }
}

impl<S> Clone for TempoSecp256k1Signer<S> {
    fn clone(&self) -> Self {
        Self {
            signer: Arc::clone(&self.signer),
            chain_id: Arc::clone(&self.chain_id),
        }
    }
}

#[async_trait::async_trait]
impl<S> Signer<PrimitiveSignature> for TempoSecp256k1Signer<S>
where
    S: Signer<Signature> + Send + Sync,
{
    async fn sign_hash(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        self.signer
            .sign_hash(hash)
            .await
            .map(PrimitiveSignature::Secp256k1)
    }

    fn address(&self) -> Address {
        self.signer.address()
    }

    fn chain_id(&self) -> Option<ChainId> {
        *self
            .chain_id
            .read()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        *self
            .chain_id
            .write()
            .unwrap_or_else(|error| error.into_inner()) = chain_id;
    }
}

impl<S> SignerSync<PrimitiveSignature> for TempoSecp256k1Signer<S>
where
    S: SignerSync<Signature>,
{
    fn sign_hash_sync(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        self.signer
            .sign_hash_sync(hash)
            .map(PrimitiveSignature::Secp256k1)
    }

    fn chain_id_sync(&self) -> Option<ChainId> {
        *self
            .chain_id
            .read()
            .unwrap_or_else(|error| error.into_inner())
    }
}

impl<S> TempoSigner for TempoSecp256k1Signer<S>
where
    S: Signer<Signature> + std::fmt::Debug + Send + Sync + 'static,
{
    fn signature_type(&self) -> SignatureType {
        SignatureType::Secp256k1
    }
}

#[cfg(test)]
mod tests {
    use alloy_signer_local::PrivateKeySigner;

    use super::*;

    #[tokio::test]
    async fn adapts_an_alloy_signer_without_changing_its_signature() {
        let signer = PrivateKeySigner::random();
        let hash = B256::random();
        let expected = signer.sign_hash(&hash).await.unwrap();
        let adapter = TempoSecp256k1Signer::new(signer.clone());

        assert_eq!(adapter.address(), signer.address());
        assert_eq!(adapter.signature_type(), SignatureType::Secp256k1);
        assert_eq!(
            adapter.sign_hash(&hash).await.unwrap(),
            PrimitiveSignature::Secp256k1(expected)
        );
    }

    #[test]
    fn cloned_adapters_share_alloy_chain_id_updates() {
        let mut adapter = TempoSecp256k1Signer::new(PrivateKeySigner::random());
        let cloned = adapter.clone();

        adapter.set_chain_id(Some(4217));

        assert_eq!(cloned.chain_id(), Some(4217));
        assert_eq!(cloned.chain_id_sync(), Some(4217));
    }
}
