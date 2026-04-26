use alloy_network::{EthereumWallet, IntoWallet, NetworkWallet};
use alloy_primitives::Address;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use tempo_primitives::{
    AASigned, TempoTxEnvelope,
    transaction::{
        TempoTypedTransaction,
        tt_signature::{KeychainSignature, PrimitiveSignature, TempoSignature},
    },
};

use crate::{TempoNetwork, account::AccessKeyAccount};

/// A Tempo-aware wallet that supports both EOA and access key signing.
///
/// For EOA accounts, signing is delegated to the inner [`EthereumWallet`].
/// For access key accounts, signing uses the domain-separated keychain scheme
/// automatically, so users can simply call `send_transaction` without manual
/// hash computation.
#[derive(Clone)]
pub struct TempoWallet {
    inner: EthereumWallet,
    access_key: Option<AccessKeyAccount>,
}

impl TempoWallet {
    /// Create a new wallet from an [`EthereumWallet`].
    pub fn new(inner: EthereumWallet) -> Self {
        Self {
            inner,
            access_key: None,
        }
    }

    /// Create a new wallet with an access key account.
    pub fn with_access_key(access_key: AccessKeyAccount) -> Self {
        Self {
            inner: EthereumWallet::default(),
            access_key: Some(access_key),
        }
    }

    /// Returns a reference to the access key account, if configured.
    pub fn access_key(&self) -> Option<&AccessKeyAccount> {
        self.access_key.as_ref()
    }
}

impl std::fmt::Debug for TempoWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempoWallet")
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

impl NetworkWallet<TempoNetwork> for TempoWallet {
    fn default_signer_address(&self) -> Address {
        if let Some(ref ak) = self.access_key {
            ak.sender_address()
        } else {
            NetworkWallet::<TempoNetwork>::default_signer_address(&self.inner)
        }
    }

    fn has_signer_for(&self, address: &Address) -> bool {
        if let Some(ref ak) = self.access_key
            && *address == ak.sender_address()
        {
            return true;
        }
        NetworkWallet::<TempoNetwork>::has_signer_for(&self.inner, address)
    }

    fn signer_addresses(&self) -> impl Iterator<Item = Address> {
        let ak_addr = self.access_key.as_ref().map(|ak| ak.sender_address());
        ak_addr
            .into_iter()
            .chain(NetworkWallet::<TempoNetwork>::signer_addresses(&self.inner))
    }

    async fn sign_transaction_from(
        &self,
        sender: Address,
        tx: TempoTypedTransaction,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        // Check if this sender matches our access key account
        if let Some(ref ak) = self.access_key
            && sender == ak.sender_address()
        {
            let TempoTypedTransaction::AA(tempo_tx) = tx else {
                return Err(alloy_signer::Error::other(
                    "access key accounts can only sign AA transactions",
                ));
            };

            let sig_hash = tempo_tx.signature_hash();
            let keychain_hash = KeychainSignature::signing_hash(sig_hash, ak.root());
            let inner_sig = ak.signer().sign_hash_sync(&keychain_hash)?;
            let signature = TempoSignature::Keychain(KeychainSignature::new(
                ak.root(),
                PrimitiveSignature::Secp256k1(inner_sig),
            ));

            return Ok(TempoTxEnvelope::AA(AASigned::new_unhashed(
                tempo_tx, signature,
            )));
        }

        // Fall through to EOA signing
        NetworkWallet::<TempoNetwork>::sign_transaction_from(&self.inner, sender, tx).await
    }
}

impl From<AccessKeyAccount> for TempoWallet {
    fn from(account: AccessKeyAccount) -> Self {
        Self::with_access_key(account)
    }
}

impl From<PrivateKeySigner> for TempoWallet {
    fn from(signer: PrivateKeySigner) -> Self {
        Self::new(EthereumWallet::from(signer))
    }
}

impl IntoWallet<TempoNetwork> for AccessKeyAccount {
    type NetworkWallet = TempoWallet;

    fn into_wallet(self) -> Self::NetworkWallet {
        self.into()
    }
}
