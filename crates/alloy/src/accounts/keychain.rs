//! Alloy wallet support for Tempo secp256k1 access keys.

use alloy_network::{NetworkTransactionBuilder, NetworkWallet, TransactionBuilder};
use alloy_primitives::{Address, Signature};
use alloy_provider::{
    Provider, SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_signer::Signer;
use alloy_transport::TransportResult;
use tempo_primitives::{
    SignatureType, TempoTxEnvelope,
    transaction::{
        KeychainSignature, KeychainVersion, PrimitiveSignature, SignedKeyAuthorization,
        TempoSignature, TempoTypedTransaction,
    },
};

use crate::{TempoNetwork, fillers::gas::resolve_key_authorization, rpc::TempoTransactionRequest};

/// An Alloy network wallet that signs Tempo AA transactions through an access
/// key authorized for a root account.
///
/// `S` is an ordinary Alloy secp256k1 signer. Store-backed Tempo Accounts,
/// including P-256 keys, use [`TempoAccountsWallet`](super::TempoAccountsWallet)
/// instead.
#[derive(Clone, Debug)]
pub struct TempoKeychainWallet<S> {
    account: Address,
    signer: S,
    key_authorization: Option<Box<SignedKeyAuthorization>>,
    version: KeychainVersion,
}

impl<S> TempoKeychainWallet<S>
where
    S: Signer<Signature> + Clone + std::fmt::Debug + Send + Sync + 'static,
{
    /// Create a keychain wallet using the current V2 account-bound signature.
    pub fn new(account: Address, signer: S) -> Self {
        Self {
            account,
            signer,
            key_authorization: None,
            version: KeychainVersion::V2,
        }
    }

    /// Attach a pending access-key authorization to the first transaction.
    pub fn with_key_authorization(mut self, authorization: SignedKeyAuthorization) -> Self {
        self.key_authorization = Some(Box::new(authorization));
        self
    }

    /// Remove a pending one-time access-key authorization.
    pub fn without_key_authorization(mut self) -> Self {
        self.key_authorization = None;
        self
    }

    /// Select a keychain wire version.
    ///
    /// V2 is the default. This setter exists only for chains that still accept
    /// the legacy V1 signature shape.
    pub fn with_version(mut self, version: KeychainVersion) -> Self {
        self.version = version;
        self
    }

    /// Root account represented by this wallet.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// Access-key signer.
    pub const fn signer(&self) -> &S {
        &self.signer
    }

    /// On-chain access-key identifier.
    pub fn key_id(&self) -> Address {
        self.signer.address()
    }

    /// Pending one-time authorization for this access key.
    pub fn key_authorization(&self) -> Option<&SignedKeyAuthorization> {
        self.key_authorization.as_deref()
    }

    /// Keychain signature wire version.
    pub const fn version(&self) -> KeychainVersion {
        self.version
    }

    /// Fill metadata and resolve a pending authorization before estimation or
    /// fee-payer signing outside an Alloy provider filler stack.
    ///
    /// The returned wallet owns the resolved authorization state and must be
    /// retained through final signing.
    pub async fn prepare_request<P>(
        &self,
        provider: &P,
        request: &mut TempoTransactionRequest,
    ) -> TransportResult<Self>
    where
        P: Provider<TempoNetwork>,
    {
        let mut prepared = self.clone();
        prepared
            .fill_request(request)
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        if let Some(key_authorization) = resolve_key_authorization(provider, request).await? {
            request.key_authorization = key_authorization.clone();
            prepared.key_authorization = key_authorization.map(Box::new);
        }
        Ok(prepared)
    }

    /// Populate request metadata used by gas estimation and signing.
    pub(crate) fn fill_request(
        &self,
        request: &mut TempoTransactionRequest,
    ) -> alloy_signer::Result<()> {
        let signer_address = self.signer.address();

        if let Some(from) = request.from()
            && from != self.account
        {
            return Err(alloy_signer::Error::other(
                TempoKeychainWalletError::SenderMismatch {
                    expected: self.account,
                    actual: from,
                },
            ));
        }
        request.set_from(self.account);

        if let Some(key_id) = request.key_id
            && key_id != signer_address
        {
            return Err(alloy_signer::Error::other(
                TempoKeychainWalletError::KeyMismatch {
                    expected: signer_address,
                    actual: key_id,
                },
            ));
        }
        request.key_id = Some(signer_address);

        let signature_type = SignatureType::Secp256k1;
        if let Some(key_type) = request.key_type
            && key_type != signature_type
        {
            return Err(alloy_signer::Error::other(
                TempoKeychainWalletError::SignatureTypeMismatch {
                    expected: signature_type,
                    actual: key_type,
                },
            ));
        }
        request.key_type = Some(signature_type);

        if request.key_authorization.is_none() {
            request.key_authorization = self.key_authorization.as_deref().cloned();
        }

        Ok(())
    }

    async fn sign_aa(
        &self,
        sender: Address,
        mut tx: tempo_primitives::transaction::TempoTransaction,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        if sender != self.account {
            return Err(alloy_signer::Error::other(
                TempoKeychainWalletError::SenderMismatch {
                    expected: self.account,
                    actual: sender,
                },
            ));
        }

        if tx.key_authorization.is_none() {
            tx.key_authorization = self.key_authorization.as_deref().cloned();
        }
        let signature_hash = tx.signature_hash();
        let signing_hash = match self.version {
            KeychainVersion::V1 => signature_hash,
            KeychainVersion::V2 => KeychainSignature::signing_hash(signature_hash, self.account),
        };
        let primitive = PrimitiveSignature::Secp256k1(self.signer.sign_hash(&signing_hash).await?);
        let keychain = match self.version {
            KeychainVersion::V1 => KeychainSignature::new_v1(self.account, primitive),
            KeychainVersion::V2 => KeychainSignature::new(self.account, primitive),
        };

        Ok(tx.into_signed(TempoSignature::Keychain(keychain)).into())
    }
}

impl<S> TxFiller<TempoNetwork> for TempoKeychainWallet<S>
where
    S: Signer<Signature> + Clone + std::fmt::Debug + Send + Sync + 'static,
{
    type Fillable = Option<SignedKeyAuthorization>;

    fn status(&self, request: &TempoTransactionRequest) -> FillerControlFlow {
        if request.from().is_none() || request.key_id.is_none() || request.key_type.is_none() {
            return FillerControlFlow::Ready;
        }

        match request.complete_preferred() {
            Ok(_) => FillerControlFlow::Ready,
            Err(error) => FillerControlFlow::Missing(vec![("TempoKeychainWallet", error)]),
        }
    }

    fn fill_sync(&self, tx: &mut SendableTx<TempoNetwork>) {
        if let Some(request) = tx.as_mut_builder() {
            // Synchronous fillers cannot return errors. `prepare` validates the
            // same metadata and returns failures through the provider.
            let _ = self.fill_request(request);
        }
    }

    async fn prepare<P>(
        &self,
        provider: &P,
        request: &TempoTransactionRequest,
    ) -> TransportResult<Self::Fillable>
    where
        P: Provider<TempoNetwork>,
    {
        let mut request = request.clone();
        self.fill_request(&mut request)
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        Ok(resolve_key_authorization(provider, &request)
            .await?
            .unwrap_or(request.key_authorization))
    }

    async fn fill(
        &self,
        key_authorization: Self::Fillable,
        tx: SendableTx<TempoNetwork>,
    ) -> TransportResult<SendableTx<TempoNetwork>> {
        let mut request = match tx {
            SendableTx::Builder(request) => request,
            _ => return Ok(tx),
        };
        request.key_authorization = key_authorization.clone();

        let mut wallet = self.clone();
        wallet.key_authorization = key_authorization.map(Box::new);
        wallet
            .fill_request(&mut request)
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        let envelope = request
            .build(&wallet)
            .await
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        Ok(SendableTx::Envelope(envelope))
    }

    fn prepare_call_sync(&self, request: &mut TempoTransactionRequest) -> TransportResult<()> {
        self.fill_request(request)
            .map_err(alloy_json_rpc::RpcError::local_usage)
    }

    async fn prepare_call(&self, request: &mut TempoTransactionRequest) -> TransportResult<()> {
        self.prepare_call_sync(request)
    }
}

impl<S> NetworkWallet<TempoNetwork> for TempoKeychainWallet<S>
where
    S: Signer<Signature> + Clone + std::fmt::Debug + Send + Sync + 'static,
{
    fn default_signer_address(&self) -> Address {
        self.account
    }

    fn has_signer_for(&self, address: &Address) -> bool {
        *address == self.account
    }

    fn signer_addresses(&self) -> impl Iterator<Item = Address> {
        std::iter::once(self.account)
    }

    async fn sign_transaction_from(
        &self,
        sender: Address,
        tx: TempoTypedTransaction,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        match tx {
            TempoTypedTransaction::AA(tx) => self.sign_aa(sender, tx).await,
            _ => Err(alloy_signer::Error::other(
                TempoKeychainWalletError::UnsupportedTransactionType,
            )),
        }
    }

    async fn sign_request(
        &self,
        mut request: TempoTransactionRequest,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        self.fill_request(&mut request)?;
        let sender = request.from().unwrap_or(self.account);
        let tx = request
            .build_unsigned()
            .map_err(alloy_signer::Error::other)?;
        self.sign_transaction_from(sender, tx).await
    }
}

#[derive(Debug, thiserror::Error)]
enum TempoKeychainWalletError {
    #[error("Tempo keychain wallet signs only AA transactions")]
    UnsupportedTransactionType,
    #[error("Tempo keychain sender mismatch: expected {expected}, got {actual}")]
    SenderMismatch { expected: Address, actual: Address },
    #[error("Tempo access-key mismatch: expected {expected}, got {actual}")]
    KeyMismatch { expected: Address, actual: Address },
    #[error("Tempo signature type mismatch: expected {expected:?}, got {actual:?}")]
    SignatureTypeMismatch {
        expected: SignatureType,
        actual: SignatureType,
    },
}

#[cfg(test)]
mod tests {
    use alloy_network::NetworkWallet;
    use alloy_provider::{ProviderBuilder, mock::Asserter};
    use alloy_rpc_types_eth::TransactionRequest;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolCall;
    use tempo_contracts::precompiles::IAccountKeychain::{
        KeyInfo, SignatureType as AbiSignatureType, getKeyCall,
    };
    use tempo_primitives::transaction::{KeyAuthorization, TempoSignature};

    use super::*;

    #[tokio::test]
    async fn prepared_wallet_does_not_restore_published_authorization() {
        let signer = PrivateKeySigner::random();
        let account = Address::repeat_byte(0x11);
        let authorization =
            KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, signer.address())
                .into_signed(PrimitiveSignature::default());
        let wallet =
            TempoKeychainWallet::new(account, signer).with_key_authorization(authorization);
        let asserter = Asserter::new();
        let provider = ProviderBuilder::<_, _, TempoNetwork>::default()
            .connect_mocked_client(asserter.clone());
        asserter.push_success(&alloy_primitives::Bytes::from(
            getKeyCall::abi_encode_returns(&KeyInfo {
                signatureType: AbiSignatureType::Secp256k1,
                keyId: wallet.key_id(),
                expiry: u64::MAX,
                enforceLimits: false,
                isRevoked: false,
            }),
        ));
        let mut request = TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(Address::repeat_byte(0x22).into()),
                chain_id: Some(4217),
                nonce: Some(0),
                gas: Some(100_000),
                max_fee_per_gas: Some(1),
                max_priority_fee_per_gas: Some(1),
                ..Default::default()
            },
            ..Default::default()
        };

        let prepared = wallet
            .prepare_request(&provider, &mut request)
            .await
            .unwrap();

        assert!(wallet.key_authorization().is_some());
        assert!(prepared.key_authorization().is_none());
        assert!(request.key_authorization.is_none());

        let TempoTxEnvelope::AA(signed) = prepared.sign_request(request).await.unwrap() else {
            panic!("expected AA transaction");
        };
        assert!(signed.tx().key_authorization.is_none());
        assert!(matches!(signed.signature(), TempoSignature::Keychain(_)));
    }
}
