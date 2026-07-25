//! Unified Tempo wallets for direct and access-key credentials.

use alloy_consensus::SignableTransaction;
use alloy_json_rpc::RpcError;
use alloy_network::{NetworkTransactionBuilder, NetworkWallet, TransactionBuilder};
use alloy_primitives::{Address, B256, ChainId};
use alloy_provider::{
    Provider, SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_signer::{Signer, SignerSync};
use alloy_transport::TransportResult;
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        KeychainVersion, PrimitiveSignature, SignedKeyAuthorization, TempoSignature,
        TempoTypedTransaction,
    },
};

use super::{TempoKeychainWallet, TempoSigner};
use crate::{TempoNetwork, rpc::TempoTransactionRequest};

/// A Tempo wallet backed by either a root credential or an access key.
///
/// The wallet owns the signing context, so consumers do not separately select
/// a signing mode. Use [`TempoWallet::new`] for direct signing and
/// [`TempoWallet::for_account`] when the signer is an access key for a root
/// account.
#[derive(Clone, Debug)]
pub enum TempoWallet<S> {
    /// The signer is the on-chain account.
    Direct(S),
    /// The signer is an access key for a root account.
    Keychain(TempoKeychainWallet<S>),
}

impl<S> TempoWallet<S>
where
    S: TempoSigner,
{
    /// Create a wallet whose signer is the on-chain account.
    pub const fn new(signer: S) -> Self {
        Self::Direct(signer)
    }

    /// Create a wallet whose signer is an access key for `account`.
    pub fn for_account(account: Address, signer: S) -> Self {
        Self::Keychain(TempoKeychainWallet::new(account, signer))
    }

    /// Attach a pending one-time access-key authorization.
    ///
    /// This has no effect on a direct wallet.
    pub fn with_key_authorization(mut self, authorization: SignedKeyAuthorization) -> Self {
        if let Self::Keychain(wallet) = self {
            self = Self::Keychain(wallet.with_key_authorization(authorization));
        }
        self
    }

    /// Remove a pending one-time access-key authorization.
    ///
    /// This has no effect on a direct wallet.
    pub fn without_key_authorization(mut self) -> Self {
        if let Self::Keychain(wallet) = self {
            self = Self::Keychain(wallet.without_key_authorization());
        }
        self
    }

    /// Select a legacy keychain wire version.
    ///
    /// Access-key wallets default to V2. This has no effect on a direct wallet.
    pub fn with_keychain_version(mut self, version: KeychainVersion) -> Self {
        if let Self::Keychain(wallet) = self {
            self = Self::Keychain(wallet.with_version(version));
        }
        self
    }

    /// On-chain account represented by this wallet.
    pub fn account(&self) -> Address {
        match self {
            Self::Direct(signer) => signer.address(),
            Self::Keychain(wallet) => wallet.account(),
        }
    }

    /// Credential that signs for this wallet.
    pub const fn signer(&self) -> &S {
        match self {
            Self::Direct(signer) => signer,
            Self::Keychain(wallet) => wallet.signer(),
        }
    }

    /// Access-key identifier, if this is a keychain wallet.
    pub fn key_id(&self) -> Option<Address> {
        match self {
            Self::Direct(_) => None,
            Self::Keychain(wallet) => Some(wallet.key_id()),
        }
    }

    /// Pending one-time access-key authorization.
    pub fn key_authorization(&self) -> Option<&SignedKeyAuthorization> {
        match self {
            Self::Direct(_) => None,
            Self::Keychain(wallet) => wallet.key_authorization(),
        }
    }

    /// Fill wallet metadata and resolve a pending access-key authorization.
    ///
    /// Call this before external gas estimation or fee-payer signing when the
    /// request is prepared outside an Alloy provider filler stack.
    pub async fn prepare_request<P>(
        &self,
        provider: &P,
        request: &mut TempoTransactionRequest,
    ) -> TransportResult<()>
    where
        P: Provider<TempoNetwork>,
    {
        match self {
            Self::Direct(_) => self.fill_request(request).map_err(RpcError::local_usage),
            Self::Keychain(wallet) => wallet.prepare_request(provider, request).await,
        }
    }

    pub(crate) fn fill_request(
        &self,
        request: &mut TempoTransactionRequest,
    ) -> alloy_signer::Result<()> {
        match self {
            Self::Direct(_) => {
                if let Some(from) = request.from()
                    && from != self.account()
                {
                    return Err(alloy_signer::Error::other(
                        TempoWalletError::SenderMismatch {
                            expected: self.account(),
                            actual: from,
                        },
                    ));
                }
                request.set_from(self.account());
                Ok(())
            }
            Self::Keychain(wallet) => wallet.fill_request(request),
        }
    }

    async fn sign_direct(
        signer: &S,
        sender: Address,
        tx: TempoTypedTransaction,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        if sender != signer.address() {
            return Err(alloy_signer::Error::other(
                TempoWalletError::SenderMismatch {
                    expected: signer.address(),
                    actual: sender,
                },
            ));
        }

        match tx {
            TempoTypedTransaction::AA(tx) => {
                let signature = signer.sign_hash(&tx.signature_hash()).await?;
                Ok(tx.into_signed(TempoSignature::Primitive(signature)).into())
            }
            tx => {
                let signature = signer.sign_hash(&tx.signature_hash()).await?;
                let PrimitiveSignature::Secp256k1(signature) = signature else {
                    return Err(alloy_signer::Error::other(
                        TempoWalletError::UnsupportedPrimitiveTransaction,
                    ));
                };
                Ok(tx.into_envelope(signature))
            }
        }
    }
}

#[async_trait::async_trait]
impl<S> Signer<PrimitiveSignature> for TempoWallet<S>
where
    S: TempoSigner,
{
    async fn sign_hash(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        self.signer().sign_hash(hash).await
    }

    fn address(&self) -> Address {
        self.signer().address()
    }

    fn chain_id(&self) -> Option<ChainId> {
        self.signer().chain_id()
    }

    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        match self {
            Self::Direct(signer) => signer.set_chain_id(chain_id),
            Self::Keychain(wallet) => wallet.signer_mut().set_chain_id(chain_id),
        }
    }
}

impl<S> SignerSync<PrimitiveSignature> for TempoWallet<S>
where
    S: TempoSigner + SignerSync<PrimitiveSignature>,
{
    fn sign_hash_sync(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        self.signer().sign_hash_sync(hash)
    }

    fn chain_id_sync(&self) -> Option<ChainId> {
        self.signer().chain_id()
    }
}

impl<S> TempoSigner for TempoWallet<S>
where
    S: TempoSigner,
{
    fn signature_type(&self) -> tempo_primitives::SignatureType {
        self.signer().signature_type()
    }

    fn key_data(&self) -> Option<alloy_primitives::Bytes> {
        self.signer().key_data()
    }
}

impl<S> NetworkWallet<TempoNetwork> for TempoWallet<S>
where
    S: TempoSigner,
{
    fn default_signer_address(&self) -> Address {
        self.account()
    }

    fn has_signer_for(&self, address: &Address) -> bool {
        *address == self.account()
    }

    fn signer_addresses(&self) -> impl Iterator<Item = Address> {
        std::iter::once(self.account())
    }

    async fn sign_transaction_from(
        &self,
        sender: Address,
        tx: TempoTypedTransaction,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        match self {
            Self::Direct(signer) => Self::sign_direct(signer, sender, tx).await,
            Self::Keychain(wallet) => wallet.sign_transaction_from(sender, tx).await,
        }
    }

    async fn sign_request(
        &self,
        request: TempoTransactionRequest,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        match self {
            Self::Direct(_) => {
                let sender = request.from().unwrap_or_else(|| self.account());
                let tx = request
                    .build_unsigned()
                    .map_err(alloy_signer::Error::other)?;
                self.sign_transaction_from(sender, tx).await
            }
            Self::Keychain(wallet) => wallet.sign_request(request).await,
        }
    }
}

/// Values prepared by [`TempoWallet`] while filling a transaction.
#[doc(hidden)]
#[derive(Debug)]
pub enum TempoWalletFillable {
    /// A direct wallet is ready to sign.
    Direct,
    /// Resolved one-time authorization for an access-key wallet.
    Keychain(Option<Box<SignedKeyAuthorization>>),
}

impl<S> TxFiller<TempoNetwork> for TempoWallet<S>
where
    S: TempoSigner,
{
    type Fillable = TempoWalletFillable;

    fn status(&self, request: &TempoTransactionRequest) -> FillerControlFlow {
        match self {
            Self::Direct(_) => {
                if request.from().is_none() {
                    return FillerControlFlow::Ready;
                }
                match request.complete_preferred() {
                    Ok(_) => FillerControlFlow::Ready,
                    Err(error) => FillerControlFlow::Missing(vec![("TempoWallet", error)]),
                }
            }
            Self::Keychain(wallet) => wallet.status(request),
        }
    }

    fn fill_sync(&self, tx: &mut SendableTx<TempoNetwork>) {
        match self {
            Self::Direct(_) => {
                if let Some(request) = tx.as_mut_builder()
                    && request.from().is_none()
                {
                    request.set_from(self.account());
                }
            }
            Self::Keychain(wallet) => wallet.fill_sync(tx),
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
        match self {
            Self::Direct(_) => Ok(TempoWalletFillable::Direct),
            Self::Keychain(wallet) => wallet
                .prepare(provider, request)
                .await
                .map(|authorization| TempoWalletFillable::Keychain(authorization.map(Box::new))),
        }
    }

    async fn fill(
        &self,
        fillable: Self::Fillable,
        tx: SendableTx<TempoNetwork>,
    ) -> TransportResult<SendableTx<TempoNetwork>> {
        match (self, fillable) {
            (Self::Direct(_), TempoWalletFillable::Direct) => {
                let request = match tx {
                    SendableTx::Builder(request) => request,
                    _ => return Ok(tx),
                };
                let envelope = request.build(self).await.map_err(RpcError::local_usage)?;
                Ok(SendableTx::Envelope(envelope))
            }
            (Self::Keychain(wallet), TempoWalletFillable::Keychain(key_authorization)) => {
                wallet
                    .fill(key_authorization.map(|authorization| *authorization), tx)
                    .await
            }
            _ => Err(RpcError::local_usage(TempoWalletError::FillModeMismatch)),
        }
    }

    fn prepare_call_sync(&self, request: &mut TempoTransactionRequest) -> TransportResult<()> {
        match self {
            Self::Direct(_) => {
                if request.from().is_none() {
                    request.set_from(self.account());
                }
                Ok(())
            }
            Self::Keychain(wallet) => wallet.prepare_call_sync(request),
        }
    }

    async fn prepare_call(&self, request: &mut TempoTransactionRequest) -> TransportResult<()> {
        self.prepare_call_sync(request)
    }
}

#[derive(Debug, thiserror::Error)]
enum TempoWalletError {
    #[error("Tempo wallet sender mismatch: expected {expected}, got {actual}")]
    SenderMismatch { expected: Address, actual: Address },
    #[error("only secp256k1 credentials can sign non-AA Tempo transactions")]
    UnsupportedPrimitiveTransaction,
    #[error("Tempo wallet filler received a value prepared for a different wallet mode")]
    FillModeMismatch,
}
