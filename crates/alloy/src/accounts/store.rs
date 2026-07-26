//! Strictly typed Tempo Accounts store integration.

use std::{
    borrow::Cow,
    fmt, fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_network::{NetworkTransactionBuilder, NetworkWallet, TransactionBuilder};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, keccak256};
use alloy_provider::{
    Provider, SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_signer::{Signer, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::TransportResult;
use serde::{
    Deserialize, Deserializer,
    de::{self, Visitor},
};
use tempo_primitives::{
    SignatureType, TempoTxEnvelope,
    transaction::{
        Call, CallScope, KeyAuthorization, KeychainSignature, PrimitiveSignature, SelectorRule,
        SignedKeyAuthorization, TempoSignature, TempoTypedTransaction, TokenLimit,
        tt_signature::{P256SignatureWithPreHash, WebAuthnSignature},
    },
};

use super::p256::{P256Jwk, P256SignerError, TempoP256Signer};
use crate::{TempoNetwork, fillers::gas::resolve_key_authorization, rpc::TempoTransactionRequest};

#[derive(Clone, Debug)]
enum AccountsSigner {
    Secp256k1(PrivateKeySigner),
    P256(TempoP256Signer),
}

impl AccountsSigner {
    const fn signature_type(&self) -> SignatureType {
        match self {
            Self::Secp256k1(_) => SignatureType::Secp256k1,
            Self::P256(_) => SignatureType::P256,
        }
    }
}

#[async_trait::async_trait]
impl Signer<PrimitiveSignature> for AccountsSigner {
    async fn sign_hash(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        match self {
            Self::Secp256k1(signer) => signer
                .sign_hash(hash)
                .await
                .map(PrimitiveSignature::Secp256k1),
            Self::P256(signer) => signer.sign_hash(hash).await,
        }
    }

    fn address(&self) -> Address {
        match self {
            Self::Secp256k1(signer) => signer.address(),
            Self::P256(signer) => signer.address(),
        }
    }

    fn chain_id(&self) -> Option<u64> {
        match self {
            Self::Secp256k1(signer) => signer.chain_id(),
            Self::P256(signer) => signer.chain_id(),
        }
    }

    fn set_chain_id(&mut self, chain_id: Option<u64>) {
        match self {
            Self::Secp256k1(signer) => signer.set_chain_id(chain_id),
            Self::P256(signer) => signer.set_chain_id(chain_id),
        }
    }
}

impl SignerSync<PrimitiveSignature> for AccountsSigner {
    fn sign_hash_sync(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        match self {
            Self::Secp256k1(signer) => signer
                .sign_hash_sync(hash)
                .map(PrimitiveSignature::Secp256k1),
            Self::P256(signer) => signer.sign_hash_sync(hash),
        }
    }

    fn chain_id_sync(&self) -> Option<u64> {
        self.chain_id()
    }
}

/// A locally signable access key selected from a Tempo Accounts store.
#[derive(Clone, Debug)]
pub struct TempoAccessKey {
    account: Address,
    address: Address,
    chain_id: u64,
    signer: AccountsSigner,
    key_authorization: Option<Box<SignedKeyAuthorization>>,
}

impl TempoAccessKey {
    /// Root Tempo account controlled by this access key.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// On-chain access-key identifier.
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Chain to which the key is scoped.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Pending authorization attached until the key is observed on-chain.
    pub fn key_authorization(&self) -> Option<&SignedKeyAuthorization> {
        self.key_authorization.as_deref()
    }

    /// Fill access-key metadata and resolve a pending authorization before
    /// external gas estimation or fee-payer signing.
    ///
    /// The returned key owns the resolved authorization state and must be
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

    fn fill_request(&self, request: &mut TempoTransactionRequest) -> alloy_signer::Result<()> {
        if super::request_uses_create(request) {
            return Err(alloy_signer::Error::other(
                TempoAccessKeyError::CreateUnsupported,
            ));
        }
        if let Some(chain_id) = request.chain_id()
            && chain_id != self.chain_id
        {
            return Err(alloy_signer::Error::other(
                TempoAccessKeyError::ChainMismatch {
                    expected: self.chain_id,
                    actual: chain_id,
                },
            ));
        }
        if request.chain_id().is_none() {
            request.set_chain_id(self.chain_id);
        }

        if let Some(from) = request.from()
            && from != self.account
        {
            return Err(alloy_signer::Error::other(
                TempoAccessKeyError::SenderMismatch {
                    expected: self.account,
                    actual: from,
                },
            ));
        }
        request.set_from(self.account);

        if let Some(key_id) = request.key_id
            && key_id != self.address
        {
            return Err(alloy_signer::Error::other(
                TempoAccessKeyError::KeyMismatch {
                    expected: self.address,
                    actual: key_id,
                },
            ));
        }
        request.key_id = Some(self.address);

        let signature_type = self.signer.signature_type();
        if let Some(key_type) = request.key_type
            && key_type != signature_type
        {
            return Err(alloy_signer::Error::other(
                TempoAccessKeyError::SignatureTypeMismatch {
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
        if super::transaction_uses_create(&tx) {
            return Err(alloy_signer::Error::other(
                TempoAccessKeyError::CreateUnsupported,
            ));
        }
        if tx.chain_id != self.chain_id {
            return Err(alloy_signer::Error::other(
                TempoAccessKeyError::ChainMismatch {
                    expected: self.chain_id,
                    actual: tx.chain_id,
                },
            ));
        }
        if sender != self.account {
            return Err(alloy_signer::Error::other(
                TempoAccessKeyError::SenderMismatch {
                    expected: self.account,
                    actual: sender,
                },
            ));
        }

        if tx.key_authorization.is_none() {
            tx.key_authorization = self.key_authorization.as_deref().cloned();
        }
        let signing_hash = KeychainSignature::signing_hash(tx.signature_hash(), self.account);
        let primitive = self.signer.sign_hash(&signing_hash).await?;
        let keychain = KeychainSignature::new(self.account, primitive);
        Ok(tx.into_signed(TempoSignature::Keychain(keychain)).into())
    }
}

#[async_trait::async_trait]
impl Signer<PrimitiveSignature> for TempoAccessKey {
    async fn sign_hash(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        self.signer.sign_hash(hash).await
    }

    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> Option<u64> {
        Some(self.chain_id)
    }

    fn set_chain_id(&mut self, chain_id: Option<u64>) {
        if let Some(chain_id) = chain_id {
            self.chain_id = chain_id;
        }
        self.signer.set_chain_id(Some(self.chain_id));
    }
}

impl SignerSync<PrimitiveSignature> for TempoAccessKey {
    fn sign_hash_sync(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        self.signer.sign_hash_sync(hash)
    }

    fn chain_id_sync(&self) -> Option<u64> {
        Some(self.chain_id)
    }
}

impl NetworkWallet<TempoNetwork> for TempoAccessKey {
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
                TempoAccessKeyError::UnsupportedTransactionType,
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

impl TxFiller<TempoNetwork> for TempoAccessKey {
    type Fillable = Option<SignedKeyAuthorization>;

    fn status(&self, request: &TempoTransactionRequest) -> FillerControlFlow {
        if request.from().is_none() || request.key_id.is_none() || request.key_type.is_none() {
            return FillerControlFlow::Ready;
        }

        match request.complete_preferred() {
            Ok(_) => FillerControlFlow::Ready,
            Err(error) => FillerControlFlow::Missing(vec![("TempoAccessKey", error)]),
        }
    }

    fn fill_sync(&self, tx: &mut SendableTx<TempoNetwork>) {
        if let Some(request) = tx.as_mut_builder() {
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

        let mut selected = self.clone();
        selected.key_authorization = key_authorization.map(Box::new);
        selected
            .fill_request(&mut request)
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        let envelope = request
            .build(&selected)
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

#[derive(Debug, thiserror::Error)]
enum TempoAccessKeyError {
    #[error("Tempo access keys sign only AA transactions")]
    UnsupportedTransactionType,
    #[error("Tempo access-key transactions cannot use CREATE")]
    CreateUnsupported,
    #[error("Tempo access-key chain mismatch: expected {expected}, got {actual}")]
    ChainMismatch { expected: u64, actual: u64 },
    #[error("Tempo access-key sender mismatch: expected {expected}, got {actual}")]
    SenderMismatch { expected: Address, actual: Address },
    #[error("Tempo access-key mismatch: expected {expected}, got {actual}")]
    KeyMismatch { expected: Address, actual: Address },
    #[error("Tempo signature type mismatch: expected {expected:?}, got {actual:?}")]
    SignatureTypeMismatch {
        expected: SignatureType,
        actual: SignatureType,
    },
}

/// Errors returned while reading or selecting from a Tempo Accounts store.
#[derive(Debug, thiserror::Error)]
pub enum TempoAccountsError {
    /// The platform did not expose a home directory.
    #[error("home directory is unavailable")]
    HomeUnavailable,
    /// The Accounts store could not be read.
    #[error("failed to read Tempo Accounts store at {path}: {source}")]
    Read {
        /// Store path.
        path: PathBuf,
        /// Filesystem error.
        source: std::io::Error,
    },
    /// The Accounts store did not match the persisted Accounts schema.
    #[error("invalid Tempo Accounts store at {path}: {source}")]
    Decode {
        /// Store path.
        path: PathBuf,
        /// JSON error.
        source: serde_json::Error,
    },
    /// The active account selector was missing or invalid.
    #[error("Tempo Accounts active account is missing or invalid")]
    ActiveAccount,
    /// No matching locally signable access key was available.
    #[error(
        "Tempo Accounts has no locally signable access key for account {account} on chain {chain_id}"
    )]
    MissingAccessKey {
        /// Root account.
        account: Address,
        /// Requested chain.
        chain_id: u64,
    },
    /// The selected wallet and request metadata disagree.
    #[error("invalid Tempo Accounts transaction metadata")]
    InvalidMetadata(#[source] alloy_signer::Error),
    /// Only Tempo AA transactions can be signed through an access key.
    #[error("Tempo Accounts access keys sign only AA transactions")]
    UnsupportedTransactionType,
}

/// A lazy Tempo Accounts wallet backed by a persisted store.
///
/// This type implements both [`NetworkWallet<TempoNetwork>`] and
/// [`TxFiller<TempoNetwork>`]. Add it with `ProviderBuilder::filler(wallet)` so
/// access-key metadata is selected synchronously before Alloy's gas filler
/// prepares its estimate. The same pinned key is then used for signing.
#[derive(Clone)]
pub struct TempoAccountsWallet {
    path: PathBuf,
    fallback_account: Address,
}

impl fmt::Debug for TempoAccountsWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempoAccountsWallet")
            .field("path", &self.path)
            .field("fallback_account", &self.fallback_account)
            .finish()
    }
}

impl TempoAccountsWallet {
    /// Open a Tempo Accounts store.
    ///
    /// Only the active root account is read eagerly. Access-key selection and
    /// key material hydration happen lazily for every transaction.
    pub fn from_store(path: impl Into<PathBuf>) -> Result<Self, TempoAccountsError> {
        let path = path.into();
        let state = load_state(&path)?;
        let fallback_account = active_account(&state)?;
        Ok(Self {
            path,
            fallback_account,
        })
    }

    /// Open `~/.tempo/wallet/store.json`.
    pub fn from_default_store() -> Result<Self, TempoAccountsError> {
        Self::from_store(default_accounts_store_path()?)
    }

    /// Path backing this wallet.
    pub fn store_path(&self) -> &Path {
        &self.path
    }

    /// Active root account observed when this wallet was opened.
    pub const fn account(&self) -> Address {
        self.fallback_account
    }

    /// Reload the currently active root account from the Accounts store.
    pub fn active_account(&self) -> Result<Address, TempoAccountsError> {
        active_account(&load_state(&self.path)?)
    }

    /// Load the active account's first unscoped, locally signable access key.
    ///
    /// This mirrors the default selection used by Tempo Accounts when no
    /// concrete call intent is supplied.
    pub fn active_access_key(&self) -> Result<TempoAccessKey, TempoAccountsError> {
        let state = load_state(&self.path)?;
        let account = active_account(&state)?;
        select_access_key(&state, account, state.chain_id, None, None, unix_now())
    }

    fn select_for_request(
        &self,
        request: &TempoTransactionRequest,
    ) -> Result<TempoAccessKey, TempoAccountsError> {
        let state = load_state(&self.path)?;
        let account = request.from().unwrap_or(active_account(&state)?);
        let chain_id = request.chain_id().unwrap_or(state.chain_id);
        let calls = request_calls(request);
        select_access_key(
            &state,
            account,
            chain_id,
            request.key_id,
            calls.as_deref(),
            unix_now(),
        )
    }

    /// Load one exact locally signable key.
    ///
    /// This is useful for durable sessions that retain an access-key ID.
    pub fn access_key(
        &self,
        account: Address,
        chain_id: u64,
        access_key: Address,
    ) -> Result<TempoAccessKey, TempoAccountsError> {
        let state = load_state(&self.path)?;
        select_access_key(
            &state,
            account,
            chain_id,
            Some(access_key),
            None,
            unix_now(),
        )
    }

    /// Select and pin an access key, fill its request metadata, and resolve a
    /// pending authorization.
    ///
    /// Call this before external gas estimation or fee-payer signing when the
    /// request is prepared outside an Alloy provider filler stack. The returned
    /// key owns the exact resolved signing state, so a caller can retain it
    /// through gas estimation and final signing.
    pub async fn prepare_request<P>(
        &self,
        provider: &P,
        request: &mut TempoTransactionRequest,
    ) -> TransportResult<TempoAccessKey>
    where
        P: Provider<TempoNetwork>,
    {
        let selected = self.prepare_selected(provider, request).await?;
        request.key_authorization = selected.key_authorization.as_deref().cloned();
        selected
            .fill_request(request)
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        Ok(selected)
    }

    fn fill_metadata(
        &self,
        request: &mut TempoTransactionRequest,
    ) -> Result<TempoAccessKey, TempoAccountsError> {
        let selected = self.select_for_request(request)?;
        if request.chain_id().is_none() {
            request.set_chain_id(selected.chain_id);
        }
        selected
            .fill_request(request)
            .map_err(TempoAccountsError::InvalidMetadata)?;
        Ok(selected)
    }

    fn select_unsigned(
        &self,
        account: Address,
        tx: &TempoTypedTransaction,
    ) -> Result<TempoAccessKey, TempoAccountsError> {
        let TempoTypedTransaction::AA(tx) = tx else {
            return Err(TempoAccountsError::UnsupportedTransactionType);
        };
        let state = load_state(&self.path)?;
        let calls = transaction_calls(tx);
        select_access_key(
            &state,
            account,
            tx.chain_id,
            None,
            calls.as_deref(),
            unix_now(),
        )
    }

    async fn prepare_selected<P>(
        &self,
        provider: &P,
        request: &TempoTransactionRequest,
    ) -> TransportResult<TempoAccessKey>
    where
        P: Provider<TempoNetwork>,
    {
        let mut selected = self
            .select_for_request(request)
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        let mut resolved_request = request.clone();
        selected
            .fill_request(&mut resolved_request)
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        if let Some(key_authorization) =
            resolve_key_authorization(provider, &resolved_request).await?
        {
            selected.key_authorization = key_authorization.map(Box::new);
        }
        Ok(selected)
    }
}

impl NetworkWallet<TempoNetwork> for TempoAccountsWallet {
    fn default_signer_address(&self) -> Address {
        load_state(&self.path)
            .and_then(|state| active_account(&state))
            .unwrap_or(self.fallback_account)
    }

    fn has_signer_for(&self, address: &Address) -> bool {
        load_state(&self.path).is_ok_and(|state| {
            state
                .accounts
                .iter()
                .any(|account| account.address == *address)
        })
    }

    fn signer_addresses(&self) -> impl Iterator<Item = Address> {
        load_state(&self.path)
            .map(|state| {
                state
                    .accounts
                    .into_iter()
                    .map(|account| account.address)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|_| vec![self.fallback_account])
            .into_iter()
    }

    async fn sign_transaction_from(
        &self,
        sender: Address,
        tx: TempoTypedTransaction,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        let selected = self
            .select_unsigned(sender, &tx)
            .map_err(alloy_signer::Error::other)?;
        selected.sign_transaction_from(sender, tx).await
    }

    async fn sign_request(
        &self,
        mut request: TempoTransactionRequest,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        let selected = self
            .fill_metadata(&mut request)
            .map_err(alloy_signer::Error::other)?;
        selected.sign_request(request).await
    }
}

impl TxFiller<TempoNetwork> for TempoAccountsWallet {
    type Fillable = TempoAccessKey;

    fn status(&self, request: &TempoTransactionRequest) -> FillerControlFlow {
        if request.from().is_none() || request.key_id.is_none() || request.key_type.is_none() {
            return FillerControlFlow::Ready;
        }

        match request.complete_preferred() {
            Ok(_) => FillerControlFlow::Ready,
            Err(error) => FillerControlFlow::Missing(vec![("TempoAccountsWallet", error)]),
        }
    }

    fn fill_sync(&self, tx: &mut SendableTx<TempoNetwork>) {
        if let Some(request) = tx.as_mut_builder() {
            // `fill_sync` cannot return errors. `prepare` repeats exact-key
            // resolution and surfaces failures through the normal filler
            // result before signing.
            let _ = self.fill_metadata(request);
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
        self.prepare_selected(provider, request).await
    }

    async fn fill(
        &self,
        selected: Self::Fillable,
        tx: SendableTx<TempoNetwork>,
    ) -> TransportResult<SendableTx<TempoNetwork>> {
        let mut request = match tx {
            SendableTx::Builder(request) => request,
            _ => return Ok(tx),
        };
        request.key_authorization = selected.key_authorization.as_deref().cloned();
        selected
            .fill_request(&mut request)
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        let envelope = request
            .build(&selected)
            .await
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        Ok(SendableTx::Envelope(envelope))
    }

    fn prepare_call_sync(&self, request: &mut TempoTransactionRequest) -> TransportResult<()> {
        self.fill_metadata(request)
            .map(|_| ())
            .map_err(alloy_json_rpc::RpcError::local_usage)
    }

    async fn prepare_call(&self, request: &mut TempoTransactionRequest) -> TransportResult<()> {
        self.prepare_call_sync(request)
    }
}

/// Return the store path shared by Tempo command-line applications.
pub fn default_accounts_store_path() -> Result<PathBuf, TempoAccountsError> {
    dirs_next::home_dir()
        .map(|directory| directory.join(".tempo/wallet/store.json"))
        .ok_or(TempoAccountsError::HomeUnavailable)
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum PersistedStoreFile {
    TempoCli(TempoCliStore),
    Envelope(PersistedStoreEnvelope),
    State(PersistedAccountsState),
}

#[derive(Clone, Deserialize)]
struct TempoCliStore {
    #[serde(rename = "tempo-cli.store")]
    store: PersistedStoreEnvelope,
}

#[derive(Clone, Deserialize)]
struct PersistedStoreEnvelope {
    state: PersistedAccountsState,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedAccountsState {
    active_account: PersistedActiveAccount,
    chain_id: u64,
    accounts: Vec<PersistedAccount>,
    #[serde(default)]
    access_keys: Vec<PersistedAccessKey>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(untagged)]
enum PersistedActiveAccount {
    Index(usize),
    Address(Address),
}

#[derive(Clone, Deserialize)]
struct PersistedAccount {
    address: Address,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedAccessKey {
    address: Address,
    access: Address,
    chain_id: u64,
    key_type: PersistedKeyType,
    #[serde(default)]
    expiry: Option<u64>,
    #[serde(default)]
    handle: Option<PersistedKeyHandle>,
    #[serde(default)]
    private_key: Option<PersistedPrivateKey>,
    #[serde(default)]
    public_key: Option<Bytes>,
    #[serde(default)]
    scopes: Option<Vec<PersistedScope>>,
    #[serde(default)]
    key_authorization: Option<PersistedSignedKeyAuthorization>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
enum PersistedKeyType {
    #[serde(rename = "secp256k1")]
    Secp256k1,
    #[serde(rename = "p256")]
    P256,
    #[serde(rename = "webAuthn")]
    WebAuthn,
    #[serde(rename = "webCrypto")]
    WebCrypto,
    #[serde(other)]
    Unsupported,
}

impl PersistedKeyType {
    fn signature_type(self) -> Result<SignatureType, PersistedKeyError> {
        match self {
            Self::Secp256k1 => Ok(SignatureType::Secp256k1),
            Self::P256 | Self::WebCrypto => Ok(SignatureType::P256),
            Self::WebAuthn => Ok(SignatureType::WebAuthn),
            Self::Unsupported => Err(PersistedKeyError::UnsupportedKeyType),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedKeyHandle {
    kind: PersistedHandleKind,
    #[serde(default)]
    jwk: Option<P256Jwk>,
    #[serde(default)]
    private_key: Option<PersistedPrivateKey>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
enum PersistedHandleKind {
    #[serde(rename = "secp256k1")]
    Secp256k1,
    #[serde(rename = "p256")]
    P256,
    #[serde(rename = "webcrypto-p256")]
    WebCryptoP256,
    #[serde(other)]
    Unsupported,
}

#[derive(Clone, Copy)]
struct PersistedPrivateKey(B256);

impl fmt::Debug for PersistedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<'de> Deserialize<'de> for PersistedPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Cow::<'de, str>::deserialize(deserializer)?;
        B256::from_str(&encoded)
            .map(Self)
            .map_err(de::Error::custom)
    }
}

#[derive(Clone, Deserialize)]
struct PersistedScope {
    #[serde(alias = "target")]
    address: Address,
    #[serde(default)]
    selector: Option<PersistedSelector>,
    #[serde(default)]
    recipients: Option<Vec<Address>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PersistedSelector([u8; 4]);

impl<'de> Deserialize<'de> for PersistedSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Cow::<'de, str>::deserialize(deserializer)?;
        if let Some(hex) = encoded.strip_prefix("0x") {
            let bytes = alloy_primitives::hex::decode(hex).map_err(de::Error::custom)?;
            return bytes
                .try_into()
                .map(Self)
                .map_err(|_| de::Error::custom("call selector must contain exactly four bytes"));
        }
        if !encoded.contains('(') || !encoded.ends_with(')') {
            return Err(de::Error::custom(
                "call selector must be four-byte hex or an ABI function signature",
            ));
        }
        let hash = keccak256(encoded.as_bytes());
        let mut selector = [0_u8; 4];
        selector.copy_from_slice(&hash[..4]);
        Ok(Self(selector))
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedSignedKeyAuthorization {
    address: Address,
    chain_id: AccountsU64,
    #[serde(default)]
    expiry: Option<AccountsU64>,
    #[serde(default)]
    limits: Option<Vec<PersistedTokenLimit>>,
    #[serde(default)]
    scopes: Option<Vec<PersistedScope>>,
    #[serde(default)]
    witness: Option<B256>,
    #[serde(default)]
    is_admin: bool,
    #[serde(default)]
    account: Option<Address>,
    #[serde(rename = "type")]
    key_type: PersistedKeyType,
    signature: PersistedPrimitiveSignature,
}

impl TryFrom<PersistedSignedKeyAuthorization> for SignedKeyAuthorization {
    type Error = PersistedKeyError;

    fn try_from(value: PersistedSignedKeyAuthorization) -> Result<Self, Self::Error> {
        let expiry = value
            .expiry
            .map(|expiry| {
                NonZeroU64::new(expiry.0).ok_or(PersistedKeyError::ZeroAuthorizationExpiry)
            })
            .transpose()?;
        let limits = value
            .limits
            .map(|limits| limits.into_iter().map(Into::into).collect());
        let allowed_calls = value
            .scopes
            .map(persisted_scopes_to_call_scopes)
            .transpose()?;
        let authorization = KeyAuthorization {
            chain_id: value.chain_id.0,
            key_type: value.key_type.signature_type()?,
            key_id: value.address,
            expiry,
            limits,
            allowed_calls,
            witness: value.witness,
            is_admin: value.is_admin,
            account: value.account,
        };
        Ok(Self::new(authorization, value.signature.try_into()?))
    }
}

#[derive(Clone, Deserialize)]
struct PersistedTokenLimit {
    token: Address,
    limit: AccountsU256,
    #[serde(default)]
    period: Option<AccountsU64>,
}

impl From<PersistedTokenLimit> for TokenLimit {
    fn from(value: PersistedTokenLimit) -> Self {
        Self {
            token: value.token,
            limit: value.limit.0,
            period: value.period.map_or(0, |period| period.0),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type")]
enum PersistedPrimitiveSignature {
    #[serde(rename = "secp256k1")]
    Secp256k1 { signature: PersistedSecpSignature },
    #[serde(rename = "p256")]
    P256 {
        signature: PersistedRs,
        #[serde(rename = "publicKey")]
        public_key: PersistedPublicKey,
        #[serde(default, alias = "preHash")]
        prehash: bool,
    },
    #[serde(rename = "webAuthn")]
    WebAuthn {
        signature: PersistedRs,
        #[serde(rename = "publicKey")]
        public_key: PersistedPublicKey,
        metadata: PersistedWebAuthnMetadata,
    },
    #[serde(other)]
    Unsupported,
}

impl TryFrom<PersistedPrimitiveSignature> for PrimitiveSignature {
    type Error = PersistedKeyError;

    fn try_from(value: PersistedPrimitiveSignature) -> Result<Self, Self::Error> {
        match value {
            PersistedPrimitiveSignature::Secp256k1 { signature } => {
                let parity = match signature.y_parity.0 {
                    U256::ZERO => false,
                    U256::ONE => true,
                    _ => return Err(PersistedKeyError::InvalidYParity),
                };
                Ok(Self::Secp256k1(Signature::new(
                    signature.r.0,
                    signature.s.0,
                    parity,
                )))
            }
            PersistedPrimitiveSignature::P256 {
                signature,
                public_key,
                prehash,
            } => {
                public_key.validate_prefix()?;
                Ok(Self::P256(P256SignatureWithPreHash {
                    r: signature.r.into_b256(),
                    s: signature.s.into_b256(),
                    pub_key_x: public_key.x.into_b256(),
                    pub_key_y: public_key.y.into_b256(),
                    pre_hash: prehash,
                }))
            }
            PersistedPrimitiveSignature::WebAuthn {
                signature,
                public_key,
                metadata,
            } => {
                public_key.validate_prefix()?;
                let mut webauthn_data = metadata.authenticator_data.to_vec();
                webauthn_data.extend_from_slice(&metadata.client_data_json.0);
                Ok(Self::WebAuthn(WebAuthnSignature {
                    r: signature.r.into_b256(),
                    s: signature.s.into_b256(),
                    pub_key_x: public_key.x.into_b256(),
                    pub_key_y: public_key.y.into_b256(),
                    webauthn_data: webauthn_data.into(),
                }))
            }
            PersistedPrimitiveSignature::Unsupported => {
                Err(PersistedKeyError::UnsupportedAuthorizationSignature)
            }
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedSecpSignature {
    r: AccountsU256,
    s: AccountsU256,
    y_parity: AccountsU256,
}

#[derive(Clone, Deserialize)]
struct PersistedRs {
    r: AccountsU256,
    s: AccountsU256,
}

#[derive(Clone, Deserialize)]
struct PersistedPublicKey {
    #[serde(default)]
    prefix: Option<u8>,
    x: AccountsU256,
    y: AccountsU256,
}

impl PersistedPublicKey {
    fn validate_prefix(&self) -> Result<(), PersistedKeyError> {
        if self.prefix.is_none_or(|prefix| prefix == 4) {
            Ok(())
        } else {
            Err(PersistedKeyError::InvalidPublicKeyPrefix)
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedWebAuthnMetadata {
    authenticator_data: Bytes,
    #[serde(rename = "clientDataJSON")]
    client_data_json: Utf8Bytes,
}

#[derive(Clone)]
struct Utf8Bytes(Bytes);

impl<'de> Deserialize<'de> for Utf8Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(value.into_bytes().into()))
    }
}

#[derive(Clone, Copy)]
struct AccountsU256(U256);

impl AccountsU256 {
    fn into_b256(self) -> B256 {
        B256::from(self.0.to_be_bytes::<32>())
    }
}

impl<'de> Deserialize<'de> for AccountsU256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AccountsU256Visitor;

        impl Visitor<'_> for AccountsU256Visitor {
            type Value = AccountsU256;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-negative integer or Accounts bigint string")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(AccountsU256(U256::from(value)))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = value.strip_suffix("#__bigint").unwrap_or(value);
                let parsed = if let Some(hex) = value.strip_prefix("0x") {
                    U256::from_str_radix(hex, 16)
                } else {
                    U256::from_str_radix(value, 10)
                };
                parsed.map(AccountsU256).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(AccountsU256Visitor)
    }
}

#[derive(Clone, Copy)]
struct AccountsU64(u64);

impl<'de> Deserialize<'de> for AccountsU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = AccountsU256::deserialize(deserializer)?;
        u64::try_from(value.0)
            .map(Self)
            .map_err(|_| de::Error::custom("Accounts integer exceeds u64"))
    }
}

#[derive(Debug, thiserror::Error)]
enum PersistedKeyError {
    #[error("unsupported access-key type")]
    UnsupportedKeyType,
    #[error("access key has no local credential")]
    MissingCredential,
    #[error("invalid local private key")]
    InvalidPrivateKey,
    #[error("WebCrypto P-256 handle is missing its JWK")]
    MissingJwk,
    #[error("WebCrypto P-256 handle is missing its public key")]
    MissingPublicKey,
    #[error("invalid P-256 key: {0}")]
    P256(#[from] P256SignerError),
    #[error("unsupported key-authorization signature type")]
    UnsupportedAuthorizationSignature,
    #[error("key-authorization expiry must be non-zero")]
    ZeroAuthorizationExpiry,
    #[error("scope recipients require an explicit selector")]
    RecipientsWithoutSelector,
    #[error("invalid secp256k1 y parity")]
    InvalidYParity,
    #[error("P-256 public key prefix must be uncompressed (4)")]
    InvalidPublicKeyPrefix,
}

#[derive(Clone, Copy)]
struct IntentCall<'a> {
    to: Option<Address>,
    input: &'a [u8],
}

fn load_state(path: &Path) -> Result<PersistedAccountsState, TempoAccountsError> {
    let bytes = fs::read(path).map_err(|source| TempoAccountsError::Read {
        path: path.to_owned(),
        source,
    })?;
    let file: PersistedStoreFile =
        serde_json::from_slice(&bytes).map_err(|source| TempoAccountsError::Decode {
            path: path.to_owned(),
            source,
        })?;
    Ok(match file {
        PersistedStoreFile::TempoCli(root) => root.store.state,
        PersistedStoreFile::Envelope(envelope) => envelope.state,
        PersistedStoreFile::State(state) => state,
    })
}

fn active_account(state: &PersistedAccountsState) -> Result<Address, TempoAccountsError> {
    match state.active_account {
        PersistedActiveAccount::Index(index) => state
            .accounts
            .get(index)
            .map(|account| account.address)
            .ok_or(TempoAccountsError::ActiveAccount),
        PersistedActiveAccount::Address(address) => state
            .accounts
            .iter()
            .any(|account| account.address == address)
            .then_some(address)
            .ok_or(TempoAccountsError::ActiveAccount),
    }
}

fn select_access_key(
    state: &PersistedAccountsState,
    account: Address,
    chain_id: u64,
    preferred: Option<Address>,
    calls: Option<&[IntentCall<'_>]>,
    now: u64,
) -> Result<TempoAccessKey, TempoAccountsError> {
    for key in state
        .access_keys
        .iter()
        .filter(|key| key.chain_id == chain_id && key.access == account)
        .filter(|key| preferred.is_none_or(|preferred| key.address == preferred))
        .filter(|key| key.expiry.is_none_or(|expiry| expiry > now))
        .filter(|key| {
            (preferred.is_some() && calls.is_none()) || scopes_match(key.scopes.as_deref(), calls)
        })
    {
        let Ok(mut signer) = hydrate_access_key(key) else {
            continue;
        };
        if signer.address() != key.address {
            continue;
        }
        signer.set_chain_id(Some(chain_id));
        let Some(key_authorization): Option<Option<SignedKeyAuthorization>> = key
            .key_authorization
            .clone()
            .map(TryInto::try_into)
            .transpose()
            .ok()
        else {
            continue;
        };
        if key_authorization.as_ref().is_some_and(|authorization| {
            authorization.key_id != key.address
                || authorization.chain_id != chain_id
                || authorization.key_type != signer.signature_type()
                || authorization
                    .account
                    .is_some_and(|authorized_account| authorized_account != account)
        }) {
            continue;
        }

        return Ok(TempoAccessKey {
            account,
            address: key.address,
            chain_id,
            signer,
            key_authorization: key_authorization.map(Box::new),
        });
    }

    Err(TempoAccountsError::MissingAccessKey { account, chain_id })
}

fn request_calls(request: &TempoTransactionRequest) -> Option<Vec<IntentCall<'_>>> {
    let mut calls = calls_from_tempo(&request.calls);
    if let Some(to) = request.inner.to.as_ref() {
        calls.push(IntentCall {
            to: call_address(to),
            input: request.inner.input.input().map_or(&[], Bytes::as_ref),
        });
    }
    (!calls.is_empty()).then_some(calls)
}

fn transaction_calls(
    transaction: &tempo_primitives::transaction::TempoTransaction,
) -> Option<Vec<IntentCall<'_>>> {
    (!transaction.calls.is_empty()).then(|| calls_from_tempo(&transaction.calls))
}

fn calls_from_tempo(calls: &[Call]) -> Vec<IntentCall<'_>> {
    calls
        .iter()
        .map(|call| IntentCall {
            to: call_address(&call.to),
            input: call.input.as_ref(),
        })
        .collect()
}

fn call_address(kind: &TxKind) -> Option<Address> {
    match kind {
        TxKind::Call(address) => Some(*address),
        TxKind::Create => None,
    }
}

fn scopes_match(scopes: Option<&[PersistedScope]>, calls: Option<&[IntentCall<'_>]>) -> bool {
    let Some(scopes) = scopes else {
        return true;
    };
    let Some(calls) = calls else {
        return false;
    };

    calls.iter().all(|call| {
        let Some(to) = call.to else {
            return false;
        };
        scopes.iter().any(|scope| {
            if scope.address != to {
                return false;
            }
            let Some(selector) = scope.selector else {
                return scope
                    .recipients
                    .as_ref()
                    .is_none_or(|recipients| recipients.is_empty());
            };
            if call.input.get(..4) != Some(selector.0.as_slice()) {
                return false;
            }
            let Some(recipients) = scope.recipients.as_deref() else {
                return true;
            };
            if recipients.is_empty() {
                return true;
            }
            let Some(word) = call.input.get(4..36) else {
                return false;
            };
            recipients.contains(&Address::from_word(B256::from_slice(word)))
        })
    })
}

fn persisted_scopes_to_call_scopes(
    scopes: Vec<PersistedScope>,
) -> Result<Vec<CallScope>, PersistedKeyError> {
    let mut grouped: Vec<(Address, Option<Vec<SelectorRule>>)> = Vec::new();

    for scope in scopes {
        if scope.selector.is_none()
            && scope
                .recipients
                .as_ref()
                .is_some_and(|recipients| !recipients.is_empty())
        {
            return Err(PersistedKeyError::RecipientsWithoutSelector);
        }

        let entry = grouped
            .iter_mut()
            .find(|(target, _)| *target == scope.address);
        match (entry, scope.selector) {
            (Some((_, rules)), None) => *rules = None,
            (Some((_, Some(rules))), Some(selector)) => rules.push(SelectorRule {
                selector: selector.0,
                recipients: scope.recipients.unwrap_or_default(),
            }),
            (Some((_, None)), Some(_)) => {}
            (None, None) => grouped.push((scope.address, None)),
            (None, Some(selector)) => grouped.push((
                scope.address,
                Some(vec![SelectorRule {
                    selector: selector.0,
                    recipients: scope.recipients.unwrap_or_default(),
                }]),
            )),
        }
    }

    Ok(grouped
        .into_iter()
        .map(|(target, selector_rules)| CallScope {
            target,
            selector_rules: selector_rules.unwrap_or_default(),
        })
        .collect())
}

fn hydrate_access_key(key: &PersistedAccessKey) -> Result<AccountsSigner, PersistedKeyError> {
    if let Some(private_key) = key.private_key {
        return hydrate_private_key(key.key_type, private_key);
    }

    let handle = key
        .handle
        .as_ref()
        .ok_or(PersistedKeyError::MissingCredential)?;
    if let Some(private_key) = handle.private_key {
        return match handle.kind {
            PersistedHandleKind::Secp256k1 => {
                hydrate_private_key(PersistedKeyType::Secp256k1, private_key)
            }
            PersistedHandleKind::P256 => hydrate_private_key(PersistedKeyType::P256, private_key),
            PersistedHandleKind::WebCryptoP256 | PersistedHandleKind::Unsupported => {
                Err(PersistedKeyError::UnsupportedKeyType)
            }
        };
    }

    match handle.kind {
        PersistedHandleKind::WebCryptoP256 => {
            if key.public_key.is_none() {
                return Err(PersistedKeyError::MissingPublicKey);
            }
            TempoP256Signer::from_webcrypto_jwk(
                handle.jwk.as_ref().ok_or(PersistedKeyError::MissingJwk)?,
            )
            .map(AccountsSigner::P256)
            .map_err(Into::into)
        }
        PersistedHandleKind::Secp256k1
        | PersistedHandleKind::P256
        | PersistedHandleKind::Unsupported => Err(PersistedKeyError::MissingCredential),
    }
}

fn hydrate_private_key(
    key_type: PersistedKeyType,
    private_key: PersistedPrivateKey,
) -> Result<AccountsSigner, PersistedKeyError> {
    match key_type {
        PersistedKeyType::P256 | PersistedKeyType::WebCrypto => {
            TempoP256Signer::from_slice(private_key.0.as_slice())
                .map(AccountsSigner::P256)
                .map_err(Into::into)
        }
        PersistedKeyType::Secp256k1 => PrivateKeySigner::from_bytes(&private_key.0)
            .map(AccountsSigner::Secp256k1)
            .map_err(|_| PersistedKeyError::InvalidPrivateKey),
        PersistedKeyType::WebAuthn | PersistedKeyType::Unsupported => {
            Err(PersistedKeyError::UnsupportedKeyType)
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use alloy_network::{NetworkWallet, TransactionBuilder};
    use alloy_provider::{ProviderBuilder, SendableTx, fillers::TxFiller};
    use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
    use tempo_primitives::{TempoTxEnvelope, transaction::TempoSignature};

    use super::*;

    const ROOT: &str = "0x1111111111111111111111111111111111111111";
    const TARGET: &str = "0x2222222222222222222222222222222222222222";

    #[test]
    fn persisted_boundary_deserializes_to_strict_types() {
        let state: PersistedAccountsState = serde_json::from_value(serde_json::json!({
            "activeAccount": ROOT,
            "chainId": 4217,
            "accounts": [{"address": ROOT}],
            "accessKeys": [{
                "access": ROOT,
                "address": "0xf0159a522607cd6ab1097204c9fafb7bbe6afb6c",
                "chainId": 4217,
                "keyType": "p256",
                "privateKey": format!("0x{}", "42".repeat(32)),
                "scopes": [{
                    "address": TARGET,
                    "selector": "transfer(address,uint256)",
                }],
            }],
        }))
        .unwrap();

        assert!(matches!(
            state.active_account,
            PersistedActiveAccount::Address(_)
        ));
        assert_eq!(
            state.access_keys[0].scopes.as_ref().unwrap()[0].selector,
            Some(PersistedSelector(
                keccak256("transfer(address,uint256)")[..4]
                    .try_into()
                    .unwrap()
            ))
        );
    }

    #[test]
    fn fills_scoped_key_metadata_before_async_prepare() {
        let first_key = format!("0x{}", "01".repeat(32));
        let selected_key = format!("0x{}", "02".repeat(32));
        let first =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&first_key).unwrap())
                .unwrap();
        let selected =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&selected_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([
            {
                "access": ROOT,
                "address": first.address(),
                "chainId": 4217,
                "keyType": "p256",
                "privateKey": first_key,
                "scopes": [{"address": TARGET, "selector": "0x01020304"}],
            },
            {
                "access": ROOT,
                "address": selected.address(),
                "chainId": 4217,
                "keyType": "p256",
                "privateKey": selected_key,
                "scopes": [{"address": TARGET, "selector": "0xaabbccdd"}],
            },
        ]));
        let wallet = TempoAccountsWallet::from_store(&path).unwrap();
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TARGET.parse::<Address>().unwrap().into()),
                input: TransactionInput::new(Bytes::from_static(&[0xaa, 0xbb, 0xcc, 0xdd])),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut sendable = SendableTx::Builder(request);

        wallet.fill_sync(&mut sendable);

        let request = sendable.as_builder().unwrap();
        assert_eq!(request.from(), Some(ROOT.parse().unwrap()));
        assert_eq!(request.chain_id(), Some(4217));
        assert_eq!(request.key_id, Some(selected.address()));
        assert_eq!(request.key_type, Some(SignatureType::P256));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_pinned_key_never_falls_back_after_store_rotation() {
        let first_key = format!("0x{}", "01".repeat(32));
        let second_key = format!("0x{}", "02".repeat(32));
        let first =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&first_key).unwrap())
                .unwrap();
        let second =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&second_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([key_json(first.address(), first_key)]));
        let wallet = TempoAccountsWallet::from_store(&path).unwrap();
        let mut request = TempoTransactionRequest::default();
        wallet.fill_metadata(&mut request).unwrap();
        assert_eq!(request.key_id, Some(first.address()));

        overwrite_store(
            &path,
            serde_json::json!([key_json(second.address(), second_key)]),
        );
        assert!(matches!(
            wallet.select_for_request(&request),
            Err(TempoAccountsError::MissingAccessKey { .. })
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_pinned_key_still_has_to_cover_the_request() {
        let private_key = format!("0x{}", "02".repeat(32));
        let signer =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&private_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([{
            "access": ROOT,
            "address": signer.address(),
            "chainId": 4217,
            "keyType": "p256",
            "privateKey": private_key,
            "scopes": [{"address": TARGET, "selector": "0xaabbccdd"}],
        }]));
        let wallet = TempoAccountsWallet::from_store(&path).unwrap();
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TARGET.parse::<Address>().unwrap().into()),
                input: TransactionInput::new(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef])),
                ..Default::default()
            },
            key_id: Some(signer.address()),
            ..Default::default()
        };

        assert!(matches!(
            wallet.select_for_request(&request),
            Err(TempoAccountsError::MissingAccessKey { .. })
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn selection_checks_calls_and_the_legacy_to_field_together() {
        let private_key = format!("0x{}", "02".repeat(32));
        let signer =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&private_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([{
            "access": ROOT,
            "address": signer.address(),
            "chainId": 4217,
            "keyType": "p256",
            "privateKey": private_key,
            "scopes": [{"address": TARGET, "selector": "0xaabbccdd"}],
        }]));
        let wallet = TempoAccountsWallet::from_store(&path).unwrap();
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(Address::repeat_byte(0x33).into()),
                input: TransactionInput::new(Bytes::from_static(&[0x01, 0x02, 0x03, 0x04])),
                ..Default::default()
            },
            calls: vec![Call {
                to: TARGET.parse::<Address>().unwrap().into(),
                value: U256::ZERO,
                input: Bytes::from_static(&[0xaa, 0xbb, 0xcc, 0xdd]),
            }],
            ..Default::default()
        };

        assert!(matches!(
            wallet.select_for_request(&request),
            Err(TempoAccountsError::MissingAccessKey { .. })
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn selected_key_rejects_a_different_chain() {
        let private_key = format!("0x{}", "02".repeat(32));
        let signer =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&private_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([key_json(signer.address(), private_key)]));
        let wallet = TempoAccountsWallet::from_store(&path).unwrap();
        let key = wallet.active_access_key().unwrap();
        let mut request = TempoTransactionRequest {
            inner: TransactionRequest {
                chain_id: Some(1),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(key.fill_request(&mut request).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn selected_key_rejects_create() {
        let private_key = format!("0x{}", "02".repeat(32));
        let signer =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&private_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([key_json(signer.address(), private_key)]));
        let wallet = TempoAccountsWallet::from_store(&path).unwrap();
        let key = wallet.active_access_key().unwrap();
        let mut request = TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Create),
                ..Default::default()
            },
            ..Default::default()
        };

        let error = key.fill_request(&mut request).unwrap_err();
        assert!(error.to_string().contains("cannot use CREATE"));
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn prepare_request_selects_from_the_store_lazily() {
        let first_key = format!("0x{}", "01".repeat(32));
        let second_key = format!("0x{}", "02".repeat(32));
        let first =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&first_key).unwrap())
                .unwrap();
        let second =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&second_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([key_json(first.address(), first_key)]));
        let wallet = TempoAccountsWallet::from_store(&path).unwrap();
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(Default::default());

        let mut first_request = TempoTransactionRequest::default();
        wallet
            .prepare_request(&provider, &mut first_request)
            .await
            .unwrap();
        assert_eq!(first_request.key_id, Some(first.address()));

        overwrite_store(
            &path,
            serde_json::json!([key_json(second.address(), second_key)]),
        );
        let mut second_request = TempoTransactionRequest::default();
        wallet
            .prepare_request(&provider, &mut second_request)
            .await
            .unwrap();
        assert_eq!(second_request.key_id, Some(second.address()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn active_account_is_reloaded_from_the_store() {
        let private_key = format!("0x{}", "02".repeat(32));
        let signer =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&private_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([key_json(signer.address(), private_key)]));
        let wallet = TempoAccountsWallet::from_store(&path).unwrap();
        let second = Address::repeat_byte(0x44);
        let value = serde_json::json!({
            "tempo-cli.store": {
                "state": {
                    "activeAccount": 1,
                    "chainId": 4217,
                    "accounts": [{"address": ROOT}, {"address": second}],
                    "accessKeys": [],
                },
            },
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert_eq!(wallet.account(), ROOT.parse::<Address>().unwrap());
        assert_eq!(wallet.active_account().unwrap(), second);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn signs_with_v2_keychain_envelope_without_a_signing_mode() {
        let private_key = format!("0x{}", "02".repeat(32));
        let signer =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&private_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([key_json(signer.address(), private_key)]));
        let wallet = TempoAccountsWallet::from_store(&path).unwrap();
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TARGET.parse::<Address>().unwrap().into()),
                nonce: Some(0),
                gas: Some(100_000),
                max_fee_per_gas: Some(1),
                max_priority_fee_per_gas: Some(1),
                ..Default::default()
            },
            ..Default::default()
        };

        let envelope = wallet.sign_request(request).await.unwrap();

        let TempoTxEnvelope::AA(signed) = envelope else {
            panic!("expected AA transaction");
        };
        let TempoSignature::Keychain(signature) = signed.signature() else {
            panic!("expected keychain signature");
        };
        assert_eq!(signature.user_address, ROOT.parse::<Address>().unwrap());
        assert!(!signature.is_legacy());
        assert_eq!(
            signature.key_id(&signed.signature_hash()).unwrap(),
            signer.address()
        );
        fs::remove_file(path).unwrap();
    }

    fn key_json(address: Address, private_key: String) -> serde_json::Value {
        serde_json::json!({
            "access": ROOT,
            "address": address,
            "chainId": 4217,
            "keyType": "p256",
            "privateKey": private_key,
        })
    }

    fn write_store(access_keys: serde_json::Value) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "tempo-alloy-accounts-{}-{unique}.json",
            std::process::id()
        ));
        overwrite_store(&path, access_keys);
        path
    }

    fn overwrite_store(path: &Path, access_keys: serde_json::Value) {
        let value = serde_json::json!({
            "tempo-cli.store": {
                "state": {
                    "activeAccount": 0,
                    "chainId": 4217,
                    "accounts": [{"address": ROOT}],
                    "accessKeys": access_keys,
                },
            },
        });
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }
}
