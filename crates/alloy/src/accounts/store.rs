//! Strictly typed Tempo Accounts store integration.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    env, fmt, fs,
    io::Write,
    num::NonZeroU64,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, LazyLock, Mutex},
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
use alloy_sol_types::SolCall;
use alloy_transport::TransportResult;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, Visitor},
};
use serde_json::value::RawValue;
use tempo_contracts::precompiles::ITIP20;
use tempo_primitives::{
    SignatureType, TempoAddressExt, TempoTxEnvelope,
    transaction::{
        Call, CallScope, KeyAuthorization, KeychainSignature, PrimitiveSignature, SelectorRule,
        SignedKeyAuthorization, TempoSignature, TempoTypedTransaction, TokenLimit,
        tt_signature::{P256SignatureWithPreHash, WebAuthnSignature},
    },
};

use super::p256::{P256Jwk, P256SignerError, TempoP256Signer};
use crate::{
    TempoNetwork, fillers::gas::resolve_key_authorization, provider::keychain::call_scopes_allow,
    rpc::TempoTransactionRequest,
};

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

static AUTHORIZATION_RESERVATIONS: LazyLock<Mutex<AuthorizationReservationState>> =
    LazyLock::new(|| Mutex::new(AuthorizationReservationState::default()));

#[derive(Default)]
struct AuthorizationReservationState {
    next_generation: u64,
    reservations: BTreeMap<AuthorizationIdentity, u64>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AuthorizationIdentity {
    chain_id: u64,
    account: Address,
    key_id: Address,
}

#[derive(Clone, Debug, Default)]
struct AuthorizationReservations {
    observed: Arc<Mutex<BTreeSet<TempoAuthorizationReservation>>>,
}

impl AuthorizationReservations {
    fn reserve(&self, identity: AuthorizationIdentity) -> Result<(), TempoAccessKeyError> {
        let mut state = AUTHORIZATION_RESERVATIONS
            .lock()
            .map_err(|_| TempoAccessKeyError::ReservationStateUnavailable)?;
        if state.reservations.contains_key(&identity) {
            return Err(TempoAccessKeyError::AuthorizationInFlight {
                chain_id: identity.chain_id,
                account: identity.account,
                key_id: identity.key_id,
            });
        }
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| TempoAccessKeyError::ReservationStateUnavailable)?;
        let generation = state
            .next_generation
            .checked_add(1)
            .ok_or(TempoAccessKeyError::ReservationStateUnavailable)?;
        state.next_generation = generation;
        state.reservations.insert(identity, generation);
        let reservation = TempoAuthorizationReservation {
            chain_id: identity.chain_id,
            account: identity.account,
            key_id: identity.key_id,
            generation,
        };
        observed.insert(reservation);
        Ok(())
    }

    fn release_owned(
        &self,
        reservation: TempoAuthorizationReservation,
    ) -> Result<(), TempoAccessKeyError> {
        let mut state = AUTHORIZATION_RESERVATIONS
            .lock()
            .map_err(|_| TempoAccessKeyError::ReservationStateUnavailable)?;
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| TempoAccessKeyError::ReservationStateUnavailable)?;
        if observed.remove(&reservation)
            && state.reservations.get(&reservation.identity()) == Some(&reservation.generation)
        {
            state.reservations.remove(&reservation.identity());
        }
        Ok(())
    }

    fn resolve_on_chain(&self, identity: AuthorizationIdentity) -> Result<(), TempoAccessKeyError> {
        let mut state = AUTHORIZATION_RESERVATIONS
            .lock()
            .map_err(|_| TempoAccessKeyError::ReservationStateUnavailable)?;
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| TempoAccessKeyError::ReservationStateUnavailable)?;
        state.reservations.remove(&identity);
        observed.retain(|reservation| reservation.identity() != identity);
        Ok(())
    }

    fn in_flight(&self) -> Result<Vec<TempoAuthorizationReservation>, TempoAccessKeyError> {
        let state = AUTHORIZATION_RESERVATIONS
            .lock()
            .map_err(|_| TempoAccessKeyError::ReservationStateUnavailable)?;
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| TempoAccessKeyError::ReservationStateUnavailable)?;
        observed.retain(|reservation| {
            state.reservations.get(&reservation.identity()) == Some(&reservation.generation)
        });
        Ok(observed.iter().copied().collect())
    }
}

/// Handle for one pending, one-time Tempo key authorization.
///
/// Payment transports can retain this value with the signed credential and
/// release it after a definitive local rejection. Ambiguous transport failures
/// should remain reserved until the key is observed on-chain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TempoAuthorizationReservation {
    chain_id: u64,
    account: Address,
    key_id: Address,
    generation: u64,
}

impl TempoAuthorizationReservation {
    const fn identity(&self) -> AuthorizationIdentity {
        AuthorizationIdentity {
            chain_id: self.chain_id,
            account: self.account,
            key_id: self.key_id,
        }
    }

    /// Chain on which the authorization can be published.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Root account that signed the authorization.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// Access-key identifier authorized by the transaction.
    pub const fn key_id(&self) -> Address {
        self.key_id
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
    authorization_reservations: AuthorizationReservations,
}

impl TempoAccessKey {
    /// Construct a chain-bound secp256k1 access key.
    pub fn from_secp256k1(account: Address, chain_id: u64, signer: PrivateKeySigner) -> Self {
        let address = signer.address();
        Self {
            account,
            address,
            chain_id,
            signer: AccountsSigner::Secp256k1(signer),
            key_authorization: None,
            authorization_reservations: AuthorizationReservations::default(),
        }
    }

    /// Attach a pending one-time access-key authorization.
    pub fn with_key_authorization(mut self, authorization: SignedKeyAuthorization) -> Self {
        self.key_authorization = Some(Box::new(authorization));
        self
    }

    /// Root Tempo account controlled by this access key.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// On-chain access-key identifier.
    pub const fn address(&self) -> Address {
        self.address
    }

    /// On-chain access-key identifier.
    pub const fn key_id(&self) -> Address {
        self.address
    }

    /// Chain to which the key is scoped.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Cryptographic signature type produced by this key.
    pub const fn signature_type(&self) -> SignatureType {
        self.signer.signature_type()
    }

    /// Pending authorization attached until the key is observed on-chain.
    pub fn key_authorization(&self) -> Option<&SignedKeyAuthorization> {
        self.key_authorization.as_deref()
    }

    fn validate_pending_authorization(&self) -> Result<(), TempoAccessKeyError> {
        let Some(authorization) = self.key_authorization.as_deref() else {
            return Ok(());
        };
        if authorization.key_id != self.address {
            return Err(TempoAccessKeyError::InvalidAuthorization(
                "key ID does not match the selected signer",
            ));
        }
        if authorization.key_type != self.signature_type() {
            return Err(TempoAccessKeyError::InvalidAuthorization(
                "key type does not match the selected signer",
            ));
        }
        if authorization.chain_id != self.chain_id {
            return Err(TempoAccessKeyError::InvalidAuthorization(
                "chain ID does not match the selected key",
            ));
        }
        if authorization
            .account
            .is_some_and(|account| account != self.account)
        {
            return Err(TempoAccessKeyError::InvalidAuthorization(
                "account does not match the selected key",
            ));
        }
        if authorization.account.is_none()
            && authorization.recover_signer().ok() != Some(self.account)
        {
            return Err(TempoAccessKeyError::InvalidAuthorization(
                "signature does not recover the root account",
            ));
        }
        Ok(())
    }

    /// Fill access-key metadata and resolve a pending authorization before
    /// external gas estimation or fee-payer signing.
    ///
    /// The returned key owns its resolved pending-key state and must be retained
    /// through final signing. Separately supplied cross-key authorizations remain
    /// attached to the request.
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
            if prepared.key_authorization.is_some() {
                prepared.key_authorization = key_authorization.map(Box::new);
            }
        }
        Ok(prepared)
    }

    fn fill_request(&self, request: &mut TempoTransactionRequest) -> alloy_signer::Result<()> {
        if super::request_uses_create(request) {
            return Err(alloy_signer::Error::other(
                TempoAccessKeyError::CreateUnsupported,
            ));
        }
        self.validate_pending_authorization()
            .map_err(alloy_signer::Error::other)?;
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

        if let Some(expected) = self.key_authorization.as_deref() {
            if request
                .key_authorization
                .as_ref()
                .is_some_and(|actual| actual != expected)
            {
                return Err(alloy_signer::Error::other(
                    TempoAccessKeyError::AuthorizationMismatch,
                ));
            }
            request.key_authorization = Some(expected.clone());
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
        self.validate_pending_authorization()
            .map_err(alloy_signer::Error::other)?;

        if let Some(expected) = self.key_authorization.as_deref() {
            if tx
                .key_authorization
                .as_ref()
                .is_some_and(|actual| actual != expected)
            {
                return Err(alloy_signer::Error::other(
                    TempoAccessKeyError::AuthorizationMismatch,
                ));
            }
            tx.key_authorization = Some(expected.clone());
        }
        let signing_hash = KeychainSignature::signing_hash(tx.signature_hash(), self.account);
        let primitive = self.signer.sign_hash(&signing_hash).await?;
        if let Some(authorization) = tx.key_authorization.as_ref() {
            self.authorization_reservations
                .reserve(AuthorizationIdentity {
                    chain_id: self.chain_id,
                    account: self.account,
                    key_id: authorization.key_id,
                })
                .map_err(alloy_signer::Error::other)?;
        } else {
            self.authorization_reservations
                .resolve_on_chain(AuthorizationIdentity {
                    chain_id: self.chain_id,
                    account: self.account,
                    key_id: self.address,
                })
                .map_err(alloy_signer::Error::other)?;
        }
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
        if selected.key_authorization.is_some() {
            selected.key_authorization = key_authorization.map(Box::new);
        }
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
        if request.from().is_none() {
            request.set_from(self.account);
        }
        Ok(())
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
    #[error("request key authorization does not match the selected Tempo Accounts key")]
    AuthorizationMismatch,
    #[error("invalid pending Tempo key authorization: {0}")]
    InvalidAuthorization(&'static str),
    #[error(
        "Tempo key authorization for {key_id} on account {account} and chain {chain_id} is already in flight"
    )]
    AuthorizationInFlight {
        chain_id: u64,
        account: Address,
        key_id: Address,
    },
    #[error("Tempo key-authorization reservation state is unavailable")]
    ReservationStateUnavailable,
}

/// Errors returned while reading or selecting from a Tempo Accounts store.
#[derive(Debug, thiserror::Error)]
pub enum TempoAccountsError {
    /// The platform did not expose a home directory.
    #[error("home directory is unavailable")]
    HomeUnavailable,
    /// The in-process authorization reservation state is unavailable.
    #[error("Tempo key-authorization reservation state is unavailable")]
    AuthorizationReservationStateUnavailable,
    /// The Accounts store could not be read.
    #[error("failed to read Tempo Accounts store at {path}: {source}")]
    Read {
        /// Store path.
        path: PathBuf,
        /// Filesystem error.
        source: std::io::Error,
    },
    /// The Accounts store could not be locked for mutation.
    #[error("failed to lock Tempo Accounts store at {path}: {source}")]
    Lock {
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
    /// The canonical Accounts store could not be encoded.
    #[error("failed to encode Tempo Accounts store at {path}: {source}")]
    Encode {
        /// Store path.
        path: PathBuf,
        /// JSON error.
        source: serde_json::Error,
    },
    /// The Accounts store could not be written atomically.
    #[error("failed to write Tempo Accounts store at {path}: {source}")]
    Write {
        /// Store path.
        path: PathBuf,
        /// Filesystem error.
        source: std::io::Error,
    },
    /// A stored access-key record was internally inconsistent.
    #[error("invalid Tempo Accounts access key {address}: {reason}")]
    InvalidAccessKey {
        /// Stored access-key address.
        address: Address,
        /// Validation failure.
        reason: String,
    },
    /// A supplied authorization did not describe the access key being stored.
    #[error("invalid Tempo Accounts access-key authorization: {0}")]
    InvalidAuthorization(&'static str),
    /// The active account selector was missing or invalid.
    #[error("Tempo Accounts active account is missing or invalid")]
    ActiveAccount,
    /// A locally supplied access key was used before its chain was known.
    #[error("Tempo Accounts needs a chain ID to select the access key")]
    MissingChainId,
    /// Store-backed direct signing cannot resolve a pending authorization.
    #[error(
        "Tempo Accounts store key has an unresolved authorization; call prepare_request or use the wallet as a provider filler"
    )]
    AuthorizationResolutionRequired,
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

/// A signed key authorization in the Tempo Accounts SDK RPC representation.
///
/// This is the strict response type returned by the Accounts device-code flow.
/// It converts the SDK's flat RPC signature envelope into the protocol-native
/// [`SignedKeyAuthorization`] used by Alloy and the Accounts store.
#[derive(Clone, Debug)]
pub struct TempoAccountsKeyAuthorization(SignedKeyAuthorization);

impl TempoAccountsKeyAuthorization {
    /// Borrow the protocol-native signed authorization.
    pub const fn as_signed(&self) -> &SignedKeyAuthorization {
        &self.0
    }

    /// Consume the SDK authorization and return its protocol-native form.
    pub fn into_signed(self) -> SignedKeyAuthorization {
        self.0
    }
}

impl AsRef<SignedKeyAuthorization> for TempoAccountsKeyAuthorization {
    fn as_ref(&self) -> &SignedKeyAuthorization {
        self.as_signed()
    }
}

impl<'de> Deserialize<'de> for TempoAccountsKeyAuthorization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        AccountsRpcKeyAuthorization::deserialize(deserializer)?
            .try_into()
            .map(Self)
            .map_err(de::Error::custom)
    }
}

/// Non-secret metadata for one access key in a Tempo Accounts store.
#[derive(Clone, Debug)]
pub struct TempoStoredAccessKey {
    account: Address,
    address: Address,
    chain_id: u64,
    key_type: SignatureType,
    expiry: Option<u64>,
    limits: Vec<TokenLimit>,
    allowed_calls: Option<Vec<CallScope>>,
    key_authorization: Option<SignedKeyAuthorization>,
    locally_signable: bool,
}

impl TempoStoredAccessKey {
    /// Root Tempo account controlled by this key.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// On-chain access-key identifier.
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Chain to which this key is scoped.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Cryptographic signature type.
    pub const fn key_type(&self) -> SignatureType {
        self.key_type
    }

    /// Unix expiry timestamp, if one was configured.
    pub const fn expiry(&self) -> Option<u64> {
        self.expiry
    }

    /// Persisted token spending limits.
    pub fn limits(&self) -> &[TokenLimit] {
        &self.limits
    }

    /// Persisted call restrictions. `None` means unrestricted calls.
    pub fn allowed_calls(&self) -> Option<&[CallScope]> {
        self.allowed_calls.as_deref()
    }

    /// Pending one-time authorization, if the key has not yet been published.
    pub const fn key_authorization(&self) -> Option<&SignedKeyAuthorization> {
        self.key_authorization.as_ref()
    }

    /// One-time authorization witness, when the stored authorization carries one.
    pub fn authorization_witness(&self) -> Option<B256> {
        self.key_authorization
            .as_ref()
            .and_then(|authorization| authorization.witness)
    }

    /// Whether the store contains usable local signing material for this key.
    pub const fn is_locally_signable(&self) -> bool {
        self.locally_signable
    }
}

/// A concrete handle for reading and updating one Tempo Accounts `store.json`.
#[derive(Clone, Debug)]
pub struct TempoAccountsStore {
    path: PathBuf,
}

impl TempoAccountsStore {
    /// Open and validate a Tempo Accounts store.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TempoAccountsError> {
        let path = path.into();
        load_state(&path)?;
        Ok(Self { path })
    }

    /// Open the default Tempo Accounts store.
    pub fn open_default() -> Result<Self, TempoAccountsError> {
        Self::open(default_accounts_store_path()?)
    }

    /// Open the default store when it exists.
    pub fn try_open_default() -> Result<Option<Self>, TempoAccountsError> {
        let path = default_accounts_store_path()?;
        match Self::open(path) {
            Ok(store) => Ok(Some(store)),
            Err(TempoAccountsError::Read { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Construct a store handle without requiring the file to exist yet.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Construct a default store handle without requiring the file to exist yet.
    pub fn default_path() -> Result<Self, TempoAccountsError> {
        Ok(Self::at(default_accounts_store_path()?))
    }

    /// Filesystem path for this store.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Currently active root account.
    pub fn active_account(&self) -> Result<Address, TempoAccountsError> {
        active_account(&load_state(&self.path)?)
    }

    /// Non-secret metadata for all usable stored key records.
    pub fn access_keys(&self) -> Result<Vec<TempoStoredAccessKey>, TempoAccountsError> {
        load_state(&self.path)?
            .access_keys
            .iter()
            .map(stored_access_key)
            .collect()
    }

    /// Atomically add or replace a locally generated secp256k1 access key.
    ///
    /// Existing accounts, access keys, capabilities, and unknown SDK fields are
    /// retained byte-for-byte as raw JSON values. An existing record is
    /// replaced only when its account, chain, and access-key address all match.
    pub fn upsert_secp256k1_access_key(
        &self,
        account: Address,
        signer: &PrivateKeySigner,
        authorization: &SignedKeyAuthorization,
    ) -> Result<(), TempoAccountsError> {
        validate_stored_authorization(account, signer, authorization)?;
        upsert_secp256k1_access_key(&self.path, account, signer, authorization)
    }

    /// Erase local signing material for one access key while retaining its non-secret metadata.
    ///
    /// Keeping the account, chain, policy, and authorization witness lets callers finish or retry
    /// on-chain revocation without leaving the key locally usable.
    pub fn retire_access_key(
        &self,
        account: Address,
        chain_id: u64,
        access_key: Address,
    ) -> Result<bool, TempoAccountsError> {
        retire_access_key(&self.path, account, chain_id, access_key)
    }
}

/// The source used by a Tempo Accounts wallet.
#[derive(Clone)]
enum AccountsSource {
    Store {
        path: PathBuf,
        fallback_account: Address,
    },
    Local {
        account: Address,
        signer: AccountsSigner,
        key_authorization: Option<Box<SignedKeyAuthorization>>,
    },
}

/// A Tempo Accounts wallet backed by `store.json` or one explicit local key.
///
/// This type implements both [`NetworkWallet<TempoNetwork>`] and
/// [`TxFiller<TempoNetwork>`]. Add it with `ProviderBuilder::filler(wallet)` so
/// access-key metadata is selected synchronously before Alloy's gas filler
/// prepares its estimate. The same pinned key is then used for signing.
#[derive(Clone)]
pub struct TempoAccountsWallet {
    source: AccountsSource,
    chain_id: Option<u64>,
    authorization_reservations: AuthorizationReservations,
}

impl fmt::Debug for TempoAccountsWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("TempoAccountsWallet");
        match &self.source {
            AccountsSource::Store {
                path,
                fallback_account,
            } => {
                debug
                    .field("source", &"store")
                    .field("path", path)
                    .field("fallback_account", fallback_account);
            }
            AccountsSource::Local {
                account, signer, ..
            } => {
                debug
                    .field("source", &"local")
                    .field("account", account)
                    .field("key_id", &signer.address());
            }
        }
        debug.field("chain_id", &self.chain_id).finish()
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
            source: AccountsSource::Store {
                path,
                fallback_account,
            },
            chain_id: None,
            authorization_reservations: AuthorizationReservations::default(),
        })
    }

    /// Open `~/.tempo/wallet/store.json`.
    pub fn from_default_store() -> Result<Self, TempoAccountsError> {
        Self::from_store(default_accounts_store_path()?)
    }

    /// Open `~/.tempo/wallet/store.json` when it exists.
    pub fn try_from_default_store() -> Result<Option<Self>, TempoAccountsError> {
        let path = default_accounts_store_path()?;
        match Self::from_store(path) {
            Ok(wallet) => Ok(Some(wallet)),
            Err(TempoAccountsError::Read { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Construct a wallet from one explicitly supplied secp256k1 access key.
    pub fn from_secp256k1(
        account: Address,
        signer: PrivateKeySigner,
        key_authorization: Option<SignedKeyAuthorization>,
    ) -> Self {
        Self {
            source: AccountsSource::Local {
                account,
                signer: AccountsSigner::Secp256k1(signer),
                key_authorization: key_authorization.map(Box::new),
            },
            chain_id: None,
            authorization_reservations: AuthorizationReservations::default(),
        }
    }

    /// Pin one access key previously loaded from an Accounts store.
    ///
    /// The resulting wallet no longer consults the store during selection, so a caller can retain
    /// the exact key and pending authorization across request preparation and signing.
    pub fn from_access_key(selected: TempoAccessKey) -> Self {
        Self {
            chain_id: Some(selected.chain_id),
            authorization_reservations: selected.authorization_reservations,
            source: AccountsSource::Local {
                account: selected.account,
                signer: selected.signer,
                key_authorization: selected.key_authorization,
            },
        }
    }

    /// Pin the chain used when a request does not already contain one.
    pub const fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Path backing this wallet, if it reads an Accounts store.
    pub fn store_path(&self) -> Option<&Path> {
        match &self.source {
            AccountsSource::Store { path, .. } => Some(path),
            AccountsSource::Local { .. } => None,
        }
    }

    /// Active root account observed when this wallet was opened.
    pub const fn account(&self) -> Address {
        match &self.source {
            AccountsSource::Store {
                fallback_account, ..
            } => *fallback_account,
            AccountsSource::Local { account, .. } => *account,
        }
    }

    /// Reload the currently active root account, or return the explicit root.
    pub fn active_account(&self) -> Result<Address, TempoAccountsError> {
        match &self.source {
            AccountsSource::Store { path, .. } => active_account(&load_state(path)?),
            AccountsSource::Local { account, .. } => Ok(*account),
        }
    }

    /// Return whether this wallet contains the root account.
    pub fn has_account(&self, address: Address) -> Result<bool, TempoAccountsError> {
        match &self.source {
            AccountsSource::Store { path, .. } => Ok(load_state(path)?
                .accounts
                .iter()
                .any(|account| account.address == address)),
            AccountsSource::Local { account, .. } => Ok(*account == address),
        }
    }

    /// Resolve the access-key identifier used without a concrete call intent.
    pub fn key_id(&self) -> Result<Address, TempoAccountsError> {
        self.active_access_key().map(|key| key.address)
    }

    /// Pending authorization on an explicitly supplied or prepared key.
    pub fn key_authorization(&self) -> Option<&SignedKeyAuthorization> {
        match &self.source {
            AccountsSource::Store { .. } => None,
            AccountsSource::Local {
                key_authorization, ..
            } => key_authorization.as_deref(),
        }
    }

    /// In-flight reservation associated with this prepared wallet's pending
    /// authorization, if signing has reserved it.
    pub fn authorization_reservation(&self) -> Option<TempoAuthorizationReservation> {
        let AccountsSource::Local {
            account,
            key_authorization: Some(authorization),
            ..
        } = &self.source
        else {
            return None;
        };
        let identity = AuthorizationIdentity {
            chain_id: self.chain_id?,
            account: *account,
            key_id: authorization.key_id,
        };
        self.authorization_reservations
            .in_flight()
            .ok()?
            .into_iter()
            .find(|reservation| reservation.identity() == identity)
    }

    /// Reservations created by authorization-bearing sends through this wallet
    /// or any of its clones.
    ///
    /// Callers can use the request's chain, account, and key ID to identify the
    /// reservation for a definitively rejected send. Ambiguous transport
    /// failures must remain reserved because the transaction may still land.
    pub fn in_flight_authorization_reservations(
        &self,
    ) -> Result<Vec<TempoAuthorizationReservation>, TempoAccountsError> {
        self.authorization_reservations
            .in_flight()
            .map_err(|_| TempoAccountsError::AuthorizationReservationStateUnavailable)
    }

    /// Release a reservation after the caller knows the signed authorization
    /// was not handed to a transport or was definitively rejected.
    ///
    /// Do not call this for an ambiguous network failure: the transaction may
    /// still be pending even when its response was lost.
    pub fn release_authorization(
        &self,
        reservation: TempoAuthorizationReservation,
    ) -> Result<(), TempoAccountsError> {
        self.authorization_reservations
            .release_owned(reservation)
            .map_err(|_| TempoAccountsError::AuthorizationReservationStateUnavailable)
    }

    /// Return whether this wallet can select a locally signable key for the
    /// complete request intent without signing or reserving it.
    pub fn has_access_key_for_request(
        &self,
        request: &TempoTransactionRequest,
    ) -> Result<bool, TempoAccountsError> {
        match self.select_for_request(request) {
            Ok(_) => Ok(true),
            Err(TempoAccountsError::MissingAccessKey { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Sign a digest with the active access key.
    pub async fn sign_hash(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        let key = self
            .active_access_key()
            .map_err(alloy_signer::Error::other)?;
        key.sign_hash(hash).await
    }

    /// Load the active account's first unscoped, locally signable access key.
    ///
    /// This mirrors the default selection used by Tempo Accounts when no
    /// concrete call intent is supplied.
    pub fn active_access_key(&self) -> Result<TempoAccessKey, TempoAccountsError> {
        match &self.source {
            AccountsSource::Store { path, .. } => {
                let state = load_state(path)?;
                let account = active_account(&state)?;
                let chain_id = self.chain_id.unwrap_or(state.chain_id);
                select_access_key(
                    &state,
                    account,
                    chain_id,
                    (None, None),
                    None,
                    unix_now(),
                    &self.authorization_reservations,
                )
            }
            AccountsSource::Local {
                account,
                signer,
                key_authorization,
            } => {
                let chain_id = self
                    .chain_id
                    .or_else(|| signer.chain_id())
                    .ok_or(TempoAccountsError::MissingChainId)?;
                Ok(TempoAccessKey {
                    account: *account,
                    address: signer.address(),
                    chain_id,
                    signer: signer.clone(),
                    key_authorization: key_authorization.clone(),
                    authorization_reservations: self.authorization_reservations.clone(),
                })
            }
        }
    }

    fn select_for_request(
        &self,
        request: &TempoTransactionRequest,
    ) -> Result<TempoAccessKey, TempoAccountsError> {
        match &self.source {
            AccountsSource::Store { path, .. } => {
                let state = load_state(path)?;
                let account = request.from().unwrap_or(active_account(&state)?);
                let chain_id = request
                    .chain_id()
                    .or(self.chain_id)
                    .ok_or(TempoAccountsError::MissingChainId)?;
                let calls = request_calls(request);
                select_access_key(
                    &state,
                    account,
                    chain_id,
                    (request.key_id, request.key_type),
                    calls.as_deref(),
                    unix_now(),
                    &self.authorization_reservations,
                )
            }
            AccountsSource::Local {
                account,
                signer,
                key_authorization,
            } => {
                let chain_id = request
                    .chain_id()
                    .or(self.chain_id)
                    .or_else(|| signer.chain_id())
                    .ok_or(TempoAccountsError::MissingChainId)?;
                Ok(TempoAccessKey {
                    account: *account,
                    address: signer.address(),
                    chain_id,
                    signer: signer.clone(),
                    key_authorization: key_authorization.clone(),
                    authorization_reservations: self.authorization_reservations.clone(),
                })
            }
        }
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
        match &self.source {
            AccountsSource::Store { path, .. } => {
                let state = load_state(path)?;
                select_access_key(
                    &state,
                    account,
                    chain_id,
                    (Some(access_key), None),
                    None,
                    unix_now(),
                    &self.authorization_reservations,
                )
            }
            AccountsSource::Local {
                account: local_account,
                signer,
                key_authorization,
            } if *local_account == account && signer.address() == access_key => {
                Ok(TempoAccessKey {
                    account,
                    address: access_key,
                    chain_id,
                    signer: signer.clone(),
                    key_authorization: key_authorization.clone(),
                    authorization_reservations: self.authorization_reservations.clone(),
                })
            }
            AccountsSource::Local { .. } => {
                Err(TempoAccountsError::MissingAccessKey { account, chain_id })
            }
        }
    }

    /// Select and pin an access key, fill its request metadata, and resolve a
    /// pending authorization.
    ///
    /// Call this before external gas estimation or fee-payer signing when the
    /// request is prepared outside an Alloy provider filler stack. Retain both
    /// the returned wallet and prepared request through gas estimation and final
    /// signing.
    pub async fn prepare_request<P>(
        &self,
        provider: &P,
        request: &mut TempoTransactionRequest,
    ) -> TransportResult<Self>
    where
        P: Provider<TempoNetwork>,
    {
        if request.chain_id().is_none() {
            let chain_id = match self.chain_id {
                Some(chain_id) => chain_id,
                None => provider.get_chain_id().await?,
            };
            request.set_chain_id(chain_id);
        }
        let (selected, key_authorization) = self.prepare_selected(provider, request).await?;
        request.key_authorization = key_authorization;
        selected
            .fill_request(request)
            .map_err(alloy_json_rpc::RpcError::local_usage)?;
        Ok(Self::from_access_key(selected))
    }

    fn fill_metadata(
        &self,
        request: &mut TempoTransactionRequest,
    ) -> Result<TempoAccessKey, TempoAccountsError> {
        if request.chain_id().is_none() {
            request.set_chain_id(self.chain_id.ok_or(TempoAccountsError::MissingChainId)?);
        }
        let selected = self.select_for_request(request)?;
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
        match &self.source {
            AccountsSource::Store { path, .. } => {
                let state = load_state(path)?;
                let calls = transaction_calls(tx);
                select_access_key(
                    &state,
                    account,
                    tx.chain_id,
                    (None, None),
                    calls.as_deref(),
                    unix_now(),
                    &self.authorization_reservations,
                )
            }
            AccountsSource::Local {
                account: local_account,
                signer,
                key_authorization,
            } if *local_account == account => Ok(TempoAccessKey {
                account,
                address: signer.address(),
                chain_id: tx.chain_id,
                signer: signer.clone(),
                key_authorization: key_authorization.clone(),
                authorization_reservations: self.authorization_reservations.clone(),
            }),
            AccountsSource::Local { .. } => Err(TempoAccountsError::MissingAccessKey {
                account,
                chain_id: tx.chain_id,
            }),
        }
    }

    async fn prepare_selected<P>(
        &self,
        provider: &P,
        request: &TempoTransactionRequest,
    ) -> TransportResult<(TempoAccessKey, Option<SignedKeyAuthorization>)>
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
        let key_authorization = resolve_key_authorization(provider, &resolved_request)
            .await?
            .unwrap_or(resolved_request.key_authorization);
        if selected.key_authorization.is_some() {
            selected.key_authorization = key_authorization.clone().map(Box::new);
        }
        Ok((selected, key_authorization))
    }

    fn ensure_direct_signing_ready(
        &self,
        selected: &TempoAccessKey,
    ) -> Result<(), TempoAccountsError> {
        if matches!(&self.source, AccountsSource::Store { .. })
            && selected.key_authorization.is_some()
        {
            return Err(TempoAccountsError::AuthorizationResolutionRequired);
        }
        Ok(())
    }
}

impl NetworkWallet<TempoNetwork> for TempoAccountsWallet {
    fn default_signer_address(&self) -> Address {
        self.active_account().unwrap_or_else(|_| self.account())
    }

    fn has_signer_for(&self, address: &Address) -> bool {
        self.has_account(*address).unwrap_or(false)
    }

    fn signer_addresses(&self) -> impl Iterator<Item = Address> {
        let addresses = match &self.source {
            AccountsSource::Store { path, .. } => load_state(path).map(|state| {
                state
                    .accounts
                    .into_iter()
                    .map(|account| account.address)
                    .collect::<Vec<_>>()
            }),
            AccountsSource::Local { account, .. } => Ok(vec![*account]),
        }
        .unwrap_or_else(|_| vec![self.account()]);
        addresses.into_iter()
    }

    async fn sign_transaction_from(
        &self,
        sender: Address,
        tx: TempoTypedTransaction,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        let selected = self
            .select_unsigned(sender, &tx)
            .map_err(alloy_signer::Error::other)?;
        self.ensure_direct_signing_ready(&selected)
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
        self.ensure_direct_signing_ready(&selected)
            .map_err(alloy_signer::Error::other)?;
        selected.sign_request(request).await
    }
}

impl TxFiller<TempoNetwork> for TempoAccountsWallet {
    type Fillable = (TempoAccessKey, Option<SignedKeyAuthorization>);

    fn status(&self, request: &TempoTransactionRequest) -> FillerControlFlow {
        if request.chain_id().is_none() && self.chain_id.is_none() {
            return FillerControlFlow::missing("TempoAccountsWallet", vec!["chain_id"]);
        }
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
        (selected, key_authorization): Self::Fillable,
        tx: SendableTx<TempoNetwork>,
    ) -> TransportResult<SendableTx<TempoNetwork>> {
        let mut request = match tx {
            SendableTx::Builder(request) => request,
            _ => return Ok(tx),
        };
        request.key_authorization = key_authorization;
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
        if request.from().is_none() {
            request.set_from(
                self.active_account()
                    .map_err(alloy_json_rpc::RpcError::local_usage)?,
            );
        }
        Ok(())
    }

    async fn prepare_call(&self, request: &mut TempoTransactionRequest) -> TransportResult<()> {
        self.prepare_call_sync(request)
    }
}

/// Return the store path shared by Tempo command-line applications.
pub fn default_accounts_store_path() -> Result<PathBuf, TempoAccountsError> {
    if let Some(directory) = env::var_os("TEMPO_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(directory).join("wallet/store.json"));
    }
    dirs_next::home_dir()
        .map(|directory| directory.join(".tempo/wallet/store.json"))
        .ok_or(TempoAccountsError::HomeUnavailable)
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
    handle: Option<Box<RawValue>>,
    #[serde(default)]
    private_key: Option<PersistedPrivateKey>,
    #[serde(default)]
    public_key: Option<Bytes>,
    #[serde(default)]
    limits: Vec<PersistedTokenLimit>,
    #[serde(default)]
    scopes: Option<Vec<PersistedScope>>,
    #[serde(default)]
    key_authorization: Option<PersistedKeyAuthorization>,
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

#[derive(Deserialize)]
struct PersistedKeyHandleKind {
    kind: PersistedHandleKind,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedPrivateKeyHandle {
    #[serde(default)]
    private_key: Option<PersistedPrivateKey>,
}

#[derive(Deserialize)]
struct PersistedWebCryptoHandle {
    #[serde(default)]
    jwk: Option<P256Jwk>,
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

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum PersistedKeyAuthorization {
    Structured(Box<PersistedSignedKeyAuthorization>),
    Rlp(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountsRpcKeyAuthorization {
    address: Address,
    chain_id: AccountsU64,
    #[serde(default)]
    expiry: Option<AccountsU64>,
    key_id: Address,
    key_type: PersistedKeyType,
    #[serde(default)]
    limits: Option<Vec<PersistedTokenLimit>>,
    signature: AccountsRpcSignature,
}

impl TryFrom<AccountsRpcKeyAuthorization> for SignedKeyAuthorization {
    type Error = PersistedKeyError;

    fn try_from(value: AccountsRpcKeyAuthorization) -> Result<Self, Self::Error> {
        if value.address != value.key_id {
            return Err(PersistedKeyError::AuthorizationAddressMismatch);
        }
        let authorization = KeyAuthorization {
            chain_id: value.chain_id.0,
            key_type: value.key_type.signature_type()?,
            key_id: value.key_id,
            expiry: value
                .expiry
                .map(|expiry| {
                    NonZeroU64::new(expiry.0).ok_or(PersistedKeyError::ZeroAuthorizationExpiry)
                })
                .transpose()?,
            limits: value
                .limits
                .map(|limits| limits.into_iter().map(Into::into).collect()),
            allowed_calls: None,
            witness: None,
            is_admin: false,
            account: None,
        };
        Ok(Self::new(authorization, value.signature.try_into()?))
    }
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum AccountsRpcSignature {
    #[serde(rename = "secp256k1")]
    Secp256k1 {
        r: AccountsU256,
        s: AccountsU256,
        #[serde(rename = "yParity")]
        y_parity: AccountsU256,
    },
    #[serde(rename = "p256")]
    P256 {
        #[serde(rename = "preHash")]
        pre_hash: bool,
        #[serde(rename = "pubKeyX")]
        pub_key_x: B256,
        #[serde(rename = "pubKeyY")]
        pub_key_y: B256,
        r: B256,
        s: B256,
    },
    #[serde(rename = "webAuthn")]
    WebAuthn {
        #[serde(rename = "pubKeyX")]
        pub_key_x: B256,
        #[serde(rename = "pubKeyY")]
        pub_key_y: B256,
        r: B256,
        s: B256,
        #[serde(rename = "webauthnData")]
        webauthn_data: Bytes,
    },
}

impl TryFrom<AccountsRpcSignature> for PrimitiveSignature {
    type Error = PersistedKeyError;

    fn try_from(value: AccountsRpcSignature) -> Result<Self, Self::Error> {
        Ok(match value {
            AccountsRpcSignature::Secp256k1 { r, s, y_parity } => {
                let parity = match y_parity.0 {
                    U256::ZERO => false,
                    U256::ONE => true,
                    _ => return Err(PersistedKeyError::InvalidYParity),
                };
                Self::Secp256k1(Signature::new(r.0, s.0, parity))
            }
            AccountsRpcSignature::P256 {
                pre_hash,
                pub_key_x,
                pub_key_y,
                r,
                s,
            } => Self::P256(P256SignatureWithPreHash {
                r,
                s,
                pub_key_x,
                pub_key_y,
                pre_hash,
            }),
            AccountsRpcSignature::WebAuthn {
                pub_key_x,
                pub_key_y,
                r,
                s,
                webauthn_data,
            } => Self::WebAuthn(WebAuthnSignature {
                r,
                s,
                pub_key_x,
                pub_key_y,
                webauthn_data,
            }),
        })
    }
}

impl TryFrom<PersistedKeyAuthorization> for SignedKeyAuthorization {
    type Error = PersistedKeyError;

    fn try_from(value: PersistedKeyAuthorization) -> Result<Self, Self::Error> {
        match value {
            PersistedKeyAuthorization::Structured(value) => (*value).try_into(),
            PersistedKeyAuthorization::Rlp(value) => {
                let bytes = alloy_primitives::hex::decode(value)
                    .map_err(|_| PersistedKeyError::InvalidAuthorizationRlp)?;
                let mut encoded = bytes.as_slice();
                let authorization = <Self as alloy_rlp::Decodable>::decode(&mut encoded)
                    .map_err(|_| PersistedKeyError::InvalidAuthorizationRlp)?;
                if !encoded.is_empty() {
                    return Err(PersistedKeyError::InvalidAuthorizationRlp);
                }
                Ok(authorization)
            }
        }
    }
}

impl TryFrom<PersistedSignedKeyAuthorization> for SignedKeyAuthorization {
    type Error = PersistedKeyError;

    fn try_from(value: PersistedSignedKeyAuthorization) -> Result<Self, Self::Error> {
        let PersistedSignedKeyAuthorization {
            address,
            chain_id,
            expiry,
            limits,
            scopes,
            witness,
            is_admin,
            account,
            key_type,
            signature,
        } = value;
        let expiry = expiry
            .map(|expiry| {
                NonZeroU64::new(expiry.0).ok_or(PersistedKeyError::ZeroAuthorizationExpiry)
            })
            .transpose()?;
        let has_scopes = scopes.is_some();
        let has_tip1053_fields = witness.is_some() || is_admin || account.is_some();
        let limits = match limits {
            Some(limits) => Some(limits.into_iter().map(Into::into).collect()),
            // Ox 0.14 uses an empty RLP list as the positional limits
            // placeholder when scopes follow it. Preserve that exact signed
            // wire shape. Newer TIP-1053 fields switched skipped fields to the
            // canonical optional null placeholder.
            None if has_scopes && !has_tip1053_fields => Some(Vec::new()),
            None => None,
        };
        let allowed_calls = scopes.map(persisted_scopes_to_call_scopes).transpose()?;
        let authorization = KeyAuthorization {
            chain_id: chain_id.0,
            key_type: key_type.signature_type()?,
            key_id: address,
            expiry,
            limits,
            allowed_calls,
            witness,
            is_admin,
            account,
        };
        Ok(Self::new(authorization, signature.try_into()?))
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
    #[error("invalid built-in access-key handle")]
    InvalidHandle,
    #[error("WebCrypto P-256 handle is missing its JWK")]
    MissingJwk,
    #[error("WebCrypto P-256 handle is missing its public key")]
    MissingPublicKey,
    #[error("invalid P-256 key: {0}")]
    P256(#[from] P256SignerError),
    #[error("unsupported key-authorization signature type")]
    UnsupportedAuthorizationSignature,
    #[error("invalid RLP key authorization")]
    InvalidAuthorizationRlp,
    #[error("key authorization address and key ID do not match")]
    AuthorizationAddressMismatch,
    #[error("key-authorization expiry must be non-zero")]
    ZeroAuthorizationExpiry,
    #[error("scope recipients require an explicit selector")]
    RecipientsWithoutSelector,
    #[error("call-scope metadata disagrees with the signed authorization")]
    AuthorizationScopesMismatch,
    #[error("call-scope targets and selectors must be unique and nonzero")]
    InvalidCallScope,
    #[error("recipient constraints require a TIP-20 transfer or approve selector")]
    InvalidRecipientConstraint,
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

fn stored_access_key(key: &PersistedAccessKey) -> Result<TempoStoredAccessKey, TempoAccountsError> {
    let key_type =
        key.key_type
            .signature_type()
            .map_err(|error| TempoAccountsError::InvalidAccessKey {
                address: key.address,
                reason: error.to_string(),
            })?;
    let key_authorization: Option<SignedKeyAuthorization> = key
        .key_authorization
        .clone()
        .map(TryInto::try_into)
        .transpose()
        .map_err(
            |error: PersistedKeyError| TempoAccountsError::InvalidAccessKey {
                address: key.address,
                reason: error.to_string(),
            },
        )?;
    if key_authorization.as_ref().is_some_and(|authorization| {
        authorization.key_id != key.address
            || authorization.chain_id != key.chain_id
            || authorization.key_type != key_type
            || authorization
                .account
                .is_some_and(|account| account != key.access)
    }) {
        return Err(TempoAccountsError::InvalidAccessKey {
            address: key.address,
            reason: "authorization metadata does not match the stored key".into(),
        });
    }

    let allowed_calls =
        effective_allowed_calls(key, key_authorization.as_ref()).map_err(|error| {
            TempoAccountsError::InvalidAccessKey {
                address: key.address,
                reason: error.to_string(),
            }
        })?;
    let limits = if key.limits.is_empty() {
        key_authorization
            .as_ref()
            .and_then(|authorization| authorization.limits.clone())
            .unwrap_or_default()
    } else {
        key.limits.clone().into_iter().map(Into::into).collect()
    };
    let authorization_expiry = key_authorization
        .as_ref()
        .and_then(|authorization| authorization.expiry)
        .map(NonZeroU64::get);
    let expiry = match (key.expiry, authorization_expiry) {
        (Some(stored), Some(signed)) => Some(stored.min(signed)),
        (stored, signed) => stored.or(signed),
    };

    Ok(TempoStoredAccessKey {
        account: key.access,
        address: key.address,
        chain_id: key.chain_id,
        key_type,
        expiry,
        limits,
        allowed_calls,
        key_authorization,
        locally_signable: hydrate_access_key(key)
            .is_ok_and(|signer| signer.address() == key.address),
    })
}

fn validate_stored_authorization(
    account: Address,
    signer: &PrivateKeySigner,
    authorization: &SignedKeyAuthorization,
) -> Result<(), TempoAccountsError> {
    if authorization.key_type != SignatureType::Secp256k1 {
        return Err(TempoAccountsError::InvalidAuthorization(
            "the authorization key type is not secp256k1",
        ));
    }
    if authorization.key_id != signer.address() {
        return Err(TempoAccountsError::InvalidAuthorization(
            "the authorization key ID does not match the local signer",
        ));
    }
    if authorization
        .account
        .is_some_and(|authorized| authorized != account)
    {
        return Err(TempoAccountsError::InvalidAuthorization(
            "the authorization targets a different account",
        ));
    }
    Ok(())
}

struct EditableTempoCliStore {
    root: BTreeMap<String, Box<RawValue>>,
    envelope: BTreeMap<String, Box<RawValue>>,
    state: BTreeMap<String, Box<RawValue>>,
    active_account: Box<RawValue>,
    chain_id: u64,
    accounts: Vec<Box<RawValue>>,
    access_keys: Vec<Box<RawValue>>,
}

#[derive(Deserialize)]
struct EditableAccountIdentity {
    address: Address,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EditableAccessKeyIdentity {
    address: Address,
    access: Address,
    chain_id: u64,
}

#[derive(Serialize)]
struct WritableAccount {
    address: Address,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WritableAccessKey {
    address: Address,
    access: Address,
    chain_id: u64,
    key_type: &'static str,
    private_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limits: Option<Vec<WritableTokenLimit>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<WritableScope>>,
    key_authorization: WritableSignedKeyAuthorization,
}

#[derive(Clone, Serialize)]
struct WritableTokenLimit {
    token: Address,
    limit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    period: Option<u64>,
}

#[derive(Serialize)]
struct WritableScope {
    address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    recipients: Vec<Address>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WritableSignedKeyAuthorization {
    address: Address,
    chain_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limits: Option<Vec<WritableTokenLimit>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<WritableScope>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness: Option<B256>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<Address>,
    #[serde(rename = "type")]
    key_type: &'static str,
    signature: WritablePrimitiveSignature,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum WritablePrimitiveSignature {
    #[serde(rename = "secp256k1")]
    Secp256k1 { signature: WritableSecpSignature },
    #[serde(rename = "p256")]
    P256 {
        signature: WritableRs,
        #[serde(rename = "publicKey")]
        public_key: WritablePublicKey,
        prehash: bool,
    },
    #[serde(rename = "webAuthn")]
    WebAuthn {
        signature: WritableRs,
        #[serde(rename = "publicKey")]
        public_key: WritablePublicKey,
        metadata: WritableWebAuthnMetadata,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WritableSecpSignature {
    r: String,
    s: String,
    y_parity: u8,
}

#[derive(Serialize)]
struct WritableRs {
    r: String,
    s: String,
}

#[derive(Serialize)]
struct WritablePublicKey {
    prefix: u8,
    x: String,
    y: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WritableWebAuthnMetadata {
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
}

fn writable_bigint(value: U256) -> String {
    format!("{value}#__bigint")
}

fn writable_b256(value: B256) -> String {
    writable_bigint(U256::from_be_bytes(value.0))
}

fn writable_signature(
    signature: &PrimitiveSignature,
) -> Result<WritablePrimitiveSignature, TempoAccountsError> {
    Ok(match signature {
        PrimitiveSignature::Secp256k1(signature) => WritablePrimitiveSignature::Secp256k1 {
            signature: WritableSecpSignature {
                r: writable_bigint(signature.r()),
                s: writable_bigint(signature.s()),
                y_parity: u8::from(signature.v()),
            },
        },
        PrimitiveSignature::P256(signature) => WritablePrimitiveSignature::P256 {
            signature: WritableRs {
                r: writable_b256(signature.r),
                s: writable_b256(signature.s),
            },
            public_key: WritablePublicKey {
                prefix: 4,
                x: writable_b256(signature.pub_key_x),
                y: writable_b256(signature.pub_key_y),
            },
            prehash: signature.pre_hash,
        },
        PrimitiveSignature::WebAuthn(signature) => {
            if signature
                .webauthn_data
                .get(32)
                .is_some_and(|flags| flags & 0xc0 != 0)
            {
                return Err(TempoAccountsError::InvalidAuthorization(
                    "WebAuthn authorization uses unsupported attested or extension data",
                ));
            }
            let (authenticator_data, client_data_json) = signature
                .webauthn_data
                .split_at_checked(37)
                .ok_or(TempoAccountsError::InvalidAuthorization(
                    "WebAuthn authorization data is too short",
                ))?;
            let client_data_json = std::str::from_utf8(client_data_json).map_err(|_| {
                TempoAccountsError::InvalidAuthorization(
                    "WebAuthn authorization client data is not UTF-8",
                )
            })?;
            WritablePrimitiveSignature::WebAuthn {
                signature: WritableRs {
                    r: writable_b256(signature.r),
                    s: writable_b256(signature.s),
                },
                public_key: WritablePublicKey {
                    prefix: 4,
                    x: writable_b256(signature.pub_key_x),
                    y: writable_b256(signature.pub_key_y),
                },
                metadata: WritableWebAuthnMetadata {
                    authenticator_data: alloy_primitives::hex::encode_prefixed(authenticator_data),
                    client_data_json: client_data_json.to_owned(),
                },
            }
        }
    })
}

fn writable_scopes(authorization: &SignedKeyAuthorization) -> Option<Vec<WritableScope>> {
    authorization.allowed_calls.as_ref().map(|scopes| {
        scopes
            .iter()
            .flat_map(|scope| {
                if scope.selector_rules.is_empty() {
                    return vec![WritableScope {
                        address: scope.target,
                        selector: None,
                        recipients: Vec::new(),
                    }];
                }
                scope
                    .selector_rules
                    .iter()
                    .map(|rule| WritableScope {
                        address: scope.target,
                        selector: Some(alloy_primitives::hex::encode_prefixed(rule.selector)),
                        recipients: rule.recipients.clone(),
                    })
                    .collect()
            })
            .collect()
    })
}

fn writable_access_key(
    account: Address,
    signer: &PrivateKeySigner,
    authorization: &SignedKeyAuthorization,
) -> Result<WritableAccessKey, TempoAccountsError> {
    let limits = authorization.limits.as_ref().map(|limits| {
        limits
            .iter()
            .map(|limit| WritableTokenLimit {
                token: limit.token,
                limit: writable_bigint(limit.limit),
                period: (limit.period != 0).then_some(limit.period),
            })
            .collect()
    });
    Ok(WritableAccessKey {
        address: signer.address(),
        access: account,
        chain_id: authorization.chain_id,
        key_type: "secp256k1",
        private_key: alloy_primitives::hex::encode_prefixed(signer.to_bytes()),
        expiry: authorization.expiry.map(NonZeroU64::get),
        limits: limits.clone(),
        scopes: writable_scopes(authorization),
        key_authorization: WritableSignedKeyAuthorization {
            address: authorization.key_id,
            chain_id: writable_bigint(U256::from(authorization.chain_id)),
            expiry: authorization.expiry.map(NonZeroU64::get),
            limits,
            scopes: writable_scopes(authorization),
            witness: authorization.witness,
            is_admin: authorization.is_admin,
            account: authorization.account,
            key_type: "secp256k1",
            signature: writable_signature(&authorization.signature)?,
        },
    })
}

fn new_editable_store(
    account: Address,
    chain_id: u64,
) -> Result<EditableTempoCliStore, serde_json::Error> {
    let mut envelope = BTreeMap::new();
    envelope.insert("version".into(), RawValue::from_string("0".into())?);
    Ok(EditableTempoCliStore {
        root: BTreeMap::new(),
        envelope,
        state: BTreeMap::new(),
        active_account: RawValue::from_string("0".into())?,
        chain_id,
        accounts: vec![serde_json::value::to_raw_value(&WritableAccount {
            address: account,
        })?],
        access_keys: Vec::new(),
    })
}

fn take_raw(
    object: &mut BTreeMap<String, Box<RawValue>>,
    field: &'static str,
) -> Result<Box<RawValue>, serde_json::Error> {
    object
        .remove(field)
        .ok_or_else(|| <serde_json::Error as de::Error>::missing_field(field))
}

fn take_field<T: for<'de> Deserialize<'de>>(
    object: &mut BTreeMap<String, Box<RawValue>>,
    field: &'static str,
) -> Result<T, serde_json::Error> {
    serde_json::from_str(take_raw(object, field)?.get())
}

fn decode_editable_store(bytes: &[u8]) -> Result<EditableTempoCliStore, serde_json::Error> {
    let mut root: BTreeMap<String, Box<RawValue>> = serde_json::from_slice(bytes)?;
    let mut envelope: BTreeMap<String, Box<RawValue>> =
        serde_json::from_str(take_raw(&mut root, "tempo-cli.store")?.get())?;
    let mut state: BTreeMap<String, Box<RawValue>> =
        serde_json::from_str(take_raw(&mut envelope, "state")?.get())?;
    let active_account = take_raw(&mut state, "activeAccount")?;
    let chain_id = take_field(&mut state, "chainId")?;
    let accounts = take_field(&mut state, "accounts")?;
    let access_keys = state
        .remove("accessKeys")
        .map(|raw| serde_json::from_str(raw.get()))
        .transpose()?
        .unwrap_or_default();
    Ok(EditableTempoCliStore {
        root,
        envelope,
        state,
        active_account,
        chain_id,
        accounts,
        access_keys,
    })
}

fn encode_editable_store(mut store: EditableTempoCliStore) -> Result<Vec<u8>, serde_json::Error> {
    store
        .state
        .insert("activeAccount".into(), store.active_account);
    store.state.insert(
        "chainId".into(),
        serde_json::value::to_raw_value(&store.chain_id)?,
    );
    store.state.insert(
        "accounts".into(),
        serde_json::value::to_raw_value(&store.accounts)?,
    );
    store.state.insert(
        "accessKeys".into(),
        serde_json::value::to_raw_value(&store.access_keys)?,
    );
    store.envelope.insert(
        "state".into(),
        serde_json::value::to_raw_value(&store.state)?,
    );
    store.root.insert(
        "tempo-cli.store".into(),
        serde_json::value::to_raw_value(&store.envelope)?,
    );
    serde_json::to_vec_pretty(&store.root)
}

fn upsert_secp256k1_access_key(
    path: &Path,
    account: Address,
    signer: &PrivateKeySigner,
    authorization: &SignedKeyAuthorization,
) -> Result<(), TempoAccountsError> {
    let _lock = lock_store(path)?;
    let mut file = match fs::read(path) {
        Ok(bytes) => {
            decode_editable_store(&bytes).map_err(|source| TempoAccountsError::Decode {
                path: path.to_owned(),
                source,
            })?
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            new_editable_store(account, authorization.chain_id).map_err(|source| {
                TempoAccountsError::Encode {
                    path: path.to_owned(),
                    source,
                }
            })?
        }
        Err(source) => {
            return Err(TempoAccountsError::Read {
                path: path.to_owned(),
                source,
            });
        }
    };

    let account_exists = file.accounts.iter().any(|raw| {
        serde_json::from_str::<EditableAccountIdentity>(raw.get())
            .is_ok_and(|stored| stored.address == account)
    });
    if !account_exists {
        file.accounts.push(
            serde_json::value::to_raw_value(&WritableAccount { address: account }).map_err(
                |source| TempoAccountsError::Encode {
                    path: path.to_owned(),
                    source,
                },
            )?,
        );
    }
    file.access_keys.retain(|raw| {
        serde_json::from_str::<EditableAccessKeyIdentity>(raw.get()).map_or(true, |stored| {
            stored.access != account
                || stored.chain_id != authorization.chain_id
                || stored.address != signer.address()
        })
    });
    file.access_keys.insert(
        0,
        serde_json::value::to_raw_value(&writable_access_key(account, signer, authorization)?)
            .map_err(|source| TempoAccountsError::Encode {
                path: path.to_owned(),
                source,
            })?,
    );

    write_store_atomic(path, file)
}

fn retire_access_key(
    path: &Path,
    account: Address,
    chain_id: u64,
    access_key: Address,
) -> Result<bool, TempoAccountsError> {
    let _lock = lock_store(path)?;
    let bytes = fs::read(path).map_err(|source| TempoAccountsError::Read {
        path: path.to_owned(),
        source,
    })?;
    let mut file = decode_editable_store(&bytes).map_err(|source| TempoAccountsError::Decode {
        path: path.to_owned(),
        source,
    })?;
    let mut changed = false;

    for raw in &mut file.access_keys {
        let Ok(identity) = serde_json::from_str::<EditableAccessKeyIdentity>(raw.get()) else {
            continue;
        };
        if identity.access != account
            || identity.chain_id != chain_id
            || identity.address != access_key
        {
            continue;
        }

        let mut entry: BTreeMap<String, Box<RawValue>> =
            serde_json::from_str(raw.get()).map_err(|source| TempoAccountsError::Decode {
                path: path.to_owned(),
                source,
            })?;
        let entry_changed = entry.remove("privateKey").is_some()
            | entry.remove("handle").is_some()
            | entry.remove("keyPair").is_some();
        if entry_changed {
            *raw = serde_json::value::to_raw_value(&entry).map_err(|source| {
                TempoAccountsError::Encode {
                    path: path.to_owned(),
                    source,
                }
            })?;
        }
        changed |= entry_changed;
    }

    if changed {
        write_store_atomic(path, file)?;
    }
    Ok(changed)
}

fn lock_store(path: &Path) -> Result<fs::File, TempoAccountsError> {
    let result = (|| {
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("Tempo Accounts store has no parent directory"))?;
        fs::create_dir_all(parent)?;
        set_private_directory_permissions(parent)?;

        let lock_path = {
            let mut name = path
                .file_name()
                .ok_or_else(|| std::io::Error::other("Tempo Accounts store has no file name"))?
                .to_os_string();
            name.push(".lock");
            parent.join(name)
        };

        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&lock_path)?;
        set_private_file_permissions(&lock_path)?;
        lock.lock()?;
        Ok(lock)
    })();
    result.map_err(|source| TempoAccountsError::Lock {
        path: path.to_owned(),
        source,
    })
}

fn write_store_atomic(path: &Path, store: EditableTempoCliStore) -> Result<(), TempoAccountsError> {
    let bytes = encode_editable_store(store).map_err(|source| TempoAccountsError::Encode {
        path: path.to_owned(),
        source,
    })?;
    let parent = path.parent().ok_or_else(|| TempoAccountsError::Write {
        path: path.to_owned(),
        source: std::io::Error::other("Tempo Accounts store has no parent directory"),
    })?;
    fs::create_dir_all(parent).map_err(|source| TempoAccountsError::Write {
        path: path.to_owned(),
        source,
    })?;
    set_private_directory_permissions(parent).map_err(|source| TempoAccountsError::Write {
        path: path.to_owned(),
        source,
    })?;

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = parent.join(format!(".store.json.{}.{}.tmp", std::process::id(), suffix));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&temp_path)?;
        output.write_all(&bytes)?;
        output.write_all(b"\n")?;
        output.sync_all()?;
        fs::rename(&temp_path, path)?;
        set_private_file_permissions(path)?;
        Ok::<_, std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result.map_err(|source| TempoAccountsError::Write {
        path: path.to_owned(),
        source,
    })
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn load_state(path: &Path) -> Result<PersistedAccountsState, TempoAccountsError> {
    let bytes = fs::read(path).map_err(|source| TempoAccountsError::Read {
        path: path.to_owned(),
        source,
    })?;
    if let Ok(root) = serde_json::from_slice::<TempoCliStore>(&bytes) {
        return Ok(root.store.state);
    }
    if let Ok(envelope) = serde_json::from_slice::<PersistedStoreEnvelope>(&bytes) {
        return Ok(envelope.state);
    }
    serde_json::from_slice(&bytes).map_err(|source| TempoAccountsError::Decode {
        path: path.to_owned(),
        source,
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
    requested_key: (Option<Address>, Option<SignatureType>),
    calls: Option<&[IntentCall<'_>]>,
    now: u64,
    authorization_reservations: &AuthorizationReservations,
) -> Result<TempoAccessKey, TempoAccountsError> {
    let (preferred, signature_type) = requested_key;
    for key in state
        .access_keys
        .iter()
        .filter(|key| key.chain_id == chain_id && key.access == account)
        .filter(|key| preferred.is_none_or(|preferred| key.address == preferred))
        .filter(|key| key.expiry.is_none_or(|expiry| expiry > now))
    {
        let Ok(mut signer) = hydrate_access_key(key) else {
            continue;
        };
        if signer.address() != key.address
            || signature_type.is_some_and(|expected| signer.signature_type() != expected)
        {
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
                    .expiry
                    .is_some_and(|expiry| expiry.get() <= now)
                || authorization
                    .account
                    .is_some_and(|authorized_account| authorized_account != account)
        }) {
            continue;
        }
        if key_authorization.as_ref().is_some_and(|authorization| {
            authorization.account.is_none() && authorization.recover_signer().ok() != Some(account)
        }) {
            continue;
        }
        let Ok(allowed_calls) = effective_allowed_calls(key, key_authorization.as_ref()) else {
            continue;
        };
        let should_match_scopes = preferred.is_none() || calls.is_some();
        if should_match_scopes && !scopes_match(allowed_calls.as_deref(), calls) {
            continue;
        }

        return Ok(TempoAccessKey {
            account,
            address: key.address,
            chain_id,
            signer,
            key_authorization: key_authorization.map(Box::new),
            authorization_reservations: authorization_reservations.clone(),
        });
    }

    Err(TempoAccountsError::MissingAccessKey { account, chain_id })
}

fn effective_allowed_calls(
    key: &PersistedAccessKey,
    authorization: Option<&SignedKeyAuthorization>,
) -> Result<Option<Vec<CallScope>>, PersistedKeyError> {
    let persisted = key
        .scopes
        .clone()
        .map(persisted_scopes_to_call_scopes)
        .transpose()?;
    let Some(authorization) = authorization else {
        return Ok(persisted);
    };

    match (persisted, authorization.allowed_calls.as_ref()) {
        (Some(persisted), Some(signed)) if &persisted != signed => {
            Err(PersistedKeyError::AuthorizationScopesMismatch)
        }
        (Some(_), None) => Err(PersistedKeyError::AuthorizationScopesMismatch),
        (Some(persisted), Some(_)) => Ok(Some(persisted)),
        (None, signed) => Ok(signed.cloned()),
    }
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

fn scopes_match(scopes: Option<&[CallScope]>, calls: Option<&[IntentCall<'_>]>) -> bool {
    if scopes.is_none() {
        return true;
    }
    let Some(calls) = calls else {
        return false;
    };

    calls.iter().all(|call| {
        call.to
            .is_some_and(|target| call_scopes_allow(scopes, &target, call.input))
    })
}

fn persisted_scopes_to_call_scopes(
    scopes: Vec<PersistedScope>,
) -> Result<Vec<CallScope>, PersistedKeyError> {
    let mut grouped: Vec<CallScope> = Vec::new();

    for scope in scopes {
        if scope.address.is_zero() {
            return Err(PersistedKeyError::InvalidCallScope);
        }
        if scope.selector.is_none()
            && scope
                .recipients
                .as_ref()
                .is_some_and(|recipients| !recipients.is_empty())
        {
            return Err(PersistedKeyError::RecipientsWithoutSelector);
        }

        let index = match grouped
            .iter()
            .position(|candidate| candidate.target == scope.address)
        {
            Some(index) => index,
            None => {
                grouped.push(CallScope {
                    target: scope.address,
                    selector_rules: Vec::new(),
                });
                grouped.len() - 1
            }
        };
        let entry = &mut grouped[index];
        let Some(selector) = scope.selector else {
            continue;
        };
        if entry
            .selector_rules
            .iter()
            .any(|rule| rule.selector == selector.0)
        {
            return Err(PersistedKeyError::InvalidCallScope);
        }
        let recipients = scope.recipients.unwrap_or_default();
        if !recipients.is_empty() {
            let valid_selector = matches!(
                selector.0,
                ITIP20::transferCall::SELECTOR
                    | ITIP20::approveCall::SELECTOR
                    | ITIP20::transferWithMemoCall::SELECTOR
            );
            let mut unique = BTreeSet::new();
            if !scope.address.is_tip20()
                || !valid_selector
                || recipients
                    .iter()
                    .any(|recipient| recipient.is_zero() || !unique.insert(*recipient))
            {
                return Err(PersistedKeyError::InvalidRecipientConstraint);
            }
        }
        entry.selector_rules.push(SelectorRule {
            selector: selector.0,
            recipients,
        });
    }

    Ok(grouped)
}

fn hydrate_access_key(key: &PersistedAccessKey) -> Result<AccountsSigner, PersistedKeyError> {
    if let Some(private_key) = key.private_key {
        return hydrate_private_key(key.key_type, private_key);
    }

    let handle = key
        .handle
        .as_ref()
        .ok_or(PersistedKeyError::MissingCredential)?;
    let kind = serde_json::from_str::<PersistedKeyHandleKind>(handle.get())
        .map_err(|_| PersistedKeyError::InvalidHandle)?
        .kind;
    match kind {
        PersistedHandleKind::Secp256k1 => {
            let handle = serde_json::from_str::<PersistedPrivateKeyHandle>(handle.get())
                .map_err(|_| PersistedKeyError::InvalidHandle)?;
            let private_key = handle
                .private_key
                .ok_or(PersistedKeyError::MissingCredential)?;
            hydrate_private_key(PersistedKeyType::Secp256k1, private_key)
        }
        PersistedHandleKind::P256 => {
            let handle = serde_json::from_str::<PersistedPrivateKeyHandle>(handle.get())
                .map_err(|_| PersistedKeyError::InvalidHandle)?;
            let private_key = handle
                .private_key
                .ok_or(PersistedKeyError::MissingCredential)?;
            hydrate_private_key(PersistedKeyType::P256, private_key)
        }
        PersistedHandleKind::WebCryptoP256 => {
            let handle = serde_json::from_str::<PersistedWebCryptoHandle>(handle.get())
                .map_err(|_| PersistedKeyError::InvalidHandle)?;
            if key.public_key.is_none() {
                return Err(PersistedKeyError::MissingPublicKey);
            }
            TempoP256Signer::from_webcrypto_jwk(
                handle.jwk.as_ref().ok_or(PersistedKeyError::MissingJwk)?,
            )
            .map(AccountsSigner::P256)
            .map_err(Into::into)
        }
        PersistedHandleKind::Unsupported => Err(PersistedKeyError::UnsupportedKeyType),
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
    use std::{
        env,
        process::{Child, Command},
        sync::mpsc,
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use alloy_network::{NetworkWallet, TransactionBuilder};
    use alloy_provider::{ProviderBuilder, SendableTx, fillers::TxFiller, mock::Asserter};
    use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
    use tempo_primitives::{TempoTxEnvelope, transaction::TempoSignature};

    use super::*;

    const ROOT: &str = "0x1111111111111111111111111111111111111111";
    const TARGET: &str = "0x2222222222222222222222222222222222222222";
    const PROCESS_STORE_PATH_ENV: &str = "TEMPO_ACCOUNTS_PROCESS_TEST_STORE_PATH";
    const PROCESS_STARTED_PATH_ENV: &str = "TEMPO_ACCOUNTS_PROCESS_TEST_STARTED_PATH";
    const PROCESS_OPERATION_ENV: &str = "TEMPO_ACCOUNTS_PROCESS_TEST_OPERATION";
    const PROCESS_SIGNER_BYTE_ENV: &str = "TEMPO_ACCOUNTS_PROCESS_TEST_SIGNER_BYTE";

    struct StoreMutationProcess {
        child: Child,
        started_path: PathBuf,
    }

    impl Drop for StoreMutationProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn stale_observation_cannot_release_a_new_reservation_generation() {
        let identity = AuthorizationIdentity {
            chain_id: 4217,
            account: Address::random(),
            key_id: Address::random(),
        };
        let first = AuthorizationReservations::default();
        let resolver = AuthorizationReservations::default();
        let second = AuthorizationReservations::default();
        let contender = AuthorizationReservations::default();

        first.reserve(identity).unwrap();
        let stale = first.in_flight().unwrap()[0];
        resolver.resolve_on_chain(identity).unwrap();
        second.reserve(identity).unwrap();
        let current = second.in_flight().unwrap()[0];

        first.release_owned(stale).unwrap();
        assert!(matches!(
            contender.reserve(identity),
            Err(TempoAccessKeyError::AuthorizationInFlight { .. })
        ));

        second.release_owned(current).unwrap();
    }

    #[test]
    fn serializes_concurrent_store_upserts() {
        let directory = unique_test_directory();
        let path = directory.join("wallet/store.json");
        let held_lock = lock_store(&path).unwrap();
        let account = ROOT.parse::<Address>().unwrap();
        let signers = [PrivateKeySigner::random(), PrivateKeySigner::random()];
        let addresses = signers.each_ref().map(|signer| signer.address());
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let handles: Vec<_> = signers
            .into_iter()
            .map(|signer| {
                let path = path.clone();
                let started_tx = started_tx.clone();
                let done_tx = done_tx.clone();
                thread::spawn(move || {
                    let authorization = KeyAuthorization::unrestricted(
                        4217,
                        SignatureType::Secp256k1,
                        signer.address(),
                    )
                    .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));
                    started_tx.send(()).unwrap();
                    let result = TempoAccountsStore::at(path)
                        .upsert_secp256k1_access_key(account, &signer, &authorization)
                        .map_err(|error| error.to_string());
                    done_tx.send(result).unwrap();
                })
            })
            .collect();
        drop(started_tx);
        drop(done_tx);

        started_rx.recv().unwrap();
        started_rx.recv().unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(held_lock);

        done_rx.recv().unwrap().unwrap();
        done_rx.recv().unwrap().unwrap();
        for handle in handles {
            handle.join().unwrap();
        }

        let keys = TempoAccountsStore::open(&path)
            .unwrap()
            .access_keys()
            .unwrap();
        assert!(
            addresses
                .iter()
                .all(|address| keys.iter().any(|key| key.address() == *address))
        );
        assert!(directory.join("wallet/store.json.lock").is_file());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn serializes_retirements_across_processes() {
        let directory = unique_test_directory();
        let path = directory.join("wallet/store.json");
        let account = ROOT.parse::<Address>().unwrap();
        let store = TempoAccountsStore::at(path.clone());
        let signers = [test_process_signer(2), test_process_signer(3)];

        for signer in &signers {
            store
                .upsert_secp256k1_access_key(account, signer, &test_process_authorization(signer))
                .unwrap();
        }

        let held_lock = lock_store(&path).unwrap();
        let mut children = [
            spawn_store_mutation_process(&directory, &path, "retire-a", "retire", 2),
            spawn_store_mutation_process(&directory, &path, "retire-b", "retire", 3),
        ];
        wait_for_store_mutation_processes_to_block(&mut children);
        drop(held_lock);
        wait_for_store_mutation_processes_to_succeed(&mut children);

        let keys = store.access_keys().unwrap();
        for signer in &signers {
            let key = keys
                .iter()
                .find(|key| key.address() == signer.address())
                .unwrap();
            assert!(!key.is_locally_signable());
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn serializes_retirement_and_upsert_across_processes() {
        let directory = unique_test_directory();
        let path = directory.join("wallet/store.json");
        let account = ROOT.parse::<Address>().unwrap();
        let store = TempoAccountsStore::at(path.clone());
        let retired_signer = test_process_signer(4);
        let inserted_signer = test_process_signer(5);
        store
            .upsert_secp256k1_access_key(
                account,
                &retired_signer,
                &test_process_authorization(&retired_signer),
            )
            .unwrap();

        let held_lock = lock_store(&path).unwrap();
        let mut children = [
            spawn_store_mutation_process(&directory, &path, "retire", "retire", 4),
            spawn_store_mutation_process(&directory, &path, "upsert", "upsert", 5),
        ];
        wait_for_store_mutation_processes_to_block(&mut children);
        drop(held_lock);
        wait_for_store_mutation_processes_to_succeed(&mut children);

        let keys = store.access_keys().unwrap();
        let retired = keys
            .iter()
            .find(|key| key.address() == retired_signer.address())
            .unwrap();
        let inserted = keys
            .iter()
            .find(|key| key.address() == inserted_signer.address())
            .unwrap();
        assert!(!retired.is_locally_signable());
        assert!(inserted.is_locally_signable());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn store_mutation_process_helper() {
        let Some(path) = env::var_os(PROCESS_STORE_PATH_ENV).map(PathBuf::from) else {
            return;
        };
        let started_path = PathBuf::from(env::var_os(PROCESS_STARTED_PATH_ENV).unwrap());
        let operation = env::var(PROCESS_OPERATION_ENV).unwrap();
        let signer_byte = env::var(PROCESS_SIGNER_BYTE_ENV)
            .unwrap()
            .parse::<u8>()
            .unwrap();
        let signer = test_process_signer(signer_byte);
        let account = ROOT.parse::<Address>().unwrap();
        fs::write(started_path, b"started").unwrap();

        let store = TempoAccountsStore::at(path);
        match operation.as_str() {
            "retire" => assert!(
                store
                    .retire_access_key(account, 4217, signer.address())
                    .unwrap()
            ),
            "upsert" => store
                .upsert_secp256k1_access_key(account, &signer, &test_process_authorization(&signer))
                .unwrap(),
            _ => panic!("unknown process store mutation {operation}"),
        }
    }

    #[test]
    fn retirement_scrubs_all_duplicate_access_key_records() {
        let directory = unique_test_directory();
        let path = directory.join("wallet/store.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let private_key = format!("0x{}", "02".repeat(32));
        let signer =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&private_key).unwrap())
                .unwrap();
        overwrite_store(
            &path,
            serde_json::json!([
                {
                    "access": ROOT,
                    "address": signer.address(),
                    "chainId": 4217,
                    "keyType": "p256",
                },
                key_json(signer.address(), private_key),
            ]),
        );
        let account = ROOT.parse().unwrap();
        let store = TempoAccountsStore::open(&path).unwrap();

        assert!(
            store
                .retire_access_key(account, 4217, signer.address())
                .unwrap()
        );
        assert!(
            store
                .access_keys()
                .unwrap()
                .iter()
                .all(|key| !key.is_locally_signable())
        );
        assert!(
            !store
                .retire_access_key(account, 4217, signer.address())
                .unwrap()
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn access_key_upsert_preserves_existing_store_defaults() {
        let directory = unique_test_directory();
        let path = directory.join("wallet/store.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let account = ROOT.parse::<Address>().unwrap();
        let active_account = TARGET.parse::<Address>().unwrap();
        let signer = PrivateKeySigner::random();
        let authorization =
            KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, signer.address())
                .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let initial = serde_json::json!({
            "tempo-cli.store": {
                "state": {
                    "activeAccount": 0,
                    "chainId": 42431,
                    "accounts": [
                        {"address": active_account},
                        {"address": account},
                    ],
                    "accessKeys": [],
                },
            },
        });
        fs::write(&path, serde_json::to_vec(&initial).unwrap()).unwrap();

        let store = TempoAccountsStore::open(&path).unwrap();
        store
            .upsert_secp256k1_access_key(account, &signer, &authorization)
            .unwrap();

        let written: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let state = &written["tempo-cli.store"]["state"];
        assert_eq!(state["activeAccount"], 0);
        assert_eq!(state["chainId"], 42431);
        assert_eq!(store.active_account().unwrap(), active_account);
        assert_eq!(store.access_keys().unwrap()[0].address(), signer.address());

        fs::remove_dir_all(directory).unwrap();
    }

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
    fn decodes_the_accounts_sdk_device_authorization_shape() {
        let key = Address::repeat_byte(0x33);
        let token = Address::repeat_byte(0x20);
        let mut webauthn_data = vec![0_u8; 37];
        webauthn_data[32] = 0x05;
        webauthn_data.extend_from_slice(br#"{"type":"webauthn.get","challenge":"test"}"#);
        let authorization: TempoAccountsKeyAuthorization =
            serde_json::from_value(serde_json::json!({
                "address": key,
                "chainId": "0x1079",
                "expiry": 4_000_000_000_u64,
                "keyId": key,
                "keyType": "secp256k1",
                "limits": [{"token": token, "limit": "0xf4240"}],
                "signature": {
                    "type": "webAuthn",
                    "pubKeyX": B256::repeat_byte(0x11),
                    "pubKeyY": B256::repeat_byte(0x22),
                    "r": B256::repeat_byte(0x33),
                    "s": B256::repeat_byte(0x44),
                    "webauthnData": alloy_primitives::hex::encode_prefixed(&webauthn_data),
                },
            }))
            .unwrap();
        let authorization = authorization.as_signed();

        assert_eq!(authorization.chain_id, 4217);
        assert_eq!(authorization.key_id, key);
        assert_eq!(authorization.key_type, SignatureType::Secp256k1);
        assert_eq!(
            authorization.expiry.map(NonZeroU64::get),
            Some(4_000_000_000)
        );
        assert_eq!(
            authorization.limits.as_deref(),
            Some(
                [TokenLimit {
                    token,
                    limit: U256::from(1_000_000_u64),
                    period: 0,
                }]
                .as_slice()
            )
        );
        let PrimitiveSignature::WebAuthn(signature) = &authorization.signature else {
            panic!("expected WebAuthn root signature")
        };
        assert_eq!(signature.webauthn_data.as_ref(), webauthn_data);
    }

    #[test]
    fn upsert_writes_the_accounts_sdk_store_without_flattening_existing_state() {
        let directory = unique_test_directory();
        let path = directory.join("wallet/store.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();

        let account = ROOT.parse::<Address>().unwrap();
        let access_key = PrivateKeySigner::random();
        let unrelated_key = Address::repeat_byte(0x33);
        let initial = serde_json::json!({
            "tempo-cli.store": {
                "state": {
                    "activeAccount": 0,
                    "chainId": 42431,
                    "accounts": [{
                        "address": account,
                        "capabilities": {"futureAccountField": true},
                    }],
                    "accessKeys": [{
                        "address": unrelated_key,
                        "access": account,
                        "chainId": 42431,
                        "keyType": "secp256k1",
                        "futureKeyField": {"nested": 7},
                    }],
                    "futureStateField": ["kept"],
                },
                "version": 9,
                "futureEnvelopeField": "kept",
            },
            "futureRootField": {"kept": true},
        });
        fs::write(&path, serde_json::to_vec(&initial).unwrap()).unwrap();

        let mut webauthn_data = vec![0_u8; 37];
        webauthn_data[32] = 0x05;
        webauthn_data.extend_from_slice(br#"{"type":"webauthn.get","challenge":"test"}"#);
        let authorization = KeyAuthorization {
            chain_id: 4217,
            key_type: SignatureType::Secp256k1,
            key_id: access_key.address(),
            expiry: NonZeroU64::new(4_000_000_000),
            limits: Some(vec![TokenLimit {
                token: Address::repeat_byte(0x20),
                limit: U256::from(1_000_000_u64),
                period: 86_400,
            }]),
            allowed_calls: Some(vec![CallScope {
                target: tempo_contracts::precompiles::PATH_USD_ADDRESS,
                selector_rules: vec![SelectorRule {
                    selector: [0xa9, 0x05, 0x9c, 0xbb],
                    recipients: vec![Address::repeat_byte(0x44)],
                }],
            }]),
            witness: Some(B256::repeat_byte(0x55)),
            is_admin: false,
            account: Some(account),
        }
        .into_signed(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            r: B256::repeat_byte(0x11),
            s: B256::repeat_byte(0x22),
            pub_key_x: B256::repeat_byte(0x33),
            pub_key_y: B256::repeat_byte(0x44),
            webauthn_data: webauthn_data.into(),
        }));

        TempoAccountsStore::at(&path)
            .upsert_secp256k1_access_key(account, &access_key, &authorization)
            .unwrap();

        let written: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let root = &written["tempo-cli.store"];
        assert_eq!(root["version"], 9);
        assert_eq!(root["futureEnvelopeField"], "kept");
        assert_eq!(written["futureRootField"]["kept"], true);
        assert_eq!(
            root["state"]["accounts"][0]["capabilities"]["futureAccountField"],
            true
        );
        assert_eq!(root["state"]["futureStateField"][0], "kept");
        assert_eq!(root["state"]["accessKeys"].as_array().unwrap().len(), 2);
        assert_eq!(
            root["state"]["accessKeys"][1]["address"],
            unrelated_key.to_string()
        );
        assert_eq!(
            root["state"]["accessKeys"][1]["futureKeyField"]["nested"],
            7
        );
        let stored_authorization = &root["state"]["accessKeys"][0]["keyAuthorization"];
        assert!(stored_authorization.is_object());
        assert_eq!(stored_authorization["type"], "secp256k1");
        assert_eq!(stored_authorization["signature"]["type"], "webAuthn");
        assert_eq!(
            stored_authorization["signature"]["metadata"]["clientDataJSON"],
            r#"{"type":"webauthn.get","challenge":"test"}"#
        );

        let store = TempoAccountsStore::open(&path).unwrap();
        assert_eq!(store.active_account().unwrap(), account);
        let keys = store.access_keys().unwrap();
        let stored = keys
            .iter()
            .find(|key| key.address() == access_key.address())
            .unwrap();
        assert!(stored.is_locally_signable());
        assert_eq!(stored.key_authorization(), Some(&authorization));
        assert_eq!(stored.limits(), authorization.limits.as_deref().unwrap());
        assert_eq!(
            stored.allowed_calls(),
            authorization.allowed_calls.as_deref()
        );
        assert_eq!(
            stored.authorization_witness(),
            Some(B256::repeat_byte(0x55))
        );

        assert!(
            store
                .retire_access_key(account, 4217, access_key.address())
                .unwrap()
        );
        assert!(
            !store
                .retire_access_key(account, 4217, access_key.address())
                .unwrap()
        );
        let retired = store
            .access_keys()
            .unwrap()
            .into_iter()
            .find(|key| key.address() == access_key.address())
            .unwrap();
        assert!(!retired.is_locally_signable());
        assert_eq!(retired.key_authorization(), Some(&authorization));
        assert_eq!(
            retired.authorization_witness(),
            Some(B256::repeat_byte(0x55))
        );
        let retired_json: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let retired_key = &retired_json["tempo-cli.store"]["state"]["accessKeys"][0];
        assert!(retired_key.get("privateKey").is_none());
        assert_eq!(
            retired_json["tempo-cli.store"]["state"]["accessKeys"][1]["futureKeyField"]["nested"],
            7
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reads_legacy_rlp_authorizations_migrated_by_the_wallet_cli() {
        let access_key = PrivateKeySigner::random();
        let authorization =
            KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, access_key.address())
                .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let mut encoded = Vec::new();
        alloy_rlp::Encodable::encode(&authorization, &mut encoded);
        let path = write_store(serde_json::json!([{
            "access": ROOT,
            "address": access_key.address(),
            "chainId": 4217,
            "keyType": "secp256k1",
            "privateKey": alloy_primitives::hex::encode_prefixed(access_key.to_bytes()),
            "keyAuthorization": alloy_primitives::hex::encode_prefixed(encoded),
        }]));

        let store = TempoAccountsStore::open(&path).unwrap();
        assert_eq!(
            store.access_keys().unwrap()[0].key_authorization(),
            Some(&authorization)
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn selects_an_access_key_matching_the_requested_signature_type() {
        let secp256k1 = PrivateKeySigner::random();
        let p256_key = format!("0x{}", "02".repeat(32));
        let p256 = TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&p256_key).unwrap())
            .unwrap();
        let path = write_store(serde_json::json!([
            {
                "access": ROOT,
                "address": secp256k1.address(),
                "chainId": 4217,
                "keyType": "secp256k1",
                "privateKey": alloy_primitives::hex::encode_prefixed(secp256k1.to_bytes()),
            },
            key_json(p256.address(), p256_key),
        ]));
        let wallet = TempoAccountsWallet::from_store(&path)
            .unwrap()
            .with_chain_id(4217);

        let mut untyped_request = TempoTransactionRequest::default();
        wallet.fill_metadata(&mut untyped_request).unwrap();
        assert_eq!(untyped_request.key_id, Some(secp256k1.address()));

        let mut p256_request = TempoTransactionRequest {
            key_type: Some(SignatureType::P256),
            ..Default::default()
        };
        wallet.fill_metadata(&mut p256_request).unwrap();
        assert_eq!(p256_request.key_id, Some(p256.address()));
        assert_eq!(p256_request.key_type, Some(SignatureType::P256));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn waits_for_the_endpoint_chain_before_selecting_a_scoped_key() {
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

        let request = sendable.as_mut_builder().unwrap();
        assert_eq!(request.from(), None);
        assert_eq!(request.chain_id(), None);
        assert_eq!(request.key_id, None);
        request.set_chain_id(4217);

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
        let wallet = TempoAccountsWallet::from_store(&path)
            .unwrap()
            .with_chain_id(4217);
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
        assert!(!wallet.has_access_key_for_request(&request).unwrap());
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
        let wallet = TempoAccountsWallet::from_store(&path)
            .unwrap()
            .with_chain_id(4217);
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
        let wallet = TempoAccountsWallet::from_store(&path)
            .unwrap()
            .with_chain_id(4217);
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
        assert_eq!(key.signature_type(), SignatureType::P256);
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
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(asserter.clone());

        let mut first_request = TempoTransactionRequest::default();
        asserter.push_success(&alloy_primitives::U64::from(4217));
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
        asserter.push_success(&alloy_primitives::U64::from(4217));
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
    async fn store_wallet_rejects_direct_signing_with_an_unresolved_authorization() {
        let directory = unique_test_directory();
        let path = directory.join("wallet/store.json");
        let root = PrivateKeySigner::random();
        let account = root.address();
        let signer = PrivateKeySigner::random();
        let authorization =
            KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, signer.address());
        let signature = root
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        let authorization = authorization.into_signed(PrimitiveSignature::Secp256k1(signature));
        TempoAccountsStore::at(&path)
            .upsert_secp256k1_access_key(account, &signer, &authorization)
            .unwrap();
        let wallet = TempoAccountsWallet::from_store(&path)
            .unwrap()
            .with_chain_id(4217);
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

        let error = wallet.sign_request(request.clone()).await.unwrap_err();
        assert!(error.to_string().contains("call prepare_request"));

        let mut unsigned_request = request;
        wallet.fill_metadata(&mut unsigned_request).unwrap();
        let tx = unsigned_request.build_unsigned().unwrap();
        let error = wallet.sign_transaction_from(account, tx).await.unwrap_err();
        assert!(error.to_string().contains("call prepare_request"));
        assert!(
            wallet
                .in_flight_authorization_reservations()
                .unwrap()
                .is_empty()
        );
        fs::remove_dir_all(directory).unwrap();
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
                chain_id: Some(4217),
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

    #[tokio::test]
    async fn explicit_secp256k1_key_uses_the_accounts_wallet_path() {
        let signer = PrivateKeySigner::random();
        let key_id = signer.address();
        let account = ROOT.parse::<Address>().unwrap();
        let wallet = TempoAccountsWallet::from_secp256k1(account, signer, None).with_chain_id(4217);
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
        assert_eq!(signature.user_address, account);
        assert!(!signature.is_legacy());
        assert_eq!(signature.key_id(&signed.signature_hash()).unwrap(), key_id);
    }

    #[tokio::test]
    async fn explicit_secp256k1_key_rejects_create_before_rpc_preparation() {
        let wallet = TempoAccountsWallet::from_secp256k1(
            ROOT.parse().unwrap(),
            PrivateKeySigner::random(),
            None,
        )
        .with_chain_id(4217);
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(Default::default());
        let mut request = TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Create),
                ..Default::default()
            },
            ..Default::default()
        };

        let error = wallet
            .prepare_request(&provider, &mut request)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cannot use CREATE"));
    }

    #[test]
    fn opaque_unsupported_handles_do_not_hide_other_accounts_keys() {
        let private_key = format!("0x{}", "02".repeat(32));
        let signer =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&private_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([
            {
                "access": ROOT,
                "address": Address::repeat_byte(0x55),
                "chainId": 4217,
                "keyType": "secp256k1",
                "handle": {
                    "kind": "future-hardware-key",
                    "jwk": {"vendorSpecific": true},
                    "privateKey": {"opaque": ["not", "a", "key"]},
                },
            },
            key_json(signer.address(), private_key),
        ]));

        let store = TempoAccountsStore::open(&path).unwrap();
        let keys = store.access_keys().unwrap();
        assert_eq!(keys.len(), 2);
        assert!(!keys[0].is_locally_signable());

        let selected = TempoAccountsWallet::from_store(&path)
            .unwrap()
            .with_chain_id(4217)
            .active_access_key()
            .unwrap();
        assert_eq!(selected.address(), signer.address());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn signed_scopes_are_authoritative_and_preserve_the_ox_placeholder() {
        let root = PrivateKeySigner::random();
        let access_key = PrivateKeySigner::random();
        let target = TARGET.parse::<Address>().unwrap();
        let selector = [0xaa, 0xbb, 0xcc, 0xdd];
        let authorization = KeyAuthorization {
            chain_id: 4217,
            key_type: SignatureType::Secp256k1,
            key_id: access_key.address(),
            expiry: None,
            // Ox 0.14 emits an empty-list positional placeholder here when
            // scopes follow an omitted limits field.
            limits: Some(Vec::new()),
            allowed_calls: Some(vec![CallScope {
                target,
                selector_rules: vec![SelectorRule {
                    selector,
                    recipients: Vec::new(),
                }],
            }]),
            witness: None,
            is_admin: false,
            account: None,
        };
        let signature = root
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        let record = serde_json::json!({
            "access": root.address(),
            "address": access_key.address(),
            "chainId": 4217,
            "keyType": "secp256k1",
            "privateKey": alloy_primitives::hex::encode_prefixed(access_key.to_bytes()),
            "keyAuthorization": {
                "address": access_key.address(),
                "chainId": 4217,
                "scopes": [{"address": target, "selector": "0xaabbccdd"}],
                "type": "secp256k1",
                "signature": {
                    "type": "secp256k1",
                    "signature": {
                        "r": writable_bigint(signature.r()),
                        "s": writable_bigint(signature.s()),
                        "yParity": u8::from(signature.v()),
                    },
                },
            },
        });
        let path = write_store(serde_json::json!([record]));
        let wallet = TempoAccountsWallet::from_store(&path)
            .unwrap()
            .with_chain_id(4217);
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(root.address()),
                to: Some(target.into()),
                input: TransactionInput::new(Bytes::copy_from_slice(&selector)),
                ..Default::default()
            },
            ..Default::default()
        };

        let selected = wallet.select_for_request(&request).unwrap();
        let stored = selected.key_authorization().unwrap();
        assert_eq!(stored.limits.as_deref(), Some([].as_slice()));
        assert_eq!(stored.recover_signer().unwrap(), root.address());

        let mut disallowed = request.clone();
        disallowed.inner.input =
            TransactionInput::new(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]));
        assert!(matches!(
            wallet.select_for_request(&disallowed),
            Err(TempoAccountsError::MissingAccessKey { .. })
        ));

        let mut drifted = record;
        drifted["scopes"] = serde_json::json!([{"address": target, "selector": "0xdeadbeef"}]);
        let drifted_path = write_store(serde_json::json!([drifted]));
        let drifted_wallet = TempoAccountsWallet::from_store(&drifted_path)
            .unwrap()
            .with_chain_id(4217);
        assert!(matches!(
            drifted_wallet.select_for_request(&request),
            Err(TempoAccountsError::MissingAccessKey { .. })
        ));

        fs::remove_file(path).unwrap();
        fs::remove_file(drifted_path).unwrap();
    }

    #[test]
    fn tip1053_scoped_authorization_preserves_the_null_limits_placeholder() {
        let root = PrivateKeySigner::random();
        let access_key = PrivateKeySigner::random();
        let target = TARGET.parse::<Address>().unwrap();
        let authorization = KeyAuthorization {
            chain_id: 4217,
            key_type: SignatureType::Secp256k1,
            key_id: access_key.address(),
            expiry: None,
            limits: None,
            allowed_calls: Some(vec![CallScope {
                target,
                selector_rules: Vec::new(),
            }]),
            witness: None,
            is_admin: false,
            account: Some(root.address()),
        };
        let signature = root
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        let persisted: PersistedSignedKeyAuthorization =
            serde_json::from_value(serde_json::json!({
                "address": access_key.address(),
                "chainId": 4217,
                "scopes": [{"address": target}],
                "account": root.address(),
                "type": "secp256k1",
                "signature": {
                    "type": "secp256k1",
                    "signature": {
                        "r": writable_bigint(signature.r()),
                        "s": writable_bigint(signature.s()),
                        "yParity": u8::from(signature.v()),
                    },
                },
            }))
            .unwrap();

        let decoded = SignedKeyAuthorization::try_from(persisted).unwrap();

        assert_eq!(decoded.limits, None);
        assert_eq!(decoded.recover_signer().unwrap(), root.address());
    }

    #[test]
    fn recipient_scope_matching_rejects_noncanonical_abi_addresses() {
        let token = tempo_contracts::precompiles::PATH_USD_ADDRESS;
        let recipient = Address::repeat_byte(0x44);
        let selector = ITIP20::transferCall::SELECTOR;
        let scopes = [CallScope {
            target: token,
            selector_rules: vec![SelectorRule {
                selector,
                recipients: vec![recipient],
            }],
        }];
        let mut input = selector.to_vec();
        input.extend_from_slice(&[0_u8; 12]);
        input.extend_from_slice(recipient.as_slice());
        let calls = [IntentCall {
            to: Some(token),
            input: &input,
        }];
        assert!(scopes_match(Some(&scopes), Some(&calls)));

        input[4] = 1;
        let calls = [IntentCall {
            to: Some(token),
            input: &input,
        }];
        assert!(!scopes_match(Some(&scopes), Some(&calls)));
    }

    #[test]
    fn read_call_preparation_only_supplies_the_sender() {
        let private_key = format!("0x{}", "02".repeat(32));
        let signer =
            TempoP256Signer::from_slice(&alloy_primitives::hex::decode(&private_key).unwrap())
                .unwrap();
        let path = write_store(serde_json::json!([key_json(signer.address(), private_key)]));
        let wallet = TempoAccountsWallet::from_store(&path).unwrap();
        let mut request = TempoTransactionRequest::default();

        wallet.prepare_call_sync(&mut request).unwrap();

        assert_eq!(request.from(), Some(ROOT.parse().unwrap()));
        assert_eq!(request.chain_id(), None);
        assert_eq!(request.key_id, None);
        assert_eq!(request.key_type, None);
        assert_eq!(request.key_authorization, None);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn selected_key_validates_its_pending_authorization() {
        let root = PrivateKeySigner::random();
        let account = root.address();
        let signer = PrivateKeySigner::random();
        let sign = |authorization: KeyAuthorization, authorizer: &PrivateKeySigner| {
            let signature = authorizer
                .sign_hash_sync(&authorization.signature_hash())
                .unwrap();
            authorization.into_signed(PrimitiveSignature::Secp256k1(signature))
        };
        let expected = sign(
            KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, signer.address()),
            &root,
        );
        let different = expected
            .authorization
            .clone()
            .with_expiry(4_000_000_000)
            .into_signed(expected.signature.clone());
        let key = TempoAccessKey::from_secp256k1(account, 4217, signer.clone())
            .with_key_authorization(expected.clone());
        let mut request = TempoTransactionRequest {
            key_authorization: Some(different),
            ..Default::default()
        };

        let error = key.fill_request(&mut request).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match the selected Tempo Accounts key")
        );

        let direct_invalid = sign(
            KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, Address::random()),
            &root,
        );
        let invalid = [
            sign(
                KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, Address::random()),
                &root,
            ),
            sign(
                KeyAuthorization::unrestricted(4217, SignatureType::P256, signer.address()),
                &root,
            ),
            sign(
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, signer.address()),
                &root,
            ),
            sign(
                KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, signer.address())
                    .with_account(Address::random()),
                &root,
            ),
            sign(
                KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, signer.address()),
                &PrivateKeySigner::random(),
            ),
        ];

        for authorization in invalid {
            let key = TempoAccessKey::from_secp256k1(account, 4217, signer.clone())
                .with_key_authorization(authorization);
            let mut request = TempoTransactionRequest::default();
            let error = key.fill_request(&mut request).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("invalid pending Tempo key authorization")
            );
            assert_eq!(request.key_authorization, None);
        }

        let key = TempoAccessKey::from_secp256k1(account, 4217, signer)
            .with_key_authorization(direct_invalid);
        let tx = tempo_primitives::transaction::TempoTransaction {
            chain_id: 4217,
            ..Default::default()
        };
        let error = key.sign_aa(account, tx).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid pending Tempo key authorization")
        );
    }

    #[tokio::test]
    async fn request_level_cross_key_authorization_remains_separate_from_the_selected_key() {
        let account = Address::random();
        let signer = PrivateKeySigner::random();
        let authorization =
            KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, Address::random())
                .with_account(account);
        let signature = signer
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        let authorization = authorization.into_signed(PrimitiveSignature::Secp256k1(signature));
        let request = || TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TARGET.parse::<Address>().unwrap().into()),
                nonce: Some(0),
                gas: Some(100_000),
                max_fee_per_gas: Some(1),
                max_priority_fee_per_gas: Some(1),
                chain_id: Some(4217),
                ..Default::default()
            },
            key_authorization: Some(authorization.clone()),
            ..Default::default()
        };
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(Asserter::new());

        let key = TempoAccessKey::from_secp256k1(account, 4217, signer.clone());
        let mut key_request = request();
        let prepared_key = key
            .prepare_request(&provider, &mut key_request)
            .await
            .unwrap();
        assert_eq!(prepared_key.key_authorization(), None);
        assert_eq!(key_request.key_authorization.as_ref(), Some(&authorization));
        let prepared_wallet = TempoAccountsWallet::from_access_key(prepared_key);
        let envelope = prepared_wallet.sign_request(key_request).await.unwrap();
        let TempoTxEnvelope::AA(signed) = envelope else {
            panic!("expected AA transaction");
        };
        assert_eq!(signed.tx().key_authorization.as_ref(), Some(&authorization));
        let reservation = prepared_wallet
            .in_flight_authorization_reservations()
            .unwrap()[0];
        prepared_wallet.release_authorization(reservation).unwrap();

        let wallet = TempoAccountsWallet::from_secp256k1(account, signer, None).with_chain_id(4217);
        let mut wallet_request = request();
        let prepared_wallet = wallet
            .prepare_request(&provider, &mut wallet_request)
            .await
            .unwrap();
        assert_eq!(prepared_wallet.key_authorization(), None);
        assert_eq!(
            wallet_request.key_authorization.as_ref(),
            Some(&authorization)
        );
        let envelope = prepared_wallet.sign_request(wallet_request).await.unwrap();
        let TempoTxEnvelope::AA(signed) = envelope else {
            panic!("expected AA transaction");
        };
        assert_eq!(signed.tx().key_authorization.as_ref(), Some(&authorization));
        let reservation = prepared_wallet
            .in_flight_authorization_reservations()
            .unwrap()[0];
        prepared_wallet.release_authorization(reservation).unwrap();
    }

    #[tokio::test]
    async fn store_filler_exposes_the_reservation_created_by_its_clone() {
        let directory = unique_test_directory();
        let path = directory.join("wallet/store.json");
        let root = PrivateKeySigner::random();
        let account = root.address();
        let signer = PrivateKeySigner::random();
        let key_id = signer.address();
        let authorization = KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, key_id);
        let signature = root
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        let authorization = authorization.into_signed(PrimitiveSignature::Secp256k1(signature));
        TempoAccountsStore::at(&path)
            .upsert_secp256k1_access_key(account, &signer, &authorization)
            .unwrap();

        let wallet = TempoAccountsWallet::from_store(&path)
            .unwrap()
            .with_chain_id(4217);
        let independent = TempoAccountsWallet::from_store(&path)
            .unwrap()
            .with_chain_id(4217);
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

        let signing_wallet = wallet.clone();
        let mut first_request = request.clone();
        let selected = signing_wallet.fill_metadata(&mut first_request).unwrap();
        let key_authorization = first_request.key_authorization.clone();
        signing_wallet
            .fill(
                (selected, key_authorization),
                SendableTx::Builder(first_request),
            )
            .await
            .unwrap();

        let reservations = wallet.in_flight_authorization_reservations().unwrap();
        assert_eq!(reservations.len(), 1);
        let reservation = reservations[0];
        assert_eq!(reservation.chain_id(), 4217);
        assert_eq!(reservation.account(), account);
        assert_eq!(reservation.key_id(), key_id);

        let mut blocked_request = request.clone();
        let selected = independent.fill_metadata(&mut blocked_request).unwrap();
        let key_authorization = blocked_request.key_authorization.clone();
        let error = independent
            .fill(
                (selected, key_authorization),
                SendableTx::Builder(blocked_request),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("already in flight"));
        assert!(
            independent
                .in_flight_authorization_reservations()
                .unwrap()
                .is_empty()
        );

        wallet.release_authorization(reservation).unwrap();
        let mut retry_request = request;
        let selected = independent.fill_metadata(&mut retry_request).unwrap();
        let key_authorization = retry_request.key_authorization.clone();
        independent
            .fill(
                (selected, key_authorization),
                SendableTx::Builder(retry_request),
            )
            .await
            .unwrap();
        let retry_reservation = independent.in_flight_authorization_reservations().unwrap()[0];
        independent
            .release_authorization(retry_reservation)
            .unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn independent_wallets_share_and_can_release_one_time_authorization_reservations() {
        let root = PrivateKeySigner::random();
        let account = root.address();
        let signer = PrivateKeySigner::random();
        let authorization =
            KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, signer.address());
        let signature = root
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        let authorization = authorization.into_signed(PrimitiveSignature::Secp256k1(signature));
        let first = TempoAccountsWallet::from_secp256k1(
            account,
            signer.clone(),
            Some(authorization.clone()),
        )
        .with_chain_id(4217);
        let second = TempoAccountsWallet::from_secp256k1(account, signer, Some(authorization))
            .with_chain_id(4217);
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

        first.sign_request(request.clone()).await.unwrap();
        let error = second.sign_request(request.clone()).await.unwrap_err();
        assert!(error.to_string().contains("already in flight"));

        first
            .release_authorization(first.authorization_reservation().unwrap())
            .unwrap();
        second.sign_request(request).await.unwrap();
        second
            .release_authorization(second.authorization_reservation().unwrap())
            .unwrap();
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

    fn test_process_signer(byte: u8) -> PrivateKeySigner {
        PrivateKeySigner::from_slice(&[byte; 32]).unwrap()
    }

    fn test_process_authorization(signer: &PrivateKeySigner) -> SignedKeyAuthorization {
        KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, signer.address())
            .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()))
    }

    fn spawn_store_mutation_process(
        directory: &Path,
        store_path: &Path,
        name: &str,
        operation: &str,
        signer_byte: u8,
    ) -> StoreMutationProcess {
        let started_path = directory.join(format!("{name}.started"));
        let child = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "accounts::store::tests::store_mutation_process_helper",
            ])
            .env(PROCESS_STORE_PATH_ENV, store_path)
            .env(PROCESS_STARTED_PATH_ENV, &started_path)
            .env(PROCESS_OPERATION_ENV, operation)
            .env(PROCESS_SIGNER_BYTE_ENV, signer_byte.to_string())
            .spawn()
            .unwrap();
        StoreMutationProcess {
            child,
            started_path,
        }
    }

    fn wait_for_store_mutation_processes_to_block(children: &mut [StoreMutationProcess]) {
        let deadline = Instant::now() + Duration::from_secs(10);
        for process in children.iter_mut() {
            while !process.started_path.is_file() {
                assert!(
                    process.child.try_wait().unwrap().is_none(),
                    "store mutation exited before starting"
                );
                assert!(Instant::now() < deadline, "store mutation did not start");
                thread::sleep(Duration::from_millis(10));
            }
        }
        thread::sleep(Duration::from_millis(100));
        for process in children {
            assert!(
                process.child.try_wait().unwrap().is_none(),
                "store mutation did not block on the lock"
            );
        }
    }

    fn wait_for_store_mutation_processes_to_succeed(children: &mut [StoreMutationProcess]) {
        let deadline = Instant::now() + Duration::from_secs(10);
        for process in children {
            loop {
                if let Some(status) = process.child.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "store mutation did not finish after the lock was released"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
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

    fn unique_test_directory() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "tempo-alloy-accounts-store-{}-{unique}",
            std::process::id()
        ))
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
