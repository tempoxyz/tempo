//! Tempo Accounts-compatible wallets and signers.
//!
//! [`TempoAccountsWallet`] reads the store written by Tempo Accounts clients,
//! selects a locally signable access key for each transaction intent, fills the
//! access-key metadata needed for gas estimation, and signs through Alloy's
//! standard wallet interfaces.

use std::future::Future;

use alloy_network::NetworkWallet;
use alloy_primitives::Address;
use alloy_provider::{Provider, fillers::TxFiller};
use alloy_transport::TransportResult;

mod keychain;
mod p256;
mod secp256k1;
mod store;
mod wallet;

pub use keychain::{TempoKeychainWallet, TempoSigner};
pub use p256::{P256Jwk, P256SignerError, TempoP256Signer, TempoPrimitiveSigner};
pub use secp256k1::TempoSecp256k1Signer;
pub use store::{
    TempoAccessKey, TempoAccountsError, TempoAccountsWallet, default_accounts_store_path,
};
pub use wallet::{TempoWallet, TempoWalletFillable};

use crate::{TempoNetwork, rpc::TempoTransactionRequest};

/// A Tempo wallet that can prepare and sign AA transaction requests.
///
/// This combines Alloy's standard network-wallet and filler contracts with the
/// one preparation operation needed when a consumer estimates gas or obtains a
/// fee-payer signature outside a provider filler stack.
pub trait TempoTransactionWallet: NetworkWallet<TempoNetwork> + TxFiller<TempoNetwork> {
    /// On-chain account represented by this wallet.
    fn account(&self) -> Address;

    /// Fill wallet metadata and resolve any pending access-key authorization.
    fn prepare_request<'a, P>(
        &'a self,
        provider: &'a P,
        request: &'a mut TempoTransactionRequest,
    ) -> impl Future<Output = TransportResult<()>> + Send + 'a
    where
        P: Provider<TempoNetwork> + 'a;
}

impl<S> TempoTransactionWallet for TempoWallet<S>
where
    S: TempoSigner,
{
    fn account(&self) -> Address {
        Self::account(self)
    }

    fn prepare_request<'a, P>(
        &'a self,
        provider: &'a P,
        request: &'a mut TempoTransactionRequest,
    ) -> impl Future<Output = TransportResult<()>> + Send + 'a
    where
        P: Provider<TempoNetwork> + 'a,
    {
        Self::prepare_request(self, provider, request)
    }
}

impl TempoTransactionWallet for TempoAccountsWallet {
    fn account(&self) -> Address {
        Self::account(self)
    }

    fn prepare_request<'a, P>(
        &'a self,
        provider: &'a P,
        request: &'a mut TempoTransactionRequest,
    ) -> impl Future<Output = TransportResult<()>> + Send + 'a
    where
        P: Provider<TempoNetwork> + 'a,
    {
        Self::prepare_request(self, provider, request)
    }
}
