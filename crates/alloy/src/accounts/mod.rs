//! Tempo Accounts-compatible wallets and signers.
//!
//! [`crate::accounts::TempoAccountsWallet`] reads the store written by Tempo
//! Accounts clients,
//! selects a locally signable access key for each transaction intent, fills the
//! access-key metadata needed for gas estimation, and signs through Alloy's
//! standard wallet interfaces.

mod p256;
mod store;

pub use store::{
    TempoAccessKey, TempoAccountsError, TempoAccountsKeyAuthorization, TempoAccountsStore,
    TempoAccountsWallet, TempoAuthorizationReservation, TempoStoredAccessKey,
    default_accounts_store_path,
};

fn request_uses_create(request: &crate::rpc::TempoTransactionRequest) -> bool {
    request.calls.iter().any(|call| call.to.is_create())
        || request.inner.to.is_some_and(|to| to.is_create())
}

fn transaction_uses_create(transaction: &tempo_primitives::transaction::TempoTransaction) -> bool {
    transaction.calls.iter().any(|call| call.to.is_create())
}

/// The accounts an authorization names without recovering a primitive signer: the account of its
/// configurable account signature, which only signs its own grants, and its explicit account. A
/// valid authorization names one account through all of them.
pub(crate) fn authorization_accounts(
    authorization: &tempo_primitives::transaction::SignedKeyAuthorization,
) -> impl Iterator<Item = alloy_primitives::Address> {
    authorization
        .signature
        .as_configurable_account()
        .map(tempo_primitives::transaction::ConfigurableAccountSignature::account)
        .into_iter()
        .chain(authorization.account)
}
