//! Tempo Accounts-compatible wallets and signers.
//!
//! [`TempoAccountsWallet`](crate::accounts::TempoAccountsWallet) reads the store written by Tempo
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
