//! Tempo Accounts-compatible wallets and signers.
//!
//! [`TempoAccountsWallet`](crate::accounts::TempoAccountsWallet) reads the store written by Tempo
//! Accounts clients,
//! selects a locally signable access key for each transaction intent, fills the
//! access-key metadata needed for gas estimation, and signs through Alloy's
//! standard wallet interfaces.

mod keychain;
mod p256;
mod store;

pub use keychain::TempoKeychainWallet;
pub use store::{
    TempoAccessKey, TempoAccountsError, TempoAccountsWallet, default_accounts_store_path,
};
