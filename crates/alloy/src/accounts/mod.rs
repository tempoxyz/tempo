//! Tempo Accounts-compatible wallets and signers.
//!
//! [`TempoAccountsWallet`] reads the store written by Tempo Accounts clients,
//! selects a locally signable access key for each transaction intent, fills the
//! access-key metadata needed for gas estimation, and signs through Alloy's
//! standard wallet interfaces.

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
