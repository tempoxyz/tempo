//! Account Keychain bindings.

use tempo_precompiles_macros::abi;

#[abi(dispatch)]
#[rustfmt::skip]
pub mod IAccountKeychain {
    use alloy::primitives::{Address, U256};

    #[cfg(feature = "precompile")]
    use crate::error::Result;

    /// Account Keychain trait for managing authorized keys.
    ///
    /// This precompile allows accounts to authorize secondary keys with:
    /// - Different signature types (secp256k1, P256, WebAuthn)
    /// - Expiry times for key rotation
    /// - Per-token spending limits for security
    ///
    /// Only the main account key can authorize/revoke keys, while secondary keys
    /// can be used for regular transactions within their spending limits.
    pub trait IAccountKeychain {
        fn get_key(&self, account: Address, key_id: Address) -> Result<KeyInfo>;
        fn get_remaining_limit(&self, account: Address, key_id: Address, token: Address) -> Result<U256>;
        fn get_transaction_key(&self) -> Result<Address>;

        fn authorize_key(&mut self, key_id: Address, signature_type: SignatureType, expiry: u64, enforce_limits: bool, limits: Vec<TokenLimit>) -> Result<()>;
        fn revoke_key(&mut self, key_id: Address) -> Result<()>;
        fn update_spending_limit(&mut self, key_id: Address, token: Address, new_limit: U256) -> Result<()>;
    }

    // Signature type
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub enum SignatureType {
        #[default]
        Secp256k1,
        P256,
        WebAuthn,
    }

    /// Token spending limit structure
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct TokenLimit {
        pub token: Address,
        pub amount: U256,
    }

    /// Key information structure
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct KeyInfo {
        pub signature_type: u8,
        pub key_id: Address,
        pub expiry: u64,
        pub enforce_limits: bool,
        pub is_revoked: bool,
    }

    // Errors
    pub enum Error {
        UnauthorizedCaller,
        KeyAlreadyExists,
        KeyNotFound,
        KeyExpired,
        SpendingLimitExceeded,
        InvalidSignatureType,
        ZeroPublicKey,
        ExpiryInPast,
        KeyAlreadyRevoked,
    }

    // Events
    pub enum Event {
        /// Emitted when a new key is authorized
        KeyAuthorized { #[indexed] account: Address, #[indexed] public_key: Address, signature_type: u8, expiry: u64 },
        /// Emitted when a key is revoked
        KeyRevoked { #[indexed] account: Address, #[indexed] public_key: Address },
        /// Emitted when a spending limit is updated
        SpendingLimitUpdated { #[indexed] account: Address, #[indexed] public_key: Address, #[indexed] token: Address, new_limit: U256 },
    }
}
