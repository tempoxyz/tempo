use tempo_precompiles_macros::abi;

#[rustfmt::skip]
#[abi(no_reexport)]
#[allow(non_snake_case)]
pub mod IAccountKeychain {
    #[cfg(feature = "precompile")]
    use crate::error::Result;
    use alloy::primitives::{Address, U256};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
    pub enum SignatureType {
        Secp256k1 = 0,
        P256      = 1,
        WebAuthn  = 2,
    }

    impl SignatureType {
        #[cfg(feature = "precompile")]
        pub fn validate(self) -> Result<()> {
            if matches!(self, Self::__Invalid) {
                return Err(crate::account_keychain::AccountKeychainError::invalid_signature_type().into());
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct TokenLimit {
        pub token: Address,
        pub amount: U256,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct KeyInfo {
        pub signature_type: SignatureType,
        pub key_id: Address,
        pub expiry: u64,
        pub enforce_limits: bool,
        pub is_revoked: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
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
        SignatureTypeMismatch { expected: SignatureType, actual: SignatureType },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Event {
        KeyAuthorized { #[indexed] account: Address, #[indexed] publicKey: Address, signatureType: SignatureType, expiry: u64 },
        KeyRevoked { #[indexed] account: Address, #[indexed] publicKey: Address },
        SpendingLimitUpdated { #[indexed] account: Address, #[indexed] publicKey: Address, #[indexed] token: Address, newLimit: U256 },
    }

    pub trait Interface {
        /// Authorize a new key for the caller's account
        #[msg_sender]
        fn authorize_key(
            &mut self,
            key_id: Address,
            signature_type: SignatureType,
            expiry: u64,
            enforce_limits: bool,
            limits: Vec<TokenLimit>,
        ) -> Result<()>;

        /// Revoke an authorized key
        #[msg_sender]
        fn revoke_key(&mut self, key_id: Address) -> Result<()>;

        /// Update spending limit for a key-token pair
        #[msg_sender]
        fn update_spending_limit(&mut self, key_id: Address, token: Address, new_limit: U256) -> Result<()>;

        /// Get key information
        fn get_key(&self, account: Address, key_id: Address) -> Result<KeyInfo>;

        /// Get remaining spending limit
        fn get_remaining_limit(&self, account: Address, key_id: Address, token: Address) -> Result<U256>;

        /// Get the key used in the current transaction
        fn get_transaction_key(&self) -> Result<Address>;
    }
}
