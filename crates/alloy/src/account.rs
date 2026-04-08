use alloy_primitives::Address;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use std::sync::Mutex;
use tempo_primitives::{
    SignatureType,
    transaction::{KeyAuthorization, PrimitiveSignature, SignedKeyAuthorization},
};

/// An access key account that encapsulates the access key signer and its root account.
///
/// This type hides the domain-separated signing scheme required for access key
/// transactions, allowing access keys to be used seamlessly with
/// [`TempoWallet`](crate::TempoWallet) and the standard `send_transaction` flow.
///
/// # New key (not yet provisioned on-chain)
///
/// Use [`authorize_with`](Self::authorize_with) to create a signed
/// [`KeyAuthorization`] that will be attached to the first transaction
/// and automatically consumed.
///
/// ```ignore
/// let access_key = AccessKeyAccount::new(PrivateKeySigner::random(), root.address())
///     .authorize_with(&root, chain_id)?;
/// ```
///
/// # Existing key (already provisioned on-chain)
///
/// Skip `authorize_with` — only the signer and root address are needed:
///
/// ```ignore
/// let access_key = AccessKeyAccount::new(existing_signer, root.address());
/// ```
// TODO: support P256 and WebAuthn signers (the protocol supports them, but alloy
// does not yet have `SignerSync` impls for those types).
#[derive(Debug)]
pub struct AccessKeyAccount {
    /// The access key signer.
    signer: PrivateKeySigner,
    /// The root account address that this access key acts on behalf of.
    root: Address,
    /// The access key's address (derived from the signer's public key).
    key_id: Address,
    /// Optional signed key authorization, consumed on first use.
    key_authorization: Mutex<Option<SignedKeyAuthorization>>,
}

impl Clone for AccessKeyAccount {
    fn clone(&self) -> Self {
        Self {
            signer: self.signer.clone(),
            root: self.root,
            key_id: self.key_id,
            key_authorization: Mutex::new(
                self.key_authorization.lock().expect("not poisoned").clone(),
            ),
        }
    }
}

impl AccessKeyAccount {
    /// Create a new access key account with the given signer and root address.
    pub fn new(signer: PrivateKeySigner, root: Address) -> Self {
        let key_id = signer.address();
        Self {
            signer,
            root,
            key_id,
            key_authorization: Mutex::new(None),
        }
    }

    /// Attach a pre-signed key authorization for provisioning this access key.
    pub fn with_key_authorization(self, auth: SignedKeyAuthorization) -> Self {
        *self.key_authorization.lock().expect("not poisoned") = Some(auth);
        self
    }

    /// Create and sign a [`KeyAuthorization`] using the root signer.
    ///
    /// The resulting authorization is automatically attached to the first
    /// transaction and consumed, so subsequent transactions won't re-send it.
    pub fn authorize_with(
        self,
        root_signer: &impl SignerSync,
        chain_id: u64,
    ) -> alloy_signer::Result<Self> {
        let key_auth = KeyAuthorization {
            chain_id,
            key_type: SignatureType::Secp256k1,
            key_id: self.key_id,
            expiry: None,
            limits: None,
        };

        let sig = root_signer.sign_hash_sync(&key_auth.signature_hash())?;
        let signed = key_auth.into_signed(PrimitiveSignature::Secp256k1(sig));
        Ok(self.with_key_authorization(signed))
    }

    /// Returns the root account address (the sender for transactions).
    pub fn sender_address(&self) -> Address {
        self.root
    }

    /// Returns the root account address.
    pub fn root(&self) -> Address {
        self.root
    }

    /// Returns the access key ID (the signer's address).
    pub fn key_id(&self) -> Address {
        self.key_id
    }

    /// Returns the signature type of this access key.
    pub fn key_type(&self) -> SignatureType {
        SignatureType::Secp256k1
    }

    /// Returns `true` if a key authorization is stored.
    pub fn has_key_authorization(&self) -> bool {
        self.key_authorization
            .lock()
            .expect("not poisoned")
            .is_some()
    }

    /// Take the stored key authorization, if any.
    ///
    /// This consumes the authorization so it is only used once.
    pub fn take_key_authorization(&self) -> Option<SignedKeyAuthorization> {
        self.key_authorization.lock().expect("not poisoned").take()
    }

    /// Returns a reference to the inner signer.
    pub fn signer(&self) -> &PrivateKeySigner {
        &self.signer
    }
}
