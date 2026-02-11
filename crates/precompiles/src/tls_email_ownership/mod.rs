pub mod dispatch;

use tempo_contracts::precompiles::TLS_EMAIL_OWNERSHIP_ADDRESS;
pub use tempo_contracts::precompiles::{ITLSEmailOwnership, TLSEmailOwnershipError};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256, keccak256};

const ALLOWED_SERVER_NAME: &str = "www.googleapis.com";
const ALLOWED_ENDPOINT: &str = "/oauth2/v3/userinfo";

#[derive(Debug, Storable)]
struct NotaryKey {
    notary_address: Address,
    active: bool,
}

#[derive(Debug, Storable)]
struct EmailClaim {
    email: String,
    email_hash: B256,
    verified_at: u64,
    notary_key_id: B256,
}

#[contract(addr = TLS_EMAIL_OWNERSHIP_ADDRESS)]
pub struct TLSEmailOwnership {
    owner: Address,
    notary_keys: Mapping<B256, NotaryKey>,
    claims: Mapping<Address, EmailClaim>,
}

impl TLSEmailOwnership {
    pub fn initialize(&mut self, owner: Address) -> Result<()> {
        self.__initialize()?;
        self.owner.write(owner)
    }

    pub fn owner(&self) -> Result<Address> {
        self.owner.read()
    }

    fn check_owner(&self, caller: Address) -> Result<()> {
        if self.owner()? != caller {
            return Err(TLSEmailOwnershipError::unauthorized())?;
        }
        Ok(())
    }

    pub fn change_owner(
        &mut self,
        sender: Address,
        call: ITLSEmailOwnership::changeOwnerCall,
    ) -> Result<()> {
        self.check_owner(sender)?;
        self.owner.write(call.newOwner)
    }

    pub fn set_notary_key(
        &mut self,
        sender: Address,
        call: ITLSEmailOwnership::setNotaryKeyCall,
    ) -> Result<()> {
        self.check_owner(sender)?;
        let key = NotaryKey {
            notary_address: call.notaryAddress,
            active: true,
        };
        self.notary_keys[call.notaryKeyId].write(key)
    }

    pub fn remove_notary_key(
        &mut self,
        sender: Address,
        call: ITLSEmailOwnership::removeNotaryKeyCall,
    ) -> Result<()> {
        self.check_owner(sender)?;
        self.notary_keys[call.notaryKeyId].delete()
    }

    pub fn get_notary_key(
        &self,
        call: ITLSEmailOwnership::getNotaryKeyCall,
    ) -> Result<Address> {
        let key = self.notary_keys[call.notaryKeyId].read()?;
        if !key.active {
            return Ok(Address::ZERO);
        }
        Ok(key.notary_address)
    }

    pub fn verify_email(
        &mut self,
        sender: Address,
        call: ITLSEmailOwnership::verifyEmailCall,
    ) -> Result<String> {
        if call.subject != sender {
            return Err(TLSEmailOwnershipError::invalid_subject())?;
        }

        if call.serverName != ALLOWED_SERVER_NAME {
            return Err(TLSEmailOwnershipError::invalid_server_name())?;
        }

        if call.endpoint != ALLOWED_ENDPOINT {
            return Err(TLSEmailOwnershipError::invalid_endpoint())?;
        }

        let notary_key = self.notary_keys[call.notaryKeyId].read()?;
        if !notary_key.active || notary_key.notary_address.is_zero() {
            return Err(TLSEmailOwnershipError::notary_key_not_found())?;
        }

        let email = extract_email_from_json(&call.responseBody)
            .ok_or(TempoPrecompileError::from(TLSEmailOwnershipError::email_not_found()))?;

        let response_body_hash = keccak256(&call.responseBody);
        let email_hash = keccak256(email.as_bytes());

        let digest = compute_attestation_digest(
            call.subject,
            &call.serverName,
            &call.endpoint,
            response_body_hash,
            email_hash,
            call.notaryKeyId,
        );

        let sig = alloy::primitives::Signature::from_scalars_and_parity(
            call.r,
            call.s,
            call.v != 0,
        );

        let recovered = sig
            .recover_address_from_prehash(&digest)
            .map_err(|_| TempoPrecompileError::from(TLSEmailOwnershipError::invalid_signature()))?;

        if recovered != notary_key.notary_address {
            return Err(TLSEmailOwnershipError::invalid_signature())?;
        }

        let claim = EmailClaim {
            email: email.clone(),
            email_hash,
            verified_at: 0,
            notary_key_id: call.notaryKeyId,
        };
        self.claims[sender].write(claim)?;

        Ok(email)
    }

    pub fn get_verified_email(
        &self,
        call: ITLSEmailOwnership::getVerifiedEmailCall,
    ) -> Result<ITLSEmailOwnership::EmailClaim> {
        let claim = self.claims[call.user].read()?;
        Ok(ITLSEmailOwnership::EmailClaim {
            email: claim.email,
            emailHash: claim.email_hash,
            verifiedAt: claim.verified_at,
            notaryKeyId: claim.notary_key_id,
        })
    }

    pub fn is_verified(
        &self,
        call: ITLSEmailOwnership::isVerifiedCall,
    ) -> Result<bool> {
        let claim = self.claims[call.user].read()?;
        Ok(!claim.email_hash.is_zero())
    }

    pub fn revoke_my_email(&mut self, sender: Address) -> Result<()> {
        let claim = self.claims[sender].read()?;
        if claim.email_hash.is_zero() {
            return Err(TLSEmailOwnershipError::not_verified())?;
        }
        self.claims[sender].delete()
    }
}

fn compute_attestation_digest(
    subject: Address,
    server_name: &str,
    endpoint: &str,
    response_body_hash: B256,
    email_hash: B256,
    notary_key_id: B256,
) -> B256 {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"TempoEmailAttestationV1");
    buf.extend_from_slice(subject.as_slice());
    buf.extend_from_slice(keccak256(server_name.as_bytes()).as_slice());
    buf.extend_from_slice(keccak256(endpoint.as_bytes()).as_slice());
    buf.extend_from_slice(response_body_hash.as_slice());
    buf.extend_from_slice(email_hash.as_slice());
    buf.extend_from_slice(notary_key_id.as_slice());
    keccak256(&buf)
}

fn extract_email_from_json(body: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;

    let email_key = "\"email\"";
    let pos = s.find(email_key)?;
    let after_key = &s[pos + email_key.len()..];

    let after_colon = after_key.trim_start();
    if !after_colon.starts_with(':') {
        return None;
    }
    let after_colon = after_colon[1..].trim_start();

    if !after_colon.starts_with('"') {
        return None;
    }
    let value_start = 1;
    let value_end = after_colon[value_start..].find('"')?;
    let email = &after_colon[value_start..value_start + value_end];

    if email.is_empty() || !email.contains('@') {
        return None;
    }

    Some(email.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::primitives::{Address, FixedBytes};

    #[test]
    fn test_extract_email_from_json() {
        let body = br#"{"sub":"123","email":"zygimantas@tempo.xyz","email_verified":true}"#;
        assert_eq!(
            extract_email_from_json(body),
            Some("zygimantas@tempo.xyz".to_string())
        );
    }

    #[test]
    fn test_extract_email_from_json_missing() {
        let body = br#"{"sub":"123","name":"test"}"#;
        assert_eq!(extract_email_from_json(body), None);
    }

    #[test]
    fn test_extract_email_from_json_no_at() {
        let body = br#"{"email":"notanemail"}"#;
        assert_eq!(extract_email_from_json(body), None);
    }

    #[test]
    fn test_extract_email_from_json_empty() {
        let body = br#"{"email":""}"#;
        assert_eq!(extract_email_from_json(body), None);
    }

    #[test]
    fn test_initialize_and_owner() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;
            assert_eq!(tls.owner()?, owner);
            Ok(())
        })
    }

    #[test]
    fn test_set_and_get_notary_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let notary_addr = Address::random();
        let key_id = FixedBytes::<32>::from([0x01; 32]);
        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;

            tls.set_notary_key(
                owner,
                ITLSEmailOwnership::setNotaryKeyCall {
                    notaryKeyId: key_id,
                    notaryAddress: notary_addr,
                },
            )?;

            let result = tls.get_notary_key(ITLSEmailOwnership::getNotaryKeyCall {
                notaryKeyId: key_id,
            })?;
            assert_eq!(result, notary_addr);

            Ok(())
        })
    }

    #[test]
    fn test_unauthorized_set_notary_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let non_owner = Address::random();
        let key_id = FixedBytes::<32>::from([0x01; 32]);
        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;

            let result = tls.set_notary_key(
                non_owner,
                ITLSEmailOwnership::setNotaryKeyCall {
                    notaryKeyId: key_id,
                    notaryAddress: Address::random(),
                },
            );
            assert_eq!(
                result,
                Err(TLSEmailOwnershipError::unauthorized().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_verify_email_invalid_subject() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let sender = Address::random();
        let wrong_subject = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;

            let result = tls.verify_email(
                sender,
                ITLSEmailOwnership::verifyEmailCall {
                    notaryKeyId: FixedBytes::<32>::ZERO,
                    subject: wrong_subject,
                    serverName: ALLOWED_SERVER_NAME.to_string(),
                    endpoint: ALLOWED_ENDPOINT.to_string(),
                    responseBody: vec![].into(),
                    v: 0,
                    r: FixedBytes::<32>::ZERO,
                    s: FixedBytes::<32>::ZERO,
                },
            );
            assert_eq!(
                result,
                Err(TLSEmailOwnershipError::invalid_subject().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_verify_email_invalid_server() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;

            let result = tls.verify_email(
                sender,
                ITLSEmailOwnership::verifyEmailCall {
                    notaryKeyId: FixedBytes::<32>::ZERO,
                    subject: sender,
                    serverName: "evil.example.com".to_string(),
                    endpoint: ALLOWED_ENDPOINT.to_string(),
                    responseBody: vec![].into(),
                    v: 0,
                    r: FixedBytes::<32>::ZERO,
                    s: FixedBytes::<32>::ZERO,
                },
            );
            assert_eq!(
                result,
                Err(TLSEmailOwnershipError::invalid_server_name().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_verify_email_end_to_end() -> eyre::Result<()> {
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;

        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let user = Address::random();

        let notary_signer = PrivateKeySigner::random();
        let notary_address = notary_signer.address();
        let notary_key_id = FixedBytes::<32>::from([0x42; 32]);

        let response_body =
            br#"{"sub":"1234567890","email":"zygimantas@tempo.xyz","email_verified":true}"#;
        let response_body_hash = keccak256(response_body);
        let email_hash = keccak256(b"zygimantas@tempo.xyz");

        let digest = compute_attestation_digest(
            user,
            ALLOWED_SERVER_NAME,
            ALLOWED_ENDPOINT,
            response_body_hash,
            email_hash,
            notary_key_id,
        );

        let sig = notary_signer.sign_hash_sync(&digest)?;

        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;

            tls.set_notary_key(
                owner,
                ITLSEmailOwnership::setNotaryKeyCall {
                    notaryKeyId: notary_key_id,
                    notaryAddress: notary_address,
                },
            )?;

            let email = tls.verify_email(
                user,
                ITLSEmailOwnership::verifyEmailCall {
                    notaryKeyId: notary_key_id,
                    subject: user,
                    serverName: ALLOWED_SERVER_NAME.to_string(),
                    endpoint: ALLOWED_ENDPOINT.to_string(),
                    responseBody: response_body.to_vec().into(),
                    v: sig.v() as u8,
                    r: FixedBytes::<32>::from(sig.r().to_be_bytes::<32>()),
                    s: FixedBytes::<32>::from(sig.s().to_be_bytes::<32>()),
                },
            )?;

            assert_eq!(email, "zygimantas@tempo.xyz");

            let claim = tls.get_verified_email(ITLSEmailOwnership::getVerifiedEmailCall {
                user,
            })?;
            assert_eq!(claim.email, "zygimantas@tempo.xyz");
            assert_eq!(claim.emailHash, email_hash);

            let verified = tls.is_verified(ITLSEmailOwnership::isVerifiedCall { user })?;
            assert!(verified);

            Ok(())
        })
    }

    #[test]
    fn test_revoke_email() -> eyre::Result<()> {
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;

        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let user = Address::random();

        let notary_signer = PrivateKeySigner::random();
        let notary_address = notary_signer.address();
        let notary_key_id = FixedBytes::<32>::from([0x42; 32]);

        let response_body =
            br#"{"sub":"1234567890","email":"zygimantas@tempo.xyz","email_verified":true}"#;
        let response_body_hash = keccak256(response_body);
        let email_hash = keccak256(b"zygimantas@tempo.xyz");

        let digest = compute_attestation_digest(
            user,
            ALLOWED_SERVER_NAME,
            ALLOWED_ENDPOINT,
            response_body_hash,
            email_hash,
            notary_key_id,
        );

        let sig = notary_signer.sign_hash_sync(&digest)?;

        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;

            tls.set_notary_key(
                owner,
                ITLSEmailOwnership::setNotaryKeyCall {
                    notaryKeyId: notary_key_id,
                    notaryAddress: notary_address,
                },
            )?;

            tls.verify_email(
                user,
                ITLSEmailOwnership::verifyEmailCall {
                    notaryKeyId: notary_key_id,
                    subject: user,
                    serverName: ALLOWED_SERVER_NAME.to_string(),
                    endpoint: ALLOWED_ENDPOINT.to_string(),
                    responseBody: response_body.to_vec().into(),
                    v: sig.v() as u8,
                    r: FixedBytes::<32>::from(sig.r().to_be_bytes::<32>()),
                    s: FixedBytes::<32>::from(sig.s().to_be_bytes::<32>()),
                },
            )?;

            assert!(tls.is_verified(ITLSEmailOwnership::isVerifiedCall { user })?);

            tls.revoke_my_email(user)?;

            assert!(!tls.is_verified(ITLSEmailOwnership::isVerifiedCall { user })?);

            Ok(())
        })
    }

    #[test]
    fn test_revoke_not_verified() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;

            let result = tls.revoke_my_email(user);
            assert_eq!(
                result,
                Err(TLSEmailOwnershipError::not_verified().into())
            );

            Ok(())
        })
    }
}
