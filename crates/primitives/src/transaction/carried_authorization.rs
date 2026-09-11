//! TIP-1086 certificate encoding and immutable policy checks.
//!
//! No state-dependent authority decision belongs here. Callers must validate the account's
//! current configuration, issuer, witness, key occupancy, and time against execution state.
use super::{CallScope, KeyAuthorization, SignatureType, TempoSignature, TokenLimit};
use crate::TempoAddressExt;
use alloc::vec::Vec;
use alloy_primitives::{Address, B256, TxKind, U256, keccak256};
use alloy_rlp::{Decodable, Encodable, Header};
use core::num::NonZeroU64;

/// Complete signed certificate size limit, including the issuer's configuration witness.
pub const MAX_CARRIED_AUTHORIZATION_BYTES: usize = 4096;
/// Domain separator; its length is 20 bytes.
pub const CARRIED_AUTHORIZATION_TAG: &[u8] = b"tempo-carried-key-v1";

/// The extra signed fields that distinguish a carried grant from a stored authorization.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct CarriedAuthorization {
    /// Inclusive Unix timestamp; also anchors periodic budgets.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub valid_after: u64,
    /// Current parent configuration commitment, or zero for an unconfigured primitive parent.
    pub authority_config: B256,
}

fn list(payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 3);
    Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend(payload);
    out
}

fn decode_list<'a>(buf: &mut &'a [u8]) -> alloy_rlp::Result<&'a [u8]> {
    let header = Header::decode(buf)?;
    if !header.list {
        return Err(alloy_rlp::Error::UnexpectedString);
    }
    if header.payload_length > buf.len() {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let (fields, rest) = buf.split_at(header.payload_length);
    *buf = rest;
    Ok(fields)
}

fn optional<T: Decodable>(buf: &mut &[u8]) -> alloy_rlp::Result<Option<T>> {
    if buf.first() == Some(&alloy_rlp::EMPTY_STRING_CODE) {
        *buf = &buf[1..];
        Ok(None)
    } else {
        T::decode(buf).map(Some)
    }
}

impl CarriedAuthorization {
    /// Encodes all ten fields, with no trailing omission or legacy period abbreviation.
    pub fn encode_fields(&self, auth: &KeyAuthorization) -> Vec<u8> {
        let mut fields = Vec::new();
        auth.chain_id.encode(&mut fields);
        auth.account.unwrap_or_default().encode(&mut fields);
        auth.key_type.encode(&mut fields);
        auth.key_id.encode(&mut fields);
        self.valid_after.encode(&mut fields);
        auth.expiry.map_or(0, NonZeroU64::get).encode(&mut fields);
        auth.witness.unwrap_or_default().encode(&mut fields);
        match &auth.limits {
            None => fields.push(alloy_rlp::EMPTY_STRING_CODE),
            Some(limits) => {
                let mut entries = Vec::new();
                for limit in limits {
                    let mut entry = Vec::new();
                    limit.token.encode(&mut entry);
                    limit.limit.encode(&mut entry);
                    limit.period.encode(&mut entry);
                    entries.extend(list(entry));
                }
                fields.extend(list(entries));
            }
        }
        match &auth.allowed_calls {
            None => fields.push(alloy_rlp::EMPTY_STRING_CODE),
            Some(scopes) => scopes.encode(&mut fields),
        }
        self.authority_config.encode(&mut fields);
        list(fields)
    }

    /// Signature-independent budget identity and issuer signing digest.
    pub fn signature_hash(&self, auth: &KeyAuthorization) -> B256 {
        let mut payload = Vec::new();
        CARRIED_AUTHORIZATION_TAG.encode(&mut payload);
        payload.extend(self.encode_fields(auth));
        keccak256(list(payload))
    }

    /// Full signed wrapper. The issuer can be primitive or a bounded configurable quorum.
    pub fn encode_signed(&self, auth: &KeyAuthorization, signature: &TempoSignature) -> Vec<u8> {
        let mut payload = Vec::new();
        CARRIED_AUTHORIZATION_TAG.encode(&mut payload);
        payload.extend(self.encode_fields(auth));
        signature.encode(&mut payload);
        list(payload)
    }

    /// Decode fields after the outer tag has been consumed. Does not perform cryptography.
    pub fn decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<(Self, KeyAuthorization)> {
        let mut fields = decode_list(buf)?;
        let chain_id = u64::decode(&mut fields)?;
        let account = Address::decode(&mut fields)?;
        let key_type = SignatureType::decode(&mut fields)?;
        let key_id = Address::decode(&mut fields)?;
        let valid_after = u64::decode(&mut fields)?;
        let expiry = NonZeroU64::new(u64::decode(&mut fields)?)
            .ok_or(alloy_rlp::Error::Custom("carried expiry is mandatory"))?;
        let witness = B256::decode(&mut fields)?;
        let limits = if fields.first() == Some(&alloy_rlp::EMPTY_STRING_CODE) {
            fields = &fields[1..];
            None
        } else {
            let mut entries = decode_list(&mut fields)?;
            let mut limits = Vec::new();
            while !entries.is_empty() {
                let mut entry = decode_list(&mut entries)?;
                limits.push(TokenLimit {
                    token: Address::decode(&mut entry)?,
                    limit: U256::decode(&mut entry)?,
                    period: u64::decode(&mut entry)?,
                });
                if !entry.is_empty() {
                    return Err(alloy_rlp::Error::UnexpectedLength);
                }
            }
            Some(limits)
        };
        let allowed_calls = optional::<Vec<CallScope>>(&mut fields)?;
        let authority_config = B256::decode(&mut fields)?;
        if !fields.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        let carried = Self {
            valid_after,
            authority_config,
        };
        let auth = KeyAuthorization {
            chain_id,
            account: Some(account),
            key_type,
            key_id,
            expiry: Some(expiry),
            witness: Some(witness),
            limits,
            allowed_calls,
            is_admin: false,
        };
        carried
            .validate_policy(&auth)
            .map_err(alloy_rlp::Error::Custom)?;
        Ok((carried, auth))
    }

    /// Checks the canonical, state-independent restrictions for every entry path, including JSON.
    pub fn validate_policy(&self, auth: &KeyAuthorization) -> Result<(), &'static str> {
        let account = auth.account.ok_or("carried account is mandatory")?;
        if account.is_zero() || auth.key_id.is_zero() || auth.key_id == account {
            return Err("invalid carried account or key");
        }
        if auth.chain_id == 0 || auth.is_admin || auth.witness.is_none() {
            return Err("invalid carried chain, admin flag or witness");
        }
        if auth
            .expiry
            .is_none_or(|expiry| self.valid_after >= expiry.get())
        {
            return Err("invalid carried validity interval");
        }
        if let Some(limits) = &auth.limits {
            if !limits.windows(2).all(|pair| pair[0].token < pair[1].token) {
                return Err("carried tokens must be strictly sorted");
            }
            for limit in limits {
                if !limit.token.is_tip20()
                    || (limit.period != 0 && limit.limit > U256::from(u128::MAX))
                {
                    return Err("invalid carried token limit");
                }
            }
        }
        if let Some(scopes) = &auth.allowed_calls {
            if !scopes
                .windows(2)
                .all(|pair| pair[0].target < pair[1].target)
            {
                return Err("carried targets must be strictly sorted");
            }
            for scope in scopes {
                if scope.target.is_zero() {
                    return Err("carried target must be nonzero");
                }
                if !scope
                    .selector_rules
                    .windows(2)
                    .all(|pair| pair[0].selector < pair[1].selector)
                {
                    return Err("carried selectors must be strictly sorted");
                }
                for rule in &scope.selector_rules {
                    if !rule.recipients.windows(2).all(|pair| pair[0] < pair[1])
                        || rule.recipients.iter().any(|address| address.is_zero())
                    {
                        return Err("carried recipients must be nonzero and strictly sorted");
                    }
                    if !rule.recipients.is_empty() {
                        use alloy_sol_types::SolCall;
                        use tempo_contracts::precompiles::ITIP20;
                        if !scope.target.is_tip20()
                            || ![
                                ITIP20::transferCall::SELECTOR,
                                ITIP20::approveCall::SELECTOR,
                                ITIP20::transferWithMemoCall::SELECTOR,
                            ]
                            .contains(&rule.selector)
                        {
                            return Err("invalid carried recipient constraint");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Top-level scope check; caller must charge the full policy scan before running any call.
    pub fn allows_call(&self, auth: &KeyAuthorization, to: &TxKind, input: &[u8]) -> bool {
        let TxKind::Call(target) = to else {
            return false;
        };
        let Some(scopes) = &auth.allowed_calls else {
            return true;
        };
        let Ok(index) = scopes.binary_search_by_key(target, |scope| scope.target) else {
            return false;
        };
        let rules = &scopes[index].selector_rules;
        if rules.is_empty() {
            return true;
        }
        let Some(selector) = input.get(..4) else {
            return false;
        };
        let Ok(index) = rules.binary_search_by(|rule| rule.selector.as_slice().cmp(selector))
        else {
            return false;
        };
        let recipients = &rules[index].recipients;
        if recipients.is_empty() {
            return true;
        }
        let Some(word) = input.get(4..36) else {
            return false;
        };
        word[..12].iter().all(|byte| *byte == 0)
            && recipients
                .binary_search(&Address::from_slice(&word[12..]))
                .is_ok()
    }

    /// Token, target, selector and recipient counts for bounded gas accounting.
    pub fn entries(&self, auth: &KeyAuthorization) -> (u64, u64) {
        let policy = auth.allowed_calls.as_ref().map_or(0, |scopes| {
            scopes
                .iter()
                .map(|scope| {
                    1 + scope
                        .selector_rules
                        .iter()
                        .map(|rule| 1 + rule.recipients.len() as u64)
                        .sum::<u64>()
                })
                .sum()
        });
        (
            auth.limits.as_ref().map_or(0, |limits| limits.len() as u64),
            policy,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{PrimitiveSignature, SignedKeyAuthorization, TempoTransaction};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    fn fixture() -> (KeyAuthorization, CarriedAuthorization, PrivateKeySigner) {
        let issuer = PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap();
        let mut auth =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::repeat_byte(2))
                .with_account(issuer.address())
                .with_witness(B256::ZERO);
        auth.expiry = NonZeroU64::new(1_000);
        (
            auth,
            CarriedAuthorization {
                valid_after: 100,
                authority_config: B256::ZERO,
            },
            issuer,
        )
    }

    fn sign(
        auth: KeyAuthorization,
        carried: CarriedAuthorization,
        issuer: &PrivateKeySigner,
    ) -> SignedKeyAuthorization {
        let signature = PrimitiveSignature::Secp256k1(
            issuer
                .sign_hash_sync(&carried.signature_hash(&auth))
                .unwrap(),
        );
        SignedKeyAuthorization::new_carried(auth, carried, signature).unwrap()
    }

    #[test]
    fn carried_rlp_json_and_signing_domains() {
        let (auth, carried, issuer) = fixture();
        assert_eq!(CARRIED_AUTHORIZATION_TAG.len(), 20);
        let signed = sign(auth.clone(), carried.clone(), &issuer);
        assert_eq!(signed.recover_signer().unwrap(), issuer.address());
        let encoded = alloy_rlp::encode(&signed);
        assert_eq!(
            SignedKeyAuthorization::decode(&mut encoded.as_slice()).unwrap(),
            signed
        );
        assert_eq!(
            serde_json::from_str::<SignedKeyAuthorization>(
                &serde_json::to_string(&signed).unwrap()
            )
            .unwrap(),
            signed
        );
        assert_ne!(signed.signature_hash(), auth.signature_hash());
        for index in 0..encoded.len() {
            assert!(SignedKeyAuthorization::decode(&mut &encoded[..index]).is_err());
        }
        let mut tx = TempoTransaction {
            key_authorization: Some(signed.clone()),
            ..Default::default()
        };
        let digest = tx.signature_hash();
        let sponsor = tx.fee_payer_signature_hash(issuer.address());
        tx.key_authorization
            .as_mut()
            .unwrap()
            .carried
            .as_mut()
            .unwrap()
            .authority_config = B256::repeat_byte(3);
        assert_ne!(tx.signature_hash(), digest);
        assert_ne!(tx.fee_payer_signature_hash(issuer.address()), sponsor);
        let mut resigned = signed.clone();
        resigned.signature =
            PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature()).into();
        assert_eq!(
            signed.signature_hash(),
            resigned.signature_hash(),
            "signature bytes cannot mint another budget"
        );
    }

    #[test]
    fn carried_policy_distinctions_and_canonical_order() {
        let (mut auth, carried, _) = fixture();
        let unlimited = carried.signature_hash(&auth);
        auth.limits = Some(vec![]);
        assert_ne!(carried.signature_hash(&auth), unlimited);
        let token = alloy_primitives::address!("20c0000000000000000000000000000000000000");
        auth.limits = Some(vec![TokenLimit {
            token,
            limit: U256::MAX,
            period: 0,
        }]);
        carried.validate_policy(&auth).unwrap();
        auth.limits.as_mut().unwrap()[0].period = 1;
        assert!(carried.validate_policy(&auth).is_err());
        auth.limits.as_mut().unwrap()[0].limit = U256::from(u128::MAX);
        carried.validate_policy(&auth).unwrap();
        let duplicate = auth.limits.as_ref().unwrap()[0].clone();
        auth.limits.as_mut().unwrap().push(duplicate);
        assert!(carried.validate_policy(&auth).is_err());
    }

    #[test]
    fn carried_exact_byte_boundaries() {
        let (mut auth, carried, issuer) = fixture();
        let mut found = [false; 4];
        for targets in 0..180 {
            auth.allowed_calls = Some(
                (1..=targets)
                    .map(|i| {
                        let mut address = [0; 20];
                        address[18..].copy_from_slice(&(i as u16).to_be_bytes());
                        CallScope {
                            target: Address::from(address),
                            selector_rules: vec![],
                        }
                    })
                    .collect(),
            );
            for cap_bytes in 0..=32 {
                let cap = U256::from_be_slice(&[0x55; 32][..cap_bytes]);
                auth.limits = Some(vec![TokenLimit {
                    token: alloy_primitives::address!("20c0000000000000000000000000000000000000"),
                    limit: cap,
                    period: 0,
                }]);
                let signature: TempoSignature = PrimitiveSignature::Secp256k1(
                    issuer
                        .sign_hash_sync(&carried.signature_hash(&auth))
                        .unwrap(),
                )
                .into();
                let bytes = carried.encode_signed(&auth, &signature);
                if let Some(index) = [1024, 1025, 4096, 4097]
                    .iter()
                    .position(|size| *size == bytes.len())
                {
                    found[index] = true;
                    assert_eq!(
                        SignedKeyAuthorization::decode(&mut bytes.as_slice()).is_ok(),
                        bytes.len() <= 4096
                    );
                    if let Ok(auth) = SignedKeyAuthorization::decode(&mut bytes.as_slice()) {
                        use alloy_sol_types::SolCall;
                        let tx = TempoTransaction {
                            key_authorization: Some(auth),
                            calls: vec![crate::transaction::Call {
                                to: TxKind::Call(alloy_primitives::address!(
                                    "20c0000000000000000000000000000000000000"
                                )),
                                value: U256::ZERO,
                                input: tempo_contracts::precompiles::ITIP20::transferCall {
                                    to: Address::repeat_byte(3),
                                    amount: U256::from(1),
                                }
                                .abi_encode()
                                .into(),
                            }],
                            ..Default::default()
                        };
                        let envelope =
                            crate::TempoTxEnvelope::AA(tx.into_signed(signature.clone()));
                        assert_eq!(envelope.is_payment_v2(), bytes.len() <= 1024);
                    }
                }
            }
        }
        assert!(
            found.iter().all(|found| *found),
            "every exact boundary is exercised: {found:?}"
        );
    }
}
