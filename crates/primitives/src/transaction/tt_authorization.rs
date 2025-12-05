use alloy_eips::eip7702::{Authorization, RecoveredAuthority, RecoveredAuthorization};
use alloy_primitives::{Address, B256, keccak256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header, Result as RlpResult, length_of_length};
use core::ops::Deref;
use std::sync::OnceLock;

use crate::TempoSignature;

/// EIP-7702 authorization magic byte
pub const MAGIC: u8 = 0x05;

/// A signed EIP-7702 authorization with AA signature support.
///
/// This is a 1:1 parallel to alloy's `SignedAuthorization`, but using `TempoSignature`
/// instead of hardcoded (y_parity, r, s) components. This allows supporting multiple
/// signature types: Secp256k1, P256, and WebAuthn.
///
/// The structure and methods mirror `SignedAuthorization` exactly to maintain
/// compatibility with the EIP-7702 spec.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
pub struct TempoSignedAuthorization {
    /// Inner authorization (reuses alloy's Authorization)
    #[cfg_attr(feature = "serde", serde(flatten))]
    inner: Authorization,
    /// The AA signature (Secp256k1, P256, or WebAuthn)
    signature: TempoSignature,
}

impl TempoSignedAuthorization {
    /// Creates a new signed authorization from an authorization and signature.
    ///
    /// This is the unchecked version - signature is not validated.
    pub const fn new_unchecked(inner: Authorization, signature: TempoSignature) -> Self {
        Self { inner, signature }
    }

    /// Gets the `signature` for the authorization.
    ///
    /// Returns a reference to the AA signature, which can be Secp256k1, P256, or WebAuthn.
    pub const fn signature(&self) -> &TempoSignature {
        &self.signature
    }

    /// Returns the inner [`Authorization`].
    pub fn strip_signature(self) -> Authorization {
        self.inner
    }

    /// Returns a reference to the inner [`Authorization`].
    pub const fn inner(&self) -> &Authorization {
        &self.inner
    }

    /// Computes the signature hash used to sign the authorization.
    ///
    /// The signature hash is `keccak(MAGIC || rlp([chain_id, address, nonce]))`
    /// following EIP-7702 spec.
    #[inline]
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::new();
        buf.push(MAGIC);
        self.inner.encode(&mut buf);
        keccak256(buf)
    }

    /// Recover the authority for the authorization.
    ///
    /// # Note
    ///
    /// Implementers should check that the authority has no code.
    pub fn recover_authority(&self) -> Result<Address, alloy_consensus::crypto::RecoveryError> {
        let sig_hash = self.signature_hash();
        self.signature.recover_signer(&sig_hash)
    }

    /// Recover the authority and transform the signed authorization into a
    /// [`RecoveredAuthorization`].
    pub fn into_recovered(self) -> RecoveredAuthorization {
        let authority_result = self.recover_authority();
        let authority =
            authority_result.map_or(RecoveredAuthority::Invalid, RecoveredAuthority::Valid);

        RecoveredAuthorization::new_unchecked(self.inner, authority)
    }

    /// Decodes the authorization from RLP bytes, including the signature.
    fn decode_fields(buf: &mut &[u8]) -> RlpResult<Self> {
        Ok(Self {
            inner: Authorization {
                chain_id: Decodable::decode(buf)?,
                address: Decodable::decode(buf)?,
                nonce: Decodable::decode(buf)?,
            },
            signature: Decodable::decode(buf)?,
        })
    }

    /// Outputs the length of the authorization's fields, without a RLP header.
    fn fields_len(&self) -> usize {
        self.inner.chain_id.length() +
            self.inner.address.length() +
            self.inner.nonce.length() +
            self.signature.length()
    }

    /// Calculates a heuristic for the in-memory size of this authorization
    pub fn size(&self) -> usize {
        core::mem::size_of::<Authorization>() + self.signature.size()
    }
}

impl Decodable for TempoSignedAuthorization {
    fn decode(buf: &mut &[u8]) -> RlpResult<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let started_len = buf.len();

        let this = Self::decode_fields(buf)?;

        let consumed = started_len - buf.len();
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }

        Ok(this)
    }
}

impl Encodable for TempoSignedAuthorization {
    fn encode(&self, buf: &mut dyn BufMut) {
        Header { list: true, payload_length: self.fields_len() }.encode(buf);
        self.inner.chain_id.encode(buf);
        self.inner.address.encode(buf);
        self.inner.nonce.encode(buf);
        self.signature.encode(buf);
    }

    fn length(&self) -> usize {
        let len = self.fields_len();
        len + length_of_length(len)
    }
}

impl Deref for TempoSignedAuthorization {
    type Target = Authorization;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// Compact implementation for reth storage
#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for TempoSignedAuthorization {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        // Encode using RLP
        let start_len = buf.remaining_mut();
        self.encode(buf);
        start_len - buf.remaining_mut()
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let mut buf_slice = &buf[..len];
        let auth = Self::decode(&mut buf_slice).expect("valid RLP encoding");
        (auth, &buf[len..])
    }
}

/// A recovered EIP-7702 authorization with AA signature support.
///
/// This wraps an `TempoSignedAuthorization` with lazy authority recovery.
/// The signature is preserved for gas calculation, and the authority
/// is recovered on first access and cached.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecoveredTempoAuthorization {
    /// Signed authorization (contains inner auth and signature)
    signed: TempoSignedAuthorization,
    /// Lazily recovered authority (cached after first access)
    #[cfg_attr(feature = "serde", serde(skip))]
    authority: OnceLock<RecoveredAuthority>,
}

impl RecoveredTempoAuthorization {
    /// Creates a new authorization from a signed authorization.
    ///
    /// Authority recovery is deferred until first access.
    pub const fn new(signed: TempoSignedAuthorization) -> Self {
        Self { signed, authority: OnceLock::new() }
    }

    /// Creates a new authorization with a pre-recovered authority.
    ///
    /// This is useful when you've already recovered the authority and want
    /// to avoid re-recovery.
    pub fn new_unchecked(signed: TempoSignedAuthorization, authority: RecoveredAuthority) -> Self {
        Self { signed, authority: authority.into() }
    }

    /// Creates a new authorization and immediately recovers the authority.
    ///
    /// Unlike `new()`, this eagerly recovers the authority upfront and caches it.
    pub fn recover(signed: TempoSignedAuthorization) -> Self {
        let authority = signed
            .recover_authority()
            .map_or(RecoveredAuthority::Invalid, RecoveredAuthority::Valid);
        Self::new_unchecked(signed, authority)
    }

    /// Returns a reference to the signed authorization.
    pub const fn signed(&self) -> &TempoSignedAuthorization {
        &self.signed
    }

    /// Returns a reference to the inner [`Authorization`].
    pub const fn inner(&self) -> &Authorization {
        self.signed.inner()
    }

    /// Gets the `signature` for the authorization.
    pub const fn signature(&self) -> &TempoSignature {
        self.signed.signature()
    }

    /// Returns the recovered authority, if valid.
    ///
    /// Recovers the authority on first access and caches the result.
    pub fn authority(&self) -> Option<Address> {
        match self.authority_status() {
            RecoveredAuthority::Valid(addr) => Some(*addr),
            RecoveredAuthority::Invalid => None,
        }
    }

    /// Returns the recovered authority status.
    ///
    /// Recovers the authority on first access and caches the result.
    pub fn authority_status(&self) -> &RecoveredAuthority {
        self.authority.get_or_init(|| {
            self.signed
                .recover_authority()
                .map_or(RecoveredAuthority::Invalid, RecoveredAuthority::Valid)
        })
    }

    /// Converts into a standard `RecoveredAuthorization`, dropping the signature.
    pub fn into_recovered_authorization(self) -> RecoveredAuthorization {
        let authority = self.authority_status().clone();
        RecoveredAuthorization::new_unchecked(self.signed.strip_signature(), authority)
    }
}

impl PartialEq for RecoveredTempoAuthorization {
    fn eq(&self, other: &Self) -> bool {
        self.signed == other.signed
    }
}

impl Eq for RecoveredTempoAuthorization {}

impl core::hash::Hash for RecoveredTempoAuthorization {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.signed.hash(state);
    }
}

impl Deref for RecoveredTempoAuthorization {
    type Target = Authorization;

    fn deref(&self) -> &Self::Target {
        self.signed.inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TempoSignature;
    use alloy_primitives::{U256, address};

    #[test]
    fn test_aa_signed_auth_encode_decode_roundtrip() {
        let auth = Authorization {
            chain_id: U256::from(1),
            address: address!("0000000000000000000000000000000000000006"),
            nonce: 1,
        };

        let signature = TempoSignature::default(); // Use secp256k1 test signature
        let signed = TempoSignedAuthorization::new_unchecked(auth, signature);

        let mut buf = Vec::new();
        signed.encode(&mut buf);

        let decoded = TempoSignedAuthorization::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(buf.len(), signed.length());
        assert_eq!(decoded, signed);
    }

    #[test]
    fn test_signature_hash() {
        let auth = Authorization {
            chain_id: U256::from(1),
            address: address!("0000000000000000000000000000000000000006"),
            nonce: 1,
        };

        let signature = TempoSignature::default();
        let signed = TempoSignedAuthorization::new_unchecked(auth.clone(), signature);

        // Signature hash should match alloy's calculation
        let expected_hash = {
            let mut buf = Vec::new();
            buf.push(MAGIC);
            auth.encode(&mut buf);
            keccak256(buf)
        };

        assert_eq!(signed.signature_hash(), expected_hash);
    }
}
