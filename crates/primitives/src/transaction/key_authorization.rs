use super::{AASignature, SignatureType};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_rlp::{BufMut, Decodable, Encodable, encode_list, list_length};
use core::mem;

/// Token spending limit for access keys
///
/// Defines a per-token spending limit for an access key provisioned via key_authorization.
/// This limit is enforced by the AccountKeychain precompile when the key is used.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
#[derive(alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
pub struct TokenLimit {
    /// TIP20 token address
    pub token: Address,

    /// Maximum spending amount for this token (enforced over the key's lifetime)
    pub limit: U256,
}

/// Key authorization for provisioning access keys
///
/// Used in TxAA to add a new key to the AccountKeychain precompile.
/// The transaction must be signed by the root key to authorize adding this access key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
pub struct KeyAuthorization {
    /// Type of key being authorized (Secp256k1, P256, or WebAuthn)
    pub key_type: SignatureType,

    /// Unix timestamp when key expires (0 = never expires)
    pub expiry: u64,

    /// TIP20 spending limits for this key
    pub limits: Vec<TokenLimit>,

    /// Key identifier, is the address derived from the public key of the key type.
    pub key_id: Address,

    /// Signature authorizing this key (signed by root key)
    pub signature: AASignature,
}

impl KeyAuthorization {
    /// Returns the RLP header for this key authorization
    #[inline]
    fn rlp_header(&self) -> alloy_rlp::Header {
        let payload_length = 1 // key_type as u8
            + self.expiry.length()
            + self.limits.length()
            + self.key_id.length()
            + self.signature.length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
    }
    /// Computes the authorization message hash to be signed by the root key.
    ///
    /// The message format is: `keccak256(rlp([key_type, key_id, expiry, limits]))`
    ///
    /// Note: The signature field is NOT included in this hash, as it signs this hash.
    pub fn authorization_message_hash(
        key_type: SignatureType,
        key_id: Address,
        expiry: u64,
        limits: &[TokenLimit],
    ) -> B256 {
        let mut auth_message = Vec::new();
        let key_type_byte: u8 = key_type.into();

        // Calculate payload length
        let payload_length =
            key_type_byte.length() + key_id.length() + expiry.length() + list_length(limits);

        // Encode outer list header
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(&mut auth_message);

        // Encode fields
        key_type_byte.encode(&mut auth_message);
        key_id.encode(&mut auth_message);
        expiry.encode(&mut auth_message);
        encode_list(limits, &mut auth_message);

        keccak256(&auth_message)
    }
}

impl Encodable for KeyAuthorization {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_header().encode(out);
        // Encode key_type as u8
        let sig_type_byte: u8 = self.key_type.clone().into();
        sig_type_byte.encode(out);
        self.expiry.encode(out);
        self.limits.encode(out);
        self.key_id.encode(out);
        self.signature.encode(out);
    }

    fn length(&self) -> usize {
        self.rlp_header().length_with_payload()
    }
}

impl Decodable for KeyAuthorization {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        if header.payload_length > remaining {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        // Decode key_type from u8
        let sig_type_byte: u8 = Decodable::decode(buf)?;
        let key_type = match sig_type_byte {
            0 => SignatureType::Secp256k1,
            1 => SignatureType::P256,
            2 => SignatureType::WebAuthn,
            _ => return Err(alloy_rlp::Error::Custom("Invalid signature type")),
        };

        let expiry: u64 = Decodable::decode(buf)?;
        let limits: Vec<TokenLimit> = Decodable::decode(buf)?;
        let key_id: Address = Decodable::decode(buf)?;
        let signature_bytes: Bytes = Decodable::decode(buf)?;
        let signature =
            AASignature::from_bytes(&signature_bytes).map_err(alloy_rlp::Error::Custom)?;

        let this = Self {
            key_type,
            expiry,
            limits,
            key_id,
            signature,
        };

        if buf.len() + header.payload_length != remaining {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        Ok(this)
    }
}

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for KeyAuthorization {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        // Use RLP encoding for compact representation
        let mut rlp_buf = Vec::new();
        alloy_rlp::Encodable::encode(self, &mut rlp_buf);
        let len = rlp_buf.len();
        buf.put_slice(&rlp_buf);
        len
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let item = alloy_rlp::Decodable::decode(&mut buf)
            .expect("Failed to decode KeyAuthorization from compact");
        (item, buf)
    }
}

impl reth_primitives_traits::InMemorySize for KeyAuthorization {
    fn size(&self) -> usize {
        mem::size_of::<u8>() + // key_type
        mem::size_of::<u64>() + // expiry
        mem::size_of::<Address>() + // key_id
        self.signature.size() + // signature
        self.limits.iter().map(|_limit| {
            mem::size_of::<Address>() + mem::size_of::<U256>()
        }).sum::<usize>()
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for KeyAuthorization {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate key_type independently - this is the type of KEY being authorized,
        // not the type of the authorization signature
        let key_type = u.arbitrary()?;

        // Generate an actual arbitrary signature for comprehensive testing
        let signature = u.arbitrary()?;

        Ok(Self {
            key_type,
            expiry: u.arbitrary()?,
            limits: u.arbitrary()?,
            key_id: u.arbitrary()?,
            signature,
        })
    }
}
