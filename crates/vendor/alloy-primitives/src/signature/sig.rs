#![allow(clippy::missing_const_for_fn)] // On purpose for forward compatibility.

use crate::{B256, U256, hex, normalize_v, signature::SignatureError, uint};
use alloc::vec::Vec;
use core::{fmt::Display, str::FromStr};

#[cfg(any(feature = "k256", feature = "secp256k1"))]
use crate::Address;

/// The order of the [Secp256k1](https://en.bitcoin.it/wiki/Secp256k1) curve.
const SECP256K1N_ORDER: U256 =
    uint!(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_U256);

/// An Ethereum ECDSA signature.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression, diesel::FromSqlRow))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Binary))]
pub struct Signature {
    y_parity: bool,
    r: U256,
    s: U256,
}

impl Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{}", hex::encode(self.as_bytes()))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = SignatureError;

    /// Parses a 65-byte long raw signature.
    ///
    /// See [`from_raw`](Self::from_raw).
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_raw(bytes)
    }
}

impl FromStr for Signature {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_raw_array(&hex::decode_to_array(s)?)
    }
}

impl From<&Signature> for [u8; 65] {
    #[inline]
    fn from(value: &Signature) -> [u8; 65] {
        value.as_bytes()
    }
}

impl From<Signature> for [u8; 65] {
    #[inline]
    fn from(value: Signature) -> [u8; 65] {
        value.as_bytes()
    }
}

impl From<&Signature> for Vec<u8> {
    #[inline]
    fn from(value: &Signature) -> Self {
        value.as_bytes().to_vec()
    }
}

impl From<Signature> for Vec<u8> {
    #[inline]
    fn from(value: Signature) -> Self {
        value.as_bytes().to_vec()
    }
}

#[cfg(feature = "k256")]
impl From<(k256::ecdsa::Signature, k256::ecdsa::RecoveryId)> for Signature {
    fn from(value: (k256::ecdsa::Signature, k256::ecdsa::RecoveryId)) -> Self {
        Self::from_signature_and_parity(value.0, value.1.is_y_odd())
    }
}

#[cfg(feature = "secp256k1")]
impl From<secp256k1::ecdsa::RecoverableSignature> for Signature {
    fn from(value: secp256k1::ecdsa::RecoverableSignature) -> Self {
        let (recid, bytes) = value.serialize_compact();
        let r = U256::from_be_slice(&bytes[..32]);
        let s = U256::from_be_slice(&bytes[32..]);
        let v = matches!(
            recid,
            secp256k1::ecdsa::RecoveryId::One | secp256k1::ecdsa::RecoveryId::Three
        );
        Self { y_parity: v, r, s }
    }
}

#[cfg(feature = "k256")]
impl TryFrom<Signature> for k256::ecdsa::Signature {
    type Error = k256::ecdsa::Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        value.to_k256()
    }
}

#[cfg(feature = "rlp")]
impl Signature {
    /// Decode an RLP-encoded VRS signature. Accepts `decode_parity` closure which allows to
    /// customize parity decoding and possibly extract additional data from it (e.g chain_id for
    /// legacy signature).
    pub fn decode_rlp_vrs(
        buf: &mut &[u8],
        decode_parity: impl FnOnce(&mut &[u8]) -> alloy_rlp::Result<bool>,
    ) -> Result<Self, alloy_rlp::Error> {
        use alloy_rlp::Decodable;

        let parity = decode_parity(buf)?;
        let r = Decodable::decode(buf)?;
        let s = Decodable::decode(buf)?;

        Ok(Self::new(r, s, parity))
    }
}

impl Signature {
    /// Instantiate a new signature from `r`, `s`, and `v` values.
    #[inline]
    pub const fn new(r: U256, s: U256, y_parity: bool) -> Self {
        Self { r, s, y_parity }
    }

    /// Parses a 65-byte long raw signature.
    ///
    /// The first 32 bytes is the `r` value, the second 32 bytes the `s` value, and the final byte
    /// is the `v` value in 'Electrum' notation.
    #[inline]
    pub fn from_raw(bytes: &[u8]) -> Result<Self, SignatureError> {
        Self::from_raw_array(
            bytes.try_into().map_err(|_| SignatureError::FromBytes("expected exactly 65 bytes"))?,
        )
    }

    /// Parses a 65-byte long raw signature.
    ///
    /// See [`from_raw`](Self::from_raw).
    #[inline]
    pub fn from_raw_array(bytes: &[u8; 65]) -> Result<Self, SignatureError> {
        let [bytes @ .., v] = bytes;
        let v = *v as u64;
        let Some(parity) = normalize_v(v) else { return Err(SignatureError::InvalidParity(v)) };
        Ok(Self::from_bytes_and_parity(bytes, parity))
    }

    /// Parses a signature from a byte slice, with a v value
    ///
    /// # Panics
    ///
    /// If the slice is not at least 64 bytes long.
    #[inline]
    #[track_caller]
    pub fn from_bytes_and_parity(bytes: &[u8], parity: bool) -> Self {
        let (r_bytes, s_bytes) = bytes[..64].split_at(32);
        let r = U256::from_be_slice(r_bytes);
        let s = U256::from_be_slice(s_bytes);
        Self::new(r, s, parity)
    }

    /// Returns the byte-array representation of this signature.
    ///
    /// The first 32 bytes are the `r` value, the second 32 bytes the `s` value
    /// and the final byte is the `v` value in 'Electrum' notation.
    #[inline]
    pub fn as_bytes(&self) -> [u8; 65] {
        let mut sig = [0u8; 65];
        sig[..32].copy_from_slice(&self.r.to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&self.s.to_be_bytes::<32>());
        sig[64] = 27 + self.y_parity as u8;
        sig
    }

    /// Returns the byte-array representation of this signature as (r, s, y_parity).
    ///
    /// The first 32 bytes are the `r` value, the second 32 bytes the `s` value,
    /// and the final byte is the `y_parity` value as-is (0 or 1).
    ///
    /// See [`as_erc2098`](Self::as_erc2098) for the compact ERC-2098 representation.
    #[inline]
    pub fn as_rsy(&self) -> [u8; 65] {
        let mut sig = [0u8; 65];
        sig[..32].copy_from_slice(&self.r.to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&self.s.to_be_bytes::<32>());
        sig[64] = self.y_parity as u8;
        sig
    }

    /// Decode the signature from the ERC-2098 compact representation.
    ///
    /// The first 32 bytes are the `r` value, and the next 32 bytes are the `s` value with `yParity`
    /// in the top bit of the `s` value, as described in ERC-2098.
    ///
    /// See <https://eips.ethereum.org/EIPS/eip-2098>
    ///
    /// # Panics
    ///
    /// If the slice is not at least 64 bytes long.
    pub fn from_erc2098(bytes: &[u8]) -> Self {
        let (r_bytes, y_and_s_bytes) = bytes[..64].split_at(32);
        let r = U256::from_be_slice(r_bytes);
        let y_and_s = U256::from_be_slice(y_and_s_bytes);
        let y_parity = y_and_s.bit(255);
        let mut s = y_and_s;
        s.set_bit(255, false);
        Self { y_parity, r, s }
    }

    /// Returns the ERC-2098 compact representation of this signature.
    ///
    /// The first 32 bytes are the `r` value, and the next 32 bytes are the `s` value with `yParity`
    /// in the top bit of the `s` value, as described in ERC-2098.
    ///
    /// See <https://eips.ethereum.org/EIPS/eip-2098>
    pub fn as_erc2098(&self) -> [u8; 64] {
        let normalized = self.normalized_s();
        // The top bit of the `s` parameters is always 0, due to the use of canonical
        // signatures which flip the solution parity to prevent negative values, which was
        // introduced as a constraint in Homestead.
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&normalized.r().to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&normalized.s().to_be_bytes::<32>());
        debug_assert_eq!(sig[32] >> 7, 0, "top bit of s should be 0");
        sig[32] |= (normalized.y_parity as u8) << 7;
        sig
    }

    /// Sets the recovery ID by normalizing a `v` value.
    #[inline]
    pub fn with_parity(mut self, v: bool) -> Self {
        self.y_parity = v;
        self
    }

    /// Returns the inner ECDSA signature.
    #[cfg(feature = "k256")]
    #[inline]
    pub fn to_k256(self) -> Result<k256::ecdsa::Signature, k256::ecdsa::Error> {
        k256::ecdsa::Signature::from_scalars(self.r.to_be_bytes(), self.s.to_be_bytes())
    }

    /// Returns the inner ECDSA recoverable signature using the `secp256k1` backend.
    #[cfg(feature = "secp256k1")]
    #[inline]
    pub fn to_secp256k1(&self) -> Result<secp256k1::ecdsa::RecoverableSignature, secp256k1::Error> {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r.to_be_bytes::<32>());
        bytes[32..].copy_from_slice(&self.s.to_be_bytes::<32>());
        secp256k1::ecdsa::RecoverableSignature::from_compact(&bytes, self.secp256k1_recid())
    }

    /// Instantiate from a signature and recovery id
    #[cfg(feature = "k256")]
    pub fn from_signature_and_parity(sig: k256::ecdsa::Signature, v: bool) -> Self {
        let r = U256::from_be_slice(sig.r().to_bytes().as_ref());
        let s = U256::from_be_slice(sig.s().to_bytes().as_ref());
        Self { y_parity: v, r, s }
    }

    /// Creates a [`Signature`] from the serialized `r` and `s` scalar values, which
    /// comprise the ECDSA signature, alongside a `v` value, used to determine the recovery ID.
    #[inline]
    pub fn from_scalars_and_parity(r: B256, s: B256, parity: bool) -> Self {
        Self::new(U256::from_be_bytes(r.0), U256::from_be_bytes(s.0), parity)
    }

    /// Normalizes the signature into "low S" form as described in
    /// [BIP 0062: Dealing with Malleability][1].
    ///
    /// If `s` is already normalized, returns `None`.
    ///
    /// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    #[inline]
    pub fn normalize_s(&self) -> Option<Self> {
        let s = self.s();
        if s > SECP256K1N_ORDER >> 1 {
            Some(Self { y_parity: !self.y_parity, r: self.r, s: SECP256K1N_ORDER - s })
        } else {
            None
        }
    }

    /// Normalizes the signature into "low S" form as described in
    /// [BIP 0062: Dealing with Malleability][1].
    ///
    /// If `s` is already normalized, returns `self`.
    ///
    /// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    #[inline]
    pub fn normalized_s(self) -> Self {
        self.normalize_s().unwrap_or(self)
    }

    /// Returns the recovery ID.
    #[cfg(feature = "k256")]
    #[inline]
    pub fn recid(&self) -> k256::ecdsa::RecoveryId {
        k256::ecdsa::RecoveryId::new(self.y_parity, false)
    }

    /// Returns the recovery ID as a [`secp256k1::ecdsa::RecoveryId`].
    #[cfg(feature = "secp256k1")]
    #[inline]
    pub fn secp256k1_recid(&self) -> secp256k1::ecdsa::RecoveryId {
        if self.y_parity {
            secp256k1::ecdsa::RecoveryId::One
        } else {
            secp256k1::ecdsa::RecoveryId::Zero
        }
    }

    /// Recovers an [`Address`] from this signature and the given message by first prefixing and
    /// hashing the message according to [EIP-191](crate::eip191_hash_message).
    #[cfg(any(feature = "k256", feature = "secp256k1"))]
    #[inline]
    pub fn recover_address_from_msg<T: AsRef<[u8]>>(
        &self,
        msg: T,
    ) -> Result<Address, SignatureError> {
        self.recover_address_from_prehash(&crate::eip191_hash_message(msg))
    }

    /// Recovers an [`Address`] from this signature and the given prehashed message.
    #[cfg(any(feature = "k256", feature = "secp256k1"))]
    #[inline]
    pub fn recover_address_from_prehash(&self, prehash: &B256) -> Result<Address, SignatureError> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "secp256k1")] {
                let pubkey = self.recover_from_prehash_secp256k1(prehash)?;
                Ok(Address::from_raw_public_key(&pubkey.serialize_uncompressed()[1..]))
            } else {
                let vk = self.recover_from_prehash_k256(prehash)?;
                Ok(Address::from_public_key(&vk))
            }
        }
    }

    /// Recovers a [`VerifyingKey`] from this signature and the given message by first prefixing and
    /// hashing the message according to [EIP-191](crate::eip191_hash_message).
    ///
    /// [`VerifyingKey`]: k256::ecdsa::VerifyingKey
    #[cfg(feature = "k256")]
    #[inline]
    pub fn recover_from_msg<T: AsRef<[u8]>>(
        &self,
        msg: T,
    ) -> Result<k256::ecdsa::VerifyingKey, SignatureError> {
        self.recover_from_prehash(&crate::eip191_hash_message(msg))
    }

    /// Recovers a [`VerifyingKey`] from this signature and the given prehashed message.
    ///
    /// [`VerifyingKey`]: k256::ecdsa::VerifyingKey
    #[cfg(feature = "k256")]
    #[inline]
    pub fn recover_from_prehash(
        &self,
        prehash: &B256,
    ) -> Result<k256::ecdsa::VerifyingKey, SignatureError> {
        self.recover_from_prehash_k256(prehash)
    }

    /// Recovers a [`VerifyingKey`] using the `k256` backend.
    ///
    /// [`VerifyingKey`]: k256::ecdsa::VerifyingKey
    #[cfg(feature = "k256")]
    #[inline]
    fn recover_from_prehash_k256(
        &self,
        prehash: &B256,
    ) -> Result<k256::ecdsa::VerifyingKey, SignatureError> {
        let this = self.normalized_s();
        k256::ecdsa::VerifyingKey::recover_from_prehash(
            prehash.as_slice(),
            &this.to_k256()?,
            this.recid(),
        )
        .map_err(Into::into)
    }

    /// Recovers a [`secp256k1::PublicKey`] from this signature and the given message by first
    /// prefixing and hashing the message according to [EIP-191](crate::eip191_hash_message).
    #[cfg(feature = "secp256k1")]
    #[inline]
    pub fn recover_from_msg_secp256k1<T: AsRef<[u8]>>(
        &self,
        msg: T,
    ) -> Result<secp256k1::PublicKey, SignatureError> {
        self.recover_from_prehash_secp256k1(&crate::eip191_hash_message(msg))
    }

    /// Recovers a [`secp256k1::PublicKey`] from this signature and the given prehashed message.
    #[cfg(feature = "secp256k1")]
    #[inline]
    pub fn recover_from_prehash_secp256k1(
        &self,
        prehash: &B256,
    ) -> Result<secp256k1::PublicKey, SignatureError> {
        let this = self.normalized_s();
        let sig = this.to_secp256k1()?;
        let msg = secp256k1::Message::from_digest(prehash.0);
        let secp = secp256k1::Secp256k1::verification_only();
        secp.recover_ecdsa(msg, &sig).map_err(Into::into)
    }

    /// Returns the `r` component of this signature.
    #[inline]
    pub fn r(&self) -> U256 {
        self.r
    }

    /// Returns the `s` component of this signature.
    #[inline]
    pub fn s(&self) -> U256 {
        self.s
    }

    /// Returns the recovery ID as a `bool`.
    #[inline]
    pub fn v(&self) -> bool {
        self.y_parity
    }

    /// Length of RLP RS field encoding
    #[cfg(feature = "rlp")]
    pub fn rlp_rs_len(&self) -> usize {
        alloy_rlp::Encodable::length(&self.r) + alloy_rlp::Encodable::length(&self.s)
    }

    /// Write R and S to an RLP buffer in progress.
    #[cfg(feature = "rlp")]
    pub fn write_rlp_rs(&self, out: &mut dyn alloy_rlp::BufMut) {
        alloy_rlp::Encodable::encode(&self.r, out);
        alloy_rlp::Encodable::encode(&self.s, out);
    }

    /// Write the VRS to the output.
    #[cfg(feature = "rlp")]
    pub fn write_rlp_vrs(&self, out: &mut dyn alloy_rlp::BufMut, v: impl alloy_rlp::Encodable) {
        v.encode(out);
        self.write_rlp_rs(out);
    }

    #[doc(hidden)]
    #[inline(always)]
    pub fn test_signature() -> Self {
        Self::from_scalars_and_parity(
            b256!("0x840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565"),
            b256!("0x25e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1"),
            false,
        )
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?, u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for Signature {
    type Parameters = ();
    type Strategy = proptest::strategy::Map<
        <(U256, U256, bool) as proptest::arbitrary::Arbitrary>::Strategy,
        fn((U256, U256, bool)) -> Self,
    >;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        use proptest::strategy::Strategy;
        proptest::arbitrary::any::<(U256, U256, bool)>()
            .prop_map(|(r, s, y_parity)| Self::new(r, s, y_parity))
    }
}

#[cfg(feature = "serde")]
mod signature_serde {
    use super::Signature;
    use crate::{U64, U256, normalize_v};
    use serde::{Deserialize, Deserializer, Serialize};

    #[derive(Serialize, Deserialize)]
    struct HumanReadableRepr {
        r: U256,
        s: U256,
        #[serde(rename = "yParity")]
        y_parity: Option<U64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        v: Option<U64>,
    }

    type NonHumanReadableRepr = (U256, U256, U64);

    impl Serialize for Signature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            // if the serializer is human readable, serialize as a map, otherwise as a tuple
            if serializer.is_human_readable() {
                HumanReadableRepr {
                    y_parity: Some(U64::from(self.y_parity as u64)),
                    v: Some(U64::from(self.y_parity as u64)),
                    r: self.r,
                    s: self.s,
                }
                .serialize(serializer)
            } else {
                let repr: NonHumanReadableRepr = (self.r, self.s, U64::from(self.y_parity as u64));
                repr.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for Signature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let (y_parity, v, r, s) = if deserializer.is_human_readable() {
                let HumanReadableRepr { y_parity, v, r, s } = <_>::deserialize(deserializer)?;
                (y_parity, v, r, s)
            } else {
                let (r, s, y_parity) = NonHumanReadableRepr::deserialize(deserializer)?;
                (Some(y_parity), None, r, s)
            };

            // Attempt to extract `y_parity` bit from either `yParity` key or `v` value.
            let y_parity = if let Some(y_parity) = y_parity {
                match y_parity.to::<u64>() {
                    0 => false,
                    1 => true,
                    _ => return Err(serde::de::Error::custom("invalid yParity")),
                }
            } else if let Some(v) = v {
                normalize_v(v.to()).ok_or(serde::de::Error::custom("invalid v"))?
            } else {
                return Err(serde::de::Error::custom("missing `yParity` or `v`"));
            };

            Ok(Self::new(r, s, y_parity))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    #[cfg(feature = "rlp")]
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    #[cfg(feature = "k256")]
    #[cfg_attr(miri, ignore = "k256 is too slow under Miri")]
    fn can_recover_tx_sender_not_normalized() {
        let sig = Signature::from_str("48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c8041b").unwrap();
        let hash = b256!("0x5eb4f5a33c621f32a8622d5f943b6b102994dfe4e5aebbefe69bb1b2aa0fc93e");
        let expected = address!("0x0f65fe9276bc9a24ae7083ae28e2660ef72df99e");
        assert_eq!(sig.recover_address_from_prehash(&hash).unwrap(), expected);
    }

    #[test]
    #[cfg(feature = "k256")]
    #[cfg_attr(miri, ignore = "k256 is too slow under Miri")]
    fn recover_web3_signature() {
        // test vector taken from:
        // https://web3js.readthedocs.io/en/v1.2.2/web3-eth-accounts.html#sign
        let sig = Signature::from_str(
            "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c"
        ).expect("could not parse signature");
        let expected = address!("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
        assert_eq!(sig.recover_address_from_msg("Some data").unwrap(), expected);
    }

    #[test]
    fn signature_from_str() {
        let s1 = Signature::from_str(
            "0xaa231fbe0ed2b5418e6ba7c19bee2522852955ec50996c02a2fe3e71d30ddaf1645baf4823fea7cb4fcc7150842493847cfb6a6d63ab93e8ee928ee3f61f503500"
        ).expect("could not parse 0x-prefixed signature");

        let s2 = Signature::from_str(
            "aa231fbe0ed2b5418e6ba7c19bee2522852955ec50996c02a2fe3e71d30ddaf1645baf4823fea7cb4fcc7150842493847cfb6a6d63ab93e8ee928ee3f61f503500"
        ).expect("could not parse non-prefixed signature");

        assert_eq!(s1, s2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_with_parity() {
        let raw_signature_with_y_parity = serde_json::json!({
            "r": "0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0",
            "s": "0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05",
            "v": "0x1",
            "yParity": "0x1"
        });

        let signature: Signature = serde_json::from_value(raw_signature_with_y_parity).unwrap();

        let expected = Signature::new(
            U256::from_str("0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0")
                .unwrap(),
            U256::from_str("0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05")
                .unwrap(),
            true,
        );

        assert_eq!(signature, expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_both_parity() {
        // this test should be removed if the struct moves to an enum based on tx type
        let signature = Signature::new(
            U256::from_str("0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0")
                .unwrap(),
            U256::from_str("0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05")
                .unwrap(),
            true,
        );

        let serialized = serde_json::to_string(&signature).unwrap();
        assert_eq!(
            serialized,
            r#"{"r":"0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0","s":"0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05","yParity":"0x1","v":"0x1"}"#
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_v_only() {
        // this test should be removed if the struct moves to an enum based on tx type
        let signature = Signature::new(
            U256::from_str("0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0")
                .unwrap(),
            U256::from_str("0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05")
                .unwrap(),
            true,
        );

        let expected = r#"{"r":"0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0","s":"0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05","yParity":"0x1","v":"0x1"}"#;

        let serialized = serde_json::to_string(&signature).unwrap();
        assert_eq!(serialized, expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn bincode_roundtrip() {
        let signature = Signature::new(
            U256::from_str("0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0")
                .unwrap(),
            U256::from_str("0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05")
                .unwrap(),
            true,
        );

        let bin = bincode::serialize(&signature).unwrap();
        assert_eq!(bincode::deserialize::<Signature>(&bin).unwrap(), signature);
    }

    #[cfg(feature = "rlp")]
    #[test]
    fn signature_rlp_encode() {
        // Given a Signature instance
        let sig = Signature::from_str("48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c8041b").unwrap();

        // Initialize an empty buffer
        let mut buf = vec![];

        // Encode the Signature into the buffer
        sig.write_rlp_vrs(&mut buf, sig.v());

        // Define the expected hex-encoded string
        let expected = "80a048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804";

        // Assert that the encoded buffer matches the expected hex-encoded string
        assert_eq!(hex::encode(&buf), expected);
    }

    #[cfg(feature = "rlp")]
    #[test]
    fn signature_rlp_length() {
        // Given a Signature instance
        let sig = Signature::from_str("48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c8041b").unwrap();

        // Assert that the length of the Signature matches the expected length
        assert_eq!(sig.rlp_rs_len() + sig.v().length(), 67);
    }

    #[cfg(feature = "rlp")]
    #[test]
    fn rlp_vrs_len() {
        let signature = Signature::test_signature();
        assert_eq!(67, signature.rlp_rs_len() + 1);
    }

    #[cfg(feature = "rlp")]
    #[test]
    fn encode_and_decode() {
        let signature = Signature::test_signature();

        let mut encoded = Vec::new();
        signature.write_rlp_vrs(&mut encoded, signature.v());
        assert_eq!(encoded.len(), signature.rlp_rs_len() + signature.v().length());
        let decoded = Signature::decode_rlp_vrs(&mut &*encoded, bool::decode).unwrap();
        assert_eq!(signature, decoded);
    }

    #[test]
    fn as_bytes() {
        let signature = Signature::new(
            U256::from_str(
                "18515461264373351373200002665853028612451056578545711640558177340181847433846",
            )
            .unwrap(),
            U256::from_str(
                "46948507304638947509940763649030358759909902576025900602547168820602576006531",
            )
            .unwrap(),
            false,
        );

        let expected = hex!(
            "0x28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa63627667cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d831b"
        );
        assert_eq!(signature.as_bytes(), expected);
    }

    #[test]
    fn as_rsy() {
        let signature = Signature::new(
            U256::from_str(
                "18515461264373351373200002665853028612451056578545711640558177340181847433846",
            )
            .unwrap(),
            U256::from_str(
                "46948507304638947509940763649030358759909902576025900602547168820602576006531",
            )
            .unwrap(),
            false,
        );

        let expected = hex!(
            "0x28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa63627667cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d8300"
        );
        assert_eq!(signature.as_rsy(), expected);
    }

    #[test]
    fn as_rsy_y_parity_true() {
        let signature = Signature::new(
            U256::from_str(
                "18515461264373351373200002665853028612451056578545711640558177340181847433846",
            )
            .unwrap(),
            U256::from_str(
                "46948507304638947509940763649030358759909902576025900602547168820602576006531",
            )
            .unwrap(),
            true,
        );

        let expected = hex!(
            "0x28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa63627667cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d8301"
        );
        assert_eq!(signature.as_rsy(), expected);
    }

    #[test]
    fn as_erc2098_y_false() {
        let signature = Signature::new(
            U256::from_str(
                "47323457007453657207889730243826965761922296599680473886588287015755652701072",
            )
            .unwrap(),
            U256::from_str(
                "57228803202727131502949358313456071280488184270258293674242124340113824882788",
            )
            .unwrap(),
            false,
        );

        let expected = hex!(
            "0x68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b907e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064"
        );
        assert_eq!(signature.as_erc2098(), expected);
    }

    #[test]
    fn as_erc2098_y_true() {
        let signature = Signature::new(
            U256::from_str("0x9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76")
                .unwrap(),
            U256::from_str("0x139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793")
                .unwrap(),
            true,
        );

        let expected = hex!(
            "0x9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76939c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793"
        );
        assert_eq!(signature.as_erc2098(), expected);
    }

    #[test]
    fn from_erc2098_y_false() {
        let expected = Signature::new(
            U256::from_str(
                "47323457007453657207889730243826965761922296599680473886588287015755652701072",
            )
            .unwrap(),
            U256::from_str(
                "57228803202727131502949358313456071280488184270258293674242124340113824882788",
            )
            .unwrap(),
            false,
        );

        assert_eq!(
            Signature::from_erc2098(&hex!(
                "0x68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b907e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064"
            )),
            expected
        );
    }

    #[test]
    fn from_erc2098_y_true() {
        let expected = Signature::new(
            U256::from_str("0x9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76")
                .unwrap(),
            U256::from_str("0x139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793")
                .unwrap(),
            true,
        );

        assert_eq!(
            Signature::from_erc2098(&hex!(
                "0x9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76939c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793"
            )),
            expected
        );
    }

    #[test]
    fn display_impl() {
        let sig = Signature::new(
            U256::from_str("0x9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76")
                .unwrap(),
            U256::from_str("0x139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793")
                .unwrap(),
            true,
        );

        assert_eq!(
            format!("{sig}"),
            "0x9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f5507931c"
        );
    }
}
