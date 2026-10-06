//! ZK signatures, signature type `0x06` ([TIP-1131]).
//!
//! A ZK signature carries a zero-knowledge proof that an issuer signed a statement for an
//! identity, committing to an access key, plus that access key's signature. Decoding checks
//! encodings only; proofs, times, and issuer keys are checked during transaction validation.
//!
//! [TIP-1131]: https://docs.tempo.xyz/protocol/tips/tip-1131

use super::tt_signature::PrimitiveSignature;
use alloc::vec::Vec;
use alloy_primitives::{Address, B256, FixedBytes, U256, keccak256, uint};
use alloy_rlp::{Decodable, Encodable, Header};

#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox as OnceLock;
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// Signature type byte of ZK signatures.
pub const SIGNATURE_TYPE_ZK: u8 = 0x06;

/// Maximum encoded size of a ZK signature, including the type byte.
pub const MAX_ZK_SIGNATURE_SIZE: usize = 2049;

/// Length of a Groth16 proof: `A` (G1) `|| B` (G2) `|| C` (G1), uncompressed.
pub const ZK_PROOF_LENGTH: usize = 256;

/// Domain prefix of the digest signed by the access key.
pub const ZK_SIGNATURE_DOMAIN: &[u8; 18] = b"tempo:zk-signature";

/// Scheme `0x01`: OIDC ID tokens signed with RS256 ([TIP-1133]).
///
/// [TIP-1133]: https://docs.tempo.xyz/protocol/tips/tip-1133
pub const ZK_SCHEME_OIDC_RS256_V1: u8 = 0x01;

/// Address namespace of OIDC schemes.
pub const ZK_NAMESPACE_OIDC: u8 = 0x01;

/// Most ZK signatures a transaction may carry, across all of its signatures.
pub const MAX_ZK_SIGNATURES_PER_TX: usize = 2;

/// The BN254 scalar field modulus. Field-element fields must be below it.
pub const BN254_SCALAR_FIELD: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

/// A Groth16 proof in its encoded form.
pub type ZkProof = FixedBytes<ZK_PROOF_LENGTH>;

/// Returns the address namespace of a scheme, or `None` for unknown schemes.
pub const fn zk_namespace(scheme: u8) -> Option<u8> {
    match scheme {
        ZK_SCHEME_OIDC_RS256_V1 => Some(ZK_NAMESPACE_OIDC),
        _ => None,
    }
}

/// Derives the address of an identity:
/// `keccak256(0x06 || namespace || publisher_id || issuer || address_seed)[12:]`.
pub fn zk_address(
    namespace: u8,
    publisher_id: &B256,
    issuer: &B256,
    address_seed: &B256,
) -> Address {
    let mut preimage = [0u8; 98];
    preimage[0] = SIGNATURE_TYPE_ZK;
    preimage[1] = namespace;
    preimage[2..34].copy_from_slice(publisher_id.as_slice());
    preimage[34..66].copy_from_slice(issuer.as_slice());
    preimage[66..].copy_from_slice(address_seed.as_slice());
    Address::from_slice(&keccak256(preimage)[12..])
}

/// A ZK signature.
///
/// Encoded as `0x06 || rlp([scheme, publisher_id, issuer, key_hash, address_seed, issued_at,
/// valid_until, proof, access_key_signature])`.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ZkSignature {
    /// Proof scheme.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub scheme: u8,
    /// TIP-1132 publisher whose key list the identity trusts.
    pub publisher_id: B256,
    /// Scheme-defined issuer hash.
    pub issuer: B256,
    /// Scheme-defined hash of the issuer key that signed the statement.
    pub key_hash: B256,
    /// Scheme-defined identity commitment.
    pub address_seed: B256,
    /// When the issuer signed the statement, in seconds.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub issued_at: u64,
    /// When the signature expires, in seconds.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub valid_until: u64,
    /// Groth16 proof.
    pub proof: ZkProof,
    /// Access key signature over [`Self::signing_hash`].
    pub access_key_signature: PrimitiveSignature,
    /// Cached result of proof and access-key verification for one digest.
    ///
    /// Excluded from encoding, equality, and hashing.
    #[cfg_attr(feature = "serde", serde(skip))]
    verification: OnceLock<ZkVerification>,
}

/// A cached verification outcome of a ZK signature for one digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkVerification {
    /// The digest the signature was checked against.
    pub digest: B256,
    /// The verified access key, or `None` if verification failed.
    pub access_key_id: Option<Address>,
}

impl ZkSignature {
    /// Creates a ZK signature with an empty verification cache.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        scheme: u8,
        publisher_id: B256,
        issuer: B256,
        key_hash: B256,
        address_seed: B256,
        issued_at: u64,
        valid_until: u64,
        proof: ZkProof,
        access_key_signature: PrimitiveSignature,
    ) -> Self {
        Self {
            scheme,
            publisher_id,
            issuer,
            key_hash,
            address_seed,
            issued_at,
            valid_until,
            proof,
            access_key_signature,
            verification: OnceLock::new(),
        }
    }

    /// Decodes a ZK signature, including its type byte.
    ///
    /// Rejects non-canonical RLP, field elements of at least the BN254 scalar field modulus,
    /// proofs that are not 256 bytes, access key signatures that do not re-encode to the same
    /// bytes, and encodings over [`MAX_ZK_SIGNATURE_SIZE`] bytes. Curve, subgroup, scheme, and
    /// time checks happen during validation.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() > MAX_ZK_SIGNATURE_SIZE {
            return Err("ZK signature too large");
        }
        let (&type_id, mut buf) = data.split_first().ok_or("ZK signature is empty")?;
        if type_id != SIGNATURE_TYPE_ZK {
            return Err("not a ZK signature");
        }

        let header = Header::decode(&mut buf).map_err(|_| "invalid ZK signature RLP header")?;
        if !header.list {
            return Err("ZK signature must be an RLP list");
        }
        if buf.len() != header.payload_length {
            return Err("ZK signature has trailing bytes");
        }

        let invalid = |_| "invalid ZK signature field";
        let scheme = u8::decode(&mut buf).map_err(invalid)?;
        let publisher_id = B256::decode(&mut buf).map_err(invalid)?;
        let issuer = B256::decode(&mut buf).map_err(invalid)?;
        let key_hash = B256::decode(&mut buf).map_err(invalid)?;
        let address_seed = B256::decode(&mut buf).map_err(invalid)?;
        let issued_at = u64::decode(&mut buf).map_err(invalid)?;
        let valid_until = u64::decode(&mut buf).map_err(invalid)?;
        let proof = ZkProof::decode(&mut buf).map_err(|_| "ZK proof must be 256 bytes")?;
        let access_key_bytes = Header::decode_bytes(&mut buf, false).map_err(invalid)?;
        if !buf.is_empty() {
            return Err("ZK signature must have exactly nine fields");
        }

        for value in [&issuer, &key_hash, &address_seed] {
            if U256::from_be_bytes(value.0) >= BN254_SCALAR_FIELD {
                return Err("ZK signature field element is not canonical");
            }
        }

        let access_key_signature = PrimitiveSignature::from_bytes(access_key_bytes)?;
        if access_key_signature.encoded_length() != access_key_bytes.len()
            || access_key_signature.to_bytes().as_ref() != access_key_bytes
        {
            return Err("ZK access key signature is not canonical");
        }

        Ok(Self::new(
            scheme,
            publisher_id,
            issuer,
            key_hash,
            address_seed,
            issued_at,
            valid_until,
            proof,
            access_key_signature,
        ))
    }

    /// Returns the encoded signature, including its type byte.
    pub fn to_bytes(&self) -> alloy_primitives::Bytes {
        let mut out = Vec::with_capacity(self.encoded_length());
        self.encode_bytes_into(&mut out);
        out.into()
    }

    /// Writes the encoded signature, including its type byte, into `out`.
    pub fn encode_bytes_into(&self, out: &mut dyn alloy_rlp::BufMut) {
        out.put_u8(SIGNATURE_TYPE_ZK);
        Header {
            list: true,
            payload_length: self.payload_length(),
        }
        .encode(out);
        self.encode_signed_fields(out);
        self.access_key_signature.encode(out);
    }

    /// Returns the length of [`Self::to_bytes`].
    pub fn encoded_length(&self) -> usize {
        1 + Header {
            list: true,
            payload_length: self.payload_length(),
        }
        .length_with_payload()
    }

    /// Returns the length of the encoded access key signature, as carried in this signature.
    pub fn access_key_signature_length(&self) -> usize {
        self.access_key_signature.length()
    }

    /// Returns the in-memory size of the signature.
    pub fn size(&self) -> usize {
        size_of::<Self>() - size_of::<PrimitiveSignature>() + self.access_key_signature.size()
    }

    /// Returns the address this signature signs for, or `None` for an unknown scheme.
    pub fn address(&self) -> Option<Address> {
        let namespace = zk_namespace(self.scheme)?;
        Some(zk_address(
            namespace,
            &self.publisher_id,
            &self.issuer,
            &self.address_seed,
        ))
    }

    /// Returns `keccak256(rlp([scheme, publisher_id, issuer, key_hash, address_seed, issued_at,
    /// valid_until, proof]))`.
    pub fn fields_hash(&self) -> B256 {
        let payload_length = self.signed_fields_length();
        let header = Header {
            list: true,
            payload_length,
        };
        let mut buf = Vec::with_capacity(header.length_with_payload());
        header.encode(&mut buf);
        self.encode_signed_fields(&mut buf);
        keccak256(buf)
    }

    /// Returns the digest the access key signs for the context digest `d`:
    /// `keccak256("tempo:zk-signature" || d || fields_hash)`.
    pub fn signing_hash(&self, d: &B256) -> B256 {
        let mut buf = [0u8; ZK_SIGNATURE_DOMAIN.len() + 64];
        buf[..ZK_SIGNATURE_DOMAIN.len()].copy_from_slice(ZK_SIGNATURE_DOMAIN);
        buf[ZK_SIGNATURE_DOMAIN.len()..ZK_SIGNATURE_DOMAIN.len() + 32]
            .copy_from_slice(d.as_slice());
        buf[ZK_SIGNATURE_DOMAIN.len() + 32..].copy_from_slice(self.fields_hash().as_slice());
        keccak256(buf)
    }

    /// Recovers the access key that signed [`Self::signing_hash`] for `d`.
    ///
    /// This verifies only the access key signature, not the proof.
    pub fn recover_access_key(
        &self,
        d: &B256,
    ) -> Result<Address, alloy_consensus::crypto::RecoveryError> {
        self.access_key_signature
            .recover_signer(&self.signing_hash(d))
    }

    /// Returns the cached verification outcome for `d`, if any.
    pub fn cached_verification(&self, d: &B256) -> Option<Option<Address>> {
        self.verification
            .get()
            .filter(|verification| verification.digest == *d)
            .map(|verification| verification.access_key_id)
    }

    /// Caches a verification outcome. Only the first outcome is kept.
    pub fn cache_verification(&self, d: B256, access_key_id: Option<Address>) {
        #[allow(clippy::useless_conversion)]
        let _ = self.verification.set(
            ZkVerification {
                digest: d,
                access_key_id,
            }
            .into(),
        );
    }

    fn signed_fields_length(&self) -> usize {
        self.scheme.length()
            + self.publisher_id.length()
            + self.issuer.length()
            + self.key_hash.length()
            + self.address_seed.length()
            + self.issued_at.length()
            + self.valid_until.length()
            + self.proof.length()
    }

    fn payload_length(&self) -> usize {
        self.signed_fields_length() + self.access_key_signature.length()
    }

    fn encode_signed_fields(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.scheme.encode(out);
        self.publisher_id.encode(out);
        self.issuer.encode(out);
        self.key_hash.encode(out);
        self.address_seed.encode(out);
        self.issued_at.encode(out);
        self.valid_until.encode(out);
        self.proof.encode(out);
    }
}

impl PartialEq for ZkSignature {
    fn eq(&self, other: &Self) -> bool {
        self.scheme == other.scheme
            && self.publisher_id == other.publisher_id
            && self.issuer == other.issuer
            && self.key_hash == other.key_hash
            && self.address_seed == other.address_seed
            && self.issued_at == other.issued_at
            && self.valid_until == other.valid_until
            && self.proof == other.proof
            && self.access_key_signature == other.access_key_signature
    }
}

impl Eq for ZkSignature {}

impl core::hash::Hash for ZkSignature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.scheme.hash(state);
        self.publisher_id.hash(state);
        self.issuer.hash(state);
        self.key_hash.hash(state);
        self.address_seed.hash(state);
        self.issued_at.hash(state);
        self.valid_until.hash(state);
        self.proof.hash(state);
        self.access_key_signature.hash(state);
    }
}

// Generates only signatures that decode back to themselves: canonical field elements and access
// key signatures small enough to keep the encoding within `MAX_ZK_SIGNATURE_SIZE`.
#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for ZkSignature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut field = || -> arbitrary::Result<B256> {
            let mut bytes: [u8; 32] = u.arbitrary()?;
            bytes[0] &= 0x1f;
            Ok(B256::from(bytes))
        };
        let (issuer, key_hash, address_seed) = (field()?, field()?, field()?);
        let mut access_key_signature: PrimitiveSignature = u.arbitrary()?;
        if access_key_signature.encoded_length() > 1024 {
            access_key_signature = PrimitiveSignature::default();
        }
        Ok(Self::new(
            u.arbitrary()?,
            u.arbitrary()?,
            issuer,
            key_hash,
            address_seed,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            access_key_signature,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Signature, hex};

    fn sample() -> ZkSignature {
        ZkSignature::new(
            ZK_SCHEME_OIDC_RS256_V1,
            B256::repeat_byte(0x11),
            B256::with_last_byte(2),
            B256::with_last_byte(3),
            B256::with_last_byte(4),
            1_700_000_000,
            1_700_000_540,
            ZkProof::repeat_byte(0x55),
            PrimitiveSignature::Secp256k1(Signature::test_signature()),
        )
    }

    #[test]
    fn roundtrip_and_layout() {
        let signature = sample();
        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), signature.encoded_length());
        assert_eq!(bytes[0], SIGNATURE_TYPE_ZK);
        assert_eq!(ZkSignature::from_bytes(&bytes).unwrap(), signature);
        // 1 type byte, a 3-byte list header, and nine fields.
        assert_eq!(bytes.len(), 1 + 3 + 1 + 4 * 33 + 5 + 5 + 259 + 67);
    }

    #[test]
    fn rejects_malformed_encodings() {
        let signature = sample();
        let bytes = signature.to_bytes().to_vec();

        // Trailing bytes after the list.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ZkSignature::from_bytes(&trailing).is_err());

        // Wrong type byte.
        let mut wrong_type = bytes;
        wrong_type[0] = 0x05;
        assert!(ZkSignature::from_bytes(&wrong_type).is_err());

        // Field element equal to the modulus.
        let mut non_canonical = signature.clone();
        non_canonical.key_hash = B256::from(BN254_SCALAR_FIELD.to_be_bytes::<32>());
        assert_eq!(
            ZkSignature::from_bytes(&non_canonical.to_bytes()),
            Err("ZK signature field element is not canonical")
        );

        // A tenth field.
        let mut ten = Vec::new();
        Header {
            list: true,
            payload_length: signature.payload_length() + 1,
        }
        .encode(&mut ten);
        signature.encode_signed_fields(&mut ten);
        signature.access_key_signature.encode(&mut ten);
        0u8.encode(&mut ten);
        let ten = [&[SIGNATURE_TYPE_ZK][..], &ten].concat();
        assert_eq!(
            ZkSignature::from_bytes(&ten),
            Err("ZK signature must have exactly nine fields")
        );

        // An access key signature that is itself a keychain or ZK signature.
        for nested in [0x03u8, 0x04, SIGNATURE_TYPE_ZK] {
            let mut inner = vec![nested];
            inner.extend_from_slice(&[0u8; 100]);
            let mut out = vec![SIGNATURE_TYPE_ZK];
            Header {
                list: true,
                payload_length: signature.signed_fields_length() + inner.as_slice().length(),
            }
            .encode(&mut out);
            signature.encode_signed_fields(&mut out);
            inner.as_slice().encode(&mut out);
            assert!(ZkSignature::from_bytes(&out).is_err());
        }

        // Too large.
        assert_eq!(
            ZkSignature::from_bytes(&vec![SIGNATURE_TYPE_ZK; MAX_ZK_SIGNATURE_SIZE + 1]),
            Err("ZK signature too large")
        );
    }

    #[test]
    fn rejects_non_canonical_access_key_signature() {
        // A P256 signature whose pre-hash byte is 0x02 decodes, but re-encodes as 0x01.
        let mut p256 = vec![0x01u8];
        p256.extend_from_slice(&[0x22; 128]);
        p256.push(0x02);
        let signature = sample();
        let mut out = vec![SIGNATURE_TYPE_ZK];
        Header {
            list: true,
            payload_length: signature.signed_fields_length() + p256.as_slice().length(),
        }
        .encode(&mut out);
        signature.encode_signed_fields(&mut out);
        p256.as_slice().encode(&mut out);
        assert_eq!(
            ZkSignature::from_bytes(&out),
            Err("ZK access key signature is not canonical")
        );
        out.truncate(out.len() - 1);
        assert!(ZkSignature::from_bytes(&out).is_err());
    }

    #[test]
    fn address_derivation() {
        let signature = sample();
        let expected = keccak256(
            [
                &[SIGNATURE_TYPE_ZK, ZK_NAMESPACE_OIDC][..],
                signature.publisher_id.as_slice(),
                signature.issuer.as_slice(),
                signature.address_seed.as_slice(),
            ]
            .concat(),
        );
        assert_eq!(
            signature.address(),
            Some(Address::from_slice(&expected[12..]))
        );

        // Independent of the key hash, times, proof, and access key.
        let mut other = signature.clone();
        other.key_hash = B256::with_last_byte(9);
        other.issued_at += 1;
        other.valid_until += 1;
        other.proof = ZkProof::repeat_byte(0x66);
        other.access_key_signature = PrimitiveSignature::default();
        assert_eq!(other.address(), signature.address());

        other.scheme = 0x02;
        assert_eq!(other.address(), None);
    }

    #[test]
    fn signing_hash_binds_every_signed_field() {
        let d = B256::repeat_byte(0xdd);
        let signature = sample();
        let base = signature.signing_hash(&d);
        assert_ne!(base, signature.signing_hash(&B256::repeat_byte(0xde)));

        let mut changes: Vec<ZkSignature> = Vec::new();
        let mut s = signature.clone();
        s.scheme = 2;
        changes.push(s);
        let mut s = signature.clone();
        s.publisher_id = B256::ZERO;
        changes.push(s);
        let mut s = signature.clone();
        s.issuer = B256::ZERO;
        changes.push(s);
        let mut s = signature.clone();
        s.key_hash = B256::ZERO;
        changes.push(s);
        let mut s = signature.clone();
        s.address_seed = B256::ZERO;
        changes.push(s);
        let mut s = signature.clone();
        s.issued_at = 0;
        changes.push(s);
        let mut s = signature.clone();
        s.valid_until = 0;
        changes.push(s);
        let mut s = signature;
        s.proof.0[200] ^= 1;
        changes.push(s);
        for changed in changes {
            assert_ne!(changed.signing_hash(&d), base);
        }

        // The domain prefix is raw ASCII.
        assert_eq!(
            hex::encode(ZK_SIGNATURE_DOMAIN),
            "74656d706f3a7a6b2d7369676e6174757265"
        );
    }

    #[test]
    fn verification_cache_is_per_digest() {
        let signature = sample();
        let d = B256::repeat_byte(1);
        assert_eq!(signature.cached_verification(&d), None);
        signature.cache_verification(d, Some(Address::repeat_byte(7)));
        assert_eq!(
            signature.cached_verification(&d),
            Some(Some(Address::repeat_byte(7)))
        );
        assert_eq!(signature.cached_verification(&B256::repeat_byte(2)), None);
        // Clones keep the cache, and equality ignores it.
        let cloned = signature.clone();
        assert_eq!(
            cloned.cached_verification(&d),
            Some(Some(Address::repeat_byte(7)))
        );
        assert_eq!(cloned, signature);
        assert_eq!(signature, sample());
    }
}
