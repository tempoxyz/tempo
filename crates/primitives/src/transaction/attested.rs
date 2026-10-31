//! Attested signatures (signature type `0x06`, attested signers PoC).
//!
//! A program key, held by attested code and registered in the Attested Key Registry, signs for
//! the address derived from a policy ID and a user tag. This module covers the stateless part:
//! encoding, address and digest derivation, and P256 verification. The registry and validity
//! window checks need block state and run in the EVM handler.

use super::tt_signature::{P256_ORDER, P256N_HALF, verify_p256_signature_internal};
use crate::gas::P256_VERIFY_GAS;
use alloc::vec::Vec;
use alloy_consensus::crypto::RecoveryError;
use alloy_eips::eip7623::{STANDARD_TOKEN_COST, tokens_in_calldata};
use alloy_primitives::{Address, B256, B512, U256, keccak256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header};

/// Tempo signature type byte for attested signatures.
pub const SIGNATURE_TYPE_ATTESTED: u8 = 0x06;

/// Domain prefix of the digest a program key signs.
pub const ATTESTED_SIGNATURE_DOMAIN: &[u8] = b"tempo:attested-signature";

/// Longest time, in seconds, before `valid_until` that an attested signature is accepted.
pub const ATTESTED_MAX_VALIDITY_WINDOW: u64 = 600;

/// Largest encoding of an attested signature, type byte included, with a 9-byte `valid_until`.
pub const MAX_ATTESTED_SIGNATURE_SIZE: usize = 210;

/// Cold storage read cost charged for each of the two registry reads.
const COLD_SLOAD_GAS: u64 = 2_100;

/// Signature by a registered program key for `attested_address(policy_id, user_tag)`.
///
/// Wire format: `0x06 || rlp([policy_id, user_tag, program_key, valid_until, signature])`.
/// Decoding checks the encoding and the `r`/`s` ranges only. [`Self::recover_signer`] checks the
/// curve point and the P256 signature. The registry and time checks belong to the caller.
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AttestedSignature {
    /// Attested Key Registry policy that registered the program key.
    pub policy_id: B256,
    /// Tag of the user whose address this signature signs for.
    pub user_tag: B256,
    /// Uncompressed P256 program key, `x || y`.
    pub program_key: B512,
    /// Last block timestamp, in seconds, at which the signature is valid.
    pub valid_until: u64,
    /// ECDSA P256 signature `r || s` over [`Self::digest`], with low `s`.
    pub signature: B512,
}

impl AttestedSignature {
    /// Returns the program key's `x` coordinate.
    pub fn program_key_x(&self) -> B256 {
        B256::from_slice(&self.program_key[..32])
    }

    /// Returns the program key's `y` coordinate.
    pub fn program_key_y(&self) -> B256 {
        B256::from_slice(&self.program_key[32..])
    }

    /// Returns the address this signature signs for.
    pub fn address(&self) -> Address {
        attested_address(self.policy_id, self.user_tag)
    }

    /// Returns the digest the program key signs for the context digest `d`, the transaction
    /// signing hash or the key authorization signature hash:
    /// `keccak256(domain || d || keccak256(rlp([policy_id, user_tag, program_key, valid_until])))`.
    pub fn digest(&self, d: B256) -> B256 {
        let payload_length = self.policy_id.length()
            + self.user_tag.length()
            + self.program_key.length()
            + self.valid_until.length();
        let mut fields = Vec::with_capacity(payload_length + 3);
        Header {
            list: true,
            payload_length,
        }
        .encode(&mut fields);
        self.policy_id.encode(&mut fields);
        self.user_tag.encode(&mut fields);
        self.program_key.encode(&mut fields);
        self.valid_until.encode(&mut fields);

        let mut preimage = Vec::with_capacity(ATTESTED_SIGNATURE_DOMAIN.len() + 64);
        preimage.extend_from_slice(ATTESTED_SIGNATURE_DOMAIN);
        preimage.extend_from_slice(d.as_slice());
        preimage.extend_from_slice(keccak256(fields).as_slice());
        keccak256(preimage)
    }

    /// Verifies the P256 signature over [`Self::digest`] of `d` and returns [`Self::address`].
    ///
    /// Does not check the registry or `valid_until`: a returned address is untrusted until the
    /// caller checks both against block state.
    pub fn recover_signer(&self, d: &B256) -> Result<Address, RecoveryError> {
        let (r, s) = self.signature.split_at(32);
        verify_p256_signature_internal(
            r,
            s,
            &self.program_key[..32],
            &self.program_key[32..],
            &self.digest(*d),
        )
        .map_err(|_| RecoveryError::new())?;
        Ok(self.address())
    }

    /// Full verification gas: one P256 verification, two cold registry reads, and the calldata
    /// cost of `policy_id || user_tag || valid_until` (8-byte big-endian).
    pub fn verification_gas(&self) -> u64 {
        let mut extra = [0u8; 72];
        extra[..32].copy_from_slice(self.policy_id.as_slice());
        extra[32..64].copy_from_slice(self.user_tag.as_slice());
        extra[64..].copy_from_slice(&self.valid_until.to_be_bytes());
        P256_VERIFY_GAS + 2 * COLD_SLOAD_GAS + tokens_in_calldata(&extra) * STANDARD_TOKEN_COST
    }

    /// Writes `0x06 || rlp(fields)`.
    pub(crate) fn encode_bytes_into(&self, out: &mut dyn BufMut) {
        out.put_u8(SIGNATURE_TYPE_ATTESTED);
        self.encode(out);
    }

    /// Length of `0x06 || rlp(fields)`.
    pub(crate) fn encoded_length(&self) -> usize {
        1 + self.length()
    }

    /// Decodes the bytes after the type byte, rejecting trailing bytes, oversize encodings, and
    /// `r` or `s` outside `[1, n - 1]` or a high `s`.
    pub(crate) fn decode_exact(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() + 1 > MAX_ATTESTED_SIGNATURE_SIZE {
            return Err("Attested signature too large");
        }
        let signature: Self =
            alloy_rlp::decode_exact(data).map_err(|_| "Invalid attested signature RLP")?;
        let (r, s) = signature.signature.split_at(32);
        let (r, s) = (U256::from_be_slice(r), U256::from_be_slice(s));
        if r.is_zero() || r >= P256_ORDER || s.is_zero() || s > P256N_HALF {
            return Err("Attested signature r or s out of range");
        }
        Ok(signature)
    }
}

impl Decodable for AttestedSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        #[derive(alloy_rlp::RlpDecodable)]
        struct Wire {
            policy_id: B256,
            user_tag: B256,
            program_key: B512,
            valid_until: u64,
            signature: B512,
        }
        let Wire {
            policy_id,
            user_tag,
            program_key,
            valid_until,
            signature,
        } = Wire::decode(buf)?;
        Ok(Self {
            policy_id,
            user_tag,
            program_key,
            valid_until,
            signature,
        })
    }
}

// Generates `r` in `[1, n - 1]` and `s` in `[1, n / 2]`, which decoding requires.
#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for AttestedSignature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let r =
            U256::from_be_bytes(u.arbitrary::<[u8; 32]>()?) % (P256_ORDER - U256::ONE) + U256::ONE;
        let s = U256::from_be_bytes(u.arbitrary::<[u8; 32]>()?) % P256N_HALF + U256::ONE;
        let mut signature = B512::ZERO;
        signature[..32].copy_from_slice(&r.to_be_bytes::<32>());
        signature[32..].copy_from_slice(&s.to_be_bytes::<32>());
        Ok(Self {
            policy_id: u.arbitrary()?,
            user_tag: u.arbitrary()?,
            program_key: u.arbitrary()?,
            valid_until: u.arbitrary()?,
            signature,
        })
    }
}

/// Returns whether `(x, y)` is an affine P256 point on the curve. The point at infinity has no
/// affine coordinates, so it is rejected.
pub fn is_valid_p256_public_key(x: &B256, y: &B256) -> bool {
    let point = p256::EncodedPoint::from_affine_coordinates(&x.0.into(), &y.0.into(), false);
    p256::PublicKey::from_sec1_bytes(point.as_bytes()).is_ok()
}

/// Returns `keccak256(0x06 || policy_id || user_tag)[12:]`.
pub fn attested_address(policy_id: B256, user_tag: B256) -> Address {
    let mut preimage = [0u8; 65];
    preimage[0] = SIGNATURE_TYPE_ATTESTED;
    preimage[1..33].copy_from_slice(policy_id.as_slice());
    preimage[33..].copy_from_slice(user_tag.as_slice());
    Address::from_word(keccak256(preimage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};

    fn signed(d: B256, valid_until: u64) -> AttestedSignature {
        let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let mut signature = AttestedSignature {
            policy_id: B256::repeat_byte(0xAA),
            user_tag: B256::repeat_byte(0xBB),
            program_key: B512::from_slice(&point.as_bytes()[1..]),
            valid_until,
            signature: B512::ZERO,
        };
        let sig: Signature = key.sign_prehash(signature.digest(d).as_slice()).unwrap();
        let sig = sig.normalize_s().unwrap_or(sig);
        signature.signature = B512::from_slice(&sig.to_bytes());
        signature
    }

    #[test]
    fn address_and_digest_layout() {
        assert_eq!(
            attested_address(B256::repeat_byte(0xAA), B256::repeat_byte(0xBB)),
            Address::from_word(keccak256([&[0x06][..], &[0xAA; 32], &[0xBB; 32]].concat()))
        );

        let signature = signed(B256::ZERO, 1_800_000_600);
        let d = B256::repeat_byte(0x42);
        // rlp([policy_id, user_tag, program_key, valid_until]): list of 33 + 33 + 66 + 5 bytes.
        let fields = [
            &[0xf8, 137][..],
            &[0xa0],
            signature.policy_id.as_slice(),
            &[0xa0],
            signature.user_tag.as_slice(),
            &[0xb8, 64],
            signature.program_key.as_slice(),
            &[0x84],
            &1_800_000_600u32.to_be_bytes(),
        ]
        .concat();
        assert_eq!(
            signature.digest(d),
            keccak256(
                [
                    b"tempo:attested-signature".as_slice(),
                    d.as_slice(),
                    keccak256(fields).as_slice()
                ]
                .concat()
            )
        );
        assert_eq!(signature.encoded_length(), 206);
    }

    #[test]
    fn roundtrip_and_recover() {
        let d = B256::repeat_byte(0x42);
        let signature = signed(d, 1_800_000_600);
        let mut bytes = Vec::new();
        signature.encode_bytes_into(&mut bytes);
        assert_eq!(bytes.len(), signature.encoded_length());
        assert_eq!(bytes[0], SIGNATURE_TYPE_ATTESTED);
        assert_eq!(
            AttestedSignature::decode_exact(&bytes[1..]).unwrap(),
            signature
        );
        assert_eq!(signature.recover_signer(&d).unwrap(), signature.address());
        assert!(signature.recover_signer(&B256::ZERO).is_err());
        // 8000 + 2 * 2100 + calldata of 68 non-zero bytes and the 4 zero high bytes of
        // `valid_until`.
        assert_eq!(
            signature.verification_gas(),
            8_000 + 4_200 + 68 * 16 + 4 * 4
        );
    }

    #[test]
    fn rejects_malformed_encodings() {
        let signature = signed(B256::ZERO, 1_800_000_600);
        let mut bytes = Vec::new();
        signature.encode_bytes_into(&mut bytes);

        let mut trailing = bytes[1..].to_vec();
        trailing.push(0);
        assert!(AttestedSignature::decode_exact(&trailing).is_err());

        let mut high_s = signature.clone();
        let s = P256_ORDER - U256::from_be_slice(&signature.signature[32..]);
        high_s.signature[32..].copy_from_slice(&s.to_be_bytes::<32>());
        let mut encoded = Vec::new();
        high_s.encode(&mut encoded);
        assert_eq!(
            AttestedSignature::decode_exact(&encoded),
            Err("Attested signature r or s out of range")
        );

        let mut off_curve = signature.clone();
        off_curve.program_key[63] ^= 1;
        assert!(off_curve.recover_signer(&B256::ZERO).is_err());
        assert!(is_valid_p256_public_key(
            &signature.program_key_x(),
            &signature.program_key_y()
        ));
        assert!(!is_valid_p256_public_key(
            &off_curve.program_key_x(),
            &off_curve.program_key_y()
        ));
        assert!(!is_valid_p256_public_key(&B256::ZERO, &B256::ZERO));

        // A list with a sixth field.
        let mut six = Vec::new();
        Header {
            list: true,
            payload_length: signature.length() - 2 + 1,
        }
        .encode(&mut six);
        six.extend_from_slice(&bytes[3..]);
        six.push(0x80);
        assert!(AttestedSignature::decode_exact(&six).is_err());
    }

    #[test]
    fn tempo_signature_accepts_attested_except_in_keychain() {
        use crate::transaction::{AccountSignature, TempoSignature};

        let signature = signed(B256::ZERO, 1_800_000_600);
        let tempo = TempoSignature::Attested(signature.clone());
        let bytes = tempo.to_bytes();
        assert_eq!(TempoSignature::from_bytes(&bytes).unwrap(), tempo);
        assert_eq!(
            AccountSignature::try_from(tempo).unwrap(),
            AccountSignature::Attested(signature)
        );

        for type_byte in [0x03, 0x04] {
            let keychain = [&[type_byte][..], &[0x11; 20], &bytes].concat();
            assert_eq!(
                TempoSignature::from_bytes(&keychain),
                Err("attested signatures cannot sign as access keys")
            );
        }
    }

    #[test]
    fn configurable_account_carries_attested_approvals() {
        use crate::transaction::{
            ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
            OwnerApproval, TempoSignature, configurable_account_digest,
        };

        let unsigned = signed(B256::ZERO, 1_800_000_600);
        let config = ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![ConfigurableAccountOwner {
                owner: unsigned.address(),
                weight: 1,
            }],
        };
        let account = config.derive_account().unwrap();
        let inner = B256::repeat_byte(0x42);
        let approval = signed(
            configurable_account_digest(inner, account, 0),
            1_800_000_600,
        );
        let signature =
            ConfigurableAccountSignature::try_new(account, config, [approval.clone()]).unwrap();

        // The approval is the standalone `0x06` encoding, as an RLP byte string.
        let tempo = TempoSignature::ConfigurableAccount(signature.clone());
        let bytes = tempo.to_bytes();
        let mut standalone = Vec::new();
        approval.encode_bytes_into(&mut standalone);
        assert!(
            bytes
                .windows(standalone.len())
                .any(|window| window == standalone)
        );
        assert_eq!(TempoSignature::from_bytes(&bytes).unwrap(), tempo);

        assert_eq!(
            signature.signatures(),
            [OwnerApproval::Attested(approval.clone())]
        );
        signature.verify_approvals(inner).unwrap();
        assert!(signature.verify_approvals(B256::ZERO).is_err());
        assert!(
            signature.verification_gas().unwrap() > approval.verification_gas(),
            "the approval is charged as a standalone attested signature"
        );
    }
}
