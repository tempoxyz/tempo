use super::{
    tempo_transaction::{TEMPO_TX_TYPE_ID, TempoTransaction},
    tt_signature::TempoSignature,
    unique_tx_identifier_from_signable,
};
use alloc::vec::Vec;
use alloy_consensus::{SignableTransaction, Transaction, transaction::TxHashRef};
use alloy_eips::{
    Decodable2718, Encodable2718, Typed2718,
    eip2718::{Eip2718Error, Eip2718Result},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{Address, B256, Bytes, Keccak256, TxKind, U256};
use alloy_rlp::{BufMut, Decodable, Encodable};
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
};

#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox as OnceLock;
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// A transaction with an AA signature and hash seal.
///
/// This wraps a TempoTransaction transaction with its multi-signature-type signature
/// (secp256k1, P256, Webauthn, Keychain) and provides cached hashes.
#[derive(Clone, Debug)]
pub struct AASigned {
    /// The inner Tempo transaction
    tx: TempoTransaction,
    /// The signature (can be secp256k1, P256, Webauthn, Keychain)
    signature: TempoSignature,
    /// Cached transaction hash
    #[doc(alias = "tx_hash", alias = "transaction_hash")]
    hash: OnceLock<B256>,
    /// Cached transaction signing hash.
    signature_hash: OnceLock<B256>,
    /// Cached sender-scoped replay hash for the first recovered sender.
    expiring_nonce_hash: OnceLock<(Address, B256)>,
}

impl AASigned {
    /// Instantiate from a transaction and signature with a known hash.
    /// Does not verify the signature.
    pub fn new_unchecked(tx: TempoTransaction, signature: TempoSignature, hash: B256) -> Self {
        let value = OnceLock::new();
        #[allow(clippy::useless_conversion)]
        value.get_or_init(|| hash.into());
        Self {
            tx,
            signature,
            hash: value,
            signature_hash: OnceLock::new(),
            expiring_nonce_hash: OnceLock::new(),
        }
    }

    /// Instantiate from a transaction and signature without computing the hash.
    /// Does not verify the signature.
    pub const fn new_unhashed(tx: TempoTransaction, signature: TempoSignature) -> Self {
        Self {
            tx,
            signature,
            hash: OnceLock::new(),
            signature_hash: OnceLock::new(),
            expiring_nonce_hash: OnceLock::new(),
        }
    }

    /// Returns a reference to the transaction.
    #[doc(alias = "transaction")]
    pub const fn tx(&self) -> &TempoTransaction {
        &self.tx
    }

    /// Returns a mutable reference to the transaction.
    pub const fn tx_mut(&mut self) -> &mut TempoTransaction {
        &mut self.tx
    }

    /// Returns a reference to the signature.
    pub const fn signature(&self) -> &TempoSignature {
        &self.signature
    }

    /// Returns the transaction without signature.
    pub fn strip_signature(self) -> TempoTransaction {
        self.tx
    }

    /// Returns a reference to the transaction hash, computing it if needed.
    #[doc(alias = "tx_hash", alias = "transaction_hash")]
    pub fn hash(&self) -> &B256 {
        #[allow(clippy::useless_conversion)]
        self.hash.get_or_init(|| self.compute_hash().into())
    }

    /// Calculate the transaction hash
    fn compute_hash(&self) -> B256 {
        let mut buf = Vec::new();
        self.eip2718_encode(&mut buf);
        alloy_primitives::keccak256(&buf)
    }

    /// Calculate the signing hash for the transaction.
    pub fn signature_hash(&self) -> B256 {
        #[allow(clippy::useless_conversion)]
        *self
            .signature_hash
            .get_or_init(|| self.tx.signature_hash().into())
    }

    /// Recover the signer and compute the expiring nonce hash in one pass when applicable.
    ///
    /// Non-expiring transactions delegate to the regular recovery path. Expiring nonce transactions
    /// reuse the encoded signing payload for both `keccak256(encode_for_signing)` and
    /// `keccak256(encode_for_signing || sender)`.
    pub fn recover_signer_with_expiring_nonce_hash(
        &self,
    ) -> Result<(Address, Option<B256>), alloy_consensus::crypto::RecoveryError> {
        if !self.tx.is_expiring_nonce_tx() {
            let signer =
                <Self as alloy_consensus::transaction::SignerRecoverable>::recover_signer(self)?;
            return Ok((signer, None));
        }

        let mut buf = Vec::with_capacity(self.tx.payload_len_for_signature());
        self.tx.encode_for_signing(&mut buf);

        let mut hasher = Keccak256::new();
        hasher.update(&buf);

        #[allow(clippy::useless_conversion)]
        let signature_hash = *self
            .signature_hash
            .get_or_init(|| hasher.clone().finalize().into());
        let signer = self.signature.recover_signer(&signature_hash)?;

        if let Some((cached_sender, cached_hash)) = self.expiring_nonce_hash.get()
            && *cached_sender == signer
        {
            return Ok((signer, Some(*cached_hash)));
        }

        hasher.update(signer.as_slice());
        let expiring_nonce_hash = hasher.finalize();
        #[allow(clippy::useless_conversion)]
        let _ = self
            .expiring_nonce_hash
            .set((signer, expiring_nonce_hash).into());

        Ok((signer, Some(expiring_nonce_hash)))
    }

    /// Calculate the expiring nonce dedup hash for replay protection.
    ///
    /// This hash is `keccak256(encode_for_signing || sender)`. It is:
    /// - **Invariant to fee payer changes**: the fee payer signature and fee token are excluded
    ///   (since `encode_for_signing` doesn't commit to them when a fee payer is present).
    /// - **Unique per sender**: different signers produce different recovered addresses, so the
    ///   hash differs even for identical transaction payloads.
    pub fn expiring_nonce_hash(&self, sender: Address) -> B256 {
        let cached = self.expiring_nonce_hash.get_or_init(|| {
            let hash = unique_tx_identifier_from_signable(&self.tx, sender);
            #[allow(clippy::useless_conversion)]
            (sender, hash).into()
        });
        if cached.0 == sender {
            cached.1
        } else {
            unique_tx_identifier_from_signable(&self.tx, sender)
        }
    }

    /// Returns the RLP header for the transaction and signature, encapsulating both
    /// payload length calculation and header creation
    #[inline]
    fn rlp_header(&self) -> alloy_rlp::Header {
        let payload_length = self.tx.rlp_encoded_fields_length_default() + self.signature.length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
    }

    /// Encode the transaction fields and signature as RLP list (without type byte)
    pub fn rlp_encode(&self, out: &mut dyn BufMut) {
        // RLP header
        self.rlp_header().encode(out);

        // Encode transaction fields
        self.tx.rlp_encode_fields_default(out);

        // Encode signature
        self.signature.encode(out);
    }

    /// Encodes this signed transaction for submission to a fee-payer service.
    pub fn encode_for_fee_payer_service(&self, out: &mut dyn BufMut) {
        let payload_length =
            self.tx.rlp_encoded_fields_length(|_| 1, true) + self.signature.length();

        out.put_u8(TEMPO_TX_TYPE_ID);
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);
        self.tx
            .rlp_encode_fields(out, |_, out| out.put_u8(0x00), true);
        self.signature.encode(out);
    }

    /// Splits the transaction into parts.
    pub fn into_parts(self) -> (TempoTransaction, TempoSignature, B256) {
        let hash = *self.hash();
        (self.tx, self.signature, hash)
    }

    /// Get the length of the transaction when RLP encoded.
    fn rlp_encoded_length(&self) -> usize {
        self.rlp_header().length_with_payload()
    }

    /// Get the length of the transaction when EIP-2718 encoded (includes type byte).
    fn eip2718_encoded_length(&self) -> usize {
        1 + self.rlp_encoded_length()
    }

    /// EIP-2718 encode the signed transaction.
    pub fn eip2718_encode(&self, out: &mut dyn BufMut) {
        // Type byte
        out.put_u8(TEMPO_TX_TYPE_ID);
        // RLP fields
        self.rlp_encode(out);
    }

    /// Decode the RLP fields (without type byte).
    pub fn rlp_decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        if header.payload_length > remaining {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        // Decode transaction fields directly from the buffer
        let tx = TempoTransaction::rlp_decode_fields(buf)?;

        // Decode signature bytes
        let sig_bytes: Bytes = Decodable::decode(buf)?;

        // Check that we consumed the expected amount
        let consumed = remaining - buf.len();
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        // Parse signature
        let signature = TempoSignature::from_bytes(&sig_bytes).map_err(alloy_rlp::Error::Custom)?;

        Ok(Self::new_unhashed(tx, signature))
    }
}

impl TxHashRef for AASigned {
    fn tx_hash(&self) -> &B256 {
        self.hash()
    }
}

impl Typed2718 for AASigned {
    fn ty(&self) -> u8 {
        TEMPO_TX_TYPE_ID
    }
}

impl Transaction for AASigned {
    #[inline]
    fn chain_id(&self) -> Option<u64> {
        self.tx.chain_id()
    }

    #[inline]
    fn nonce(&self) -> u64 {
        self.tx.nonce()
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        self.tx.gas_limit()
    }

    #[inline]
    fn gas_price(&self) -> Option<u128> {
        self.tx.gas_price()
    }

    #[inline]
    fn max_fee_per_gas(&self) -> u128 {
        self.tx.max_fee_per_gas()
    }

    #[inline]
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.tx.max_priority_fee_per_gas()
    }

    #[inline]
    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    #[inline]
    fn priority_fee_or_price(&self) -> u128 {
        self.tx.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.tx.effective_gas_price(base_fee)
    }

    #[inline]
    fn is_dynamic_fee(&self) -> bool {
        true
    }

    #[inline]
    fn kind(&self) -> TxKind {
        // Return first call's `to` or Create if empty
        self.tx
            .calls
            .first()
            .map(|c| c.to)
            .unwrap_or(TxKind::Create)
    }

    #[inline]
    fn is_create(&self) -> bool {
        self.kind().is_create()
    }

    #[inline]
    fn value(&self) -> U256 {
        // Return sum of all call values
        self.tx
            .calls
            .iter()
            .fold(U256::ZERO, |acc, call| acc + call.value)
    }

    #[inline]
    fn input(&self) -> &Bytes {
        // Return first call's input or empty
        static EMPTY_BYTES: Bytes = Bytes::new();
        self.tx
            .calls
            .first()
            .map(|c| &c.input)
            .unwrap_or(&EMPTY_BYTES)
    }

    #[inline]
    fn access_list(&self) -> Option<&AccessList> {
        Some(&self.tx.access_list)
    }

    #[inline]
    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    #[inline]
    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        None
    }
}

impl Hash for AASigned {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash().hash(state);
        self.tx.hash(state);
        self.signature.hash(state);
    }
}

impl PartialEq for AASigned {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash() && self.tx == other.tx && self.signature == other.signature
    }
}

impl Eq for AASigned {}

impl alloy_consensus::transaction::SignerRecoverable for AASigned {
    fn recover_signer(
        &self,
    ) -> Result<alloy_primitives::Address, alloy_consensus::crypto::RecoveryError> {
        let sig_hash = self.signature_hash();
        self.signature.recover_signer(&sig_hash)
    }

    fn recover_signer_unchecked(
        &self,
    ) -> Result<alloy_primitives::Address, alloy_consensus::crypto::RecoveryError> {
        // For Tempo transactions, verified and unverified recovery are the same
        // since signature verification happens during recover_signer
        self.recover_signer()
    }
}

impl Encodable2718 for AASigned {
    fn encode_2718_len(&self) -> usize {
        self.eip2718_encoded_length()
    }

    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.eip2718_encode(out)
    }

    fn trie_hash(&self) -> B256 {
        *self.hash()
    }
}

impl Decodable2718 for AASigned {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        if ty != TEMPO_TX_TYPE_ID {
            return Err(Eip2718Error::UnexpectedType(ty));
        }
        Self::rlp_decode(buf).map_err(Into::into)
    }

    fn fallback_decode(_: &mut &[u8]) -> Eip2718Result<Self> {
        Err(Eip2718Error::UnexpectedType(0))
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for AASigned {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let tx = TempoTransaction::arbitrary(u)?;
        let signature = TempoSignature::arbitrary(u)?;
        Ok(Self::new_unhashed(tx, signature))
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use alloc::borrow::Cow;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct AASignedHelper<'a> {
        #[serde(flatten)]
        tx: Cow<'a, TempoTransaction>,
        signature: Cow<'a, TempoSignature>,
        hash: Cow<'a, B256>,
    }

    impl Serialize for super::AASigned {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if let TempoSignature::Keychain(keychain_sig) = &self.signature {
                // Initialize the `key_id` field for keychain signatures so that it's serialized.
                let _ = keychain_sig.key_id(&self.signature_hash());
            }
            AASignedHelper {
                tx: Cow::Borrowed(&self.tx),
                signature: Cow::Borrowed(&self.signature),
                hash: Cow::Borrowed(self.hash()),
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for super::AASigned {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            AASignedHelper::deserialize(deserializer).map(|value| {
                Self::new_unchecked(
                    value.tx.into_owned(),
                    value.signature.into_owned(),
                    value.hash.into_owned(),
                )
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::transaction::{
            tempo_transaction::{Call, TempoTransaction},
            tt_signature::{PrimitiveSignature, TempoSignature},
        };
        use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};

        #[test]
        fn test_serde_output() {
            // Create a simple Tempo transaction
            let tx = TempoTransaction {
                chain_id: 1337,
                fee_token: None,
                max_priority_fee_per_gas: 1000000000,
                max_fee_per_gas: 2000000000,
                gas_limit: 21000,
                calls: vec![Call {
                    to: TxKind::Call(Address::repeat_byte(0x42)),
                    value: U256::from(1000),
                    input: Bytes::from(vec![1, 2, 3, 4]),
                }],
                nonce_key: U256::ZERO,
                nonce: 5,
                ..Default::default()
            };

            // Create a secp256k1 signature
            let signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                Signature::test_signature(),
            ));

            let aa_signed = super::super::AASigned::new_unhashed(tx, signature);

            // Serialize to JSON
            let json = serde_json::to_string_pretty(&aa_signed).unwrap();
            assert!(
                !json.contains("signature_hash"),
                "signature_hash cache must not be serialized"
            );

            println!("\n=== AASigned JSON Output ===");
            println!("{json}");
            println!("============================\n");

            // Also test deserialization round-trip
            let deserialized: super::super::AASigned = serde_json::from_str(&json).unwrap();
            assert_eq!(aa_signed.tx(), deserialized.tx());
            assert_eq!(aa_signed.signature_hash(), deserialized.signature_hash());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{
        tempo_transaction::Call,
        tt_authorization::tests::{generate_secp256k1_keypair, sign_hash},
        tt_signature::PrimitiveSignature,
    };
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use alloy_signer_local::PrivateKeySigner;
    use core::num::NonZeroU64;
    use proptest::prelude::*;

    fn make_tx() -> TempoTransaction {
        TempoTransaction {
            chain_id: 1,
            gas_limit: 21000,
            calls: vec![Call {
                to: TxKind::Call(Address::repeat_byte(0x42)),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            ..Default::default()
        }
    }

    fn signed_pair_for_tx(tx: TempoTransaction) -> (AASigned, AASigned) {
        let signer = PrivateKeySigner::from_bytes(&B256::with_last_byte(1)).unwrap();
        let signature = sign_hash(&signer, &tx.signature_hash());
        (
            AASigned::new_unhashed(tx.clone(), signature.clone()),
            AASigned::new_unhashed(tx, signature),
        )
    }

    fn arb_address() -> impl Strategy<Value = Address> {
        any::<[u8; 20]>().prop_map(|bytes| Address::from_slice(&bytes))
    }

    fn arb_fee_payer_signature() -> impl Strategy<Value = Signature> {
        (any::<u64>(), any::<u64>(), any::<bool>()).prop_map(|(r, s, parity)| {
            Signature::new(
                U256::from(r).saturating_add(U256::ONE),
                U256::from(s).saturating_add(U256::ONE),
                parity,
            )
        })
    }

    fn arb_call() -> impl Strategy<Value = Call> {
        (
            arb_address(),
            any::<u64>(),
            proptest::collection::vec(any::<u8>(), 0..128),
        )
            .prop_map(|(to, value, input)| Call {
                to: TxKind::Call(to),
                value: U256::from(value),
                input: Bytes::from(input),
            })
    }

    fn arb_valid_window() -> impl Strategy<Value = (Option<NonZeroU64>, Option<NonZeroU64>)> {
        prop::option::of((1u64..1_000_000, 1u64..1_000)).prop_map(|window| {
            window.map_or((None, None), |(valid_after, offset)| {
                let valid_after = NonZeroU64::new(valid_after).unwrap();
                let valid_before = NonZeroU64::new(valid_after.get() + offset).unwrap();
                (Some(valid_after), Some(valid_before))
            })
        })
    }

    fn arb_tempo_tx() -> impl Strategy<Value = TempoTransaction> {
        (
            any::<u64>(),
            prop::option::of(arb_address()),
            any::<u128>(),
            any::<u128>(),
            any::<u64>(),
            proptest::collection::vec(arb_call(), 1..8),
            any::<u64>(),
            prop::option::of(arb_fee_payer_signature()),
            arb_valid_window(),
        )
            .prop_map(
                |(
                    chain_id,
                    fee_token,
                    max_priority_fee_per_gas,
                    max_fee_per_gas,
                    gas_limit,
                    calls,
                    nonce,
                    fee_payer_signature,
                    (valid_after, valid_before),
                )| TempoTransaction {
                    chain_id,
                    fee_token,
                    max_priority_fee_per_gas,
                    max_fee_per_gas,
                    gas_limit,
                    calls,
                    nonce_key: U256::ZERO,
                    nonce,
                    fee_payer_signature,
                    valid_before,
                    valid_after,
                    ..Default::default()
                },
            )
    }

    #[test]
    fn test_hash_and_transaction_trait() {
        let tx = make_tx();
        let sig =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));

        // new_unhashed: hash not computed yet
        let signed = AASigned::new_unhashed(tx.clone(), sig.clone());

        // First call computes hash
        let hash1 = *signed.hash();
        // Second call returns cached hash (same reference)
        let hash2 = *signed.hash();
        assert_eq!(hash1, hash2, "hash should be deterministic");
        assert_ne!(hash1, B256::ZERO);

        // new_unchecked: hash provided directly
        let known_hash = B256::random();
        let signed_unchecked = AASigned::new_unchecked(tx.clone(), sig.clone(), known_hash);
        assert_eq!(
            *signed_unchecked.hash(),
            known_hash,
            "new_unchecked should use provided hash"
        );

        // into_parts returns the hash
        let signed_for_parts = AASigned::new_unhashed(tx.clone(), sig.clone());
        let (returned_tx, returned_sig, returned_hash) = signed_for_parts.into_parts();
        assert_eq!(returned_tx, tx);
        assert_eq!(returned_sig, sig);
        assert_eq!(returned_hash, hash1);
    }

    #[test]
    fn test_rlp_encode_decode_roundtrip() {
        use alloy_eips::eip2718::Encodable2718;

        let tx = make_tx();
        let sig =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let signed = AASigned::new_unhashed(tx, sig);

        // Encode
        let mut buf = Vec::new();
        signed.rlp_encode(&mut buf);
        let encoded_before_cache = buf.clone();
        let _ = signed.signature_hash();
        let mut encoded_after_cache = Vec::new();
        signed.rlp_encode(&mut encoded_after_cache);
        assert_eq!(
            encoded_before_cache, encoded_after_cache,
            "signature_hash cache must not change RLP encoding"
        );

        // Decode
        let decoded = AASigned::rlp_decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.tx(), signed.tx());
        assert_eq!(decoded.signature(), signed.signature());

        // EIP-2718 encode/decode
        let mut eip_buf = Vec::new();
        signed.eip2718_encode(&mut eip_buf);
        assert_eq!(eip_buf[0], TEMPO_TX_TYPE_ID);

        let decoded_2718 =
            AASigned::typed_decode(TEMPO_TX_TYPE_ID, &mut eip_buf[1..].as_ref()).unwrap();
        assert_eq!(decoded_2718.tx(), signed.tx());

        // trie_hash equals hash
        assert_eq!(signed.trie_hash(), *signed.hash());

        // fallback_decode returns error (Tempo txs must be typed)
        let fallback_result = AASigned::fallback_decode(&mut [].as_ref());
        assert!(fallback_result.is_err());

        // encode_2718_len matches actual encoded length
        assert_eq!(signed.encode_2718_len(), eip_buf.len());
    }

    #[test]
    fn test_rlp_decode_error_paths() {
        // Empty buffer
        let result = AASigned::rlp_decode(&mut [].as_ref());
        assert!(result.is_err());

        // Not a list (string header)
        let result = AASigned::rlp_decode(&mut [0x80].as_ref());
        assert!(result.is_err());

        // Payload length exceeds buffer
        let result = AASigned::rlp_decode(&mut [0xc1, 0x00].as_ref()); // list of 1 byte but only 0 available
        assert!(result.is_err());

        // Wrong type for typed_decode
        let result = AASigned::typed_decode(0x00, &mut [].as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_expiring_nonce_hash_invariant_to_fee_payer() {
        let sender = Address::repeat_byte(0x01);

        let make_sponsored_tx = |fee_payer_sig: Signature| -> TempoTransaction {
            TempoTransaction {
                chain_id: 1,
                gas_limit: 1_000_000,
                nonce_key: U256::MAX, // TEMPO_EXPIRING_NONCE_KEY
                nonce: 0,
                fee_token: Some(Address::repeat_byte(0xFE)),
                fee_payer_signature: Some(fee_payer_sig),
                valid_before: Some(core::num::NonZeroU64::new(100).unwrap()),
                calls: vec![Call {
                    to: TxKind::Call(Address::repeat_byte(0x42)),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                ..Default::default()
            }
        };

        let sig =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));

        // Two txs identical except for fee_payer_signature
        let tx1 = make_sponsored_tx(Signature::new(U256::from(1), U256::from(2), false));
        let tx2 = make_sponsored_tx(Signature::new(U256::from(3), U256::from(4), true));

        let signed1 = AASigned::new_unhashed(tx1, sig.clone());
        let signed2 = AASigned::new_unhashed(tx2, sig);

        // tx_hash MUST differ (fee_payer_signature is part of the envelope)
        assert_ne!(signed1.hash(), signed2.hash(), "tx hashes must differ");

        // expiring_nonce_hash MUST be identical (invariant to fee payer)
        let hash1 = signed1.expiring_nonce_hash(sender);
        let hash2 = signed2.expiring_nonce_hash(sender);
        assert_eq!(
            hash1, hash2,
            "expiring_nonce_hash must be invariant to fee payer signature changes"
        );
        assert_ne!(hash1, B256::ZERO);
    }

    #[test]
    fn test_expiring_nonce_hash_unique_per_sender() {
        let tx = TempoTransaction {
            chain_id: 1,
            gas_limit: 1_000_000,
            nonce_key: U256::MAX,
            nonce: 0,
            valid_before: Some(core::num::NonZeroU64::new(100).unwrap()),
            calls: vec![Call {
                to: TxKind::Call(Address::repeat_byte(0x42)),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            ..Default::default()
        };
        let sig =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let signed = AASigned::new_unhashed(tx, sig);

        let sender_a = Address::repeat_byte(0x01);
        let sender_b = Address::repeat_byte(0x02);

        assert_ne!(
            signed.expiring_nonce_hash(sender_a),
            signed.expiring_nonce_hash(sender_b),
            "different senders must produce different expiring_nonce_hash"
        );
    }

    #[test]
    fn test_expiring_nonce_hash_deterministic() {
        let tx = make_tx();
        let sig =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let signed = AASigned::new_unhashed(tx, sig);
        let sender = Address::repeat_byte(0xAB);

        let h1 = signed.expiring_nonce_hash(sender);
        let h2 = signed.expiring_nonce_hash(sender);
        assert_eq!(h1, h2, "expiring_nonce_hash must be deterministic");
    }

    #[test]
    fn test_recover_signer() {
        let (signing_key, expected_address) = generate_secp256k1_keypair();

        let tx = make_tx();

        // Create signed transaction with placeholder sig to get sig_hash
        let placeholder =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let temp_signed = AASigned::new_unhashed(tx.clone(), placeholder);
        let sig_hash = temp_signed.signature_hash();

        // Sign the correct hash
        let signature = sign_hash(&signing_key, &sig_hash);
        let signed = AASigned::new_unhashed(tx.clone(), signature);

        // Recovery should succeed with correct address
        let recovered = signed.recover_signer().unwrap();
        assert_eq!(recovered, expected_address);

        // recover_signer_unchecked should give same result
        let recovered_unchecked = signed.recover_signer_unchecked().unwrap();
        assert_eq!(recovered_unchecked, expected_address);

        // Wrong signature yields wrong address
        let wrong_sig = sign_hash(&signing_key, &B256::random());
        let bad_signed = AASigned::new_unhashed(tx, wrong_sig);
        let bad_recovered = bad_signed.recover_signer().unwrap();
        assert_ne!(bad_recovered, expected_address);
    }

    #[test]
    fn test_recover_signer_with_expiring_nonce_hash() {
        let (signing_key, expected_address) = generate_secp256k1_keypair();

        let mut tx = make_tx();
        tx.nonce_key = U256::MAX;

        let placeholder =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let temp_signed = AASigned::new_unhashed(tx.clone(), placeholder);
        let sig_hash = temp_signed.signature_hash();

        let signature = sign_hash(&signing_key, &sig_hash);
        let signed = AASigned::new_unhashed(tx, signature);

        let (recovered, expiring_nonce_hash) =
            signed.recover_signer_with_expiring_nonce_hash().unwrap();
        assert_eq!(recovered, expected_address);
        assert_eq!(
            expiring_nonce_hash,
            Some(signed.expiring_nonce_hash(expected_address))
        );
        assert_eq!(signed.signature_hash(), sig_hash);
    }

    #[test]
    fn test_recover_signer_with_expiring_nonce_hash_non_expiring() {
        let (signing_key, expected_address) = generate_secp256k1_keypair();

        let tx = make_tx();

        let placeholder =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let temp_signed = AASigned::new_unhashed(tx.clone(), placeholder);
        let sig_hash = temp_signed.signature_hash();

        let signature = sign_hash(&signing_key, &sig_hash);
        let signed = AASigned::new_unhashed(tx, signature);

        let (recovered, expiring_nonce_hash) =
            signed.recover_signer_with_expiring_nonce_hash().unwrap();
        assert_eq!(recovered, expected_address);
        assert_eq!(expiring_nonce_hash, None);
    }

    proptest! {
        #[test]
        fn proptest_recover_signer_with_expiring_nonce_hash_matches_individuals(mut tx in arb_tempo_tx()) {
            tx.nonce_key = U256::MAX;
            let (individual, helper) = signed_pair_for_tx(tx);

            let individual_signer = individual.recover_signer().unwrap();
            let individual_expiring_nonce_hash = individual.expiring_nonce_hash(individual_signer);
            let (helper_signer, helper_expiring_nonce_hash) =
                helper.recover_signer_with_expiring_nonce_hash().unwrap();

            prop_assert_eq!(helper_signer, individual_signer);
            prop_assert_eq!(helper_expiring_nonce_hash, Some(individual_expiring_nonce_hash));
        }

        #[test]
        fn proptest_recover_signer_with_expiring_nonce_hash_matches_individuals_for_non_expiring(mut tx in arb_tempo_tx()) {
            tx.nonce_key = U256::ZERO;
            let (individual, helper) = signed_pair_for_tx(tx);

            let individual_signer = individual.recover_signer().unwrap();
            let (helper_signer, helper_expiring_nonce_hash) =
                helper.recover_signer_with_expiring_nonce_hash().unwrap();

            prop_assert_eq!(helper_signer, individual_signer);
            prop_assert_eq!(helper_expiring_nonce_hash, None);
        }
    }
}
