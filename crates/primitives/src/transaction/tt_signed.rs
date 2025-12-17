use super::{
    tempo_transaction::{TEMPO_TX_TYPE_ID, TempoTransaction},
    tt_signature::TempoSignature,
};
use alloy_consensus::{Transaction, transaction::TxHashRef};
use alloy_eips::{
    Decodable2718, Encodable2718, Typed2718,
    eip2718::{Eip2718Error, Eip2718Result},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{B256, Bytes, TxKind, U256};
use alloy_rlp::{BufMut, Decodable, Encodable};
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
};
use std::sync::OnceLock;

/// A transaction with an AA signature and hash seal.
///
/// This wraps a TempoTransaction transaction with its multi-signature-type signature
/// (secp256k1, P256, Webauthn, Keychain) and provides a cached transaction hash.
#[derive(Clone, Debug)]
pub struct AASigned {
    /// The inner Tempo transaction
    tx: TempoTransaction,
    /// The signature (can be secp256k1, P256, Webauthn, Keychain)
    signature: TempoSignature,
    /// Cached transaction hash
    #[doc(alias = "tx_hash", alias = "transaction_hash")]
    hash: OnceLock<B256>,
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
        }
    }

    /// Instantiate from a transaction and signature without computing the hash.
    /// Does not verify the signature.
    pub const fn new_unhashed(tx: TempoTransaction, signature: TempoSignature) -> Self {
        Self {
            tx,
            signature,
            hash: OnceLock::new(),
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
        self.hash.get_or_init(|| self.compute_hash())
    }

    /// Calculate the transaction hash
    fn compute_hash(&self) -> B256 {
        let mut buf = Vec::new();
        self.eip2718_encode(&mut buf);
        alloy_primitives::keccak256(&buf)
    }

    /// Calculate the signing hash for the transaction.
    pub fn signature_hash(&self) -> B256 {
        self.tx.signature_hash()
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

#[cfg(feature = "reth")]
impl reth_primitives_traits::InMemorySize for AASigned {
    fn size(&self) -> usize {
        core::mem::size_of::<Self>()
            + self.tx.size()
            + self.signature.encoded_length()
            + core::mem::size_of::<B256>()
    }
}

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
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::borrow::Cow;

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

            println!("\n=== AASigned JSON Output ===");
            println!("{json}");
            println!("============================\n");

            // Also test deserialization round-trip
            let deserialized: super::super::AASigned = serde_json::from_str(&json).unwrap();
            assert_eq!(aa_signed.tx(), deserialized.tx());
        }
    }
}
