use alloy_consensus::{SignableTransaction, Transaction};
use alloy_eips::{Typed2718, eip2930::AccessList, eip7702::SignedAuthorization};
use alloy_primitives::{Address, B256, Bytes, ChainId, Signature, TxKind, U256, keccak256};
use alloy_rlp::{Buf, BufMut, Decodable, EMPTY_STRING_CODE, Encodable};
use core::mem;

/// Account abstraction transaction type byte (0x5)
pub const AA_TX_TYPE_ID: u8 = 0x5;

/// Signature type constants
pub const SECP256K1_SIGNATURE_LENGTH: usize = 65;
pub const P256_SIGNATURE_LENGTH: usize = 129;
pub const MAX_WEBAUTHN_SIGNATURE_LENGTH: usize = 2048; // 2KB max

/// Signature type enumeration
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureType {
    Secp256k1,
    P256,
    WebAuthn,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Call {
    pub to: TxKind,
    pub value: U256,
    pub input: Bytes,
}

impl Encodable for Call {
    fn encode(&self, out: &mut dyn BufMut) {
        let payload_length = self.to.length() + self.value.length() + self.input.length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.to.length() + self.value.length() + self.input.length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .length_with_payload()
    }
}

impl Decodable for Call {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        Ok(Self {
            to: Decodable::decode(buf)?,
            value: Decodable::decode(buf)?,
            input: Decodable::decode(buf)?,
        })
    }
}
/// Account abstraction transaction following the Tempo spec.
///
/// This transaction type supports:
/// - Multiple signature types (secp256k1, P256, WebAuthn)
/// - Parallelizable nonces via 2D nonce system (nonce_key + nonce_sequence)
/// - Gas sponsorship via fee payer
/// - Scheduled transactions (validBefore/validAfter)
/// - EIP-7702 authorization lists
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[doc(alias = "AATransaction", alias = "TransactionAA")]
pub struct TxAA {
    /// EIP-155: Simple replay attack protection
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub chain_id: ChainId,

    /// Optional fee token preference (nil means no preference)
    pub fee_token: Option<Address>,

    /// Max Priority fee per gas (EIP-1559)
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub max_priority_fee_per_gas: u128,

    /// Max fee per gas (EIP-1559)
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub max_fee_per_gas: u128,

    /// Gas limit
    #[cfg_attr(
        feature = "serde",
        serde(with = "alloy_serde::quantity", rename = "gas", alias = "gasLimit")
    )]
    pub gas_limit: u64,

    // TODO: What happens if this vec is empty?
    pub calls: Vec<Call>,

    /// Access list (EIP-2930)
    pub access_list: AccessList,

    /// AA-specific fields

    /// Nonce key for 2D nonce system (192 bits)
    /// Key 0 is the protocol nonce, keys 1-N are user nonces for parallelization
    pub nonce_key: u64,

    /// Current sequence value for the nonce key
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub nonce_sequence: u64,

    /// Optional features

    /// Optional fee payer signature for sponsored transactions (secp256k1 only)
    pub fee_payer_signature: Option<Signature>,

    /// Transaction can only be included in a block before this timestamp
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub valid_before: u64,

    /// Transaction can only be included in a block after this timestamp
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity::opt"))]
    pub valid_after: Option<u64>,
}

impl Default for TxAA {
    fn default() -> Self {
        Self {
            chain_id: 0,
            fee_token: None,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 0,
            calls: Vec::new(),
            access_list: AccessList::default(),
            nonce_key: 0,
            nonce_sequence: 0,
            fee_payer_signature: None,
            valid_before: 0,
            valid_after: None,
        }
    }
}

impl TxAA {
    /// Get the transaction type
    #[doc(alias = "transaction_type")]
    pub const fn tx_type() -> u8 {
        AA_TX_TYPE_ID
    }

    /// Validates the transaction according to the spec rules
    pub fn validate(&self) -> Result<(), &'static str> {
        // calls must not be empty (similar to EIP-7702 rejecting empty auth lists)
        if self.calls.is_empty() {
            return Err("calls list cannot be empty");
        }

        // validBefore must be greater than validAfter if both are set
        if let Some(valid_after) = self.valid_after {
            if self.valid_before > 0 && self.valid_before <= valid_after {
                return Err("valid_before must be greater than valid_after");
            }
        }

        Ok(())
    }

    /// Calculates a heuristic for the in-memory size of the transaction
    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<ChainId>() + // chain_id
        mem::size_of::<Option<Address>>() + // fee_token
        mem::size_of::<u128>() + // max_priority_fee_per_gas
        mem::size_of::<u128>() + // max_fee_per_gas
        mem::size_of::<u64>() + // gas_limit
        self.calls.iter().map(|call| {
            mem::size_of::<TxKind>() + mem::size_of::<U256>() + call.input.len()
        }).sum::<usize>() + // calls
        self.access_list.size() + // access_list
        mem::size_of::<u64>() + // nonce_key
        mem::size_of::<u64>() + // nonce_sequence
        mem::size_of::<Option<Signature>>() + // fee_payer_signature
        mem::size_of::<u64>() + // valid_before
        mem::size_of::<Option<u64>>() // valid_after
    }

    /// Calculate the signing hash for this transaction
    /// This is the hash that should be signed by the sender
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::new();
        self.encode_for_signing(&mut buf);
        keccak256(&buf)
    }

    /// Calculate the fee payer signature hash
    /// This hash is signed by the fee payer to sponsor the transaction
    pub fn fee_payer_signature_hash(&self, sender: Address) -> B256 {
        let mut buf = Vec::new();

        // Type byte
        buf.put_u8(AA_TX_TYPE_ID);

        // Compute payload length (fields + sender address, no fee_token)
        let payload_length = self.chain_id.length() +
            self.max_priority_fee_per_gas.length() +
            self.max_fee_per_gas.length() +
            self.gas_limit.length() +
            self.calls.length() +
            self.access_list.length() +
            self.nonce_key.length() +
            self.nonce_sequence.length() +
            self.valid_before.length() +
            if self.valid_after.is_some() {
                self.valid_after.unwrap().length()
            } else {
                1
            } +
            1 + // fee_token = empty (skip)
            sender.length(); // sender instead of fee_payer_signature

        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(&mut buf);

        // Encode fields
        self.chain_id.encode(&mut buf);
        self.max_priority_fee_per_gas.encode(&mut buf);
        self.max_fee_per_gas.encode(&mut buf);
        self.gas_limit.encode(&mut buf);
        self.calls.encode(&mut buf);
        self.access_list.encode(&mut buf);
        self.nonce_key.encode(&mut buf);
        self.nonce_sequence.encode(&mut buf);
        self.valid_before.encode(&mut buf);
        if let Some(valid_after) = self.valid_after {
            valid_after.encode(&mut buf);
        } else {
            buf.put_u8(EMPTY_STRING_CODE);
        }
        buf.put_u8(EMPTY_STRING_CODE); // skip fee_token
        sender.encode(&mut buf); // encode sender instead of fee_payer_signature

        keccak256(&buf)
    }
}

impl TxAA {
    /// Outputs the length of the transaction's fields, without a RLP header.
    pub(crate) fn rlp_encoded_fields_length(&self) -> usize {
        self.chain_id.length() +
            self.max_priority_fee_per_gas.length() +
            self.max_fee_per_gas.length() +
            self.gas_limit.length() +
            // calls (vector of Call structs)
            self.calls.length() +
            self.access_list.length() +
            // nonce_key
            self.nonce_key.length() +
            // nonce_sequence
            self.nonce_sequence.length() +
            // valid_before
            self.valid_before.length() +
            // valid_after (optional u64)
            if let Some(valid_after) = self.valid_after {
                valid_after.length()
            } else {
                1 // EMPTY_STRING_CODE
            } +
            // fee_token (optional Address)
            if let Some(addr) = self.fee_token {
                addr.length()
            } else {
                1 // EMPTY_STRING_CODE
            } +
            // fee_payer_signature (optional)
            if let Some(sig) = &self.fee_payer_signature {
                alloy_rlp::Header {
                    list: true,
                    payload_length: sig.rlp_rs_len() + sig.v().length(),
                }
                .length_with_payload()
            } else {
                1 // EMPTY_STRING_CODE
            }
    }

    pub(crate) fn rlp_encode_fields(&self, out: &mut dyn BufMut) {
        self.chain_id.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);

        // Encode calls vector
        self.calls.encode(out);

        self.access_list.encode(out);

        // Encode nonce_key
        self.nonce_key.encode(out);

        // Encode nonce_sequence
        self.nonce_sequence.encode(out);

        // Encode valid_before
        self.valid_before.encode(out);

        // Encode valid_after
        if let Some(valid_after) = self.valid_after {
            valid_after.encode(out);
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }

        // Encode fee_token
        if let Some(addr) = self.fee_token {
            addr.encode(out);
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }

        // Encode fee_payer_signature
        if let Some(signature) = &self.fee_payer_signature {
            let payload_length = signature.rlp_rs_len() + signature.v().length();
            alloy_rlp::Header {
                list: true,
                payload_length,
            }
            .encode(out);
            signature.write_rlp_vrs(out, signature.v());
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }
    }
}

impl TxAA {
    /// Decodes the inner TxAA fields from RLP bytes
    pub(crate) fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let chain_id = Decodable::decode(buf)?;
        let max_priority_fee_per_gas = Decodable::decode(buf)?;
        let max_fee_per_gas = Decodable::decode(buf)?;
        let gas_limit = Decodable::decode(buf)?;
        let calls = Decodable::decode(buf)?;
        let access_list = Decodable::decode(buf)?;
        let nonce_key = Decodable::decode(buf)?;
        let nonce_sequence = Decodable::decode(buf)?;
        let valid_before = Decodable::decode(buf)?;

        let valid_after = if let Some(first) = buf.first() {
            if *first == EMPTY_STRING_CODE {
                buf.advance(1);
                None
            } else {
                Some(Decodable::decode(buf)?)
            }
        } else {
            return Err(alloy_rlp::Error::InputTooShort);
        };

        let fee_token = if let Some(first) = buf.first() {
            if *first == EMPTY_STRING_CODE {
                buf.advance(1);
                None
            } else {
                TxKind::decode(buf)?.into_to()
            }
        } else {
            return Err(alloy_rlp::Error::InputTooShort);
        };

        let fee_payer_signature = if let Some(first) = buf.first() {
            if *first == EMPTY_STRING_CODE {
                buf.advance(1);
                None
            } else {
                let header = alloy_rlp::Header::decode(buf)?;
                if buf.len() < header.payload_length {
                    return Err(alloy_rlp::Error::InputTooShort);
                }
                if !header.list {
                    return Err(alloy_rlp::Error::UnexpectedString);
                }
                Some(Signature::decode_rlp_vrs(buf, bool::decode)?)
            }
        } else {
            return Err(alloy_rlp::Error::InputTooShort);
        };

        let tx = Self {
            chain_id,
            fee_token,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            calls,
            access_list,
            nonce_key,
            nonce_sequence,
            fee_payer_signature,
            valid_before,
            valid_after,
        };

        // Validate the transaction
        tx.validate().map_err(alloy_rlp::Error::Custom)?;

        Ok(tx)
    }
}

impl Transaction for TxAA {
    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }

    #[inline]
    fn nonce(&self) -> u64 {
        self.nonce_sequence
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    #[inline]
    fn gas_price(&self) -> Option<u128> {
        None
    }

    #[inline]
    fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    #[inline]
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.max_priority_fee_per_gas)
    }

    #[inline]
    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    #[inline]
    fn priority_fee_or_price(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        base_fee.map_or(self.max_fee_per_gas, |base_fee| {
            // if the tip is greater than the max priority fee per gas, set it to the max
            // priority fee per gas + base fee
            let tip = self.max_fee_per_gas.saturating_sub(base_fee as u128);
            if tip > self.max_priority_fee_per_gas {
                self.max_priority_fee_per_gas + base_fee as u128
            } else {
                // otherwise return the max fee per gas
                self.max_fee_per_gas
            }
        })
    }

    #[inline]
    fn is_dynamic_fee(&self) -> bool {
        true
    }

    #[inline]
    fn kind(&self) -> TxKind {
        // Return first call's `to` or Create if empty
        self.calls.first().map(|c| c.to).unwrap_or(TxKind::Create)
    }

    #[inline]
    fn is_create(&self) -> bool {
        self.kind().is_create()
    }

    #[inline]
    fn value(&self) -> U256 {
        // Return sum of all call values
        self.calls
            .iter()
            .fold(U256::ZERO, |acc, call| acc + call.value)
    }

    #[inline]
    fn input(&self) -> &Bytes {
        // Return first call's input or empty
        static EMPTY_BYTES: Bytes = Bytes::new();
        self.calls.first().map(|c| &c.input).unwrap_or(&EMPTY_BYTES)
    }

    #[inline]
    fn access_list(&self) -> Option<&AccessList> {
        Some(&self.access_list)
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

impl Typed2718 for TxAA {
    fn ty(&self) -> u8 {
        AA_TX_TYPE_ID
    }
}

impl SignableTransaction<Signature> for TxAA {
    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = chain_id;
    }

    fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        // Skip fee_token if fee_payer_signature is present to ensure user doesn't commit to a specific fee token
        let skip_fee_token = self.fee_payer_signature.is_some();

        // Type byte
        out.put_u8(Self::tx_type());

        // Compute payload length (all fields, no signature)
        let payload_length = self.chain_id.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.calls.length()
            + self.access_list.length()
            + self.nonce_key.length()
            + self.nonce_sequence.length()
            + self.valid_before.length()
            + if self.valid_after.is_some() {
                self.valid_after.unwrap().length()
            } else {
                1
            }
            + if !skip_fee_token && self.fee_token.is_some() {
                self.fee_token.unwrap().length()
            } else {
                1
            }
            + if self.fee_payer_signature.is_some() {
                1 // placeholder for fee_payer_signature when signing
            } else {
                1
            };

        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);

        // Encode fields
        self.chain_id.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.calls.encode(out);
        self.access_list.encode(out);
        self.nonce_key.encode(out);
        self.nonce_sequence.encode(out);
        self.valid_before.encode(out);
        if let Some(valid_after) = self.valid_after {
            valid_after.encode(out);
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }

        // fee_token: skip if fee_payer_signature is present
        if !skip_fee_token {
            if let Some(addr) = self.fee_token {
                addr.encode(out);
            } else {
                out.put_u8(EMPTY_STRING_CODE);
            }
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }

        // fee_payer_signature placeholder
        if self.fee_payer_signature.is_some() {
            out.put_u8(0); // placeholder byte
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }
    }

    fn payload_len_for_signature(&self) -> usize {
        let skip_fee_token = self.fee_payer_signature.is_some();
        let payload_length = self.chain_id.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.calls.length()
            + self.access_list.length()
            + self.nonce_key.length()
            + self.nonce_sequence.length()
            + self.valid_before.length()
            + if self.valid_after.is_some() {
                self.valid_after.unwrap().length()
            } else {
                1
            }
            + if !skip_fee_token && self.fee_token.is_some() {
                self.fee_token.unwrap().length()
            } else {
                1
            }
            + 1; // fee_payer_signature placeholder

        1 + alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .length_with_payload()
    }
}

impl Encodable for TxAA {
    fn encode(&self, out: &mut dyn BufMut) {
        // Encode as RLP list of fields
        let payload_length = self.rlp_encoded_fields_length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);
        self.rlp_encode_fields(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_encoded_fields_length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .length_with_payload()
    }
}

impl Decodable for TxAA {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        Self::rlp_decode_fields(buf)
    }
}

impl reth_primitives_traits::InMemorySize for TxAA {
    fn size(&self) -> usize {
        Self::size(self)
    }
}

#[cfg(feature = "serde-bincode-compat")]
impl reth_primitives_traits::serde_bincode_compat::RlpBincode for TxAA {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::aa_signature::{AASignature, derive_p256_address};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256, address, hex};
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn test_tx_aa_validation() {
        // Create a dummy call to satisfy validation
        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Valid: valid_before > valid_after
        let tx1 = TxAA {
            valid_before: 100,
            valid_after: Some(50),
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx1.validate().is_ok());

        // Invalid: valid_before <= valid_after
        let tx2 = TxAA {
            valid_before: 50,
            valid_after: Some(100),
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx2.validate().is_err());

        // Invalid: valid_before == valid_after
        let tx3 = TxAA {
            valid_before: 100,
            valid_after: Some(100),
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx3.validate().is_err());

        // Valid: no valid_after
        let tx4 = TxAA {
            valid_before: 100,
            valid_after: None,
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx4.validate().is_ok());

        // Invalid: empty calls
        let tx5 = TxAA {
            ..Default::default()
        };
        assert!(tx5.validate().is_err());
    }

    #[test]
    fn test_tx_type() {
        assert_eq!(TxAA::tx_type(), 0x05);
        assert_eq!(AA_TX_TYPE_ID, 0x05);
    }

    #[test]
    fn test_signature_type_detection() {
        use crate::transaction::aa_signature::{SIGNATURE_TYPE_P256, SIGNATURE_TYPE_WEBAUTHN};

        // Secp256k1 (detected by 65-byte length, no type identifier)
        let sig1_bytes = vec![0u8; SECP256K1_SIGNATURE_LENGTH];
        let sig1 = AASignature::from_bytes(&sig1_bytes).unwrap();
        assert_eq!(sig1.signature_type(), SignatureType::Secp256k1);

        // P256
        let mut sig2_bytes = vec![SIGNATURE_TYPE_P256];
        sig2_bytes.extend_from_slice(&vec![0u8; P256_SIGNATURE_LENGTH]);
        let sig2 = AASignature::from_bytes(&sig2_bytes).unwrap();
        assert_eq!(sig2.signature_type(), SignatureType::P256);

        // WebAuthn
        let mut sig3_bytes = vec![SIGNATURE_TYPE_WEBAUTHN];
        sig3_bytes.extend_from_slice(&vec![0u8; 200]);
        let sig3 = AASignature::from_bytes(&sig3_bytes).unwrap();
        assert_eq!(sig3.signature_type(), SignatureType::WebAuthn);
    }

    #[test]
    fn test_rlp_roundtrip() {
        let call = Call {
            to: TxKind::Call(address!("0000000000000000000000000000000000000002")),
            value: U256::from(1000),
            input: Bytes::from(vec![1, 2, 3, 4]),
        };

        let tx = TxAA {
            chain_id: 1,
            fee_token: Some(address!("0000000000000000000000000000000000000001")),
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![call.clone()],
            access_list: Default::default(),
            nonce_key: 0,
            nonce_sequence: 1,
            fee_payer_signature: Some(Signature::test_signature()),
            valid_before: 1000000,
            valid_after: Some(500000),
        };

        // Encode
        let mut buf = Vec::new();
        tx.encode(&mut buf);

        // Decode
        let decoded = TxAA::decode(&mut buf.as_slice()).unwrap();

        // Verify fields
        assert_eq!(decoded.chain_id, tx.chain_id);
        assert_eq!(decoded.fee_token, tx.fee_token);
        assert_eq!(
            decoded.max_priority_fee_per_gas,
            tx.max_priority_fee_per_gas
        );
        assert_eq!(decoded.max_fee_per_gas, tx.max_fee_per_gas);
        assert_eq!(decoded.gas_limit, tx.gas_limit);
        assert_eq!(decoded.calls.len(), 1);
        assert_eq!(decoded.calls[0].to, call.to);
        assert_eq!(decoded.calls[0].value, call.value);
        assert_eq!(decoded.calls[0].input, call.input);
        assert_eq!(decoded.nonce_key, tx.nonce_key);
        assert_eq!(decoded.nonce_sequence, tx.nonce_sequence);
        assert_eq!(decoded.valid_before, tx.valid_before);
        assert_eq!(decoded.valid_after, tx.valid_after);
        assert_eq!(decoded.fee_payer_signature, tx.fee_payer_signature);
    }

    #[test]
    fn test_rlp_roundtrip_no_optional_fields() {
        let call = Call {
            to: TxKind::Call(address!("0000000000000000000000000000000000000002")),
            value: U256::from(1000),
            input: Bytes::new(),
        };

        let tx = TxAA {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![call],
            access_list: Default::default(),
            nonce_key: 0,
            nonce_sequence: 1,
            fee_payer_signature: None,
            valid_before: 0,
            valid_after: None,
        };

        // Encode
        let mut buf = Vec::new();
        tx.encode(&mut buf);

        // Decode
        let decoded = TxAA::decode(&mut buf.as_slice()).unwrap();

        // Verify fields
        assert_eq!(decoded.chain_id, tx.chain_id);
        assert_eq!(decoded.fee_token, None);
        assert_eq!(decoded.fee_payer_signature, None);
        assert_eq!(decoded.valid_after, None);
        assert_eq!(decoded.calls.len(), 1);
    }

    #[test]
    fn test_p256_address_derivation() {
        let pub_key_x =
            hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").into();
        let pub_key_y =
            hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").into();

        let addr1 = derive_p256_address(&pub_key_x, &pub_key_y);
        let addr2 = derive_p256_address(&pub_key_x, &pub_key_y);

        // Should be deterministic
        assert_eq!(addr1, addr2);

        // Should not be zero address
        assert_ne!(addr1, Address::ZERO);
    }

    #[test]
    fn test_nonce_system() {
        use alloy_consensus::Transaction;

        // Create a dummy call to satisfy validation
        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Protocol nonce (key 0)
        let tx1 = TxAA {
            nonce_key: 0,
            nonce_sequence: 1,
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx1.validate().is_ok());
        assert_eq!(tx1.nonce(), 1);

        // User parallel nonce (key > 0)
        let tx2 = TxAA {
            nonce_key: 1,
            nonce_sequence: 0,
            calls: vec![dummy_call],
            ..Default::default()
        };
        assert!(tx2.validate().is_ok());
        assert_eq!(tx2.nonce(), 0);
    }

    #[test]
    fn test_transaction_trait_impl() {
        use alloy_consensus::Transaction;

        let call = Call {
            to: TxKind::Call(address!("0000000000000000000000000000000000000002")),
            value: U256::from(1000),
            input: Bytes::new(),
        };

        let tx = TxAA {
            chain_id: 1,
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![call],
            ..Default::default()
        };

        assert_eq!(tx.chain_id(), Some(1));
        assert_eq!(tx.gas_limit(), 21000);
        assert_eq!(tx.max_fee_per_gas(), 2000000000);
        assert_eq!(tx.max_priority_fee_per_gas(), Some(1000000000));
        assert_eq!(tx.value(), U256::from(1000));
        assert!(tx.is_dynamic_fee());
        assert!(!tx.is_create());
    }

    #[test]
    fn test_effective_gas_price() {
        use alloy_consensus::Transaction;

        // Create a dummy call to satisfy validation
        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        let tx = TxAA {
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            calls: vec![dummy_call],
            ..Default::default()
        };

        // With base fee
        let effective1 = tx.effective_gas_price(Some(500000000));
        assert_eq!(effective1, 1500000000); // base_fee + max_priority_fee_per_gas

        // Without base fee
        let effective2 = tx.effective_gas_price(None);
        assert_eq!(effective2, 2000000000); // max_fee_per_gas
    }
}
