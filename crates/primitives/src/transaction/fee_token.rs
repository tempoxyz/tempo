use alloy_consensus::{
    SignableTransaction, Signed, Transaction,
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx},
};
use alloy_eips::{Typed2718, eip2930::AccessList, eip7702::SignedAuthorization};
use alloy_primitives::{Address, B256, Bytes, ChainId, Signature, TxKind, U256, keccak256};
use alloy_rlp::{Buf, BufMut, Decodable, EMPTY_STRING_CODE, Encodable};
use core::mem;

/// Fee token transaction type byte (0x77)
pub const FEE_TOKEN_TX_TYPE_ID: u8 = 0x77;

/// Magic byte for the fee payer signature
pub const FEE_PAYER_SIGNATURE_MAGIC_BYTE: u8 = 0x78;

/// A transaction with fee token preference following the Tempo spec.
///
/// This transaction type supports:
/// - Specifying a fee token preference
/// - EIP-7702 authorization lists
/// - Contract creation (when authorization_list is empty)
/// - Dynamic fee market (EIP-1559)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[doc(alias = "FeeTokenTransaction", alias = "TransactionFeeToken")]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
pub struct TxFeeToken {
    /// EIP-155: Simple replay attack protection
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub chain_id: ChainId,

    /// A scalar value equal to the number of transactions sent by the sender
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub nonce: u64,

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

    /// The recipient address (TxKind::Create for contract creation if authorization_list is empty)
    pub to: TxKind,

    /// Value to transfer
    pub value: U256,

    /// Access list (EIP-2930)
    pub access_list: AccessList,

    /// Authorization list (EIP-7702)
    pub authorization_list: Vec<SignedAuthorization>,

    /// Optional fee payer signature.
    pub fee_payer_signature: Option<Signature>,

    /// Input data
    // Note: This is at last position for the codecs derive
    pub input: Bytes,
}

impl Default for TxFeeToken {
    fn default() -> Self {
        Self {
            chain_id: 0,
            nonce: 0,
            fee_token: None,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 0,
            to: TxKind::Create,
            value: U256::ZERO,
            access_list: AccessList::default(),
            authorization_list: Vec::new(),
            fee_payer_signature: None,
            input: Bytes::new(),
        }
    }
}

impl TxFeeToken {
    /// Get the transaction type
    #[doc(alias = "transaction_type")]
    pub const fn tx_type() -> u8 {
        FEE_TOKEN_TX_TYPE_ID
    }

    /// Validates the transaction according to the spec rules
    pub fn validate(&self) -> Result<(), &'static str> {
        // Creation rule: if authorization_list is non-empty, to MUST NOT be Create
        if !self.authorization_list.is_empty() && self.to.is_create() {
            return Err("to field cannot be Create when authorization_list is non-empty");
        }
        Ok(())
    }

    /// Calculates a heuristic for the in-memory size of the transaction
    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<ChainId>() + // chain_id
        mem::size_of::<u64>() + // nonce
        mem::size_of::<Option<Address>>() + // fee_token
        mem::size_of::<u128>() + // max_priority_fee_per_gas
        mem::size_of::<u128>() + // max_fee_per_gas
        mem::size_of::<u64>() + // gas_limit
        mem::size_of::<TxKind>() + // to
        mem::size_of::<U256>() + // value
        self.access_list.size() + // access_list
        self.authorization_list.len() * mem::size_of::<SignedAuthorization>() + // authorization_list
        self.input.len() // input
    }

    /// Combines this transaction with `signature`, taking `self`. Returns [`Signed`].
    pub fn into_signed(self, signature: Signature) -> Signed<Self> {
        let tx_hash = self.tx_hash(&signature);
        Signed::new_unchecked(self, signature, tx_hash)
    }

    /// Outputs the length of the transaction's fields, without a RLP header.
    fn rlp_encoded_fields_length(
        &self,
        signature_length: impl FnOnce(&Option<Signature>) -> usize,
        skip_fee_token: bool,
    ) -> usize {
        self.chain_id.length() +
            self.nonce.length() +
            self.max_priority_fee_per_gas.length() +
            self.max_fee_per_gas.length() +
            self.gas_limit.length() +
            self.to.length() +
            self.value.length() +
            self.input.length() +
            self.access_list.length() +
            self.authorization_list.length() +
            // fee_token encoded like TxKind: Address or 1 byte for None
            if !skip_fee_token && let Some(addr) = self.fee_token {
                addr.length()
            } else {
                1 // EMPTY_STRING_CODE is a single byte
            } +
            signature_length(&self.fee_payer_signature)
    }

    fn rlp_encode_fields(
        &self,
        out: &mut dyn BufMut,
        encode_signature: impl FnOnce(&Option<Signature>, &mut dyn BufMut),
        skip_fee_token: bool,
    ) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.encode(out);
        self.access_list.encode(out);
        self.authorization_list.encode(out);
        // Encode fee_token like TxKind: Address or EMPTY_STRING_CODE for None
        if !skip_fee_token && let Some(addr) = self.fee_token {
            addr.encode(out);
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }
        encode_signature(&self.fee_payer_signature, out);
    }

    pub fn fee_payer_signature_hash(&self, sender: Address) -> B256 {
        let rlp_header = alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_encoded_fields_length(|_| sender.length(), false),
        };
        let mut buf = Vec::with_capacity(rlp_header.length_with_payload());
        buf.put_u8(FEE_PAYER_SIGNATURE_MAGIC_BYTE);
        rlp_header.encode(&mut buf);
        self.rlp_encode_fields(
            &mut buf,
            |_, out| {
                sender.encode(out);
            },
            false,
        );

        keccak256(&buf)
    }
}

impl RlpEcdsaEncodableTx for TxFeeToken {
    /// Outputs the length of the transaction's fields, without a RLP header
    fn rlp_encoded_fields_length(&self) -> usize {
        self.rlp_encoded_fields_length(
            |signature| {
                signature.map_or(1, |s| {
                    alloy_rlp::Header {
                        list: true,
                        payload_length: s.rlp_rs_len() + s.v().length(),
                    }
                    .length_with_payload()
                })
            },
            false,
        )
    }

    /// Encodes only the transaction's fields into the desired buffer, without a RLP header
    fn rlp_encode_fields(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.rlp_encode_fields(
            out,
            |signature, out| {
                if let Some(signature) = signature {
                    let payload_length = signature.rlp_rs_len() + signature.v().length();
                    alloy_rlp::Header { list: true, payload_length }.encode(out);
                    signature.write_rlp_vrs(out, signature.v());
                } else {
                    out.put_u8(EMPTY_STRING_CODE);
                }
            },
            false,
        );
    }
}

impl RlpEcdsaDecodableTx for TxFeeToken {
    const DEFAULT_TX_TYPE: u8 = FEE_TOKEN_TX_TYPE_ID;

    /// Decodes the inner TxFeeToken fields from RLP bytes
    fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let chain_id = Decodable::decode(buf)?;
        let nonce = Decodable::decode(buf)?;

        let tx = Self {
            chain_id,
            nonce,
            max_priority_fee_per_gas: Decodable::decode(buf)?,
            max_fee_per_gas: Decodable::decode(buf)?,
            gas_limit: Decodable::decode(buf)?,
            to: Decodable::decode(buf)?,
            value: Decodable::decode(buf)?,
            input: Decodable::decode(buf)?,
            access_list: Decodable::decode(buf)?,
            authorization_list: Decodable::decode(buf)?,
            // Decode fee_token like TxKind: EMPTY_STRING_CODE for None, Address for Some
            fee_token: TxKind::decode(buf)?.into_to(),
            fee_payer_signature: if let Some(first) = buf.first() {
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
            },
        };

        // Validate the transaction
        tx.validate().map_err(alloy_rlp::Error::Custom)?;

        Ok(tx)
    }
}

impl Transaction for TxFeeToken {
    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }

    #[inline]
    fn nonce(&self) -> u64 {
        self.nonce
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
        alloy_eips::eip1559::calc_effective_gas_price(
            self.max_fee_per_gas,
            self.max_priority_fee_per_gas,
            base_fee,
        )
    }

    #[inline]
    fn is_dynamic_fee(&self) -> bool {
        true
    }

    #[inline]
    fn kind(&self) -> TxKind {
        self.to
    }

    #[inline]
    fn is_create(&self) -> bool {
        self.to.is_create()
    }

    #[inline]
    fn value(&self) -> U256 {
        self.value
    }

    #[inline]
    fn input(&self) -> &Bytes {
        &self.input
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
        Some(&self.authorization_list)
    }
}

impl Typed2718 for TxFeeToken {
    fn ty(&self) -> u8 {
        FEE_TOKEN_TX_TYPE_ID
    }
}

impl SignableTransaction<Signature> for TxFeeToken {
    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = chain_id;
    }

    fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        // We skip encoding the fee token if the signature is present to ensure that user
        // does not commit to a specific fee token when someone else is paying for the transaction.
        let skip_fee_token = self.fee_payer_signature.is_some();
        // For signing, we don't encode the signature but only encode a single byte marking the
        // presence of the signature
        out.put_u8(Self::tx_type());
        let payload_length = self.rlp_encoded_fields_length(|_| 1, skip_fee_token);
        alloy_rlp::Header { list: true, payload_length }.encode(out);
        self.rlp_encode_fields(
            out,
            |signature, out| {
                if signature.is_some() {
                    out.put_u8(0);
                } else {
                    out.put_u8(EMPTY_STRING_CODE);
                }
            },
            skip_fee_token,
        );
    }

    fn payload_len_for_signature(&self) -> usize {
        let payload_length =
            self.rlp_encoded_fields_length(|_| 1, self.fee_payer_signature.is_some());
        1 + alloy_rlp::Header { list: true, payload_length }.length_with_payload()
    }
}

impl Encodable for TxFeeToken {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_encode(out);
    }

    fn length(&self) -> usize {
        self.rlp_encoded_length()
    }
}

impl Decodable for TxFeeToken {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::rlp_decode(buf)
    }
}

impl reth_primitives_traits::InMemorySize for TxFeeToken {
    fn size(&self) -> usize {
        Self::size(self)
    }
}

#[cfg(feature = "serde-bincode-compat")]
impl reth_primitives_traits::serde_bincode_compat::RlpBincode for TxFeeToken {}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for TxFeeToken {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate authorization_list first to determine constraints on `to`
        let authorization_list: Vec<SignedAuthorization> = u.arbitrary()?;

        // If authorization_list is non-empty, to MUST NOT be Create
        let to = if !authorization_list.is_empty() {
            // Force it to be a Call variant
            TxKind::Call(u.arbitrary()?)
        } else {
            // Can be either Create or Call
            u.arbitrary()?
        };

        Ok(Self {
            chain_id: u.arbitrary()?,
            nonce: u.arbitrary()?,
            fee_token: u.arbitrary()?,
            max_priority_fee_per_gas: u.arbitrary()?,
            max_fee_per_gas: u.arbitrary()?,
            gas_limit: u.arbitrary()?,
            to,
            value: u.arbitrary()?,
            access_list: u.arbitrary()?,
            authorization_list,
            fee_payer_signature: u.arbitrary()?,
            input: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip7702::{Authorization, SignedAuthorization};
    use alloy_primitives::{Address, U256};

    #[test]
    fn test_tx_fee_token_validation() {
        // Valid: no authorization list, to can be Create
        let tx1 =
            TxFeeToken { to: TxKind::Create, authorization_list: vec![], ..Default::default() };
        assert!(tx1.validate().is_ok());

        // Valid: authorization list with to address
        let tx2 = TxFeeToken {
            to: TxKind::Call(Address::ZERO),
            authorization_list: vec![SignedAuthorization::new_unchecked(
                Authorization { chain_id: U256::from(1), address: Address::ZERO, nonce: 0 },
                0,
                U256::ZERO,
                U256::ZERO,
            )],
            ..Default::default()
        };
        assert!(tx2.validate().is_ok());

        // Invalid: authorization list with Create
        let tx3 = TxFeeToken {
            to: TxKind::Create,
            authorization_list: vec![SignedAuthorization::new_unchecked(
                Authorization { chain_id: U256::from(1), address: Address::ZERO, nonce: 0 },
                0,
                U256::ZERO,
                U256::ZERO,
            )],
            ..Default::default()
        };
        assert!(tx3.validate().is_err());
    }

    #[test]
    fn test_tx_type() {
        assert_eq!(TxFeeToken::tx_type(), 0x77);
    }
}
