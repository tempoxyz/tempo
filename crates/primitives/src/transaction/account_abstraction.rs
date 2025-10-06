use alloy_consensus::{
    SignableTransaction, Signed, Transaction,
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx},
};
use alloy_eips::{Typed2718, eip2930::AccessList, eip7702::SignedAuthorization};
use alloy_primitives::{Address, B256, Bytes, ChainId, Signature, TxKind, U256, Uint, keccak256};
use alloy_rlp::{Buf, BufMut, Decodable, EMPTY_STRING_CODE, Encodable};
use core::mem;

/// Account abstraction transaction type byte (0x5)
pub const AA_TX_TYPE_ID: u8 = 0x5;

/// 192-bit unsigned integer for nonce keys
pub type U192 = Uint<192, 3>;

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

    /// The recipient address
    pub to: TxKind,

    /// Value to transfer
    pub value: U256,

    /// Access list (EIP-2930)
    pub access_list: AccessList,

    /// AA-specific fields

    /// Nonce key for 2D nonce system (192 bits)
    /// Key 0 is the protocol nonce, keys 1-N are user nonces for parallelization
    pub nonce_key: U192,

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

    // Note: This is at last position for the codecs derive
    /// Input data (ERC-7821 encoded operations for batching)
    pub input: Bytes,

    /// Variable length signature based on type:
    /// - secp256k1: 65 bytes
    /// - P256: 129 bytes
    /// - WebAuthn: variable (max 2KB)
    pub signature: Bytes,
}

impl Default for TxAA {
    fn default() -> Self {
        Self {
            chain_id: 0,
            fee_token: None,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 0,
            to: TxKind::Create,
            value: U256::ZERO,
            access_list: AccessList::default(),
            signature: Bytes::new(),
            nonce_key: U192::ZERO,
            nonce_sequence: 0,
            fee_payer_signature: None,
            valid_before: 0,
            valid_after: None,
            input: Bytes::new(),
        }
    }
}

impl TxAA {
    /// Get the transaction type
    #[doc(alias = "transaction_type")]
    pub const fn tx_type() -> u8 {
        AA_TX_TYPE_ID
    }

    /// Detect signature type based on signature length
    pub fn signature_type(&self) -> Result<SignatureType, &'static str> {
        match self.signature.len() {
            SECP256K1_SIGNATURE_LENGTH => Ok(SignatureType::Secp256k1),
            P256_SIGNATURE_LENGTH => Ok(SignatureType::P256),
            len if len > P256_SIGNATURE_LENGTH && len <= MAX_WEBAUTHN_SIGNATURE_LENGTH => {
                Ok(SignatureType::WebAuthn)
            }
            _ => Err("Invalid signature length"),
        }
    }

    /// Validates the transaction according to the spec rules
    pub fn validate(&self) -> Result<(), &'static str> {
        // Validate signature length
        self.signature_type()?;

        // Signature must not be empty
        if self.signature.is_empty() {
            return Err("Signature cannot be empty");
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
        mem::size_of::<TxKind>() + // to
        mem::size_of::<U256>() + // value
        self.access_list.size() + // access_list
        self.signature.len() + // signature
        mem::size_of::<U192>() + // nonce_key
        mem::size_of::<u64>() + // nonce_sequence
        mem::size_of::<Option<Signature>>() + // fee_payer_signature
        mem::size_of::<u64>() + // valid_before
        mem::size_of::<Option<u64>>() + // valid_after
        self.input.len() // input
    }

    /// Combines this transaction with `signature`, taking `self`. Returns [`Signed`].
    pub fn into_signed(self, signature: Bytes) -> Signed<Self> {
        let mut tx = self;
        tx.signature = signature;
        let tx_hash = tx.signature_hash();
        Signed::new_unchecked(tx, Signature::test_signature(), tx_hash)
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
        let rlp_header = alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_encoded_fields_length(|_| sender.length(), false, true),
        };
        let mut buf = Vec::with_capacity(rlp_header.length_with_payload());
        rlp_header.encode(&mut buf);
        self.rlp_encode_fields(
            &mut buf,
            |_, out| {
                sender.encode(out);
            },
            false,
            true,
        );

        keccak256(&buf)
    }
}

/// Derives a P256 address from public key coordinates
/// Uses domain separation to prevent collision with secp256k1 addresses
pub fn derive_p256_address(pub_key_x: &B256, pub_key_y: &B256) -> Address {
    // Domain separator prevents collision with standard secp256k1 addresses
    let prefix = b"TEMPO_P256";

    let hash = keccak256(
        &[
            prefix.as_slice(),
            pub_key_x.as_slice(),
            pub_key_y.as_slice(),
        ]
        .concat(),
    );

    // Take last 20 bytes as address
    Address::from_slice(&hash[12..])
}

impl TxAA {
    /// Outputs the length of the transaction's fields, without a RLP header.
    fn rlp_encoded_fields_length(
        &self,
        signature_length: impl FnOnce(&Option<Signature>) -> usize,
        skip_fee_token: bool,
        skip_signature: bool,
    ) -> usize {
        self.chain_id.length() +
            self.max_priority_fee_per_gas.length() +
            self.max_fee_per_gas.length() +
            self.gas_limit.length() +
            self.to.length() +
            self.value.length() +
            self.access_list.length() +
            // nonce_key (U192)
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
            if !skip_fee_token {
                if let Some(addr) = self.fee_token {
                    addr.length()
                } else {
                    1 // EMPTY_STRING_CODE
                }
            } else {
                1 // EMPTY_STRING_CODE
            } +
            // fee_payer_signature
            signature_length(&self.fee_payer_signature) +
            // input
            self.input.length() +
            // signature (variable length bytes)
            if !skip_signature {
                self.signature.length()
            } else {
                1 // EMPTY_STRING_CODE or placeholder
            }
    }

    fn rlp_encode_fields(
        &self,
        out: &mut dyn BufMut,
        encode_signature: impl FnOnce(&Option<Signature>, &mut dyn BufMut),
        skip_fee_token: bool,
        skip_signature: bool,
    ) {
        self.chain_id.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.access_list.encode(out);

        // Encode nonce_key (U192)
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
        if !skip_fee_token {
            if let Some(addr) = self.fee_token {
                addr.encode(out);
            } else {
                out.put_u8(EMPTY_STRING_CODE);
            }
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }

        // Encode fee_payer_signature
        encode_signature(&self.fee_payer_signature, out);

        // Encode input
        self.input.encode(out);

        // Encode signature
        if !skip_signature {
            self.signature.encode(out);
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }
    }
}

impl RlpEcdsaEncodableTx for TxAA {
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
                    alloy_rlp::Header {
                        list: true,
                        payload_length,
                    }
                    .encode(out);
                    signature.write_rlp_vrs(out, signature.v());
                } else {
                    out.put_u8(EMPTY_STRING_CODE);
                }
            },
            false,
            false,
        );
    }
}

impl RlpEcdsaDecodableTx for TxAA {
    const DEFAULT_TX_TYPE: u8 = AA_TX_TYPE_ID;

    /// Decodes the inner TxAA fields from RLP bytes
    fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let chain_id = Decodable::decode(buf)?;
        let max_priority_fee_per_gas = Decodable::decode(buf)?;
        let max_fee_per_gas = Decodable::decode(buf)?;
        let gas_limit = Decodable::decode(buf)?;
        let to = Decodable::decode(buf)?;
        let value = Decodable::decode(buf)?;
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

        let input = Decodable::decode(buf)?;
        let signature = Decodable::decode(buf)?;

        let tx = Self {
            chain_id,
            fee_token,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            access_list,
            nonce_key,
            nonce_sequence,
            fee_payer_signature,
            valid_before,
            valid_after,
            input,
            signature,
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
        // For signing, we skip encoding the actual signature
        out.put_u8(Self::tx_type());
        let payload_length = self.rlp_encoded_fields_length(|_| 1, skip_fee_token, true);
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);
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
            true,
        );
    }

    fn payload_len_for_signature(&self) -> usize {
        let payload_length =
            self.rlp_encoded_fields_length(|_| 1, self.fee_payer_signature.is_some(), true);
        1 + alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .length_with_payload()
    }
}

impl Encodable for TxAA {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_encode(out);
    }

    fn length(&self) -> usize {
        self.rlp_encoded_length()
    }
}

impl Decodable for TxAA {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::rlp_decode(buf)
    }
}

impl reth_primitives_traits::InMemorySize for TxAA {
    fn size(&self) -> usize {
        Self::size(self)
    }
}

#[cfg(feature = "serde-bincode-compat")]
impl reth_primitives_traits::serde_bincode_compat::RlpBincode for TxAA {}

// TODO: Don't know what's going on here, this is claude generated
// Because the reth-codec macro couldn't be applied to the TxAA struct
// with multiple Bytes & Uint192 fields
#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for TxAA {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_primitives::bytes::BufMut + AsMut<[u8]>,
    {

        let mut len = 0;
        len += self.chain_id.to_compact(buf);
        len += self.max_priority_fee_per_gas.to_compact(buf);
        len += self.max_fee_per_gas.to_compact(buf);
        len += self.gas_limit.to_compact(buf);
        len += self.to.to_compact(buf);
        len += self.value.to_compact(buf);
        len += self.access_list.to_compact(buf);

        // Manually encode U192 (3 u64 limbs)
        let limbs = self.nonce_key.as_limbs();
        buf.put_u64_le(limbs[0]);
        buf.put_u64_le(limbs[1]);
        buf.put_u64_le(limbs[2]);
        len += 24;

        len += self.nonce_sequence.to_compact(buf);
        len += self.valid_before.to_compact(buf);
        len += self.valid_after.to_compact(buf);
        len += self.fee_token.to_compact(buf);
        len += self.fee_payer_signature.to_compact(buf);

        // Variable-length fields (write length + data)
        buf.put_u32(self.input.len() as u32);
        buf.put_slice(&self.input);
        len += 4 + self.input.len();

        buf.put_u32(self.signature.len() as u32);
        buf.put_slice(&self.signature);
        len += 4 + self.signature.len();

        len
    }

    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        use alloy_primitives::bytes::Buf;

        let (chain_id, buf) = ChainId::from_compact(buf, buf.len());
        let (max_priority_fee_per_gas, buf) = u128::from_compact(buf, buf.len());
        let (max_fee_per_gas, buf) = u128::from_compact(buf, buf.len());
        let (gas_limit, buf) = u64::from_compact(buf, buf.len());
        let (to, buf) = TxKind::from_compact(buf, buf.len());
        let (value, buf) = U256::from_compact(buf, buf.len());
        let (access_list, buf) = AccessList::from_compact(buf, buf.len());

        // Manually decode U192 (3 u64 limbs)
        let mut buf = buf;
        let limb0 = buf.get_u64_le();
        let limb1 = buf.get_u64_le();
        let limb2 = buf.get_u64_le();
        let nonce_key = U192::from_limbs([limb0, limb1, limb2]);

        let (nonce_sequence, buf) = u64::from_compact(buf, buf.len());
        let (valid_before, buf) = u64::from_compact(buf, buf.len());
        let (valid_after, buf) = Option::<u64>::from_compact(buf, buf.len());
        let (fee_token, buf) = Option::<Address>::from_compact(buf, buf.len());
        let (fee_payer_signature, buf) = Option::<Signature>::from_compact(buf, buf.len());

        // Read variable-length input
        let mut buf = buf;
        let input_len = buf.get_u32() as usize;
        let input = Bytes::copy_from_slice(&buf[..input_len]);
        buf.advance(input_len);

        // Read variable-length signature
        let sig_len = buf.get_u32() as usize;
        let signature = Bytes::copy_from_slice(&buf[..sig_len]);
        buf.advance(sig_len);

        let tx = Self {
            chain_id,
            fee_token,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            access_list,
            nonce_key,
            nonce_sequence,
            fee_payer_signature,
            valid_before,
            valid_after,
            input,
            signature,
        };

        (tx, buf)
    }
}

impl TxAA {
    /// Recover the signer address from the transaction signature
    ///
    /// This function extracts the address from the signature based on signature type:
    /// - secp256k1: Uses standard ecrecover
    /// - P256: Derives address from public key using domain separation
    /// - WebAuthn: Derives address from P256 public key using domain separation
    ///
    /// Note: This only recovers the address. Actual signature verification happens
    /// during transaction execution.
    pub fn recover_signer(&self) -> Result<Address, &'static str> {
        let sig_type = self.signature_type()?;
        let sig_hash = self.signature_hash();

        match sig_type {
            SignatureType::Secp256k1 => {
                // Standard secp256k1 recovery using alloy's built-in methods
                if self.signature.len() != SECP256K1_SIGNATURE_LENGTH {
                    return Err("Invalid secp256k1 signature length");
                }

                // Parse as alloy Signature and use built-in recovery
                let sig = Signature::try_from(&self.signature[..])
                    .map_err(|_| "Failed to parse secp256k1 signature")?;

                sig.recover_address_from_prehash(&sig_hash)
                    .map_err(|_| "Failed to recover secp256k1 address")
            }
            SignatureType::P256 => {
                // P256 signature format: r (32) || s (32) || pubKeyX (32) || pubKeyY (32) || preHash (1)
                if self.signature.len() != P256_SIGNATURE_LENGTH {
                    return Err("Invalid P256 signature length");
                }

                // Extract public key coordinates (bytes 64-96 for X, 96-128 for Y)
                let mut pub_key_x = B256::ZERO;
                let mut pub_key_y = B256::ZERO;
                pub_key_x.copy_from_slice(&self.signature[64..96]);
                pub_key_y.copy_from_slice(&self.signature[96..128]);

                // Derive address using domain-separated hash
                Ok(derive_p256_address(&pub_key_x, &pub_key_y))
            }
            SignatureType::WebAuthn => {
                // WebAuthn signature format (from spec):
                // authenticatorData || clientDataJSON || r (32) || s (32) || pubKeyX (32) || pubKeyY (32)
                //
                // Parse by working backwards:
                // - Last 32 bytes: pubKeyY
                // - Previous 32 bytes: pubKeyX
                // - Previous 32 bytes: s
                // - Previous 32 bytes: r
                // - Remaining bytes: authenticatorData || clientDataJSON

                if self.signature.len() < 128 {
                    return Err("WebAuthn signature too short");
                }

                let sig_len = self.signature.len();

                // Extract public key from last 64 bytes
                let mut pub_key_x = B256::ZERO;
                let mut pub_key_y = B256::ZERO;
                pub_key_x.copy_from_slice(&self.signature[sig_len - 64..sig_len - 32]);
                pub_key_y.copy_from_slice(&self.signature[sig_len - 32..]);

                // WebAuthn uses P256, derive address from public key
                Ok(derive_p256_address(&pub_key_x, &pub_key_y))
            }
        }
    }
}
