use crate::{
    subblock::{PartialValidatorKey, has_sub_block_nonce_key_prefix},
    transaction::{
        AASigned, TempoSignature, TempoSignedAuthorization,
        key_authorization::SignedKeyAuthorization,
    },
};
use alloy_consensus::{SignableTransaction, Transaction, crypto::RecoveryError};
use alloy_eips::{Typed2718, eip2930::AccessList, eip7702::SignedAuthorization};
use alloy_primitives::{Address, B256, Bytes, ChainId, Signature, TxKind, U256, keccak256};
use alloy_rlp::{Buf, BufMut, Decodable, EMPTY_STRING_CODE, Encodable};

/// Tempo transaction type byte (0x76)
pub const TEMPO_TX_TYPE_ID: u8 = 0x76;

/// Magic byte for the fee payer signature
pub const FEE_PAYER_SIGNATURE_MAGIC_BYTE: u8 = 0x78;

/// Signature type constants
pub const SECP256K1_SIGNATURE_LENGTH: usize = 65;
pub const P256_SIGNATURE_LENGTH: usize = 129;
pub const MAX_WEBAUTHN_SIGNATURE_LENGTH: usize = 2048; // 2KB max

/// Nonce key marking an expiring nonce transaction (uses tx hash for replay protection).
pub const TEMPO_EXPIRING_NONCE_KEY: U256 = U256::MAX;

/// Maximum allowed expiry window for expiring nonce transactions (30 seconds).
pub const TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS: u64 = 30;

/// Signature type enumeration
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum SignatureType {
    Secp256k1 = 0,
    P256 = 1,
    WebAuthn = 2,
}

impl From<SignatureType> for u8 {
    fn from(sig_type: SignatureType) -> Self {
        match sig_type {
            SignatureType::Secp256k1 => 0,
            SignatureType::P256 => 1,
            SignatureType::WebAuthn => 2,
        }
    }
}

impl alloy_rlp::Encodable for SignatureType {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        (*self as u8).encode(out);
    }

    fn length(&self) -> usize {
        1
    }
}

impl alloy_rlp::Decodable for SignatureType {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let byte: u8 = alloy_rlp::Decodable::decode(buf)?;
        match byte {
            0 => Ok(Self::Secp256k1),
            1 => Ok(Self::P256),
            2 => Ok(Self::WebAuthn),
            _ => Err(alloy_rlp::Error::Custom("Invalid signature type")),
        }
    }
}

/// Helper function to create an RLP header for a list with the given payload length
#[inline]
fn rlp_header(payload_length: usize) -> alloy_rlp::Header {
    alloy_rlp::Header {
        list: true,
        payload_length,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
pub struct Call {
    /// Call target.
    pub to: TxKind,

    /// Call value.
    pub value: U256,

    /// Call input.
    #[cfg_attr(feature = "serde", serde(flatten, with = "serde_input"))]
    pub input: Bytes,
}

impl Call {
    /// Returns the RLP header for this call, encapsulating both length calculation and header creation
    #[inline]
    fn rlp_header(&self) -> alloy_rlp::Header {
        let payload_length = self.to.length() + self.value.length() + self.input.length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
    }

    fn size(&self) -> usize {
        size_of::<Self>() + self.input.len()
    }
}

impl Encodable for Call {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_header().encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.encode(out);
    }

    fn length(&self) -> usize {
        self.rlp_header().length_with_payload()
    }
}

impl Decodable for Call {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        if header.payload_length > remaining {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        let this = Self {
            to: Decodable::decode(buf)?,
            value: Decodable::decode(buf)?,
            input: Decodable::decode(buf)?,
        };

        if buf.len() + header.payload_length != remaining {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        Ok(this)
    }
}

/// Tempo transaction following the Tempo spec.
///
/// This transaction type supports:
/// - Multiple signature types (secp256k1, P256, WebAuthn)
/// - Parallelizable nonces via 2D nonce system (nonce_key + nonce)
/// - Gas sponsorship via fee payer
/// - Scheduled transactions (validBefore/validAfter)
/// - EIP-7702 authorization lists
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
pub struct TempoTransaction {
    /// EIP-155: Simple replay attack protection
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub chain_id: ChainId,

    /// Optional fee token preference (`None` means no preference)
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

    /// Calls to be executed atomically
    pub calls: Vec<Call>,

    /// Access list (EIP-2930)
    pub access_list: AccessList,

    /// TT-specific fields

    /// Nonce key for 2D nonce system
    /// Key 0 is the protocol nonce, keys 1-N are user nonces for parallelization
    pub nonce_key: U256,

    /// Current nonce value for the nonce key
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub nonce: u64,

    /// Optional features

    /// Optional fee payer signature for sponsored transactions (secp256k1 only)
    pub fee_payer_signature: Option<Signature>,

    /// Transaction can only be included in a block before this timestamp
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity::opt"))]
    pub valid_before: Option<u64>,

    /// Transaction can only be included in a block after this timestamp
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity::opt"))]
    pub valid_after: Option<u64>,

    /// Optional key authorization for provisioning a new access key
    ///
    /// When present, this transaction will add the specified key to the AccountKeychain precompile,
    /// before verifying the transaction signature.
    /// The authorization must be signed with the root key, the tx can be signed by the Keychain signature.
    pub key_authorization: Option<SignedKeyAuthorization>,

    /// Authorization list (EIP-7702 style with Tempo signatures)
    #[cfg_attr(feature = "serde", serde(rename = "aaAuthorizationList"))]
    pub tempo_authorization_list: Vec<TempoSignedAuthorization>,
}

/// Validates the calls list structure for Tempo transactions.
///
/// This is a shared validation function used by both `TempoTransaction::validate()`
/// and the revm handler's `validate_env()` to ensure consistent validation.
///
/// Rules:
/// - Calls list must not be empty
/// - CREATE calls are not allowed when authorization list is non-empty (EIP-7702 semantics)
/// - Only the first call can be a CREATE; all subsequent calls must be CALL
pub fn validate_calls(calls: &[Call], has_authorization_list: bool) -> Result<(), &'static str> {
    // Calls must not be empty (similar to EIP-7702 rejecting empty auth lists)
    if calls.is_empty() {
        return Err("calls list cannot be empty");
    }

    let mut calls_iter = calls.iter();

    // Only the first call in the batch can be a CREATE call.
    if let Some(call) = calls_iter.next()
        // Authorization list validation: Can NOT have CREATE when authorization list is non-empty
        // This follows EIP-7702 semantics - when using delegation
        && has_authorization_list
        && call.to.is_create()
    {
        return Err("calls cannot contain CREATE when 'aa_authorization_list' is non-empty");
    }

    // All subsequent calls must be CALL.
    for call in calls_iter {
        if call.to.is_create() {
            return Err(
                "only one CREATE call is allowed per transaction, and it must be the first call of the batch",
            );
        }
    }

    Ok(())
}

impl TempoTransaction {
    /// Get the transaction type
    #[doc(alias = "transaction_type")]
    pub const fn tx_type() -> u8 {
        TEMPO_TX_TYPE_ID
    }

    /// Returns true if this is an expiring nonce transaction.
    ///
    /// Expiring nonce transactions use the tx hash for replay protection instead of
    /// sequential nonces. They are identified by `nonce_key == U256::MAX`.
    #[inline]
    pub fn is_expiring_nonce_tx(&self) -> bool {
        self.nonce_key == TEMPO_EXPIRING_NONCE_KEY
    }

    /// Validates the transaction according to invariant rules.
    ///
    /// This performs structural validation that is always required, regardless of hardfork.
    /// Hardfork-dependent validation (e.g., expiring nonce constraints) is performed by
    /// the transaction pool validator and execution handler where hardfork context is available.
    pub fn validate(&self) -> Result<(), &'static str> {
        // Validate calls list structure using the shared function
        validate_calls(&self.calls, !self.tempo_authorization_list.is_empty())?;

        // validBefore must be greater than validAfter if both are set
        if let Some(valid_after) = self.valid_after
            && let Some(valid_before) = self.valid_before
            && valid_before <= valid_after
        {
            return Err("valid_before must be greater than valid_after");
        }

        Ok(())
    }

    /// Calculates a heuristic for the in-memory size of the transaction
    #[inline]
    pub fn size(&self) -> usize {
        size_of::<Self>()
            + self.calls.iter().map(|call| call.size()).sum::<usize>()
            + self.access_list.size()
            + self.key_authorization.as_ref().map_or(0, |k| k.size())
            + self
                .tempo_authorization_list
                .iter()
                .map(|auth| auth.size())
                .sum::<usize>()
    }

    /// Convert the transaction into a signed transaction
    pub fn into_signed(self, signature: TempoSignature) -> AASigned {
        AASigned::new_unhashed(self, signature)
    }

    /// Calculate the signing hash for this transaction
    /// This is the hash that should be signed by the sender
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::new();
        self.encode_for_signing(&mut buf);
        keccak256(&buf)
    }

    /// Calculate the fee payer signature hash.
    ///
    /// This hash is signed by the fee payer to sponsor the transaction
    pub fn fee_payer_signature_hash(&self, sender: Address) -> B256 {
        // Use helper functions for consistent encoding
        let payload_length = self.rlp_encoded_fields_length(|_| sender.length(), false);

        let mut buf = Vec::with_capacity(1 + rlp_header(payload_length).length_with_payload());

        // Magic byte for fee payer signature (like TxFeeToken)
        buf.put_u8(FEE_PAYER_SIGNATURE_MAGIC_BYTE);

        // RLP header
        rlp_header(payload_length).encode(&mut buf);

        // Encode fields using helper (skip_fee_token = false, so fee_token IS included)
        self.rlp_encode_fields(
            &mut buf,
            |_, out| {
                // Encode sender address instead of fee_payer_signature
                sender.encode(out);
            },
            false, // skip_fee_token = FALSE - fee payer commits to fee_token!
        );

        keccak256(&buf)
    }

    /// Recovers the fee payer for this transaction.
    ///
    /// This returns the given sender if the transaction doesn't include a fee payer signature
    pub fn recover_fee_payer(&self, sender: Address) -> Result<Address, RecoveryError> {
        if let Some(fee_payer_signature) = &self.fee_payer_signature {
            alloy_consensus::crypto::secp256k1::recover_signer(
                fee_payer_signature,
                self.fee_payer_signature_hash(sender),
            )
        } else {
            Ok(sender)
        }
    }

    /// Outputs the length of the transaction's fields, without a RLP header.
    ///
    /// This is the internal helper that takes closures for flexible encoding.
    fn rlp_encoded_fields_length(
        &self,
        signature_length: impl FnOnce(&Option<Signature>) -> usize,
        skip_fee_token: bool,
    ) -> usize {
        self.chain_id.length() +
            self.max_priority_fee_per_gas.length() +
            self.max_fee_per_gas.length() +
            self.gas_limit.length() +
            self.calls.length() +
            self.access_list.length() +
            self.nonce_key.length() +
            self.nonce.length() +
            if let Some(valid_before) = self.valid_before {
                valid_before.length()
            } else {
                1 // EMPTY_STRING_CODE
            } +
            // valid_after (optional u64)
            if let Some(valid_after) = self.valid_after {
                valid_after.length()
            } else {
                1 // EMPTY_STRING_CODE
            } +
            // fee_token (optional Address)
            if !skip_fee_token && let Some(addr) = self.fee_token {
                addr.length()
            } else {
                1 // EMPTY_STRING_CODE
            } +
            signature_length(&self.fee_payer_signature) +
            // authorization_list
            self.tempo_authorization_list.length() +
            // key_authorization (only included if present)
            if let Some(key_auth) = &self.key_authorization {
                key_auth.length()
            } else {
                0 // No bytes when None
            }
    }

    fn rlp_encode_fields(
        &self,
        out: &mut dyn BufMut,
        encode_signature: impl FnOnce(&Option<Signature>, &mut dyn BufMut),
        skip_fee_token: bool,
    ) {
        self.chain_id.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.calls.encode(out);
        self.access_list.encode(out);
        self.nonce_key.encode(out);
        self.nonce.encode(out);

        if let Some(valid_before) = self.valid_before {
            valid_before.encode(out);
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }

        if let Some(valid_after) = self.valid_after {
            valid_after.encode(out);
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }

        if !skip_fee_token && let Some(addr) = self.fee_token {
            addr.encode(out);
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }

        encode_signature(&self.fee_payer_signature, out);

        // Encode authorization_list
        self.tempo_authorization_list.encode(out);

        // Encode key_authorization (truly optional - only encoded if present)
        if let Some(key_auth) = &self.key_authorization {
            key_auth.encode(out);
        }
        // No bytes at all when None - maintains backwards compatibility
    }

    /// Public version for normal RLP encoding
    pub(crate) fn rlp_encoded_fields_length_default(&self) -> usize {
        self.rlp_encoded_fields_length(
            |signature| {
                signature.map_or(1, |s| {
                    rlp_header(s.rlp_rs_len() + s.v().length()).length_with_payload()
                })
            },
            false,
        )
    }

    /// Public version for normal RLP encoding
    pub(crate) fn rlp_encode_fields_default(&self, out: &mut dyn BufMut) {
        self.rlp_encode_fields(
            out,
            |signature, out| {
                if let Some(signature) = signature {
                    let payload_length = signature.rlp_rs_len() + signature.v().length();
                    rlp_header(payload_length).encode(out);
                    signature.write_rlp_vrs(out, signature.v());
                } else {
                    out.put_u8(EMPTY_STRING_CODE);
                }
            },
            false,
        )
    }

    /// Decodes the inner TempoTransaction fields from RLP bytes
    pub(crate) fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let chain_id = Decodable::decode(buf)?;
        let max_priority_fee_per_gas = Decodable::decode(buf)?;
        let max_fee_per_gas = Decodable::decode(buf)?;
        let gas_limit = Decodable::decode(buf)?;
        let calls = Decodable::decode(buf)?;
        let access_list = Decodable::decode(buf)?;
        let nonce_key = Decodable::decode(buf)?;
        let nonce = Decodable::decode(buf)?;

        let valid_before = if let Some(first) = buf.first() {
            if *first == EMPTY_STRING_CODE {
                buf.advance(1);
                None
            } else {
                Some(Decodable::decode(buf)?)
            }
        } else {
            return Err(alloy_rlp::Error::InputTooShort);
        };

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

        let tempo_authorization_list = Decodable::decode(buf)?;

        // Decode optional key_authorization field at the end
        // Check if the next byte looks like it could be a KeyAuthorization (RLP list)
        // KeyAuthorization is encoded as a list, so it would start with 0xc0-0xf7 (short list) or 0xf8-0xff (long list)
        // If it's a bytes string (0x80-0xbf for short, 0xb8-0xbf for long), it's not a
        // KeyAuthorization and most likely a signature bytes following the AA transaction.
        let key_authorization = if let Some(&first) = buf.first() {
            // Check if this looks like an RLP list (KeyAuthorization is always a list)
            if first >= 0xc0 {
                // This could be a KeyAuthorization
                Some(Decodable::decode(buf)?)
            } else {
                // This is likely not a KeyAuthorization (probably signature bytes in AASigned context)
                None
            }
        } else {
            None
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
            nonce,
            fee_payer_signature,
            valid_before,
            valid_after,
            key_authorization,
            tempo_authorization_list,
        };

        // Validate the transaction
        tx.validate().map_err(alloy_rlp::Error::Custom)?;

        Ok(tx)
    }

    /// Returns true if the nonce key of this transaction has the [`TEMPO_SUBBLOCK_NONCE_KEY_PREFIX`](crate::subblock::TEMPO_SUBBLOCK_NONCE_KEY_PREFIX).
    pub fn has_sub_block_nonce_key_prefix(&self) -> bool {
        has_sub_block_nonce_key_prefix(&self.nonce_key)
    }

    /// Returns the proposer of the subblock if this is a subblock transaction.
    pub fn subblock_proposer(&self) -> Option<PartialValidatorKey> {
        if self.has_sub_block_nonce_key_prefix() {
            Some(PartialValidatorKey::from_slice(
                &self.nonce_key.to_be_bytes::<32>()[1..16],
            ))
        } else {
            None
        }
    }
}

impl Transaction for TempoTransaction {
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
        // Return first call's `to` or Create if empty
        self.calls.first().map(|c| c.to).unwrap_or(TxKind::Create)
    }

    #[inline]
    fn is_create(&self) -> bool {
        self.kind().is_create()
    }

    #[inline]
    fn value(&self) -> U256 {
        // Return sum of all call values, saturating to U256::MAX on overflow
        self.calls
            .iter()
            .fold(U256::ZERO, |acc, call| acc.saturating_add(call.value))
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

impl Typed2718 for TempoTransaction {
    fn ty(&self) -> u8 {
        TEMPO_TX_TYPE_ID
    }
}

impl SignableTransaction<Signature> for TempoTransaction {
    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = chain_id;
    }

    fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        // Skip fee_token if fee_payer_signature is present to ensure user doesn't commit to a specific fee token
        let skip_fee_token = self.fee_payer_signature.is_some();

        // Type byte
        out.put_u8(Self::tx_type());

        // Compute payload length using helper
        let payload_length = self.rlp_encoded_fields_length(|_| 1, skip_fee_token);

        rlp_header(payload_length).encode(out);

        // Encode fields using helper
        self.rlp_encode_fields(
            out,
            |signature, out| {
                if signature.is_some() {
                    out.put_u8(0); // placeholder byte
                } else {
                    out.put_u8(EMPTY_STRING_CODE);
                }
            },
            skip_fee_token,
        );
    }

    fn payload_len_for_signature(&self) -> usize {
        let skip_fee_token = self.fee_payer_signature.is_some();
        let payload_length = self.rlp_encoded_fields_length(|_| 1, skip_fee_token);

        1 + rlp_header(payload_length).length_with_payload()
    }
}

impl Encodable for TempoTransaction {
    fn encode(&self, out: &mut dyn BufMut) {
        // Encode as RLP list of fields
        let payload_length = self.rlp_encoded_fields_length_default();
        rlp_header(payload_length).encode(out);
        self.rlp_encode_fields_default(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_encoded_fields_length_default();
        rlp_header(payload_length).length_with_payload()
    }
}

impl Decodable for TempoTransaction {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        if header.payload_length > remaining {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        let mut fields_buf = &buf[..header.payload_length];
        let this = Self::rlp_decode_fields(&mut fields_buf)?;

        if !fields_buf.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        buf.advance(header.payload_length);

        Ok(this)
    }
}

#[cfg(feature = "reth")]
impl reth_primitives_traits::InMemorySize for TempoTransaction {
    fn size(&self) -> usize {
        Self::size(self)
    }
}

#[cfg(feature = "serde-bincode-compat")]
impl reth_primitives_traits::serde_bincode_compat::RlpBincode for TempoTransaction {}

// Custom Arbitrary implementation to ensure calls is never empty and CREATE validation passes
#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for TempoTransaction {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate all fields using the default Arbitrary implementation
        let chain_id = u.arbitrary()?;
        let fee_token = u.arbitrary()?;
        let max_priority_fee_per_gas = u.arbitrary()?;
        let max_fee_per_gas = u.arbitrary()?;
        let gas_limit = u.arbitrary()?;

        // Generate calls - ensure at least one call is present and CREATE validation passes
        // CREATE must be first (if present) and only one CREATE allowed
        let mut calls: Vec<Call> = u.arbitrary()?;
        if calls.is_empty() {
            calls.push(Call {
                to: u.arbitrary()?,
                value: u.arbitrary()?,
                input: u.arbitrary()?,
            });
        }

        // Filter out CREATEs from non-first positions and ensure only one CREATE (if any)
        let first_is_create = calls.first().map(|c| c.to.is_create()).unwrap_or(false);
        if first_is_create {
            // Keep the first CREATE, remove all other CREATEs
            for call in calls.iter_mut().skip(1) {
                if call.to.is_create() {
                    // Replace with a CALL to a random address
                    call.to = TxKind::Call(u.arbitrary()?);
                }
            }
        } else {
            // Remove all CREATEs (they would be at non-first positions)
            for call in &mut calls {
                if call.to.is_create() {
                    call.to = TxKind::Call(u.arbitrary()?);
                }
            }
        }

        let access_list = u.arbitrary()?;

        // For now, always set nonce_key to 0 (protocol nonce) to pass validation
        let nonce_key = U256::ZERO;
        let nonce = u.arbitrary()?;
        let fee_payer_signature = u.arbitrary()?;

        // Ensure valid_before > valid_after if both are set
        // Note: We avoid generating Some(0) for valid_after because in RLP encoding,
        // 0 encodes as 0x80 (EMPTY_STRING_CODE), which is indistinguishable from None.
        // This is a known limitation of RLP for optional integer fields.
        let valid_after: Option<u64> = u.arbitrary::<Option<u64>>()?.filter(|v| *v != 0);
        let valid_before: Option<u64> = match valid_after {
            Some(after) => {
                // Generate a value greater than valid_after
                let offset: u64 = u.int_in_range(1..=1000)?;
                Some(after.saturating_add(offset))
            }
            None => {
                // Similarly avoid Some(0) for valid_before
                u.arbitrary::<Option<u64>>()?.filter(|v| *v != 0)
            }
        };

        Ok(Self {
            chain_id,
            fee_token,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            calls,
            access_list,
            nonce_key,
            nonce,
            fee_payer_signature,
            valid_before,
            valid_after,
            key_authorization: u.arbitrary()?,
            tempo_authorization_list: vec![],
        })
    }
}

#[cfg(feature = "serde")]
mod serde_input {
    //! Helper module for serializing and deserializing the `input` field of a [`Call`] as either `input` or `data` fields.

    use std::borrow::Cow;

    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct SerdeHelper<'a> {
        input: Option<Cow<'a, Bytes>>,
        data: Option<Cow<'a, Bytes>>,
    }

    pub(super) fn serialize<S>(input: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeHelper {
            input: Some(Cow::Borrowed(input)),
            data: None,
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = SerdeHelper::deserialize(deserializer)?;
        Ok(helper
            .input
            .or(helper.data)
            .ok_or(serde::de::Error::missing_field(
                "missing `input` or `data` field",
            ))?
            .into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TempoTxEnvelope,
        transaction::{
            KeyAuthorization, TempoSignedAuthorization,
            tt_signature::{
                PrimitiveSignature, SIGNATURE_TYPE_P256, SIGNATURE_TYPE_WEBAUTHN, TempoSignature,
                derive_p256_address,
            },
        },
    };
    use alloy_eips::{Decodable2718, Encodable2718, eip7702::Authorization};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256, address, bytes, hex};
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn test_tempo_transaction_validation() {
        // Create a dummy call to satisfy validation
        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Valid: valid_before > valid_after
        let tx1 = TempoTransaction {
            valid_before: Some(100),
            valid_after: Some(50),
            tempo_authorization_list: vec![],
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx1.validate().is_ok());

        // Invalid: valid_before <= valid_after
        let tx2 = TempoTransaction {
            valid_before: Some(50),
            valid_after: Some(100),
            tempo_authorization_list: vec![],
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx2.validate().is_err());

        // Invalid: valid_before == valid_after
        let tx3 = TempoTransaction {
            valid_before: Some(100),
            valid_after: Some(100),
            tempo_authorization_list: vec![],
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx3.validate().is_err());

        // Valid: no valid_after
        let tx4 = TempoTransaction {
            valid_before: Some(100),
            valid_after: None,
            tempo_authorization_list: vec![],
            calls: vec![dummy_call],
            ..Default::default()
        };
        assert!(tx4.validate().is_ok());

        // Invalid: empty calls
        let tx5 = TempoTransaction {
            ..Default::default()
        };
        assert!(tx5.validate().is_err());
    }

    #[test]
    fn test_tx_type() {
        assert_eq!(TempoTransaction::tx_type(), 0x76);
        assert_eq!(TEMPO_TX_TYPE_ID, 0x76);
    }

    #[test]
    fn test_signature_type_detection() {
        // Secp256k1 (detected by 65-byte length, no type identifier)
        let sig1_bytes = vec![0u8; SECP256K1_SIGNATURE_LENGTH];
        let sig1 = TempoSignature::from_bytes(&sig1_bytes).unwrap();
        assert_eq!(sig1.signature_type(), SignatureType::Secp256k1);

        // P256
        let mut sig2_bytes = vec![SIGNATURE_TYPE_P256];
        sig2_bytes.extend_from_slice(&[0u8; P256_SIGNATURE_LENGTH]);
        let sig2 = TempoSignature::from_bytes(&sig2_bytes).unwrap();
        assert_eq!(sig2.signature_type(), SignatureType::P256);

        // WebAuthn
        let mut sig3_bytes = vec![SIGNATURE_TYPE_WEBAUTHN];
        sig3_bytes.extend_from_slice(&[0u8; 200]);
        let sig3 = TempoSignature::from_bytes(&sig3_bytes).unwrap();
        assert_eq!(sig3.signature_type(), SignatureType::WebAuthn);
    }

    #[test]
    fn test_rlp_roundtrip() {
        let call = Call {
            to: TxKind::Call(address!("0000000000000000000000000000000000000002")),
            value: U256::from(1000),
            input: Bytes::from(vec![1, 2, 3, 4]),
        };

        let tx = TempoTransaction {
            chain_id: 1,
            fee_token: Some(address!("0000000000000000000000000000000000000001")),
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![call.clone()],
            access_list: Default::default(),
            nonce_key: U256::ZERO,
            nonce: 1,
            fee_payer_signature: Some(Signature::test_signature()),
            valid_before: Some(1000000),
            valid_after: Some(500000),
            key_authorization: None,
            tempo_authorization_list: vec![],
        };

        // Encode
        let mut buf = Vec::new();
        tx.encode(&mut buf);

        // Decode
        let decoded = TempoTransaction::decode(&mut buf.as_slice()).unwrap();

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
        assert_eq!(decoded.nonce, tx.nonce);
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

        let tx = TempoTransaction {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![call],
            access_list: Default::default(),
            nonce_key: U256::ZERO,
            nonce: 1,
            fee_payer_signature: None,
            valid_before: Some(1000),
            valid_after: None,
            key_authorization: None,
            tempo_authorization_list: vec![],
        };

        // Encode
        let mut buf = Vec::new();
        tx.encode(&mut buf);

        // Decode
        let decoded = TempoTransaction::decode(&mut buf.as_slice()).unwrap();

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
        // Create a dummy call to satisfy validation
        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Test 1: Protocol nonce (key 0)
        let tx1 = TempoTransaction {
            nonce_key: U256::ZERO,
            nonce: 1,
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx1.validate().is_ok());
        assert_eq!(tx1.nonce(), 1);
        assert_eq!(tx1.nonce_key, U256::ZERO);

        // Test 2: User nonce (key 1, nonce 0) - first transaction in parallel sequence
        let tx2 = TempoTransaction {
            nonce_key: U256::from(1),
            nonce: 0,
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx2.validate().is_ok());
        assert_eq!(tx2.nonce(), 0);
        assert_eq!(tx2.nonce_key, U256::from(1));

        // Test 3: Different nonce key (key 42) - independent parallel sequence
        let tx3 = TempoTransaction {
            nonce_key: U256::from(42),
            nonce: 10,
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(tx3.validate().is_ok());
        assert_eq!(tx3.nonce(), 10);
        assert_eq!(tx3.nonce_key, U256::from(42));

        // Test 4: Verify nonce independence between different keys
        // Transactions with same nonce but different keys are independent
        let tx4a = TempoTransaction {
            nonce_key: U256::from(1),
            nonce: 100,
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        let tx4b = TempoTransaction {
            nonce_key: U256::from(2),
            nonce: 100,
            calls: vec![dummy_call],
            ..Default::default()
        };
        assert!(tx4a.validate().is_ok());
        assert!(tx4b.validate().is_ok());
        assert_eq!(tx4a.nonce(), tx4b.nonce()); // Same nonce value
        assert_ne!(tx4a.nonce_key, tx4b.nonce_key); // Different keys = independent
    }

    #[test]
    fn test_transaction_trait_impl() {
        let call = Call {
            to: TxKind::Call(address!("0000000000000000000000000000000000000002")),
            value: U256::from(1000),
            input: Bytes::new(),
        };

        let tx = TempoTransaction {
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
        // Create a dummy call to satisfy validation
        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        let tx = TempoTransaction {
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

    #[test]
    fn test_fee_payer_commits_to_fee_token() {
        // This test verifies that the fee payer signature commits to the fee_token value
        // i.e., changing fee_token changes the fee_payer_signature_hash

        let sender = address!("0000000000000000000000000000000000000001");
        let token1 = address!("0000000000000000000000000000000000000002");
        let token2 = address!("0000000000000000000000000000000000000003");

        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Transaction with fee_token = None
        let tx_no_token = TempoTransaction {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![dummy_call],
            nonce_key: U256::ZERO,
            nonce: 1,
            fee_payer_signature: Some(Signature::test_signature()),
            valid_before: Some(1000),
            valid_after: None,
            ..Default::default()
        };

        // Transaction with fee_token = token1
        let tx_token1 = TempoTransaction {
            fee_token: Some(token1),
            ..tx_no_token.clone()
        };

        // Transaction with fee_token = token2
        let tx_token2 = TempoTransaction {
            fee_token: Some(token2),
            ..tx_no_token.clone()
        };

        // Calculate fee payer signature hashes
        let fee_payer_hash_no_token = tx_no_token.fee_payer_signature_hash(sender);
        let fee_payer_hash_token1 = tx_token1.fee_payer_signature_hash(sender);
        let fee_payer_hash_token2 = tx_token2.fee_payer_signature_hash(sender);

        // All three fee payer hashes should be different (fee payer commits to fee_token)
        assert_ne!(
            fee_payer_hash_no_token, fee_payer_hash_token1,
            "Fee payer hash should change when fee_token changes from None to Some"
        );
        assert_ne!(
            fee_payer_hash_token1, fee_payer_hash_token2,
            "Fee payer hash should change when fee_token changes from token1 to token2"
        );
        assert_ne!(
            fee_payer_hash_no_token, fee_payer_hash_token2,
            "Fee payer hash should be different for None vs token2"
        );

        // Calculate user signature hashes (what the sender signs)
        let user_hash_no_token = tx_no_token.signature_hash();
        let user_hash_token1 = tx_token1.signature_hash();
        let user_hash_token2 = tx_token2.signature_hash();

        // All three user hashes should be THE SAME (user skips fee_token when fee_payer is present)
        assert_eq!(
            user_hash_no_token, user_hash_token1,
            "User hash should be the same regardless of fee_token (user skips fee_token)"
        );
        assert_eq!(
            user_hash_token1, user_hash_token2,
            "User hash should be the same regardless of fee_token (user skips fee_token)"
        );
        assert_eq!(
            user_hash_no_token, user_hash_token2,
            "User hash should be the same regardless of fee_token (user skips fee_token)"
        );
    }

    #[test]
    fn test_fee_payer_signature_uses_magic_byte() {
        // Verify that fee payer signature hash uses the magic byte 0x78

        let sender = address!("0000000000000000000000000000000000000001");
        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        let tx = TempoTransaction {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![dummy_call],
            nonce_key: U256::ZERO,
            nonce: 1,
            fee_payer_signature: Some(Signature::test_signature()),
            valid_before: Some(1000),
            ..Default::default()
        };

        // The fee_payer_signature_hash should start with the magic byte
        // We can't directly inspect the hash construction, but we can verify it's different
        // from the sender signature hash which uses TEMPO_TX_TYPE_ID (0x76)
        let sender_hash = tx.signature_hash();
        let fee_payer_hash = tx.fee_payer_signature_hash(sender);

        // These should be different because they use different type bytes
        assert_ne!(
            sender_hash, fee_payer_hash,
            "Sender and fee payer hashes should be different (different magic bytes)"
        );
    }

    #[test]
    fn test_user_signature_without_fee_payer() {
        // Test that user signature hash INCLUDES fee_token when fee_payer is NOT present

        let token1 = address!("0000000000000000000000000000000000000002");
        let token2 = address!("0000000000000000000000000000000000000003");

        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Transaction WITHOUT fee_payer, fee_token = None
        let tx_no_payer_no_token = TempoTransaction {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![dummy_call],
            nonce_key: U256::ZERO,
            nonce: 1,
            fee_payer_signature: None, // No fee payer
            valid_before: Some(1000),
            valid_after: None,
            tempo_authorization_list: vec![],
            access_list: Default::default(),
            key_authorization: None,
        };

        // Transaction WITHOUT fee_payer, fee_token = token1
        let tx_no_payer_token1 = TempoTransaction {
            fee_token: Some(token1),
            ..tx_no_payer_no_token.clone()
        };

        // Transaction WITHOUT fee_payer, fee_token = token2
        let tx_no_payer_token2 = TempoTransaction {
            fee_token: Some(token2),
            ..tx_no_payer_no_token.clone()
        };

        // Calculate user signature hashes
        let hash_no_token = tx_no_payer_no_token.signature_hash();
        let hash_token1 = tx_no_payer_token1.signature_hash();
        let hash_token2 = tx_no_payer_token2.signature_hash();

        // All three hashes should be DIFFERENT (user includes fee_token when no fee_payer)
        assert_ne!(
            hash_no_token, hash_token1,
            "User hash should change when fee_token changes (no fee_payer)"
        );
        assert_ne!(
            hash_token1, hash_token2,
            "User hash should change when fee_token changes (no fee_payer)"
        );
        assert_ne!(
            hash_no_token, hash_token2,
            "User hash should change when fee_token changes (no fee_payer)"
        );
    }

    #[test]
    fn test_rlp_encoding_includes_fee_token() {
        // Test that RLP encoding always includes fee_token in the encoded data

        let token = address!("0000000000000000000000000000000000000002");

        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Transaction with fee_token
        let tx_with_token = TempoTransaction {
            chain_id: 1,
            fee_token: Some(token),
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![dummy_call],
            nonce_key: U256::ZERO,
            nonce: 1,
            fee_payer_signature: Some(Signature::test_signature()),
            valid_before: Some(1000),
            valid_after: None,
            tempo_authorization_list: vec![],
            access_list: Default::default(),
            key_authorization: None,
        };

        // Transaction without fee_token
        let tx_without_token = TempoTransaction {
            fee_token: None,
            ..tx_with_token.clone()
        };

        // Encode both transactions
        let mut buf_with = Vec::new();
        tx_with_token.encode(&mut buf_with);

        let mut buf_without = Vec::new();
        tx_without_token.encode(&mut buf_without);

        // The encoded bytes should be different lengths
        assert_ne!(
            buf_with.len(),
            buf_without.len(),
            "RLP encoding should include fee_token in the encoded data"
        );

        // The one with token should be longer (20 bytes for address vs 1 byte for empty)
        assert!(
            buf_with.len() > buf_without.len(),
            "Transaction with fee_token should have longer encoding"
        );

        // Decode and verify
        let decoded_with = TempoTransaction::decode(&mut buf_with.as_slice()).unwrap();
        let decoded_without = TempoTransaction::decode(&mut buf_without.as_slice()).unwrap();

        assert_eq!(decoded_with.fee_token, Some(token));
        assert_eq!(decoded_without.fee_token, None);
    }

    #[test]
    fn test_signature_hash_behavior_with_and_without_fee_payer() {
        // Comprehensive test showing all signature hash behaviors

        let token = address!("0000000000000000000000000000000000000002");

        let dummy_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Scenario 1: No fee payer, no token
        let tx_no_payer_no_token = TempoTransaction {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![dummy_call],
            nonce_key: U256::ZERO,
            nonce: 1,
            fee_payer_signature: None,
            valid_before: Some(1000),
            valid_after: None,
            tempo_authorization_list: vec![],
            access_list: Default::default(),
            key_authorization: None,
        };

        // Scenario 2: No fee payer, with token
        let tx_no_payer_with_token = TempoTransaction {
            fee_token: Some(token),
            ..tx_no_payer_no_token.clone()
        };

        // Scenario 3: With fee payer, no token
        let tx_with_payer_no_token = TempoTransaction {
            fee_payer_signature: Some(Signature::test_signature()),
            ..tx_no_payer_no_token.clone()
        };

        // Scenario 4: With fee payer, with token
        let tx_with_payer_with_token = TempoTransaction {
            fee_token: Some(token),
            fee_payer_signature: Some(Signature::test_signature()),
            ..tx_no_payer_no_token.clone()
        };

        // Calculate user signature hashes
        let hash1 = tx_no_payer_no_token.signature_hash();
        let hash2 = tx_no_payer_with_token.signature_hash();
        let hash3 = tx_with_payer_no_token.signature_hash();
        let hash4 = tx_with_payer_with_token.signature_hash();

        // Without fee_payer: user includes fee_token, so hash1 != hash2
        assert_ne!(
            hash1, hash2,
            "User hash changes with fee_token when no fee_payer"
        );

        // With fee_payer: user skips fee_token, so hash3 == hash4
        assert_eq!(
            hash3, hash4,
            "User hash ignores fee_token when fee_payer is present"
        );

        // Hashes without fee_payer should differ from hashes with fee_payer
        // (because skip_fee_token logic changes)
        assert_ne!(hash1, hash3, "User hash changes when fee_payer is added");
    }

    #[test]
    fn test_backwards_compatibility_key_authorization() {
        // Test that transactions without key_authorization are backwards compatible
        // and that the RLP encoding doesn't include any extra bytes for None

        let call = Call {
            to: TxKind::Call(address!("0000000000000000000000000000000000000002")),
            value: U256::from(1000),
            input: Bytes::from(vec![1, 2, 3, 4]),
        };

        // Create transaction WITHOUT key_authorization (old format)
        let tx_without = TempoTransaction {
            chain_id: 1,
            fee_token: Some(address!("0000000000000000000000000000000000000001")),
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![call],
            access_list: Default::default(),
            nonce_key: U256::ZERO,
            nonce: 1,
            fee_payer_signature: Some(Signature::test_signature()),
            valid_before: Some(1000000),
            valid_after: Some(500000),
            key_authorization: None, // No key authorization
            tempo_authorization_list: vec![],
        };

        // Encode the transaction
        let mut buf_without = Vec::new();
        tx_without.encode(&mut buf_without);

        // Decode it back
        let decoded_without = TempoTransaction::decode(&mut buf_without.as_slice()).unwrap();

        // Verify it matches
        assert_eq!(decoded_without.key_authorization, None);
        assert_eq!(decoded_without.chain_id, tx_without.chain_id);
        assert_eq!(decoded_without.calls.len(), tx_without.calls.len());

        // Create transaction WITH key_authorization (new format)
        let key_auth = KeyAuthorization {
            chain_id: 1, // Test chain ID
            key_type: SignatureType::Secp256k1,
            expiry: Some(1234567890),
            limits: Some(vec![crate::transaction::TokenLimit {
                token: address!("0000000000000000000000000000000000000003"),
                limit: U256::from(10000),
            }]),
            key_id: address!("0000000000000000000000000000000000000004"),
        }
        .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));

        let tx_with = TempoTransaction {
            key_authorization: Some(key_auth.clone()),
            ..tx_without.clone()
        };

        // Encode the transaction
        let mut buf_with = Vec::new();
        tx_with.encode(&mut buf_with);

        // Decode it back
        let decoded_with = TempoTransaction::decode(&mut buf_with.as_slice()).unwrap();

        // Verify the key_authorization is preserved
        assert!(decoded_with.key_authorization.is_some());
        let decoded_key_auth = decoded_with.key_authorization.unwrap();
        assert_eq!(decoded_key_auth.key_type, key_auth.key_type);
        assert_eq!(decoded_key_auth.expiry, key_auth.expiry);
        assert_eq!(
            decoded_key_auth.limits.as_ref().map(|l| l.len()),
            key_auth.limits.as_ref().map(|l| l.len())
        );
        assert_eq!(decoded_key_auth.key_id, key_auth.key_id);

        // Important: The encoded transaction WITHOUT key_authorization should be shorter
        // This proves we're not encoding empty bytes for None
        assert!(
            buf_without.len() < buf_with.len(),
            "Transaction without key_authorization should have shorter encoding"
        );

        // Test that an old decoder (simulated by truncating at the right position)
        // can still decode a transaction without key_authorization
        // This simulates backwards compatibility with old code that doesn't know about key_authorization
        let decoded_old_format = TempoTransaction::decode(&mut buf_without.as_slice()).unwrap();
        assert_eq!(decoded_old_format.key_authorization, None);
    }

    #[test]
    fn test_aa_signed_rlp_direct() {
        // Simple test for AASigned RLP encoding/decoding without key_authorization
        let call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        let tx = TempoTransaction {
            chain_id: 0,
            fee_token: None,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 0,
            calls: vec![call],
            access_list: Default::default(),
            nonce_key: U256::ZERO,
            nonce: 0,
            fee_payer_signature: None,
            valid_before: None,
            valid_after: None,
            key_authorization: None, // No key_authorization
            tempo_authorization_list: vec![],
        };

        let signature =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let signed = AASigned::new_unhashed(tx, signature);

        // Test direct RLP encoding/decoding
        let mut buf = Vec::new();
        signed.rlp_encode(&mut buf);

        // Decode
        let decoded =
            AASigned::rlp_decode(&mut buf.as_slice()).expect("Should decode AASigned RLP");
        assert_eq!(decoded.tx().key_authorization, None);
    }

    #[test]
    fn test_tempo_transaction_envelope_roundtrip_without_key_auth() {
        // Test that TempoTransaction in envelope works without key_authorization
        let call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        let tx = TempoTransaction {
            chain_id: 0,
            fee_token: None,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 0,
            calls: vec![call],
            access_list: Default::default(),
            nonce_key: U256::ZERO,
            nonce: 0,
            fee_payer_signature: None,
            valid_before: None,
            valid_after: None,
            key_authorization: None, // No key_authorization
            tempo_authorization_list: vec![],
        };

        let signature =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let signed = AASigned::new_unhashed(tx, signature);
        let envelope = TempoTxEnvelope::AA(signed);

        // Encode and decode the envelope
        let mut buf = Vec::new();
        envelope.encode_2718(&mut buf);
        let decoded = TempoTxEnvelope::decode_2718(&mut buf.as_slice())
            .expect("Should decode envelope successfully");

        // Verify it's the same
        if let TempoTxEnvelope::AA(aa_signed) = decoded {
            assert_eq!(aa_signed.tx().key_authorization, None);
            assert_eq!(aa_signed.tx().calls.len(), 1);
            assert_eq!(aa_signed.tx().chain_id, 0);
        } else {
            panic!("Expected AA envelope");
        }
    }

    #[test]
    fn test_call_decode_rejects_malformed_rlp() {
        // Test that Call decoding rejects RLP with mismatched header length
        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::random(),
            input: Bytes::from(vec![1, 2, 3, 4]),
        };

        // Encode the call normally
        let mut buf = Vec::new();
        call.encode(&mut buf);

        // Corrupt the header to claim less payload than actually encoded
        // This simulates the case where header.payload_length doesn't match actual consumed bytes
        let original_len = buf.len();
        buf.truncate(original_len - 2); // Remove 2 bytes from the end

        let result = Call::decode(&mut buf.as_slice());
        assert!(
            result.is_err(),
            "Decoding should fail when header length doesn't match"
        );
        // The error could be InputTooShort or UnexpectedLength depending on what field is truncated
        assert!(matches!(
            result.unwrap_err(),
            alloy_rlp::Error::InputTooShort | alloy_rlp::Error::UnexpectedLength
        ));
    }

    #[test]
    fn test_tempo_transaction_decode_rejects_malformed_rlp() {
        // Test that TempoTransaction decoding rejects RLP with mismatched header length
        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::random(),
            input: Bytes::from(vec![1, 2, 3, 4]),
        };

        let tx = TempoTransaction {
            chain_id: 1,
            fee_token: Some(Address::random()),
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            calls: vec![call],
            access_list: Default::default(),
            nonce_key: U256::ZERO,
            nonce: 1,
            fee_payer_signature: Some(Signature::test_signature()),
            valid_before: Some(1000000),
            valid_after: Some(500000),
            key_authorization: None,
            tempo_authorization_list: vec![],
        };

        // Encode the transaction normally
        let mut buf = Vec::new();
        tx.encode(&mut buf);

        // Corrupt by truncating - simulates header claiming more bytes than available
        let original_len = buf.len();
        buf.truncate(original_len - 5); // Remove 5 bytes from the end

        let result = TempoTransaction::decode(&mut buf.as_slice());
        assert!(
            result.is_err(),
            "Decoding should fail when data is truncated"
        );
        // The error could be InputTooShort or UnexpectedLength depending on what field is truncated
        assert!(matches!(
            result.unwrap_err(),
            alloy_rlp::Error::InputTooShort | alloy_rlp::Error::UnexpectedLength
        ));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn call_serde() {
        let call: Call = serde_json::from_str(
            r#"{"to":"0x0000000000000000000000000000000000000002","value":"0x1","input":"0x1234"}"#,
        )
        .unwrap();
        assert_eq!(
            call.to,
            TxKind::Call(address!("0000000000000000000000000000000000000002"))
        );
        assert_eq!(call.value, U256::ONE);
        assert_eq!(call.input, bytes!("0x1234"));
    }

    #[test]
    fn test_create_must_be_first_call() {
        let create_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let call_call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Valid: CREATE as first call
        let tx_valid = TempoTransaction {
            calls: vec![create_call.clone(), call_call.clone()],
            ..Default::default()
        };
        assert!(tx_valid.validate().is_ok());

        // Invalid: CREATE as second call
        let tx_invalid = TempoTransaction {
            calls: vec![call_call, create_call],
            ..Default::default()
        };
        assert!(tx_invalid.validate().is_err());
        assert!(tx_invalid.validate().unwrap_err().contains("first call"));
    }

    #[test]
    fn test_only_one_create_allowed() {
        let create_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Valid: Single CREATE
        let tx_valid = TempoTransaction {
            calls: vec![create_call.clone()],
            ..Default::default()
        };
        assert!(tx_valid.validate().is_ok());

        // Invalid: Multiple CREATEs (both at first position, second one triggers error)
        let tx_invalid = TempoTransaction {
            calls: vec![create_call.clone(), create_call],
            ..Default::default()
        };
        assert!(tx_invalid.validate().is_err());
        assert!(
            tx_invalid
                .validate()
                .unwrap_err()
                .contains("only one CREATE")
        );
    }

    #[test]
    fn test_create_forbidden_with_auth_list() {
        let create_call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };

        let signed_auth = TempoSignedAuthorization::new_unchecked(
            Authorization {
                chain_id: U256::ONE,
                address: Address::random(),
                nonce: 1,
            },
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        );

        // Invalid: CREATE call with auth list
        let tx = TempoTransaction {
            calls: vec![create_call],
            tempo_authorization_list: vec![signed_auth],
            ..Default::default()
        };

        let result = tx.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("aa_authorization_list"));
    }

    #[test]
    fn test_create_validation_allows_call_only_batch() {
        // A batch with only CALL operations should be valid
        let call1 = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let call2 = Call {
            to: TxKind::Call(Address::random()),
            value: U256::random(),
            input: Bytes::from(vec![1, 2, 3]),
        };

        let tx = TempoTransaction {
            calls: vec![call1, call2],
            ..Default::default()
        };
        assert!(tx.validate().is_ok());
    }

    #[test]
    fn test_value_saturates_on_overflow() {
        let call1 = Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::MAX,
            input: Bytes::new(),
        };
        let call2 = Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::from(1),
            input: Bytes::new(),
        };

        let tx = TempoTransaction {
            calls: vec![call1, call2],
            ..Default::default()
        };

        assert_eq!(tx.value(), U256::MAX);
    }

    #[test]
    fn test_validate_does_not_check_expiring_nonce_constraints() {
        let dummy_call = Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Transaction with expiring nonce key but nonce != 0 should pass validate()
        // (expiring nonce constraints are hardfork-dependent and checked elsewhere)
        let tx_with_nonzero_nonce = TempoTransaction {
            nonce_key: TEMPO_EXPIRING_NONCE_KEY,
            nonce: 42,
            valid_before: None,
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(
            tx_with_nonzero_nonce.validate().is_ok(),
            "validate() should not enforce expiring nonce constraints (hardfork-dependent)"
        );

        // Transaction with expiring nonce key but no valid_before should pass validate()
        let tx_without_valid_before = TempoTransaction {
            nonce_key: TEMPO_EXPIRING_NONCE_KEY,
            nonce: 0,
            valid_before: None,
            calls: vec![dummy_call.clone()],
            ..Default::default()
        };
        assert!(
            tx_without_valid_before.validate().is_ok(),
            "validate() should not enforce expiring nonce constraints (hardfork-dependent)"
        );

        // Sanity check: a fully valid expiring nonce tx should also pass
        let valid_expiring_tx = TempoTransaction {
            nonce_key: TEMPO_EXPIRING_NONCE_KEY,
            nonce: 0,
            valid_before: Some(1000),
            calls: vec![dummy_call],
            ..Default::default()
        };
        assert!(valid_expiring_tx.validate().is_ok());
    }
}
