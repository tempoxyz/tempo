use alloy_consensus::{
    SignableTransaction, Signed, Transaction,
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx},
};
use alloy_eips::{Typed2718, eip2930::AccessList, eip7702::SignedAuthorization};
use alloy_primitives::{Address, B256, Bytes, ChainId, Signature, TxKind, U256, keccak256};
use alloy_rlp::{Buf, BufMut, Decodable, EMPTY_STRING_CODE, Encodable};
use core::mem;

extern crate alloc;

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
            nonce_key: 0,
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
        mem::size_of::<u64>() + // nonce_key
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

/// Verifies a P256 signature using the provided components
///
/// This performs actual cryptographic verification of the P256 signature
/// according to the spec. Called during `recover_signer()` to ensure only
/// valid signatures enter the mempool.
fn verify_p256_signature_internal(
    r: &[u8],
    s: &[u8],
    pub_key_x: &[u8],
    pub_key_y: &[u8],
    message_hash: &B256,
) -> Result<(), &'static str> {
    use p256::ecdsa::{Signature as P256Signature, VerifyingKey, signature::Verifier};
    use p256::EncodedPoint;

    // Construct uncompressed public key point (0x04 || x || y)
    let mut pub_key_bytes = [0u8; 65];
    pub_key_bytes[0] = 0x04; // Uncompressed point marker
    pub_key_bytes[1..33].copy_from_slice(pub_key_x);
    pub_key_bytes[33..65].copy_from_slice(pub_key_y);

    // Parse public key
    let encoded_point = EncodedPoint::from_bytes(&pub_key_bytes)
        .map_err(|_| "Invalid P256 public key encoding")?;

    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|_| "Invalid P256 public key")?;

    // Construct signature from r and s
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0..32].copy_from_slice(r);
    sig_bytes[32..64].copy_from_slice(s);

    let signature = P256Signature::from_bytes(&sig_bytes.into())
        .map_err(|_| "Invalid P256 signature encoding")?;

    // Verify signature
    verifying_key
        .verify(message_hash.as_slice(), &signature)
        .map_err(|_| "P256 signature verification failed")
}

/// Parses and validates WebAuthn data, returning the message hash for P256 verification
///
/// According to the spec, this:
/// 1. Parses authenticatorData and clientDataJSON
/// 2. Validates authenticatorData (min 37 bytes, UP flag set)
/// 3. Validates clientDataJSON (type="webauthn.get", challenge matches tx_hash)
/// 4. Computes message hash = sha256(authenticatorData || sha256(clientDataJSON))
fn verify_webauthn_data_internal(
    webauthn_data: &[u8],
    tx_hash: &B256,
) -> Result<B256, &'static str> {
    use sha2::{Sha256, Digest};

    // Minimum authenticatorData is 37 bytes (32 rpIdHash + 1 flags + 4 signCount)
    if webauthn_data.len() < 37 {
        return Err("WebAuthn data too short");
    }

    // Find the split between authenticatorData and clientDataJSON
    // Strategy: Try to parse as JSON from different split points
    // authenticatorData is minimum 37 bytes, so start searching from there
    let mut auth_data_len = 37;
    let mut client_data_json = None;

    // Check if AT flag (bit 6) is set in flags byte (byte 32)
    let flags = webauthn_data[32];
    let at_flag_set = (flags & 0x40) != 0;

    if !at_flag_set {
        // Simple case: authenticatorData is exactly 37 bytes
        if webauthn_data.len() > 37 {
            let potential_json = &webauthn_data[37..];
            if let Ok(json_str) = core::str::from_utf8(potential_json) {
                if json_str.starts_with('{') && json_str.ends_with('}') {
                    client_data_json = Some(potential_json);
                    auth_data_len = 37;
                }
            }
        }
    } else {
        // AT flag is set, need to parse CBOR data (complex)
        // For now, try multiple split points and validate JSON
        for split_point in 37..webauthn_data.len().saturating_sub(20) {
            let potential_json = &webauthn_data[split_point..];
            if let Ok(json_str) = core::str::from_utf8(potential_json) {
                if json_str.starts_with('{') && json_str.ends_with('}') {
                    // Basic JSON validation - check for required fields
                    if json_str.contains("\"type\"") && json_str.contains("\"challenge\"") {
                        client_data_json = Some(potential_json);
                        auth_data_len = split_point;
                        break;
                    }
                }
            }
        }
    }

    let client_data_json = client_data_json.ok_or("Failed to parse clientDataJSON from WebAuthn data")?;
    let authenticator_data = &webauthn_data[..auth_data_len];

    // Validate authenticatorData
    if authenticator_data.len() < 37 {
        return Err("AuthenticatorData too short");
    }

    // Check UP flag (bit 0) is set
    let flags = authenticator_data[32];
    if (flags & 0x01) == 0 {
        return Err("User Presence (UP) flag not set in authenticatorData");
    }

    // Validate clientDataJSON
    let json_str = core::str::from_utf8(client_data_json)
        .map_err(|_| "clientDataJSON is not valid UTF-8")?;

    // Check for required type field
    if !json_str.contains("\"type\":\"webauthn.get\"") {
        return Err("clientDataJSON missing required type field");
    }

    // Verify challenge matches tx_hash (Base64URL encoded)
    let challenge_b64url = base64_url_encode(tx_hash.as_slice());
    let challenge_property = format!("\"challenge\":\"{}\"", challenge_b64url);
    if !json_str.contains(&challenge_property) {
        return Err("clientDataJSON challenge does not match transaction hash");
    }

    // Compute message hash according to spec:
    // messageHash = sha256(authenticatorData || sha256(clientDataJSON))
    let mut hasher = Sha256::new();
    hasher.update(client_data_json);
    let client_data_hash = hasher.finalize();

    let mut final_hasher = Sha256::new();
    final_hasher.update(authenticator_data);
    final_hasher.update(&client_data_hash);
    let message_hash = final_hasher.finalize();

    Ok(B256::from_slice(&message_hash))
}

/// Base64URL encode (without padding) as required by WebAuthn spec
fn base64_url_encode(data: &[u8]) -> alloc::string::String {
    use alloc::string::String;
    const BASE64URL_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::new();
    let mut i = 0;

    while i + 2 < data.len() {
        let b1 = data[i];
        let b2 = data[i + 1];
        let b3 = data[i + 2];

        result.push(BASE64URL_CHARS[(b1 >> 2) as usize] as char);
        result.push(BASE64URL_CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
        result.push(BASE64URL_CHARS[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize] as char);
        result.push(BASE64URL_CHARS[(b3 & 0x3f) as usize] as char);

        i += 3;
    }

    // Handle remaining bytes
    if i < data.len() {
        let b1 = data[i];
        result.push(BASE64URL_CHARS[(b1 >> 2) as usize] as char);

        if i + 1 < data.len() {
            let b2 = data[i + 1];
            result.push(BASE64URL_CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
            result.push(BASE64URL_CHARS[((b2 & 0x0f) << 2) as usize] as char);
        } else {
            result.push(BASE64URL_CHARS[((b1 & 0x03) << 4) as usize] as char);
        }
    }

    result
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

// TODO: Claude code generated this, because reth-codec macro doesn't support multiple Bytes fields in the tx field.
// This is probably incorrect, and just kept here as a placeholder.
#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for TxAA {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        use reth_codecs::Compact;

        let mut total_length = 0;

        // Encode all fixed-size and known-size fields
        total_length += self.chain_id.to_compact(buf);
        total_length += self.fee_token.to_compact(buf);
        total_length += self.max_priority_fee_per_gas.to_compact(buf);
        total_length += self.max_fee_per_gas.to_compact(buf);
        total_length += self.gas_limit.to_compact(buf);
        total_length += self.to.to_compact(buf);
        total_length += self.value.to_compact(buf);
        total_length += self.access_list.to_compact(buf);
        total_length += self.nonce_key.to_compact(buf);
        total_length += self.nonce_sequence.to_compact(buf);
        total_length += self.fee_payer_signature.to_compact(buf);
        total_length += self.valid_before.to_compact(buf);
        total_length += self.valid_after.to_compact(buf);

        // Encode input with length prefix (Bytes::to_compact handles this)
        total_length += self.input.to_compact(buf);

        // Encode signature last (raw bytes, no length prefix)
        buf.put_slice(&self.signature);
        total_length += self.signature.len();

        total_length
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        use reth_codecs::Compact;

        // Decode all fixed-size and known-size fields
        let (chain_id, new_buf) = ChainId::from_compact(buf, 0);
        buf = new_buf;

        let (fee_token, new_buf) = Option::<Address>::from_compact(buf, 0);
        buf = new_buf;

        let (max_priority_fee_per_gas, new_buf) = u128::from_compact(buf, 0);
        buf = new_buf;

        let (max_fee_per_gas, new_buf) = u128::from_compact(buf, 0);
        buf = new_buf;

        let (gas_limit, new_buf) = u64::from_compact(buf, 0);
        buf = new_buf;

        let (to, new_buf) = TxKind::from_compact(buf, 0);
        buf = new_buf;

        let (value, new_buf) = U256::from_compact(buf, 0);
        buf = new_buf;

        let (access_list, new_buf) = AccessList::from_compact(buf, 0);
        buf = new_buf;

        let (nonce_key, new_buf) = u64::from_compact(buf, 0);
        buf = new_buf;

        let (nonce_sequence, new_buf) = u64::from_compact(buf, 0);
        buf = new_buf;

        let (fee_payer_signature, new_buf) = Option::<Signature>::from_compact(buf, 0);
        buf = new_buf;

        let (valid_before, new_buf) = u64::from_compact(buf, 0);
        buf = new_buf;

        let (valid_after, new_buf) = Option::<u64>::from_compact(buf, 0);
        buf = new_buf;

        // Decode input (Bytes::from_compact reads its own length)
        let (input, new_buf) = Bytes::from_compact(buf, buf.len());
        buf = new_buf;

        // Decode signature (rest of buffer, raw bytes)
        let signature = Bytes::copy_from_slice(buf);
        buf = &[];

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
    /// This function verifies the signature and extracts the address based on signature type:
    /// - secp256k1: Uses standard ecrecover (signature verification + address recovery)
    /// - P256: Verifies P256 signature then derives address from public key
    /// - WebAuthn: Parses WebAuthn data, verifies P256 signature, derives address
    ///
    /// Signature verification happens here (before pool entry) for all types,
    /// matching the secp256k1 flow for consistency and security.
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

                // This simultaneously verifies the signature AND recovers the address
                sig.recover_address_from_prehash(&sig_hash)
                    .map_err(|_| "Failed to recover secp256k1 address")
            }
            SignatureType::P256 => {
                // P256 signature format: r (32) || s (32) || pubKeyX (32) || pubKeyY (32) || preHash (1)
                if self.signature.len() != P256_SIGNATURE_LENGTH {
                    return Err("Invalid P256 signature length");
                }

                // Extract signature components
                let r = &self.signature[0..32];
                let s = &self.signature[32..64];
                let pub_key_x = &self.signature[64..96];
                let pub_key_y = &self.signature[96..128];
                let pre_hash = self.signature[128] != 0;

                // Prepare message hash for verification
                let message_hash = if pre_hash {
                    // Some P256 implementations (like Web Crypto) require pre-hashing
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(sig_hash.as_slice());
                    let result = hasher.finalize();
                    B256::from_slice(&result)
                } else {
                    sig_hash
                };

                // Verify P256 signature cryptographically
                verify_p256_signature_internal(r, s, pub_key_x, pub_key_y, &message_hash)?;

                // Derive and return address
                let pub_x = B256::from_slice(pub_key_x);
                let pub_y = B256::from_slice(pub_key_y);
                Ok(derive_p256_address(&pub_x, &pub_y))
            }
            SignatureType::WebAuthn => {
                // WebAuthn signature format (from spec):
                // authenticatorData || clientDataJSON || r (32) || s (32) || pubKeyX (32) || pubKeyY (32)

                if self.signature.len() < 128 {
                    return Err("WebAuthn signature too short");
                }

                let sig_len = self.signature.len();

                // Extract P256 signature components and public key (last 128 bytes)
                let r = &self.signature[sig_len - 128..sig_len - 96];
                let s = &self.signature[sig_len - 96..sig_len - 64];
                let pub_key_x = &self.signature[sig_len - 64..sig_len - 32];
                let pub_key_y = &self.signature[sig_len - 32..];

                // Extract WebAuthn data (everything except the last 128 bytes)
                let webauthn_data = &self.signature[..sig_len - 128];

                // Parse and verify WebAuthn data, compute challenge hash
                let message_hash = verify_webauthn_data_internal(webauthn_data, &sig_hash)?;

                // Verify P256 signature over the computed message hash
                verify_p256_signature_internal(r, s, pub_key_x, pub_key_y, &message_hash)?;

                // Derive and return address
                let pub_x = B256::from_slice(pub_key_x);
                let pub_y = B256::from_slice(pub_key_y);
                Ok(derive_p256_address(&pub_x, &pub_y))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256, address, hex};
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn test_tx_aa_validation() {
        // Valid: secp256k1 signature (65 bytes)
        let mut tx1 = TxAA {
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
            ..Default::default()
        };
        assert!(tx1.validate().is_ok());

        // Valid: P256 signature (129 bytes)
        let mut tx2 = TxAA {
            signature: Bytes::from(vec![0u8; P256_SIGNATURE_LENGTH]),
            ..Default::default()
        };
        assert!(tx2.validate().is_ok());

        // Valid: WebAuthn signature (>129 bytes, <=2KB)
        let mut tx3 = TxAA {
            signature: Bytes::from(vec![0u8; 200]),
            ..Default::default()
        };
        assert!(tx3.validate().is_ok());

        // Invalid: empty signature
        let mut tx4 = TxAA {
            signature: Bytes::new(),
            ..Default::default()
        };
        assert!(tx4.validate().is_err());

        // Invalid: signature too short
        let mut tx5 = TxAA {
            signature: Bytes::from(vec![0u8; 64]),
            ..Default::default()
        };
        assert!(tx5.validate().is_err());

        // Invalid: signature too long (>2KB)
        let mut tx6 = TxAA {
            signature: Bytes::from(vec![0u8; MAX_WEBAUTHN_SIGNATURE_LENGTH + 1]),
            ..Default::default()
        };
        assert!(tx6.validate().is_err());

        // Valid: valid_before > valid_after
        let mut tx7 = TxAA {
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
            valid_before: 100,
            valid_after: Some(50),
            ..Default::default()
        };
        assert!(tx7.validate().is_ok());

        // Invalid: valid_before <= valid_after
        let mut tx8 = TxAA {
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
            valid_before: 50,
            valid_after: Some(100),
            ..Default::default()
        };
        assert!(tx8.validate().is_err());

        // Invalid: valid_before == valid_after
        let mut tx9 = TxAA {
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
            valid_before: 100,
            valid_after: Some(100),
            ..Default::default()
        };
        assert!(tx9.validate().is_err());
    }

    #[test]
    fn test_tx_type() {
        assert_eq!(TxAA::tx_type(), 0x05);
        assert_eq!(AA_TX_TYPE_ID, 0x05);
    }

    #[test]
    fn test_signature_type_detection() {
        // Secp256k1
        let tx1 = TxAA {
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
            ..Default::default()
        };
        assert_eq!(tx1.signature_type().unwrap(), SignatureType::Secp256k1);

        // P256
        let tx2 = TxAA {
            signature: Bytes::from(vec![0u8; P256_SIGNATURE_LENGTH]),
            ..Default::default()
        };
        assert_eq!(tx2.signature_type().unwrap(), SignatureType::P256);

        // WebAuthn
        let tx3 = TxAA {
            signature: Bytes::from(vec![0u8; 200]),
            ..Default::default()
        };
        assert_eq!(tx3.signature_type().unwrap(), SignatureType::WebAuthn);
    }

    #[test]
    fn test_rlp_roundtrip() {
        let tx = TxAA {
            chain_id: 1,
            fee_token: Some(address!("0000000000000000000000000000000000000001")),
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            to: TxKind::Call(address!("0000000000000000000000000000000000000002")),
            value: U256::from(1000),
            access_list: Default::default(),
            nonce_key: 0,
            nonce_sequence: 1,
            fee_payer_signature: Some(Signature::test_signature()),
            valid_before: 1000000,
            valid_after: Some(500000),
            input: Bytes::from(vec![1, 2, 3, 4]),
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
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
        assert_eq!(decoded.to, tx.to);
        assert_eq!(decoded.value, tx.value);
        assert_eq!(decoded.nonce_key, tx.nonce_key);
        assert_eq!(decoded.nonce_sequence, tx.nonce_sequence);
        assert_eq!(decoded.valid_before, tx.valid_before);
        assert_eq!(decoded.valid_after, tx.valid_after);
        assert_eq!(decoded.fee_payer_signature, tx.fee_payer_signature);
        assert_eq!(decoded.input, tx.input);
        assert_eq!(decoded.signature, tx.signature);
    }

    #[test]
    fn test_rlp_roundtrip_no_optional_fields() {
        let tx = TxAA {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            to: TxKind::Call(address!("0000000000000000000000000000000000000002")),
            value: U256::from(1000),
            access_list: Default::default(),
            nonce_key: 0,
            nonce_sequence: 1,
            fee_payer_signature: None,
            valid_before: 0,
            valid_after: None,
            input: Bytes::new(),
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
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
        // Protocol nonce (key 0)
        let tx1 = TxAA {
            nonce_key: 0,
            nonce_sequence: 1,
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
            ..Default::default()
        };
        assert!(tx1.validate().is_ok());
        assert_eq!(tx1.nonce(), 1);

        // User parallel nonce (key > 0)
        let tx2 = TxAA {
            nonce_key: 1,
            nonce_sequence: 0,
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
            ..Default::default()
        };
        assert!(tx2.validate().is_ok());
        assert_eq!(tx2.nonce(), 0);
    }

    #[test]
    fn test_transaction_trait_impl() {
        let tx = TxAA {
            chain_id: 1,
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            gas_limit: 21000,
            to: TxKind::Call(address!("0000000000000000000000000000000000000002")),
            value: U256::from(1000),
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
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
        let tx = TxAA {
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 2000000000,
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
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
    fn test_base64_url_encode() {
        // Test empty input
        let result = base64_url_encode(&[]);
        assert_eq!(result, "");

        // Test single byte
        let result = base64_url_encode(&[0x00]);
        assert_eq!(result, "AA");

        // Test two bytes
        let result = base64_url_encode(&[0x00, 0x00]);
        assert_eq!(result, "AAA");

        // Test three bytes (complete block)
        let result = base64_url_encode(&[0x00, 0x00, 0x00]);
        assert_eq!(result, "AAAA");

        // Test known value
        let input = b"hello world";
        let result = base64_url_encode(input);
        assert_eq!(result, "aGVsbG8gd29ybGQ");

        // Test that it uses URL-safe characters (- and _ instead of + and /)
        let input = &[0xFB, 0xFF];
        let result = base64_url_encode(input);
        assert!(result.contains('-') || result.contains('_'));
        assert!(!result.contains('+'));
        assert!(!result.contains('/'));
    }

    #[test]
    fn test_p256_signature_verification_invalid_pubkey() {
        // Invalid public key should fail
        let r = [0u8; 32];
        let s = [0u8; 32];
        let pub_key_x = [0u8; 32]; // Invalid: point not on curve
        let pub_key_y = [0u8; 32];
        let message_hash = B256::ZERO;

        let result = verify_p256_signature_internal(&r, &s, &pub_key_x, &pub_key_y, &message_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_p256_signature_verification_invalid_signature() {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;

        // Generate a valid key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Extract public key coordinates
        let encoded_point = verifying_key.to_encoded_point(false);
        let pub_key_x = encoded_point.x().unwrap();
        let pub_key_y = encoded_point.y().unwrap();

        // Use invalid signature (all zeros)
        let r = [0u8; 32];
        let s = [0u8; 32];
        let message_hash = B256::ZERO;

        let result = verify_p256_signature_internal(&r, &s, pub_key_x.as_slice(), pub_key_y.as_slice(), &message_hash);
        assert!(result.is_err(), "Invalid signature should fail verification");
    }

    #[test]
    fn test_p256_signature_verification_valid() {
        use p256::ecdsa::{SigningKey, signature::Signer};
        use p256::elliptic_curve::rand_core::OsRng;
        use sha2::{Sha256, Digest};

        // Generate a valid key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Create a message and sign it
        let message = b"test message";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = B256::from_slice(&hasher.finalize());

        // Sign the message
        let signature: p256::ecdsa::Signature = signing_key.sign(message_hash.as_slice());
        let sig_bytes = signature.to_bytes();
        let r = &sig_bytes[0..32];
        let s = &sig_bytes[32..64];

        // Extract public key coordinates
        let encoded_point = verifying_key.to_encoded_point(false);
        let pub_key_x = encoded_point.x().unwrap();
        let pub_key_y = encoded_point.y().unwrap();

        // Verify the signature
        let result = verify_p256_signature_internal(r, s, pub_key_x.as_slice(), pub_key_y.as_slice(), &message_hash);
        assert!(result.is_ok(), "Valid P256 signature should verify successfully");
    }

    #[test]
    fn test_webauthn_data_verification_too_short() {
        // WebAuthn data must be at least 37 bytes (authenticatorData minimum)
        let short_data = vec![0u8; 36];
        let tx_hash = B256::ZERO;

        let result = verify_webauthn_data_internal(&short_data, &tx_hash);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "WebAuthn data too short");
    }

    #[test]
    fn test_webauthn_data_verification_missing_up_flag() {
        // Create authenticatorData without UP flag set
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x00; // flags byte with UP flag not set

        // Add minimal clientDataJSON
        let client_data = b"{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
        let mut webauthn_data = auth_data;
        webauthn_data.extend_from_slice(client_data);

        let tx_hash = B256::ZERO;
        let result = verify_webauthn_data_internal(&webauthn_data, &tx_hash);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "User Presence (UP) flag not set in authenticatorData");
    }

    #[test]
    fn test_webauthn_data_verification_invalid_type() {
        // Create valid authenticatorData with UP flag
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // flags byte with UP flag set

        // Add clientDataJSON with wrong type
        let client_data = b"{\"type\":\"webauthn.create\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
        let mut webauthn_data = auth_data;
        webauthn_data.extend_from_slice(client_data);

        let tx_hash = B256::ZERO;
        let result = verify_webauthn_data_internal(&webauthn_data, &tx_hash);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "clientDataJSON missing required type field");
    }

    #[test]
    fn test_webauthn_data_verification_invalid_challenge() {
        // Create valid authenticatorData with UP flag
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // flags byte with UP flag set

        // Add clientDataJSON with wrong challenge
        let client_data = b"{\"type\":\"webauthn.get\",\"challenge\":\"wrong_challenge_value_here\"}";
        let mut webauthn_data = auth_data;
        webauthn_data.extend_from_slice(client_data);

        let tx_hash = B256::ZERO;
        let result = verify_webauthn_data_internal(&webauthn_data, &tx_hash);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "clientDataJSON challenge does not match transaction hash");
    }

    #[test]
    fn test_webauthn_data_verification_valid() {
        use sha2::{Sha256, Digest};

        // Create valid authenticatorData with UP flag
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // flags byte with UP flag set

        // Create a test transaction hash
        let tx_hash = B256::from_slice(&[0xAA; 32]);

        // Encode challenge as Base64URL
        let challenge_b64url = base64_url_encode(tx_hash.as_slice());

        // Create valid clientDataJSON with matching challenge
        let client_data = format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{}\"}}", challenge_b64url);
        let mut webauthn_data = auth_data.clone();
        webauthn_data.extend_from_slice(client_data.as_bytes());

        let result = verify_webauthn_data_internal(&webauthn_data, &tx_hash);
        assert!(result.is_ok(), "Valid WebAuthn data should verify successfully");

        // Verify the computed message hash is correct
        let message_hash = result.unwrap();

        // Manually compute expected hash
        let mut hasher = Sha256::new();
        hasher.update(client_data.as_bytes());
        let client_data_hash = hasher.finalize();

        let mut final_hasher = Sha256::new();
        final_hasher.update(&auth_data);
        final_hasher.update(&client_data_hash);
        let expected_hash = final_hasher.finalize();

        assert_eq!(message_hash.as_slice(), expected_hash.as_slice());
    }

    #[test]
    fn test_p256_address_derivation_deterministic() {
        // Test that address derivation is deterministic
        let pub_key_x = hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").into();
        let pub_key_y = hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").into();

        let addr1 = derive_p256_address(&pub_key_x, &pub_key_y);
        let addr2 = derive_p256_address(&pub_key_x, &pub_key_y);

        assert_eq!(addr1, addr2, "Address derivation should be deterministic");
    }

    #[test]
    fn test_p256_address_different_keys_different_addresses() {
        // Different keys should produce different addresses
        let pub_key_x1 = hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").into();
        let pub_key_y1 = hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").into();

        let pub_key_x2 = hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").into();
        let pub_key_y2 = hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").into();

        let addr1 = derive_p256_address(&pub_key_x1, &pub_key_y1);
        let addr2 = derive_p256_address(&pub_key_x2, &pub_key_y2);

        assert_ne!(addr1, addr2, "Different keys should produce different addresses");
    }

    #[test]
    fn test_recover_signer_secp256k1_invalid() {
        // Test that invalid secp256k1 signature fails
        let tx = TxAA {
            signature: Bytes::from(vec![0u8; SECP256K1_SIGNATURE_LENGTH]),
            ..Default::default()
        };

        let result = tx.recover_signer();
        assert!(result.is_err(), "Invalid secp256k1 signature should fail");
    }

    #[test]
    fn test_recover_signer_p256_valid() {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;
        use p256::ecdsa::signature::Signer;
        use sha2::{Sha256, Digest};

        // Generate a valid key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Create transaction
        let mut tx = TxAA {
            chain_id: 1,
            gas_limit: 21000,
            to: TxKind::Call(Address::ZERO),
            signature: Bytes::new(), // Will be filled
            ..Default::default()
        };

        // Compute signature hash
        let sig_hash = tx.signature_hash();

        // Sign the hash
        let signature: p256::ecdsa::Signature = signing_key.sign(sig_hash.as_slice());
        let sig_bytes = signature.to_bytes();

        // Extract public key coordinates
        let encoded_point = verifying_key.to_encoded_point(false);
        let pub_key_x = encoded_point.x().unwrap();
        let pub_key_y = encoded_point.y().unwrap();

        // Build P256 signature: r || s || pubKeyX || pubKeyY || preHash
        let mut p256_sig = Vec::new();
        p256_sig.extend_from_slice(&sig_bytes[0..32]); // r
        p256_sig.extend_from_slice(&sig_bytes[32..64]); // s
        p256_sig.extend_from_slice(pub_key_x.as_slice()); // pubKeyX
        p256_sig.extend_from_slice(pub_key_y.as_slice()); // pubKeyY
        p256_sig.push(0); // preHash = false

        tx.signature = Bytes::from(p256_sig);

        // Recover signer
        let result = tx.recover_signer();
        assert!(result.is_ok(), "Valid P256 signature should recover successfully");

        let recovered_address = result.unwrap();
        let expected_address = derive_p256_address(
            &B256::from_slice(pub_key_x.as_slice()),
            &B256::from_slice(pub_key_y.as_slice())
        );

        assert_eq!(recovered_address, expected_address, "Recovered address should match derived address");
    }
}
