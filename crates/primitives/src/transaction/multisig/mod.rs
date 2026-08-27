use super::{tempo_transaction::MAX_WEBAUTHN_SIGNATURE_LENGTH, tt_signature::TempoSignature};
use alloc::vec::Vec;
#[cfg(any(test, feature = "serde"))]
use alloy_primitives::Bytes;
use alloy_primitives::{Address, B256, address, b256, keccak256};
use alloy_rlp::Encodable as _;
use core::mem::size_of;
use tempo_contracts::{SAFE_DEPLOYER_ADDRESS, precompiles::INativeMultisig};

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Tempo signature type byte for native multisig signatures.
pub const SIGNATURE_TYPE_MULTISIG: u8 = 0x05;

/// Domain prefix for native multisig owner approvals.
pub const MULTISIG_SIGNATURE_DOMAIN: &[u8] = b"tempo:multisig:signature";

/// Maximum number of owners allowed in a native multisig config.
pub const MAX_MULTISIG_OWNERS: usize = 48;

/// Maximum threshold accepted by a native multisig config.
pub const MAX_MULTISIG_THRESHOLD: u8 = u8::MAX;

/// Maximum number of owner approvals allowed in one native multisig signature.
pub const MAX_MULTISIG_SIGNATURES: usize = 8;

/// Maximum number of native multisig signatures in one nested authorization path, including the
/// top-level transaction signature.
pub const MAX_MULTISIG_NESTING_DEPTH: usize = 2;

/// Maximum encoded byte length for one primitive owner approval.
pub const MAX_MULTISIG_OWNER_SIGNATURE_BYTES: usize = 1 + MAX_WEBAUTHN_SIGNATURE_LENGTH;

/// Domain prefix for native multisig account CREATE2 salt derivation.
pub const MULTISIG_ACCOUNT_DOMAIN: &[u8] = b"tempo:multisig:account";

/// Safe Singleton Factory used to deploy the dedicated recovery factory.
pub const MULTISIG_RECOVERY_SINGLETON_FACTORY: Address = SAFE_DEPLOYER_ADDRESS;

/// Expected runtime-code hash of [`MULTISIG_RECOVERY_SINGLETON_FACTORY`].
pub const MULTISIG_RECOVERY_SINGLETON_FACTORY_RUNTIME_HASH: B256 =
    b256!("2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989");

/// Dedicated CREATE2 factory for recovery wallets on non-Tempo EVM chains.
pub const MULTISIG_RECOVERY_FACTORY: Address = address!("5B572547f14c002Aac05f2deb19a36fbf23F2f33");

/// Keccak-256 of the dedicated recovery factory creation code.
pub const MULTISIG_RECOVERY_FACTORY_INIT_CODE_HASH: B256 =
    b256!("32c2f9b9926477ca22da4308d7efa1b92a2c2db3f434a0afa77fc32bdecbe48b");

/// Keccak-256 of the dedicated recovery factory runtime code.
pub const MULTISIG_RECOVERY_FACTORY_RUNTIME_HASH: B256 =
    b256!("e74489073cf29a2000b643988575b615febec333a826512de4e1e8db10228a60");

/// Keccak-256 of the canonical recovery wallet creation code.
pub const MULTISIG_RECOVERY_WALLET_INIT_CODE_HASH: B256 =
    b256!("583cc63a2e37f645b43eac911b1a6d6de08b83abdc308c61364edda8cfc3bd37");

/// CREATE2 preimage length: 1-byte `0xff` + 20-byte factory + 32-byte salt +
/// 32-byte init-code hash.
pub const MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN: usize = 1 + 20 + 32 + 32;

/// Domain prefix for native multisig configuration commitments.
pub const MULTISIG_CONFIG_DOMAIN: &[u8] = b"tempo:multisig:config";

/// Native multisig owner entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct MultisigOwner {
    /// Address recovered from a primitive signature or named by a nested multisig signature.
    pub owner: Address,
    /// Nonzero owner weight.
    pub weight: u8,
}

impl From<INativeMultisig::MultisigOwner> for MultisigOwner {
    fn from(value: INativeMultisig::MultisigOwner) -> Self {
        Self {
            owner: value.owner,
            weight: value.weight,
        }
    }
}

impl From<MultisigOwner> for INativeMultisig::MultisigOwner {
    fn from(value: MultisigOwner) -> Self {
        Self {
            owner: value.owner,
            weight: value.weight,
        }
    }
}

/// Native multisig configuration carried by an account signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct MultisigConfig {
    /// Caller-chosen salt that establishes the account identity.
    pub salt: B256,
    /// Configuration version. Zero identifies the initial configuration.
    pub version: u64,
    /// Minimum total owner weight required to authorize a transaction.
    pub threshold: u8,
    /// Sorted weighted owner list.
    pub owners: Vec<MultisigOwner>,
}

impl MultisigConfig {
    /// Byte length of the account-salt preimage: domain, 32-byte salt, 1-byte threshold,
    /// 1-byte owner count, and a 20-byte address plus 1-byte weight per owner.
    pub fn account_salt_preimage_len(&self) -> usize {
        MULTISIG_ACCOUNT_DOMAIN.len() + 32 + 2 + self.owners.len() * 21
    }

    /// Byte length of the commitment preimage: domain, 32-byte salt, 8-byte version, 1-byte
    /// threshold, 1-byte owner count, and a 20-byte address plus 1-byte weight per owner.
    pub fn commitment_preimage_len(&self) -> usize {
        MULTISIG_CONFIG_DOMAIN.len() + 32 + 8 + 2 + self.owners.len() * 21
    }

    /// Encodes the canonical account-salt preimage.
    ///
    /// This checks that the owner count is encodable; callers must separately validate the config
    /// before relying on the resulting hash.
    pub fn account_salt_preimage(&self) -> Result<Vec<u8>, MultisigConfigError> {
        let owner_count = self.encoded_owner_count()?;
        let mut input = Vec::with_capacity(self.account_salt_preimage_len());
        input.extend_from_slice(MULTISIG_ACCOUNT_DOMAIN);
        input.extend_from_slice(self.salt.as_slice());
        self.append_owner_set(&mut input, owner_count);
        Ok(input)
    }

    /// Encodes the canonical configuration-commitment preimage.
    ///
    /// This checks that the owner count is encodable; callers must separately validate the config
    /// before relying on the resulting hash.
    pub fn commitment_preimage(&self) -> Result<Vec<u8>, MultisigConfigError> {
        let owner_count = self.encoded_owner_count()?;
        let mut input = Vec::with_capacity(self.commitment_preimage_len());
        input.extend_from_slice(MULTISIG_CONFIG_DOMAIN);
        input.extend_from_slice(self.salt.as_slice());
        input.extend_from_slice(&self.version.to_be_bytes());
        self.append_owner_set(&mut input, owner_count);
        Ok(input)
    }

    fn encoded_owner_count(&self) -> Result<u8, MultisigConfigError> {
        if self.owners.len() > MAX_MULTISIG_OWNERS {
            return Err(MultisigConfigError::TooManyOwners);
        }
        Ok(self.owners.len() as u8)
    }

    fn append_owner_set(&self, input: &mut Vec<u8>, owner_count: u8) {
        input.push(self.threshold);
        input.push(owner_count);
        for owner in &self.owners {
            input.extend_from_slice(owner.owner.as_slice());
            input.push(owner.weight);
        }
    }

    /// Validates owner count, ordering, addresses, weights, and threshold reachability, returning
    /// the total owner weight.
    pub fn validate(&self) -> Result<u8, MultisigConfigError> {
        self.validate_inner(None)
    }

    /// Performs [`Self::validate`] and rejects the account itself as an owner.
    pub fn validate_for_account(&self, account: Address) -> Result<u8, MultisigConfigError> {
        self.validate_inner(Some(account))
    }

    fn validate_inner(&self, account: Option<Address>) -> Result<u8, MultisigConfigError> {
        if self.owners.is_empty() {
            return Err(MultisigConfigError::EmptyOwners);
        }
        if self.owners.len() > MAX_MULTISIG_OWNERS {
            return Err(MultisigConfigError::TooManyOwners);
        }
        if self.threshold == 0 {
            return Err(MultisigConfigError::ZeroThreshold);
        }
        let mut total_weight = 0u16;
        let mut approval_weights = [0u8; MAX_MULTISIG_SIGNATURES];
        let mut prev_owner = None;
        for owner in &self.owners {
            if owner.owner.is_zero() {
                return Err(MultisigConfigError::ZeroOwner);
            }
            if account == Some(owner.owner) {
                return Err(MultisigConfigError::AccountIsOwner);
            }
            if owner.weight == 0 {
                return Err(MultisigConfigError::ZeroWeight);
            }
            if let Some(prev) = prev_owner {
                if prev == owner.owner {
                    return Err(MultisigConfigError::DuplicateOwner);
                }
                if prev > owner.owner {
                    return Err(MultisigConfigError::OwnersNotAscending);
                }
            }

            prev_owner = Some(owner.owner);
            total_weight += u16::from(owner.weight);
            if owner.weight > approval_weights[0] {
                approval_weights[0] = owner.weight;
                approval_weights.sort_unstable();
            }
        }

        if total_weight > u16::from(u8::MAX) {
            return Err(MultisigConfigError::TotalWeightExceedsMax);
        }
        let reachable_weight = approval_weights.into_iter().map(u16::from).sum::<u16>();
        if u16::from(self.threshold) > reachable_weight {
            return Err(MultisigConfigError::ThresholdExceedsWeight);
        }

        Ok(total_weight as u8)
    }

    /// Derives the CREATE2 salt for this configuration's initial account identity.
    pub fn account_salt(&self) -> Result<B256, MultisigConfigError> {
        self.validate()?;
        Ok(self.account_salt_validated())
    }

    /// Derives the native multisig account using the canonical recovery wallet's CREATE2 address.
    pub fn derive_account(&self) -> Result<Address, MultisigConfigError> {
        self.validate()?;
        self.derive_account_validated()
    }

    fn account_salt_validated(&self) -> B256 {
        keccak256(
            self.account_salt_preimage()
                .expect("validated multisig config has an encodable owner count"),
        )
    }

    fn derive_account_validated(&self) -> Result<Address, MultisigConfigError> {
        let account = multisig_account_address(self.account_salt_validated());
        if account.is_zero() {
            return Err(MultisigConfigError::DerivedAccountZero);
        }
        if self.owner_weight(account).is_some() {
            return Err(MultisigConfigError::AccountIsOwner);
        }
        Ok(account)
    }

    /// Computes the persisted commitment for this configuration.
    pub fn commitment(&self) -> Result<B256, MultisigConfigError> {
        self.validate()?;
        Ok(self.commitment_validated())
    }

    fn commitment_validated(&self) -> B256 {
        keccak256(
            self.commitment_preimage()
                .expect("validated multisig config has an encodable owner count"),
        )
    }

    /// Returns the configured weight for an owner, if present.
    pub fn owner_weight(&self, owner: Address) -> Option<u8> {
        self.owners
            .binary_search_by_key(&owner, |entry| entry.owner)
            .ok()
            .map(|idx| self.owners[idx].weight)
    }
    /// Returns a heuristic for the in-memory size of the config.
    pub fn size(&self) -> usize {
        size_of::<Self>() + self.owners.capacity() * size_of::<MultisigOwner>()
    }
}

// This cannot use `RlpDecodable`: the derived `Vec` decoder has no element limit and would decode
// an unbounded owner list before validation.
impl alloy_rlp::Decodable for MultisigConfig {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        if buf.len() < header.payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        let body = *buf;
        let (mut fields, rest) = body.split_at(header.payload_length);
        let salt = <B256 as alloy_rlp::Decodable>::decode(&mut fields)?;
        let version = <u64 as alloy_rlp::Decodable>::decode(&mut fields)?;
        let threshold = <u8 as alloy_rlp::Decodable>::decode(&mut fields)?;

        let owners_header = alloy_rlp::Header::decode(&mut fields)?;
        if !owners_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        if fields.len() < owners_header.payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let (mut owner_fields, trailing_fields) = fields.split_at(owners_header.payload_length);
        let mut owners = Vec::new();
        while !owner_fields.is_empty() {
            if owners.len() == MAX_MULTISIG_OWNERS {
                return Err(alloy_rlp::Error::Custom("too many multisig owners"));
            }
            owners.push(<MultisigOwner as alloy_rlp::Decodable>::decode(
                &mut owner_fields,
            )?);
        }
        if !trailing_fields.is_empty() {
            return Err(alloy_rlp::Error::Custom(
                "unexpected trailing multisig config fields",
            ));
        }

        *buf = rest;
        Ok(Self {
            salt,
            version,
            threshold,
            owners,
        })
    }
}

impl From<INativeMultisig::MultisigConfig> for MultisigConfig {
    fn from(value: INativeMultisig::MultisigConfig) -> Self {
        Self {
            salt: value.salt,
            version: value.version,
            threshold: value.threshold,
            owners: value.owners.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MultisigConfig> for INativeMultisig::MultisigConfig {
    fn from(value: MultisigConfig) -> Self {
        Self {
            salt: value.salt,
            version: value.version,
            threshold: value.threshold,
            owners: value.owners.into_iter().map(Into::into).collect(),
        }
    }
}

/// Native multisig transaction signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct MultisigSignature {
    /// Native multisig account authorized by this signature.
    ///
    /// This is explicit because a versioned configuration cannot derive the account's stable
    /// address.
    account: Address,
    /// Complete applicable account configuration.
    config: MultisigConfig,
    /// Owner approvals over the multisig digest.
    ///
    /// Each approval is either a primitive signature or a nested native multisig signature.
    signatures: Vec<TempoSignature>,
}

impl MultisigSignature {
    pub fn try_new(
        account: Address,
        config: MultisigConfig,
        signatures: Vec<TempoSignature>,
    ) -> Result<Self, MultisigSignatureError> {
        let signature = Self {
            account,
            config,
            signatures,
        };
        signature.validate_shape()?;
        Ok(signature)
    }

    #[cfg(feature = "serde")]
    fn decode_exact(bytes: &[u8]) -> alloy_rlp::Result<Self> {
        let mut input = bytes;
        let signature = Self::decode_with_depth(&mut input, 1)?;
        if !input.is_empty() {
            return Err(alloy_rlp::Error::Custom(
                "trailing native multisig signature bytes",
            ));
        }
        Ok(signature)
    }

    /// Decodes a native multisig signature while bounding recursive nesting.
    ///
    /// `depth` is the nesting level of this signature node; the top-level transaction signature is
    /// depth `1` and each nested owner approval is one level deeper. Owner approvals are decoded at
    /// `depth + 1`, and a node deeper than [`MAX_MULTISIG_NESTING_DEPTH`] is rejected. Enforcing the
    /// bound during decoding (not only during authorization) prevents untrusted, deeply nested
    /// input from exhausting the stack before any gas, fee, or hardfork check runs.
    pub(crate) fn decode_with_depth(buf: &mut &[u8], depth: usize) -> alloy_rlp::Result<Self> {
        if depth > MAX_MULTISIG_NESTING_DEPTH {
            return Err(alloy_rlp::Error::Custom(
                "native multisig nesting depth exceeded",
            ));
        }

        let outer = alloy_rlp::Header::decode(buf)?;
        if !outer.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        if buf.len() < outer.payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        let body = *buf;
        let (mut fields, rest) = body.split_at(outer.payload_length);

        let account = <Address as alloy_rlp::Decodable>::decode(&mut fields)?;
        let config = <MultisigConfig as alloy_rlp::Decodable>::decode(&mut fields)?;

        // Decode owner approvals one nesting level deeper so nested multisig approvals are bounded.
        let sig_header = alloy_rlp::Header::decode(&mut fields)?;
        if !sig_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        if fields.len() < sig_header.payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let (mut sig_fields, sig_rest) = fields.split_at(sig_header.payload_length);
        let mut signatures = Vec::new();
        while !sig_fields.is_empty() {
            if signatures.len() == MAX_MULTISIG_SIGNATURES {
                return Err(alloy_rlp::Error::Custom("too many multisig signatures"));
            }
            signatures.push(TempoSignature::decode_with_depth(
                &mut sig_fields,
                depth + 1,
            )?);
        }
        if !sig_rest.is_empty() {
            return Err(alloy_rlp::Error::Custom(
                "unexpected trailing native multisig signature fields",
            ));
        }

        *buf = rest;
        Self::try_new(account, config, signatures)
            .map_err(|error| alloy_rlp::Error::Custom(error.as_str()))
    }

    /// Returns the native multisig account address.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// Returns the complete applicable account configuration.
    pub const fn config(&self) -> &MultisigConfig {
        &self.config
    }

    /// Returns encoded owner approvals.
    pub fn signatures(&self) -> &[TempoSignature] {
        &self.signatures
    }

    fn validate_shape(&self) -> Result<(), MultisigSignatureError> {
        self.validate_shape_at_depth(1)
    }

    /// Validates one node in a path where the outer signature is depth 1 and its nested owner is
    /// depth 2.
    fn validate_shape_at_depth(&self, depth: usize) -> Result<(), MultisigSignatureError> {
        if depth > MAX_MULTISIG_NESTING_DEPTH {
            return Err(MultisigSignatureError::NestingDepthExceeded);
        }
        if self.account().is_zero() {
            return Err(MultisigSignatureError::ZeroAccount);
        }
        self.config.validate_for_account(self.account())?;
        if self.config.version == 0 {
            let expected = self.config.derive_account_validated()?;
            let actual = self.account();
            if actual != expected {
                return Err(MultisigSignatureError::InitialAccountMismatch { expected, actual });
            }
        }
        if self.signatures.is_empty() {
            return Err(MultisigSignatureError::EmptySignatures);
        }
        if self.signatures.len() > MAX_MULTISIG_SIGNATURES {
            return Err(MultisigSignatureError::TooManySignatures);
        }
        for signature in &self.signatures {
            match signature {
                TempoSignature::Primitive(signature)
                    if signature.encoded_length() > MAX_MULTISIG_OWNER_SIGNATURE_BYTES =>
                {
                    return Err(MultisigSignatureError::OwnerSignatureTooLarge);
                }
                TempoSignature::Keychain(_) => {
                    return Err(MultisigSignatureError::KeychainOwnerSignature);
                }
                TempoSignature::Multisig(nested) => nested.validate_shape_at_depth(depth + 1)?,
                TempoSignature::Primitive(_) => {}
            }
        }
        Ok(())
    }

    /// Returns the multisig owner-approval digest for this signature.
    pub fn digest(&self, inner_digest: B256) -> B256 {
        multisig_digest(inner_digest, self.account(), self.config.version)
    }

    /// Computes the commitment of the configuration validated at construction or decoding.
    pub fn config_commitment(&self) -> B256 {
        self.config.commitment_validated()
    }

    /// Returns a heuristic for the in-memory size of the signature.
    pub fn size(&self) -> usize {
        size_of::<Self>()
            + self.config.size()
            + self.signatures.capacity() * size_of::<TempoSignature>()
            + self
                .signatures
                .iter()
                .map(TempoSignature::size)
                .sum::<usize>()
    }

    fn rlp_payload_length(&self) -> usize {
        self.account.length() + self.config.length() + self.signatures.length()
    }
}

#[cfg(feature = "serde")]
impl Serialize for MultisigSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut encoded = Vec::with_capacity(self.length());
        self.encode(&mut encoded);
        Bytes::from(encoded).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for MultisigSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Bytes::deserialize(deserializer)?;
        Self::decode_exact(&encoded).map_err(D::Error::custom)
    }
}

impl alloy_rlp::Decodable for MultisigSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::decode_with_depth(buf, 1)
    }
}

impl alloy_rlp::Encodable for MultisigSignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let payload_length = self.rlp_payload_length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);
        self.account.encode(out);
        self.config.encode(out);
        self.signatures.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_payload_length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .length()
            + payload_length
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for MultisigSignature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(1..=MAX_MULTISIG_SIGNATURES)?;
        let mut signatures = Vec::new();
        for _ in 0..len {
            signatures.push(TempoSignature::Primitive(u.arbitrary()?));
        }

        let mut owner = Address::arbitrary(u)?;
        if owner.is_zero() {
            owner = Address::repeat_byte(1);
        }
        let config = MultisigConfig {
            salt: u.arbitrary()?,
            version: 0,
            threshold: 1,
            owners: vec![MultisigOwner { owner, weight: 1 }],
        };
        let account = config
            .derive_account()
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;

        Self::try_new(account, config, signatures).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

/// Native multisig config validation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MultisigConfigError {
    /// The owner list is empty.
    EmptyOwners,
    /// The owner list exceeds [`MAX_MULTISIG_OWNERS`].
    TooManyOwners,
    /// The threshold is zero.
    ZeroThreshold,
    /// An owner address is zero.
    ZeroOwner,
    /// An owner weight is zero.
    ZeroWeight,
    /// The owner list contains a duplicate owner.
    DuplicateOwner,
    /// The owner list is not strictly ascending.
    OwnersNotAscending,
    /// Total owner weight exceeds `u8::MAX`.
    TotalWeightExceedsMax,
    /// The threshold exceeds the weight reachable within the approval limit.
    ThresholdExceedsWeight,
    /// The derived multisig account address is zero.
    DerivedAccountZero,
    /// The multisig account is included in its own owner set.
    AccountIsOwner,
}

impl MultisigConfigError {
    /// Returns the stable validation message for this error.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyOwners => "multisig owners cannot be empty",
            Self::TooManyOwners => "too many multisig owners",
            Self::ZeroThreshold => "multisig threshold cannot be zero",
            Self::ZeroOwner => "multisig owner cannot be zero",
            Self::ZeroWeight => "multisig owner weight cannot be zero",
            Self::DuplicateOwner => "multisig owners cannot contain duplicates",
            Self::OwnersNotAscending => "multisig owners must be strictly ascending",
            Self::TotalWeightExceedsMax => "multisig total owner weight exceeds u8::MAX",
            Self::ThresholdExceedsWeight => {
                "multisig threshold cannot be reached within the owner approval limit"
            }
            Self::DerivedAccountZero => "multisig account cannot be zero",
            Self::AccountIsOwner => "multisig account cannot own itself",
        }
    }
}

impl core::fmt::Display for MultisigConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Native multisig signature construction and shape validation error.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MultisigSignatureError {
    /// The supplied config is invalid.
    InvalidConfig(MultisigConfigError),
    /// The claimed account does not match its initial config.
    InitialAccountMismatch {
        /// Account derived from the initial config.
        expected: Address,
        /// Account claimed by the signature.
        actual: Address,
    },
    /// The signature exceeds [`MAX_MULTISIG_NESTING_DEPTH`].
    NestingDepthExceeded,
    /// The claimed multisig account is zero.
    ZeroAccount,
    /// The owner approval list is empty.
    EmptySignatures,
    /// The owner approval list exceeds [`MAX_MULTISIG_SIGNATURES`].
    TooManySignatures,
    /// An encoded primitive owner approval exceeds [`MAX_MULTISIG_OWNER_SIGNATURE_BYTES`].
    OwnerSignatureTooLarge,
    /// A keychain signature was supplied as an owner approval.
    KeychainOwnerSignature,
}

impl MultisigSignatureError {
    /// Returns the stable validation message for this error.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig(error) => error.as_str(),
            Self::InitialAccountMismatch { .. } => {
                "initial multisig config does not derive account"
            }
            Self::NestingDepthExceeded => "native multisig nesting depth exceeded",
            Self::ZeroAccount => "multisig account cannot be zero",
            Self::EmptySignatures => "multisig signatures cannot be empty",
            Self::TooManySignatures => "too many multisig signatures",
            Self::OwnerSignatureTooLarge => "multisig owner signature too large",
            Self::KeychainOwnerSignature => {
                "keychain signatures cannot authorize native multisig owners"
            }
        }
    }
}

impl core::fmt::Display for MultisigSignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InitialAccountMismatch { expected, actual } => {
                write!(
                    f,
                    "initial multisig account mismatch: expected {expected}, actual {actual}"
                )
            }
            _ => f.write_str(self.as_str()),
        }
    }
}

impl From<MultisigConfigError> for MultisigSignatureError {
    fn from(error: MultisigConfigError) -> Self {
        Self::InvalidConfig(error)
    }
}

/// Native multisig quorum validation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MultisigQuorumError {
    /// The configured threshold is zero.
    ZeroThreshold,
    /// The signature list is empty.
    EmptySignatures,
    /// The signature list exceeds [`MAX_MULTISIG_SIGNATURES`].
    TooManySignatures,
    /// The signature list has entries after quorum is reached.
    ExcessSignatures,
    /// A recovered signer is not a configured owner.
    SignerNotOwner,
    /// Recovered signers are not strictly ascending.
    SignersNotAscending,
    /// Recovered signer weight does not meet the threshold.
    WeightBelowThreshold,
}

impl MultisigQuorumError {
    /// Returns the stable validation message for this error.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroThreshold => "multisig threshold cannot be zero",
            Self::EmptySignatures => "multisig signatures cannot be empty",
            Self::TooManySignatures => "too many multisig signatures",
            Self::ExcessSignatures => "excess multisig owner signatures",
            Self::SignerNotOwner => "multisig signer is not an owner",
            Self::SignersNotAscending => "multisig recovered owners must be strictly ascending",
            Self::WeightBelowThreshold => "multisig signature weight below threshold",
        }
    }
}

impl core::fmt::Display for MultisigQuorumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Accumulates recovered native multisig owner weights while enforcing owner ordering.
pub struct MultisigWeightAccumulator {
    threshold: u8,
    prev_owner: Option<Address>,
    recovered_weight: u16,
    signer_count: usize,
}

impl MultisigWeightAccumulator {
    /// Creates a new accumulator for a native multisig threshold.
    pub const fn new(threshold: u8) -> Result<Self, MultisigQuorumError> {
        if threshold == 0 {
            return Err(MultisigQuorumError::ZeroThreshold);
        }
        Ok(Self {
            threshold,
            prev_owner: None,
            recovered_weight: 0,
            signer_count: 0,
        })
    }

    /// Records one recovered owner address and its configured weight.
    pub fn record_owner(&mut self, owner: Address, weight: u8) -> Result<(), MultisigQuorumError> {
        self.signer_count = self
            .signer_count
            .checked_add(1)
            .ok_or(MultisigQuorumError::TooManySignatures)?;
        if self.signer_count > MAX_MULTISIG_SIGNATURES {
            return Err(MultisigQuorumError::TooManySignatures);
        }

        if self.prev_owner.is_some_and(|prev| prev >= owner) {
            return Err(MultisigQuorumError::SignersNotAscending);
        }
        self.prev_owner = Some(owner);

        self.recovered_weight += u16::from(weight);
        Ok(())
    }

    /// Returns whether the accumulated weight satisfies the configured threshold.
    pub fn has_quorum(&self) -> bool {
        self.signer_count > 0 && self.recovered_weight >= u16::from(self.threshold)
    }

    /// Enforces that at least one signer reached the configured threshold.
    pub fn finish(self) -> Result<(), MultisigQuorumError> {
        if self.signer_count == 0 {
            return Err(MultisigQuorumError::EmptySignatures);
        }
        if self.recovered_weight < u16::from(self.threshold) {
            return Err(MultisigQuorumError::WeightBelowThreshold);
        }
        Ok(())
    }
}

/// Returns the canonical native multisig account for a precomputed account salt.
pub fn multisig_account_address(account_salt: B256) -> Address {
    MULTISIG_RECOVERY_FACTORY.create2(account_salt, MULTISIG_RECOVERY_WALLET_INIT_CODE_HASH)
}

/// Computes the digest that native multisig owners approve.
///
/// This free function is also used while constructing a signature, before a [`MultisigSignature`]
/// exists; [`MultisigSignature::digest`] supplies the account and version from an existing value.
pub fn multisig_digest(inner_digest: B256, account: Address, config_version: u64) -> B256 {
    let mut input = [0u8; MULTISIG_SIGNATURE_DOMAIN.len() + 32 + 20 + 8];
    let mut offset = 0;
    input[offset..offset + MULTISIG_SIGNATURE_DOMAIN.len()]
        .copy_from_slice(MULTISIG_SIGNATURE_DOMAIN);
    offset += MULTISIG_SIGNATURE_DOMAIN.len();
    input[offset..offset + 32].copy_from_slice(inner_digest.as_slice());
    offset += 32;
    input[offset..offset + 20].copy_from_slice(account.as_slice());
    offset += 20;
    input[offset..].copy_from_slice(&config_version.to_be_bytes());
    keccak256(input)
}

#[cfg(test)]
mod tests;
