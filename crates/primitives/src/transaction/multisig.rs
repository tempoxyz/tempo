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

/// Returns the canonical native multisig account for a precomputed account salt.
pub fn multisig_account_address(account_salt: B256) -> Address {
    MULTISIG_RECOVERY_FACTORY.create2(account_salt, MULTISIG_RECOVERY_WALLET_INIT_CODE_HASH)
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
    InitialAccountMismatch,
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
            Self::InitialAccountMismatch => "initial multisig config does not derive account",
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
        f.write_str(self.as_str())
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
        if self.config.version == 0 && self.config.derive_account_validated()? != self.account() {
            return Err(MultisigSignatureError::InitialAccountMismatch);
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

impl MultisigSignature {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{
        KeychainSignature, PrimitiveSignature, TempoSignature, derive_p256_address,
        tt_authorization::tests::{generate_secp256k1_keypair, sign_hash},
        tt_signature::{P256SignatureWithPreHash, WebAuthnSignature, normalize_p256_s},
    };
    use alloy_rlp::{Decodable, Encodable};
    use p256::{
        ecdsa::{SigningKey as P256SigningKey, signature::hazmat::PrehashSigner},
        elliptic_curve::rand_core::OsRng,
    };
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    fn sorted_secp_config(owners: &[(Address, u8)], threshold: u8) -> MultisigConfig {
        let mut owners = owners
            .iter()
            .map(|(owner, weight)| MultisigOwner {
                owner: *owner,
                weight: *weight,
            })
            .collect::<Vec<_>>();
        owners.sort_by_key(|owner| owner.owner);
        MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold,
            owners,
        }
    }

    fn indexed_owner(index: u16) -> Address {
        let mut bytes = [0u8; 20];
        bytes[18..].copy_from_slice(&index.to_be_bytes());
        Address::from(bytes)
    }

    fn valid_owner_signature_bytes() -> Bytes {
        valid_owner_signature().to_bytes()
    }

    fn valid_owner_signature() -> TempoSignature {
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        ))
    }

    fn initial_multisig_signature() -> MultisigSignature {
        let config = sorted_secp_config(&[(indexed_owner(2), 1)], 1);
        MultisigSignature::try_new(
            config.derive_account().unwrap(),
            config,
            vec![TempoSignature::Primitive(PrimitiveSignature::default())],
        )
        .unwrap()
    }

    fn current_config(owner: Address) -> MultisigConfig {
        MultisigConfig {
            salt: B256::ZERO,
            version: 1,
            threshold: 1,
            owners: vec![MultisigOwner { owner, weight: 1 }],
        }
    }

    fn generate_p256_keypair() -> (P256SigningKey, B256, B256, Address) {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let pub_key_x = B256::from_slice(encoded_point.x().unwrap().as_ref());
        let pub_key_y = B256::from_slice(encoded_point.y().unwrap().as_ref());
        let owner = derive_p256_address(&pub_key_x, &pub_key_y);
        (signing_key, pub_key_x, pub_key_y, owner)
    }

    fn sign_p256_owner_approval_with_prehash(
        signing_key: &P256SigningKey,
        digest: B256,
        pub_key_x: B256,
        pub_key_y: B256,
    ) -> Bytes {
        let prehashed = B256::from_slice(Sha256::digest(digest).as_ref());
        let signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(prehashed.as_slice()).unwrap();
        let sig_bytes = signature.to_bytes();
        PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::from_slice(&sig_bytes[..32]),
            s: normalize_p256_s(&sig_bytes[32..64]).expect("p256 crate produces valid s"),
            pub_key_x,
            pub_key_y,
            pre_hash: true,
        })
        .to_bytes()
    }

    fn encoded_multisig(
        account: Address,
        config: &MultisigConfig,
        signatures: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let signatures = signatures.into_iter().map(Bytes::from).collect::<Vec<_>>();
        let payload_length = account.length() + config.length() + signatures.length();
        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(&mut encoded);
        account.encode(&mut encoded);
        config.encode(&mut encoded);
        signatures.encode(&mut encoded);
        encoded
    }

    /// Builds `levels` of nested current-configuration multisig signatures, where the innermost
    /// approval is primitive and each outer level has a single nested multisig owner.
    fn nested_multisig_encoding(levels: usize) -> Vec<u8> {
        let mut current = encoded_multisig(
            indexed_owner(100),
            &current_config(indexed_owner(200)),
            vec![valid_owner_signature_bytes().to_vec()],
        );
        for level in 1..levels {
            let mut owner_approval = vec![SIGNATURE_TYPE_MULTISIG];
            owner_approval.extend_from_slice(&current);
            current = encoded_multisig(
                indexed_owner(100 + level as u16),
                &current_config(indexed_owner(200 + level as u16)),
                vec![owner_approval],
            );
        }
        current
    }

    #[test]
    fn account_derivation_is_stable_and_validates_owner_order() {
        let owner_a = Address::from([0x11; 20]);
        let owner_b = Address::from([0x22; 20]);
        let config = sorted_secp_config(&[(owner_b, 2), (owner_a, 1)], 2);

        config.validate().expect("config is valid");
        assert_eq!(
            config.derive_account().unwrap(),
            config.derive_account().unwrap()
        );

        let unsorted = MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![
                MultisigOwner {
                    owner: owner_b,
                    weight: 1,
                },
                MultisigOwner {
                    owner: owner_a,
                    weight: 1,
                },
            ],
        };
        assert!(unsorted.validate().is_err());
    }

    #[test]
    fn account_derivation_includes_salt() {
        let owner = Address::from([0x11; 20]);
        let zero_salt = sorted_secp_config(&[(owner, 1)], 1);
        let mut nonzero_salt = zero_salt.clone();
        nonzero_salt.salt = B256::repeat_byte(0x42);

        assert_ne!(
            zero_salt.derive_account().unwrap(),
            nonzero_salt.derive_account().unwrap()
        );
        zero_salt.validate().expect("zero salt is valid");
    }

    #[test]
    fn recovery_factory_matches_singleton_create2_vector() {
        let factory = MULTISIG_RECOVERY_SINGLETON_FACTORY
            .create2(B256::ZERO, MULTISIG_RECOVERY_FACTORY_INIT_CODE_HASH);
        assert_eq!(factory, MULTISIG_RECOVERY_FACTORY);
    }

    #[test]
    fn multisig_domains_match_spec_vectors() {
        let mut config = sorted_secp_config(&[(Address::repeat_byte(0x11), 1)], 1);
        let account_salt = config.account_salt().unwrap();
        let account = config.derive_account().unwrap();

        assert_eq!(
            account_salt,
            alloy_primitives::b256!(
                "7162e370e58784e6b33d61878820d1497eeaf4f68e00b2cfc00a2f3b1dbb00da"
            )
        );
        assert_eq!(
            account,
            alloy_primitives::address!("91847576f406d0842ad7c1a0c97c22a122e64278")
        );
        assert_eq!(multisig_account_address(account_salt), account);
        assert_eq!(
            multisig_digest(B256::repeat_byte(0x42), account, 0),
            alloy_primitives::b256!(
                "7a62ef46efdf76a6a0ab6c38c5fdeda2169d6a0de3643bb9912a4fbce881a870"
            )
        );

        let initial_commitment = config.commitment().unwrap();
        config.version = 1;
        assert_ne!(config.commitment().unwrap(), initial_commitment);
    }

    #[test]
    fn config_accepts_max_owners() {
        let owners = (1..=MAX_MULTISIG_OWNERS as u16)
            .map(|index| (indexed_owner(index), 1))
            .collect::<Vec<_>>();
        let config = sorted_secp_config(&owners, MAX_MULTISIG_SIGNATURES as u8);

        assert_eq!(config.validate(), Ok(MAX_MULTISIG_OWNERS as u8));
        assert!(config.derive_account().is_ok());
    }

    #[test]
    fn config_rejects_more_than_max_owners() {
        let owners = (1..=MAX_MULTISIG_OWNERS as u16 + 1)
            .map(|index| (indexed_owner(index), 1))
            .collect::<Vec<_>>();
        let config = sorted_secp_config(&owners, 1);

        assert_eq!(config.validate(), Err(MultisigConfigError::TooManyOwners));
    }

    #[test]
    fn config_total_weight_is_capped_at_u8_max() {
        let owner_a = Address::from([0x11; 20]);
        let owner_b = Address::from([0x22; 20]);
        let config = sorted_secp_config(&[(owner_a, 128), (owner_b, 128)], 1);

        assert_eq!(
            config.validate(),
            Err(MultisigConfigError::TotalWeightExceedsMax)
        );
    }

    #[test]
    fn config_accepts_threshold_above_signature_cap() {
        let owner = Address::from([0x11; 20]);
        let threshold = MAX_MULTISIG_THRESHOLD;
        let config = sorted_secp_config(&[(owner, threshold)], threshold);

        assert_eq!(config.validate(), Ok(threshold));
    }

    #[test]
    fn config_rejects_threshold_requiring_too_many_approvals() {
        let owners = (1..=MAX_MULTISIG_SIGNATURES as u16 + 1)
            .map(|index| (indexed_owner(index), 1))
            .collect::<Vec<_>>();
        let config = sorted_secp_config(&owners, owners.len() as u8);

        assert_eq!(
            config.validate(),
            Err(MultisigConfigError::ThresholdExceedsWeight)
        );
    }

    #[test]
    fn config_rejects_own_account_as_owner() {
        let account = indexed_owner(1);
        let config = sorted_secp_config(&[(account, 1)], 1);

        assert_eq!(
            config.validate_for_account(account),
            Err(MultisigConfigError::AccountIsOwner)
        );

        let config = sorted_secp_config(&[(account, 0)], 1);
        assert_eq!(
            config.validate_for_account(account),
            Err(MultisigConfigError::AccountIsOwner)
        );
    }

    #[test]
    fn multisig_shape_rejects_keychain_owner_approval() {
        let account = indexed_owner(1);
        let approval = TempoSignature::Keychain(KeychainSignature::new(
            indexed_owner(2),
            PrimitiveSignature::default(),
        ));

        assert_eq!(
            MultisigSignature::try_new(account, current_config(indexed_owner(2)), vec![approval],),
            Err(MultisigSignatureError::KeychainOwnerSignature)
        );
    }

    #[test]
    fn multisig_shape_allows_nested_initial_approval() {
        let nested = initial_multisig_signature();
        let account = indexed_owner(1);
        assert!(
            MultisigSignature::try_new(
                account,
                current_config(nested.account()),
                vec![TempoSignature::Multisig(nested)],
            )
            .is_ok()
        );
    }

    #[test]
    fn multisig_shape_rejects_programmatic_excess_nesting() {
        let leaf = MultisigSignature::try_new(
            indexed_owner(3),
            current_config(indexed_owner(4)),
            vec![TempoSignature::Primitive(PrimitiveSignature::default())],
        )
        .unwrap();
        let middle = MultisigSignature::try_new(
            indexed_owner(2),
            current_config(indexed_owner(3)),
            vec![TempoSignature::Multisig(leaf)],
        )
        .unwrap();

        assert_eq!(
            MultisigSignature::try_new(
                indexed_owner(1),
                current_config(indexed_owner(2)),
                vec![TempoSignature::Multisig(middle)],
            ),
            Err(MultisigSignatureError::NestingDepthExceeded)
        );
    }

    #[test]
    fn shared_quorum_helpers_verify_order_and_threshold() {
        let owner_a = indexed_owner(1);
        let owner_b = indexed_owner(2);
        let owner_c = indexed_owner(3);
        let config = sorted_secp_config(&[(owner_a, 1), (owner_b, 3), (owner_c, 2)], 4);

        // Reproduce the weight-accounting the native multisig verifier performs: look up each
        // recovered owner's configured weight and feed it to the shared accumulator in order.
        let ordered_weights = |owners: &[Address]| -> Result<(), MultisigQuorumError> {
            let mut accumulator = MultisigWeightAccumulator::new(config.threshold)?;
            for &owner in owners {
                let weight = config
                    .owner_weight(owner)
                    .ok_or(MultisigQuorumError::SignerNotOwner)?;
                accumulator.record_owner(owner, weight)?;
            }
            accumulator.finish()
        };

        assert_eq!(ordered_weights(&[owner_a, owner_b]), Ok(()));
        assert_eq!(
            ordered_weights(&[owner_b]),
            Err(MultisigQuorumError::WeightBelowThreshold)
        );
        assert_eq!(
            ordered_weights(&[owner_b, owner_a]),
            Err(MultisigQuorumError::SignersNotAscending)
        );
        assert_eq!(
            ordered_weights(&[indexed_owner(4)]),
            Err(MultisigQuorumError::SignerNotOwner)
        );

        assert_eq!(
            MultisigWeightAccumulator::new(0).err(),
            Some(MultisigQuorumError::ZeroThreshold)
        );
    }

    #[test]
    fn owner_signature_cannot_replay_across_accounts_with_same_owners() {
        let (signer, owner) = generate_secp256k1_keypair();
        let mut config_a = sorted_secp_config(&[(owner, 1)], 1);
        config_a.salt = B256::repeat_byte(0x11);
        let mut config_b = sorted_secp_config(&[(owner, 1)], 1);
        config_b.salt = B256::repeat_byte(0x22);

        let account_a = config_a.derive_account().unwrap();
        let account_b = config_b.derive_account().unwrap();
        assert_ne!(account_a, account_b);

        let inner_digest = B256::repeat_byte(0x42);
        let digest_a = multisig_digest(inner_digest, account_a, 0);
        let digest_b = multisig_digest(inner_digest, account_b, 0);
        assert_ne!(digest_a, digest_b, "digest is domain-separated by account");

        // An owner approval recovers the owner only against the account it was signed for; replaying
        // it against another account's digest recovers a different address that is not an owner.
        let signature = sign_hash(&signer, &digest_a);
        assert_eq!(signature.recover_signer(&digest_a).unwrap(), owner);
        assert_ne!(signature.recover_signer(&digest_b).unwrap(), owner);
    }

    #[test]
    fn owner_signature_cannot_replay_across_config_versions() {
        let (signer, owner) = generate_secp256k1_keypair();
        let config = sorted_secp_config(&[(owner, 1)], 1);
        let account = config.derive_account().unwrap();
        let inner_digest = B256::repeat_byte(0x42);
        let initial_digest = multisig_digest(inner_digest, account, 0);
        let rotated_digest = multisig_digest(inner_digest, account, 1);

        assert_ne!(initial_digest, rotated_digest);
        let signature = sign_hash(&signer, &initial_digest);
        assert_eq!(signature.recover_signer(&initial_digest).unwrap(), owner);
        assert_ne!(signature.recover_signer(&rotated_digest).unwrap(), owner);
    }

    #[test]
    fn verifies_weighted_owner_signatures_in_sorted_order() {
        let (signer_a, owner_a) = generate_secp256k1_keypair();
        let (signer_b, owner_b) = generate_secp256k1_keypair();
        let config = sorted_secp_config(&[(owner_a, 1), (owner_b, 1)], 2);
        let account = config.derive_account().unwrap();
        let digest = multisig_digest(B256::repeat_byte(0x42), account, 0);

        let mut signed = [
            (owner_a, sign_hash(&signer_a, &digest)),
            (owner_b, sign_hash(&signer_b, &digest)),
        ];
        signed.sort_by_key(|(owner, _)| *owner);

        // Feed the recovered owners through the shared accumulator, as the verifier does.
        let quorum_weight = |approvals: &[&TempoSignature]| -> Result<(), MultisigQuorumError> {
            let mut accumulator = MultisigWeightAccumulator::new(config.threshold)?;
            for approval in approvals {
                let owner = approval.recover_signer(&digest).unwrap();
                let weight = config
                    .owner_weight(owner)
                    .ok_or(MultisigQuorumError::SignerNotOwner)?;
                accumulator.record_owner(owner, weight)?;
            }
            accumulator.finish()
        };

        let both = [&signed[0].1, &signed[1].1];
        assert_eq!(quorum_weight(&both), Ok(()));

        // A single owner falls short of the threshold of 2.
        assert!(quorum_weight(&[&signed[0].1]).is_err());
    }

    #[test]
    fn noncanonical_p256_owner_prehash_flag_canonicalizes() {
        // A P256 owner approval carrying a noncanonical pre_hash flag byte decodes to the same
        // signature and re-encodes with the canonical flag, so it cannot malleate the transaction
        // hash even though the raw wire byte differs. This structural canonicalization replaces the
        // (STF-breaking) strict-flag rejection that was previously attempted at decode time.
        let (signer, pub_key_x, pub_key_y, owner) = generate_p256_keypair();
        let config = sorted_secp_config(&[(owner, 1)], 1);
        let account = config.derive_account().unwrap();
        let digest = multisig_digest(B256::repeat_byte(0x42), account, 0);

        let canonical_signature =
            sign_p256_owner_approval_with_prehash(&signer, digest, pub_key_x, pub_key_y);
        assert_eq!(
            canonical_signature[canonical_signature.len() - 1],
            1,
            "test setup should use canonical pre_hash=true encoding"
        );

        let mut noncanonical_signature = canonical_signature.to_vec();
        let flag_index = noncanonical_signature.len() - 1;
        noncanonical_signature[flag_index] = 2;

        let decoded = TempoSignature::from_bytes(&noncanonical_signature)
            .expect("noncanonical pre_hash flag decodes leniently");
        assert_eq!(
            decoded.to_bytes(),
            canonical_signature,
            "noncanonical owner approval re-encodes to the canonical signature bytes"
        );
    }

    #[test]
    fn multisig_signature_encodes_complete_config() {
        let config = current_config(indexed_owner(2));
        let account = Address::repeat_byte(0x11);
        let signatures = [valid_owner_signature_bytes()];
        let signature =
            MultisigSignature::try_new(account, config.clone(), vec![valid_owner_signature()])
                .unwrap();

        let mut encoded = Vec::new();
        signature.encode(&mut encoded);
        assert_eq!(
            encoded,
            encoded_multisig(
                account,
                &config,
                signatures
                    .iter()
                    .map(|signature| signature.to_vec())
                    .collect(),
            )
        );

        let mut input = encoded.as_slice();
        let decoded = MultisigSignature::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, signature);
    }

    #[test]
    fn multisig_signature_rejects_initial_account_mismatch() {
        let owner = Address::from([0x11; 20]);
        let config = sorted_secp_config(&[(owner, 1)], 1);
        let wrong_account = Address::repeat_byte(0x99);

        let signature =
            MultisigSignature::try_new(wrong_account, config, vec![valid_owner_signature()]);

        assert_eq!(
            signature,
            Err(MultisigSignatureError::InitialAccountMismatch)
        );
    }

    #[test]
    fn tempo_signature_decode_bounds_multisig_nesting() {
        // Nesting up to MAX_MULTISIG_NESTING_DEPTH decodes structurally.
        let mut ok = vec![SIGNATURE_TYPE_MULTISIG];
        ok.extend(nested_multisig_encoding(MAX_MULTISIG_NESTING_DEPTH));
        assert!(
            TempoSignature::from_bytes(&ok).is_ok(),
            "nesting within the depth bound must decode"
        );

        // One level deeper exceeds the bound and is rejected at decode time.
        let mut too_deep = vec![SIGNATURE_TYPE_MULTISIG];
        too_deep.extend(nested_multisig_encoding(MAX_MULTISIG_NESTING_DEPTH + 1));
        assert!(
            TempoSignature::from_bytes(&too_deep).is_err(),
            "nesting past the depth bound must be rejected"
        );

        // A pathologically deep payload is rejected quickly instead of recursing into a stack
        // overflow during decoding.
        let mut pathological = vec![SIGNATURE_TYPE_MULTISIG];
        pathological.extend(nested_multisig_encoding(4096));
        assert!(TempoSignature::from_bytes(&pathological).is_err());
    }

    #[test]
    fn multisig_signature_decode_rejects_invalid_config() {
        let invalid_config = MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 0,
            owners: Vec::new(),
        };
        let encoded = encoded_multisig(
            Address::repeat_byte(0x11),
            &invalid_config,
            vec![valid_owner_signature_bytes().to_vec()],
        );

        let mut input = encoded.as_slice();
        assert!(
            MultisigSignature::decode(&mut input).is_err(),
            "decode must reject a semantically invalid config"
        );

        // The same payload reaches the decoder through the 0x05-prefixed signature form.
        let mut tempo_encoded = vec![SIGNATURE_TYPE_MULTISIG];
        tempo_encoded.extend(encoded);
        assert!(TempoSignature::from_bytes(&tempo_encoded).is_err());
    }

    #[test]
    fn multisig_config_decode_bounds_owner_count() {
        let config = MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: MAX_MULTISIG_THRESHOLD,
            owners: (1..=MAX_MULTISIG_OWNERS as u16 + 1)
                .map(|index| MultisigOwner {
                    owner: Address::from_word(B256::from(alloy_primitives::U256::from(index))),
                    weight: 1,
                })
                .collect(),
        };
        let mut encoded = Vec::new();
        config.encode(&mut encoded);

        let mut input = encoded.as_slice();
        assert!(matches!(
            MultisigConfig::decode(&mut input),
            Err(alloy_rlp::Error::Custom("too many multisig owners"))
        ));
    }

    #[test]
    fn multisig_signature_decode_bounds_approval_count() {
        let encoded = encoded_multisig(
            Address::repeat_byte(0x11),
            &current_config(indexed_owner(2)),
            vec![valid_owner_signature_bytes().to_vec(); MAX_MULTISIG_SIGNATURES + 1],
        );

        let mut input = encoded.as_slice();
        assert!(matches!(
            MultisigSignature::decode(&mut input),
            Err(alloy_rlp::Error::Custom("too many multisig signatures"))
        ));
    }

    #[test]
    fn multisig_signature_shape_rejects_oversized_owner_signature() {
        let signature = MultisigSignature::try_new(
            Address::repeat_byte(0x11),
            current_config(indexed_owner(2)),
            vec![TempoSignature::Primitive(PrimitiveSignature::WebAuthn(
                WebAuthnSignature {
                    webauthn_data: Bytes::from(vec![0; MAX_WEBAUTHN_SIGNATURE_LENGTH + 1]),
                    r: B256::ZERO,
                    s: B256::ZERO,
                    pub_key_x: B256::ZERO,
                    pub_key_y: B256::ZERO,
                },
            ))],
        );

        assert_eq!(
            signature,
            Err(MultisigSignatureError::OwnerSignatureTooLarge)
        );
    }

    #[test]
    fn multisig_signature_shape_allows_nested_signature_above_primitive_byte_cap() {
        let primitive = PrimitiveSignature::WebAuthn(WebAuthnSignature {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: B256::ZERO,
            pub_key_y: B256::ZERO,
            webauthn_data: Bytes::from(vec![0; MAX_WEBAUTHN_SIGNATURE_LENGTH - 128]),
        });
        let nested = TempoSignature::Multisig(
            MultisigSignature::try_new(
                Address::repeat_byte(0x22),
                current_config(indexed_owner(3)),
                vec![
                    TempoSignature::Primitive(primitive.clone()),
                    TempoSignature::Primitive(primitive),
                ],
            )
            .unwrap(),
        );
        assert!(nested.encoded_length() > MAX_MULTISIG_OWNER_SIGNATURE_BYTES);

        let signature = MultisigSignature::try_new(
            Address::repeat_byte(0x11),
            current_config(Address::repeat_byte(0x22)),
            vec![nested],
        );

        assert!(signature.is_ok());
    }

    #[test]
    fn multisig_signature_decode_rejects_oversized_owner_signature() {
        let encoded = encoded_multisig(
            Address::repeat_byte(0x11),
            &current_config(indexed_owner(2)),
            vec![vec![0xaa; MAX_MULTISIG_OWNER_SIGNATURE_BYTES + 1]],
        );
        let mut input = encoded.as_slice();

        assert!(
            MultisigSignature::decode(&mut input).is_err(),
            "RLP decode should reject oversized owner approval bytes"
        );
    }

    #[test]
    fn tempo_signature_decode_rejects_oversized_multisig_owner_signature() {
        let mut encoded = vec![SIGNATURE_TYPE_MULTISIG];
        encoded.extend(encoded_multisig(
            Address::repeat_byte(0x11),
            &current_config(indexed_owner(2)),
            vec![vec![0xaa; MAX_MULTISIG_OWNER_SIGNATURE_BYTES + 1]],
        ));

        assert!(
            TempoSignature::from_bytes(&encoded).is_err(),
            "TempoSignature decode should reject multisig payloads with oversized owner approvals"
        );
    }

    #[test]
    fn multisig_signature_roundtrips_through_tempo_signature_bytes() {
        let (signer, owner) = generate_secp256k1_keypair();
        let config = sorted_secp_config(&[(owner, 1)], 1);
        let account = config.derive_account().unwrap();
        let signature_hash = B256::ZERO;
        let digest = multisig_digest(signature_hash, account, 0);
        let signature =
            MultisigSignature::try_new(account, config, vec![sign_hash(&signer, &digest)]).unwrap();
        let tempo_signature = TempoSignature::Multisig(signature.clone());

        let encoded = tempo_signature.to_bytes();
        assert_eq!(encoded[0], SIGNATURE_TYPE_MULTISIG);
        let decoded = TempoSignature::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.as_multisig(), Some(&signature));
        assert_eq!(
            decoded.recover_signer(&signature_hash).unwrap(),
            signature.account()
        );
    }

    #[test]
    fn multisig_signature_roundtrips_init_config() {
        let (signer, owner) = generate_secp256k1_keypair();
        let mut config = sorted_secp_config(&[(owner, 1)], 1);
        config.salt = B256::repeat_byte(0x33);
        let account = config.derive_account().unwrap();
        let signature_hash = B256::ZERO;
        let digest = multisig_digest(signature_hash, account, 0);
        let signatures = vec![sign_hash(&signer, &digest)];
        let signature =
            MultisigSignature::try_new(account, config.clone(), signatures.clone()).unwrap();
        let tempo_signature = TempoSignature::Multisig(signature.clone());

        let encoded = tempo_signature.to_bytes();
        assert_eq!(
            &encoded[1..],
            encoded_multisig(
                account,
                &config,
                signatures
                    .iter()
                    .map(|signature| signature.to_bytes().to_vec())
                    .collect(),
            )
        );
        let decoded = TempoSignature::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.as_multisig(), Some(&signature));
        assert_eq!(
            decoded.recover_signer(&signature_hash).unwrap(),
            signature.account()
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn multisig_signature_serde_roundtrips_rlp_bytes() {
        let (signer, owner) = generate_secp256k1_keypair();
        let config = sorted_secp_config(&[(owner, 1)], 1);
        let account = config.derive_account().unwrap();
        let digest = multisig_digest(B256::ZERO, account, 0);
        let owner_signature = sign_hash(&signer, &digest);
        let signatures = vec![owner_signature];

        let signature = MultisigSignature::try_new(account, config, signatures).unwrap();
        let mut encoded = Vec::with_capacity(signature.length());
        signature.encode(&mut encoded);
        let json = serde_json::to_value(&signature).unwrap();
        assert_eq!(
            json,
            serde_json::to_value(Bytes::from(encoded.clone())).unwrap()
        );
        assert_eq!(
            serde_json::from_value::<MultisigSignature>(json.clone()).unwrap(),
            signature
        );
        assert_eq!(
            serde_json::from_value::<TempoSignature>(json).unwrap(),
            TempoSignature::Multisig(signature)
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn multisig_signature_json_bytes_bound_nesting_during_deserialization() {
        let json = serde_json::to_value(Bytes::from(nested_multisig_encoding(4_096))).unwrap();
        assert!(serde_json::from_value::<TempoSignature>(json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn multisig_signature_json_bytes_reject_excess_approvals() {
        let json = serde_json::to_value(Bytes::from(encoded_multisig(
            indexed_owner(1),
            &current_config(indexed_owner(2)),
            vec![valid_owner_signature_bytes().to_vec(); MAX_MULTISIG_SIGNATURES + 1],
        )))
        .unwrap();

        assert!(serde_json::from_value::<TempoSignature>(json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn multisig_signature_json_rejects_structured_form() {
        let json = serde_json::json!({
            "account": Address::repeat_byte(0x11),
            "signatures": [],
        });
        let error = serde_json::from_value::<TempoSignature>(json)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("did not match any variant") || error.contains("missing field"),
            "unexpected error: {error}"
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn binary_multisig_deserializer_roundtrips_bytes() {
        let primitive =
            PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature());
        let signature = TempoSignature::Multisig(
            MultisigSignature::try_new(
                indexed_owner(2),
                current_config(indexed_owner(3)),
                vec![TempoSignature::Primitive(primitive)],
            )
            .unwrap(),
        );
        let signature = signature.as_multisig().unwrap();

        let mut encoded = Vec::new();
        signature.encode(&mut encoded);
        let decoded =
            MultisigSignature::deserialize(serde::de::value::BorrowedBytesDeserializer::<
                serde::de::value::Error,
            >::new(&encoded))
            .unwrap();

        assert_eq!(&decoded, signature);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn binary_multisig_deserializer_bounds_shape_before_typed_recursion() {
        fn decode(bytes: &[u8]) -> Result<MultisigSignature, serde::de::value::Error> {
            MultisigSignature::deserialize(serde::de::value::BorrowedBytesDeserializer::new(bytes))
        }

        let excess_approvals = encoded_multisig(
            indexed_owner(1),
            &current_config(indexed_owner(2)),
            vec![valid_owner_signature_bytes().to_vec(); MAX_MULTISIG_SIGNATURES + 1],
        );
        assert!(decode(&excess_approvals).is_err());

        let pathological_nesting = nested_multisig_encoding(4_096);
        assert!(decode(&pathological_nesting).is_err());
    }

    proptest! {
        #[test]
        fn proptest_multisig_signature_decode_encode_canonicalizes_accepted_raw_bytes(
            raw in prop_oneof![
                proptest::collection::vec(any::<u8>(), 0..256),
                (
                    any::<Address>(),
                    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..128), 0..=MAX_MULTISIG_SIGNATURES),
                ).prop_map(|(account, signatures)| {
                    encoded_multisig(account, &current_config(indexed_owner(2)), signatures)
                }),
            ],
        ) {
            let mut input = raw.as_slice();
            if let Ok(decoded) = MultisigSignature::decode(&mut input) {
                prop_assert!(input.is_empty());

                let mut reencoded = Vec::new();
                decoded.encode(&mut reencoded);

                let mut canonical_input = reencoded.as_slice();
                let canonical_decoded = MultisigSignature::decode(&mut canonical_input).unwrap();
                prop_assert!(canonical_input.is_empty());
                prop_assert_eq!(&canonical_decoded, &decoded);

                let mut canonical_reencoded = Vec::new();
                canonical_decoded.encode(&mut canonical_reencoded);
                prop_assert_eq!(canonical_reencoded, reencoded);
            }
        }
    }
}
