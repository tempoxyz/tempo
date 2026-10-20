use super::{tempo_transaction::MAX_WEBAUTHN_SIGNATURE_LENGTH, tt_signature::PrimitiveSignature};
use alloc::vec::Vec;
use alloy_primitives::{Address, B256, Keccak256, b256, keccak256};
use alloy_rlp::{Decodable, Error as RlpError};

/// Tempo signature type byte for configurable account signatures.
pub const SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT: u8 = 0x05;

/// Domain prefix for configurable account owner approvals.
pub const CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN: &[u8] = b"tempo:configurable-account:signature";

/// Maximum number of owners allowed in an account config.
pub const MAX_CONFIGURABLE_ACCOUNT_OWNERS: usize = 48;

/// Maximum number of owner approvals allowed in one configurable account signature.
pub const MAX_CONFIGURABLE_ACCOUNT_SIGNATURES: usize = 8;

/// Maximum encoded byte length for one primitive owner approval.
pub const MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES: usize = 1 + MAX_WEBAUTHN_SIGNATURE_LENGTH;

/// Domain prefix for configurable account CREATE2 salt derivation.
pub const CONFIGURABLE_ACCOUNT_DOMAIN: &[u8] = b"tempo:configurable-account:account";

/// Domain prefix for the salt of an account migrated in place (TIP-1113).
pub const CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN: &[u8] = b"tempo:configurable-account:upgrade";

/// Keccak-256 of the account proxy creation code. The creation code is identical for every
/// account, takes no constructor arguments and embeds the beacon address as a constant.
///
/// Placeholder until the canonical account proxy is final: TIP-1110 leaves the value TBD.
// TODO: replace with the canonical account proxy init-code hash before T14 activation
pub const ACCOUNT_PROXY_INIT_CODE_HASH: B256 =
    b256!("583cc63a2e37f645b43eac911b1a6d6de08b83abdc308c61364edda8cfc3bd37");

/// CREATE2 preimage length: 1-byte `0xff` + 20-byte factory + 32-byte salt +
/// 32-byte init-code hash.
pub const CONFIGURABLE_ACCOUNT_CREATE2_PREIMAGE_LEN: usize = 1 + 20 + 32 + 32;

/// Domain prefix for configurable account configuration commitments.
pub const CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN: &[u8] = b"tempo:configurable-account:config";

/// Configurable account owner entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct ConfigurableAccountOwner {
    /// Address recovered from a primitive signature.
    pub owner: Address,
    /// Nonzero owner weight.
    pub weight: u8,
}

/// Configuration of a configurable account, carried by its signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct ConfigurableAccountConfig {
    /// Caller-chosen salt that establishes the account identity.
    pub salt: B256,
    /// Configuration version. Zero identifies the initial configuration.
    pub version: u64,
    /// Minimum total owner weight required to authorize a transaction.
    pub threshold: u8,
    /// Sorted weighted owner list.
    pub owners: Vec<ConfigurableAccountOwner>,
}

impl ConfigurableAccountConfig {
    /// Validates owner count, ordering, addresses, weights, and threshold reachability, returning
    /// the total owner weight.
    pub fn validate(&self) -> Result<u8, ConfigurableAccountConfigError> {
        self.validate_inner(None)
    }

    /// Performs [`Self::validate`] and rejects initial self-ownership.
    pub fn validate_for_account(
        &self,
        account: Address,
    ) -> Result<u8, ConfigurableAccountConfigError> {
        self.validate_inner(Some(account))
    }

    /// Derives the account using the caller's committed recovery factory address.
    ///
    /// TIP-1110 has not selected the production factory address. No default is supplied here.
    /// Reserved namespace checks belong to the caller's chain context.
    pub fn derive_account(
        &self,
        factory: Address,
    ) -> Result<Address, ConfigurableAccountConfigError> {
        self.validate()?;
        self.derive_account_validated(factory)
    }

    /// Computes the persisted commitment for this configuration.
    pub fn commitment(&self) -> Result<B256, ConfigurableAccountConfigError> {
        self.validate()?;
        Ok(self.commitment_validated())
    }

    /// Returns the configured weight for an owner, if present.
    pub fn owner_weight(&self, owner: Address) -> Option<u8> {
        self.owners
            .binary_search_by_key(&owner, |entry| entry.owner)
            .ok()
            .map(|idx| self.owners[idx].weight)
    }
    /// Byte length of the account-salt preimage: domain, 32-byte salt, 1-byte threshold,
    /// 1-byte owner count, and a 20-byte address plus 1-byte weight per owner.
    pub const fn account_salt_preimage_len(&self) -> usize {
        CONFIGURABLE_ACCOUNT_DOMAIN.len() + 32 + 2 + self.owners.len() * 21
    }

    /// Byte length of the commitment preimage: domain, 32-byte salt, 8-byte version, 1-byte
    /// threshold, 1-byte owner count, and a 20-byte address plus 1-byte weight per owner.
    pub const fn commitment_preimage_len(&self) -> usize {
        CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN.len() + 32 + 8 + 2 + self.owners.len() * 21
    }

    /// Encodes the canonical account-salt preimage.
    ///
    /// This checks that the owner count is encodable; callers must separately validate the config
    /// before relying on the resulting hash.
    pub fn account_salt_preimage(&self) -> Result<Vec<u8>, ConfigurableAccountConfigError> {
        let owner_count = self.encoded_owner_count()?;
        let mut input = Vec::with_capacity(self.account_salt_preimage_len());
        input.extend_from_slice(CONFIGURABLE_ACCOUNT_DOMAIN);
        input.extend_from_slice(self.salt.as_slice());
        self.append_owner_set(&mut input, owner_count);
        Ok(input)
    }

    /// Encodes the canonical configuration-commitment preimage.
    ///
    /// This checks that the owner count is encodable; callers must separately validate the config
    /// before relying on the resulting hash.
    pub fn commitment_preimage(&self) -> Result<Vec<u8>, ConfigurableAccountConfigError> {
        let owner_count = self.encoded_owner_count()?;
        let mut input = Vec::with_capacity(self.commitment_preimage_len());
        input.extend_from_slice(CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN);
        input.extend_from_slice(self.salt.as_slice());
        input.extend_from_slice(&self.version.to_be_bytes());
        self.append_owner_set(&mut input, owner_count);
        Ok(input)
    }

    fn validate_inner(
        &self,
        account: Option<Address>,
    ) -> Result<u8, ConfigurableAccountConfigError> {
        if self.owners.is_empty() {
            return Err(ConfigurableAccountConfigError::EmptyOwners);
        }
        if self.owners.len() > MAX_CONFIGURABLE_ACCOUNT_OWNERS {
            return Err(ConfigurableAccountConfigError::TooManyOwners);
        }
        if self.threshold == 0 {
            return Err(ConfigurableAccountConfigError::ZeroThreshold);
        }
        // TIP-1109 orders errors across the entire owner list, not within each owner.
        for owner in &self.owners {
            if owner.owner.is_zero() {
                return Err(ConfigurableAccountConfigError::ZeroOwner);
            }
            if self.version == 0 && account == Some(owner.owner) {
                return Err(ConfigurableAccountConfigError::AccountIsOwner);
            }
        }
        if self.owners.iter().any(|owner| owner.weight == 0) {
            return Err(ConfigurableAccountConfigError::ZeroWeight);
        }
        if self
            .owners
            .windows(2)
            .any(|pair| pair[0].owner >= pair[1].owner)
        {
            // Only invalid ordering needs this bounded scan for nonadjacent duplicates.
            // Valid sorted configurations retain linear, allocation-free validation.
            if self.owners.iter().enumerate().any(|(index, owner)| {
                self.owners[..index]
                    .iter()
                    .any(|previous| previous.owner == owner.owner)
            }) {
                return Err(ConfigurableAccountConfigError::DuplicateOwner);
            }
            return Err(ConfigurableAccountConfigError::OwnersNotAscending);
        }
        let total_weight = self
            .owners
            .iter()
            .try_fold(0u8, |total, owner| total.checked_add(owner.weight))
            .ok_or(ConfigurableAccountConfigError::TotalWeightExceedsMax)?;
        let mut largest_weights = [0u8; MAX_CONFIGURABLE_ACCOUNT_SIGNATURES];
        for owner in &self.owners {
            if owner.weight > largest_weights[0] {
                largest_weights[0] = owner.weight;
                largest_weights.sort_unstable();
            }
        }
        let reachable_weight: u16 = largest_weights.into_iter().map(u16::from).sum();
        if u16::from(self.threshold) > reachable_weight {
            return Err(ConfigurableAccountConfigError::ThresholdExceedsWeight);
        }

        Ok(total_weight)
    }

    fn account_salt_validated(&self) -> B256 {
        keccak256(
            self.account_salt_preimage()
                .expect("validated account config has an encodable owner count"),
        )
    }

    fn derive_account_validated(
        &self,
        factory: Address,
    ) -> Result<Address, ConfigurableAccountConfigError> {
        let account = configurable_account_address(factory, self.account_salt_validated());
        if account.is_zero() {
            return Err(ConfigurableAccountConfigError::DerivedAccountZero);
        }
        if self.owner_weight(account).is_some() {
            return Err(ConfigurableAccountConfigError::AccountIsOwner);
        }
        Ok(account)
    }

    fn commitment_validated(&self) -> B256 {
        keccak256(
            self.commitment_preimage()
                .expect("validated account config has an encodable owner count"),
        )
    }

    const fn encoded_owner_count(&self) -> Result<u8, ConfigurableAccountConfigError> {
        if self.owners.len() > MAX_CONFIGURABLE_ACCOUNT_OWNERS {
            return Err(ConfigurableAccountConfigError::TooManyOwners);
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
}

/// Configurable account transaction signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable)]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct ConfigurableAccountSignature {
    /// Configurable account authorized by this signature.
    ///
    /// This is explicit because a versioned configuration cannot derive the account's stable
    /// address.
    account: Address,
    /// Complete applicable account configuration.
    config: ConfigurableAccountConfig,
    /// Owner approvals over the configurable account digest.
    ///
    /// Each approval is a primitive signature; recursive authorization is not supported.
    signatures: Vec<PrimitiveSignature>,
}

impl ConfigurableAccountSignature {
    /// Constructs a bounded primitive-owner witness.
    ///
    /// The named account remains untrusted: factory-derived identity or the stored commitment,
    /// account code, and the owner quorum must be checked against state.
    pub fn try_new(
        account: Address,
        config: ConfigurableAccountConfig,
        signatures: Vec<PrimitiveSignature>,
    ) -> Result<Self, ConfigurableAccountSignatureError> {
        let signature = Self {
            account,
            config,
            signatures,
        };
        signature.validate_shape()?;
        Ok(signature)
    }

    /// Returns the configurable account address.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// Returns the complete applicable account configuration.
    pub const fn config(&self) -> &ConfigurableAccountConfig {
        &self.config
    }

    /// Returns encoded owner approvals.
    pub fn signatures(&self) -> &[PrimitiveSignature] {
        &self.signatures
    }

    /// Returns the configurable account owner-approval digest for this signature.
    pub fn digest(&self, inner_digest: B256) -> B256 {
        configurable_account_digest(inner_digest, self.account(), self.config.version)
    }

    /// Computes the commitment of the configuration validated at construction or decoding.
    pub fn config_commitment(&self) -> B256 {
        self.config.commitment_validated()
    }

    fn validate_shape(&self) -> Result<(), ConfigurableAccountSignatureError> {
        if self.account().is_zero() {
            return Err(ConfigurableAccountSignatureError::ZeroAccount);
        }
        self.config.validate_for_account(self.account())?;
        if self.signatures.is_empty() {
            return Err(ConfigurableAccountSignatureError::EmptySignatures);
        }
        if self.signatures.len() > MAX_CONFIGURABLE_ACCOUNT_SIGNATURES {
            return Err(ConfigurableAccountSignatureError::TooManySignatures);
        }
        for signature in &self.signatures {
            if signature.encoded_length() > MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES {
                return Err(ConfigurableAccountSignatureError::OwnerSignatureTooLarge);
            }
        }
        Ok(())
    }

    /// Verifies the owner approvals against this configuration, without checking account state.
    pub fn verify_approvals(
        &self,
        inner_digest: B256,
    ) -> Result<(), ConfigurableAccountQuorumError> {
        let digest = self.digest(inner_digest);
        let mut weight = ConfigurableAccountWeightAccumulator::new(self.config.threshold)?;
        for (approval_index, approval) in self.signatures.iter().enumerate() {
            let owner = approval.recover_signer(&digest).map_err(|_| {
                ConfigurableAccountQuorumError::OwnerSignatureRecoveryFailed { approval_index }
            })?;
            let owner_weight = self
                .config
                .owner_weight(owner)
                .ok_or(ConfigurableAccountQuorumError::SignerNotOwner)?;
            weight.record_owner(owner, owner_weight)?;
            if weight.has_quorum() && approval_index + 1 != self.signatures.len() {
                return Err(ConfigurableAccountQuorumError::ExcessSignatures);
            }
        }
        weight.finish()
    }

    /// Checks the stored commitment or, on first use, derives the named account.
    /// Does not read state, inspect code, or verify owner approvals.
    pub fn validate_account_commitment(
        &self,
        stored: B256,
        factory: Option<Address>,
    ) -> Result<(), ConfigurableAccountStateError> {
        let actual = self.config_commitment();
        if actual.is_zero() || (!stored.is_zero() && stored != actual) {
            return Err(ConfigurableAccountStateError::CommitmentMismatch {
                expected: stored,
                actual,
            });
        }
        if stored.is_zero() {
            if self.config.version != 0 {
                return Err(ConfigurableAccountStateError::UnregisteredVersion {
                    actual: self.config.version,
                });
            }
            let factory = factory.ok_or(ConfigurableAccountStateError::FactoryNotConfigured)?;
            // The config was validated against `account` at construction, which excludes a zero or
            // owner account, so a derived collision with either is reported as a mismatch.
            let expected =
                configurable_account_address(factory, self.config.account_salt_validated());
            if expected != self.account {
                return Err(ConfigurableAccountStateError::InitialAccountMismatch {
                    expected,
                    actual: self.account,
                });
            }
        }
        Ok(())
    }
}

impl Decodable for ConfigurableAccountSignature {
    /// Decodes the signature and checks its configuration and size limits.
    /// Does not verify owner signatures or account state.
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        #[derive(alloy_rlp::RlpDecodable)]
        struct WireSignature {
            account: Address,
            config: ConfigurableAccountConfig,
            signatures: Vec<PrimitiveSignature>,
        }
        let wire = <WireSignature as Decodable>::decode(buf)?;
        Self::try_new(wire.account, wire.config, wire.signatures)
            .map_err(|error| RlpError::Custom(error.as_str()))
    }
}

/// Account config validation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurableAccountConfigError {
    /// The owner list is empty.
    EmptyOwners,
    /// The owner list exceeds [`MAX_CONFIGURABLE_ACCOUNT_OWNERS`].
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
    /// The derived configurable account address is zero.
    DerivedAccountZero,
    /// The configurable account is included in its own owner set.
    AccountIsOwner,
}

impl ConfigurableAccountConfigError {
    /// Returns the stable validation message for this error.
    const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyOwners => "configurable account owners cannot be empty",
            Self::TooManyOwners => "too many configurable account owners",
            Self::ZeroThreshold => "configurable account threshold cannot be zero",
            Self::ZeroOwner => "configurable account owner cannot be zero",
            Self::ZeroWeight => "configurable account owner weight cannot be zero",
            Self::DuplicateOwner => "configurable account owners cannot contain duplicates",
            Self::OwnersNotAscending => "configurable account owners must be strictly ascending",
            Self::TotalWeightExceedsMax => {
                "configurable account total owner weight exceeds u8::MAX"
            }
            Self::ThresholdExceedsWeight => {
                "configurable account threshold cannot be reached within the owner approval limit"
            }
            Self::DerivedAccountZero => "configurable account cannot be zero",
            Self::AccountIsOwner => "configurable account cannot own itself",
        }
    }
}

impl core::fmt::Display for ConfigurableAccountConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configurable account signature construction and shape validation error.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurableAccountSignatureError {
    /// The supplied config is invalid.
    InvalidConfig(ConfigurableAccountConfigError),
    /// The claimed configurable account is zero.
    ZeroAccount,
    /// The owner approval list is empty.
    EmptySignatures,
    /// The owner approval list exceeds [`MAX_CONFIGURABLE_ACCOUNT_SIGNATURES`].
    TooManySignatures,
    /// An encoded primitive owner approval exceeds
    /// [`MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES`].
    OwnerSignatureTooLarge,
}

impl ConfigurableAccountSignatureError {
    /// Returns the stable validation message for this error.
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig(error) => error.as_str(),
            Self::ZeroAccount => "configurable account cannot be zero",
            Self::EmptySignatures => "configurable account signatures cannot be empty",
            Self::TooManySignatures => "too many configurable account signatures",
            Self::OwnerSignatureTooLarge => "configurable account owner signature too large",
        }
    }
}

impl core::fmt::Display for ConfigurableAccountSignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<ConfigurableAccountConfigError> for ConfigurableAccountSignatureError {
    fn from(error: ConfigurableAccountConfigError) -> Self {
        Self::InvalidConfig(error)
    }
}

/// Why a witness does not match the current account commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurableAccountStateError {
    /// The witness hash differs from the stored hash or is zero.
    CommitmentMismatch {
        /// Stored hash.
        expected: B256,
        /// Witness hash.
        actual: B256,
    },
    /// First use requires version zero.
    UnregisteredVersion {
        /// Witness version.
        actual: u64,
    },
    /// First use requires a configured recovery factory.
    FactoryNotConfigured,
    /// The initial configuration derives a different address.
    InitialAccountMismatch {
        /// Derived account.
        expected: Address,
        /// Account named in the witness.
        actual: Address,
    },
}

impl core::fmt::Display for ConfigurableAccountStateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CommitmentMismatch { expected, actual } => write!(
                f,
                "account configuration commitment mismatch: expected {expected}, actual {actual}"
            ),
            Self::UnregisteredVersion { actual } => {
                write!(
                    f,
                    "unregistered configuration version mismatch: expected 0, actual {actual}"
                )
            }
            Self::FactoryNotConfigured => f.write_str("recovery factory is not configured"),
            Self::InitialAccountMismatch { expected, actual } => {
                write!(
                    f,
                    "initial configurable account mismatch: expected {expected}, actual {actual}"
                )
            }
        }
    }
}

/// Configurable account quorum validation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurableAccountQuorumError {
    /// The configured threshold is zero.
    ZeroThreshold,
    /// The signature list is empty.
    EmptySignatures,
    /// The signature list exceeds [`MAX_CONFIGURABLE_ACCOUNT_SIGNATURES`].
    TooManySignatures,
    /// The signature list has entries after quorum is reached.
    ExcessSignatures,
    /// A recovered signer is not a configured owner.
    SignerNotOwner,
    /// Recovered signers are not strictly ascending.
    SignersNotAscending,
    /// Recovered signer weight does not meet the threshold.
    WeightBelowThreshold,
    /// An owner approval could not recover a signer.
    OwnerSignatureRecoveryFailed { approval_index: usize },
}

impl ConfigurableAccountQuorumError {
    /// Returns the stable validation message for this error.
    const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroThreshold => "configurable account threshold cannot be zero",
            Self::EmptySignatures => "configurable account signatures cannot be empty",
            Self::TooManySignatures => "too many configurable account signatures",
            Self::ExcessSignatures => "excess configurable account owner signatures",
            Self::SignerNotOwner => "configurable account signer is not an owner",
            Self::SignersNotAscending => {
                "configurable account recovered owners must be strictly ascending"
            }
            Self::WeightBelowThreshold => "configurable account signature weight below threshold",
            Self::OwnerSignatureRecoveryFailed { .. } => {
                "invalid configurable account owner signature"
            }
        }
    }
}

impl core::fmt::Display for ConfigurableAccountQuorumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Accumulates recovered configurable account owner weights while enforcing owner ordering.
pub struct ConfigurableAccountWeightAccumulator {
    threshold: u8,
    prev_owner: Option<Address>,
    recovered_weight: u16,
    signer_count: usize,
}

impl ConfigurableAccountWeightAccumulator {
    /// Creates a new accumulator for a configurable account threshold.
    pub const fn new(threshold: u8) -> Result<Self, ConfigurableAccountQuorumError> {
        if threshold == 0 {
            return Err(ConfigurableAccountQuorumError::ZeroThreshold);
        }
        Ok(Self {
            threshold,
            prev_owner: None,
            recovered_weight: 0,
            signer_count: 0,
        })
    }

    /// Records one recovered owner address and its configured weight.
    pub fn record_owner(
        &mut self,
        owner: Address,
        weight: u8,
    ) -> Result<(), ConfigurableAccountQuorumError> {
        if self.has_quorum() {
            return Err(ConfigurableAccountQuorumError::ExcessSignatures);
        }
        if weight == 0 {
            return Err(ConfigurableAccountQuorumError::SignerNotOwner);
        }
        self.signer_count += 1;
        if self.signer_count > MAX_CONFIGURABLE_ACCOUNT_SIGNATURES {
            return Err(ConfigurableAccountQuorumError::TooManySignatures);
        }

        if self.prev_owner.is_some_and(|prev| prev >= owner) {
            return Err(ConfigurableAccountQuorumError::SignersNotAscending);
        }
        self.prev_owner = Some(owner);

        self.recovered_weight += u16::from(weight);
        Ok(())
    }

    /// Returns whether the accumulated weight satisfies the configured threshold.
    fn has_quorum(&self) -> bool {
        self.signer_count > 0 && self.recovered_weight >= u16::from(self.threshold)
    }

    /// Enforces that at least one signer reached the configured threshold.
    pub fn finish(self) -> Result<(), ConfigurableAccountQuorumError> {
        if self.signer_count == 0 {
            return Err(ConfigurableAccountQuorumError::EmptySignatures);
        }
        if self.recovered_weight < u16::from(self.threshold) {
            return Err(ConfigurableAccountQuorumError::WeightBelowThreshold);
        }
        Ok(())
    }
}

/// Computes the digest that configurable account owners approve.
///
/// This free function is also used while constructing a signature, before a
/// [`ConfigurableAccountSignature`] exists; [`ConfigurableAccountSignature::digest`] supplies the
/// account and version from an existing value.
pub fn configurable_account_digest(
    inner_digest: B256,
    account: Address,
    config_version: u64,
) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN);
    hasher.update(inner_digest);
    hasher.update(account);
    hasher.update(config_version.to_be_bytes());
    hasher.finalize()
}

/// Returns the configurable account for a committed factory and precomputed account salt.
fn configurable_account_address(factory: Address, account_salt: B256) -> Address {
    factory.create2(account_salt, ACCOUNT_PROXY_INIT_CODE_HASH)
}

#[cfg(feature = "serde")]
mod serde_impls {
    use super::ConfigurableAccountSignature;
    use alloy_primitives::Bytes;
    use alloy_rlp::decode_exact;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

    impl Serialize for ConfigurableAccountSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Bytes::from(alloy_rlp::encode(self)).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ConfigurableAccountSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let encoded = Bytes::deserialize(deserializer)?;
            decode_exact(&encoded).map_err(D::Error::custom)
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod arbitrary_impl {
    use super::{
        ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        MAX_CONFIGURABLE_ACCOUNT_SIGNATURES, MAX_WEBAUTHN_SIGNATURE_LENGTH, PrimitiveSignature,
    };
    use alloc::{vec, vec::Vec};
    use alloy_primitives::Address;
    use arbitrary::{Arbitrary, Result, Unstructured};

    impl<'a> Arbitrary<'a> for ConfigurableAccountSignature {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
            let len = u.int_in_range(1..=MAX_CONFIGURABLE_ACCOUNT_SIGNATURES)?;
            let mut signatures = Vec::with_capacity(len);
            for _ in 0..len {
                let mut signature = PrimitiveSignature::arbitrary(u)?;
                if let PrimitiveSignature::WebAuthn(signature) = &mut signature {
                    // Standalone primitive generation is unbounded; an owner approval is not.
                    let len = signature
                        .webauthn_data
                        .len()
                        .min(MAX_WEBAUTHN_SIGNATURE_LENGTH - 128);
                    signature.webauthn_data = signature.webauthn_data.slice(..len);
                }
                signatures.push(signature);
            }

            let mut owner = Address::arbitrary(u)?;
            if owner.is_zero() {
                owner = Address::repeat_byte(1);
            }
            let config = ConfigurableAccountConfig {
                salt: u.arbitrary()?,
                version: 0,
                threshold: 1,
                owners: vec![ConfigurableAccountOwner { owner, weight: 1 }],
            };
            // A single nonzero owner of weight 1 at threshold 1 is valid, a CREATE2 account equals
            // zero or that owner only by a hash collision, and every approval is within the owner
            // size cap: a failure here is a generator bug that fuzzing must surface, not skip.
            let account = config
                .derive_account(Address::repeat_byte(0x99))
                .expect("generated single-owner account config is valid");
            Ok(Self::try_new(account, config, signatures)
                .expect("generated configurable account signature satisfies its shape limits"))
        }
    }
}
