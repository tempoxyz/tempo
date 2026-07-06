use super::{PrimitiveSignature, tempo_transaction::MAX_WEBAUTHN_SIGNATURE_LENGTH};
use crate::TempoAddressExt;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use alloy_primitives::{Address, B256, Bytes, keccak256};
use core::hash::{Hash, Hasher};
use tempo_contracts::{TempoHardfork, precompiles::INativeMultisig};

#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox as OnceLock;
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// Tempo signature type byte for native multisig signatures.
pub const SIGNATURE_TYPE_MULTISIG: u8 = 0x05;

/// Domain prefix for native multisig owner approvals.
pub const MULTISIG_SIGNATURE_DOMAIN: &[u8] = b"tempo:multisig:signature";

/// Maximum number of owners allowed in a native multisig config.
pub const MAX_MULTISIG_OWNERS: usize = 255;

/// Maximum threshold accepted by a native multisig config.
///
/// Owner weights are nonzero, so this also bounds the number of owner approvals required to
/// satisfy one multisig authorization node.
pub const MAX_MULTISIG_THRESHOLD: u8 = 8;

/// Maximum number of owner approvals allowed in one native multisig signature.
pub const MAX_MULTISIG_SIGNATURES: usize = MAX_MULTISIG_THRESHOLD as usize;

/// Maximum number of native multisig signatures in one nested authorization path, including the
/// top-level transaction signature.
pub const MAX_MULTISIG_NESTING_DEPTH: usize = 2;

/// Maximum encoded byte length for one primitive owner approval.
pub const MAX_MULTISIG_OWNER_SIGNATURE_BYTES: usize = 1 + MAX_WEBAUTHN_SIGNATURE_LENGTH;

const MULTISIG_ACCOUNT_DOMAIN: &[u8] = b"tempo:multisig:account";

/// Native multisig config validation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MultisigConfigError {
    /// The owner list is empty.
    EmptyOwners,
    /// The owner list exceeds [`MAX_MULTISIG_OWNERS`].
    TooManyOwners,
    /// The threshold is zero.
    ZeroThreshold,
    /// The threshold exceeds [`MAX_MULTISIG_THRESHOLD`].
    ThresholdTooHigh,
    /// An owner address is zero.
    ZeroOwner,
    /// An owner weight is zero.
    ZeroWeight,
    /// The owner list contains a duplicate owner.
    DuplicateOwner,
    /// The owner list is not strictly ascending.
    OwnersNotAscending,
    /// Owner weight accumulation overflowed.
    WeightOverflow,
    /// Total owner weight exceeds `u8::MAX`.
    TotalWeightExceedsMax,
    /// The threshold exceeds total owner weight.
    ThresholdExceedsWeight,
    /// The derived multisig account address is zero.
    DerivedAccountZero,
}

impl MultisigConfigError {
    /// Returns the stable validation message for this error.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyOwners => "multisig owners cannot be empty",
            Self::TooManyOwners => "too many multisig owners",
            Self::ZeroThreshold => "multisig threshold cannot be zero",
            Self::ThresholdTooHigh => "multisig threshold exceeds max threshold",
            Self::ZeroOwner => "multisig owner cannot be zero",
            Self::ZeroWeight => "multisig owner weight cannot be zero",
            Self::DuplicateOwner => "multisig owners cannot contain duplicates",
            Self::OwnersNotAscending => "multisig owners must be strictly ascending",
            Self::WeightOverflow => "multisig owner weight overflow",
            Self::TotalWeightExceedsMax => "multisig total owner weight exceeds u8::MAX",
            Self::ThresholdExceedsWeight => "multisig threshold exceeds total owner weight",
            Self::DerivedAccountZero => "multisig account cannot be zero",
        }
    }
}

impl core::fmt::Display for MultisigConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Native multisig quorum validation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MultisigQuorumError {
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
    /// Recovered signer weight accumulation overflowed.
    WeightOverflow,
    /// Recovered signer weight does not meet the threshold.
    WeightBelowThreshold,
}

impl MultisigQuorumError {
    /// Returns the stable validation message for this error.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptySignatures => "multisig signatures cannot be empty",
            Self::TooManySignatures => "too many multisig signatures",
            Self::ExcessSignatures => "excess multisig owner signatures",
            Self::SignerNotOwner => "multisig signer is not an owner",
            Self::SignersNotAscending => "multisig recovered owners must be strictly ascending",
            Self::WeightOverflow => "multisig recovered owner weight overflow",
            Self::WeightBelowThreshold => "multisig signature weight below threshold",
        }
    }
}

impl core::fmt::Display for MultisigQuorumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<MultisigQuorumError> for &'static str {
    fn from(err: MultisigQuorumError) -> Self {
        err.as_str()
    }
}

impl From<MultisigQuorumError> for String {
    fn from(err: MultisigQuorumError) -> Self {
        err.as_str().to_string()
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
    /// Creates a new accumulator for a validated native multisig threshold.
    pub const fn new(threshold: u8) -> Self {
        Self {
            threshold,
            prev_owner: None,
            recovered_weight: 0,
            signer_count: 0,
        }
    }

    /// Records one recovered owner address and its configured weight.
    pub fn record_owner(&mut self, owner: Address, weight: u8) -> Result<u8, MultisigQuorumError> {
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

        self.recovered_weight = self
            .recovered_weight
            .checked_add(u16::from(weight))
            .ok_or(MultisigQuorumError::WeightOverflow)?;
        Ok(weight)
    }

    /// Returns whether the accumulated weight satisfies the configured threshold.
    pub fn has_quorum(&self) -> bool {
        self.signer_count > 0 && self.recovered_weight >= u16::from(self.threshold)
    }

    /// Returns the accumulated weight after enforcing the configured threshold.
    pub fn finish(self) -> Result<u8, MultisigQuorumError> {
        if self.signer_count == 0 {
            return Err(MultisigQuorumError::EmptySignatures);
        }
        if self.recovered_weight < u16::from(self.threshold) {
            return Err(MultisigQuorumError::WeightBelowThreshold);
        }

        u8::try_from(self.recovered_weight).map_err(|_| MultisigQuorumError::WeightOverflow)
    }
}

/// Native multisig owner entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct MultisigOwner {
    /// Owner address recovered from a primitive signature.
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

/// Initial native multisig config carried by the first transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct InitMultisig {
    /// Caller-chosen salt mixed into the derived account address.
    pub salt: B256,
    /// Minimum total owner weight required to authorize a transaction.
    pub threshold: u8,
    /// Sorted weighted owner list.
    pub owners: Vec<MultisigOwner>,
}

impl InitMultisig {
    /// Validates this native multisig config and returns its total owner weight.
    pub fn validate(&self) -> Result<u8, MultisigConfigError> {
        if self.owners.is_empty() {
            return Err(MultisigConfigError::EmptyOwners);
        }
        if self.owners.len() > MAX_MULTISIG_OWNERS {
            return Err(MultisigConfigError::TooManyOwners);
        }
        if self.threshold == 0 {
            return Err(MultisigConfigError::ZeroThreshold);
        }
        if self.threshold > MAX_MULTISIG_THRESHOLD {
            return Err(MultisigConfigError::ThresholdTooHigh);
        }

        let mut total_weight = 0u16;
        let mut prev_owner = None;
        for owner in &self.owners {
            if owner.owner.is_zero() {
                return Err(MultisigConfigError::ZeroOwner);
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
            total_weight = total_weight
                .checked_add(u16::from(owner.weight))
                .ok_or(MultisigConfigError::WeightOverflow)?;
        }

        if total_weight > u16::from(u8::MAX) {
            return Err(MultisigConfigError::TotalWeightExceedsMax);
        }
        if u16::from(self.threshold) > total_weight {
            return Err(MultisigConfigError::ThresholdExceedsWeight);
        }

        Ok(total_weight as u8)
    }

    /// Derives the native multisig account address for this initial config.
    pub fn account(&self) -> Result<Address, MultisigConfigError> {
        self.validate()?;

        let owner_count =
            u8::try_from(self.owners.len()).expect("validated multisig owner count fits in u8");
        let mut input = Vec::with_capacity(
            MULTISIG_ACCOUNT_DOMAIN.len() + 32 + 2 + self.owners.len() * (20 + 1),
        );
        input.extend_from_slice(MULTISIG_ACCOUNT_DOMAIN);
        input.extend_from_slice(self.salt.as_slice());
        input.push(self.threshold);
        input.push(owner_count);
        for owner in &self.owners {
            input.extend_from_slice(owner.owner.as_slice());
            input.push(owner.weight);
        }

        let account = Address::from_slice(&keccak256(input)[12..]);
        if account.is_zero() {
            return Err(MultisigConfigError::DerivedAccountZero);
        }
        Ok(account)
    }

    /// Returns the configured weight for an owner, if present.
    pub fn owner_weight(&self, owner: Address) -> Option<u8> {
        self.owners
            .binary_search_by_key(&owner, |entry| entry.owner)
            .ok()
            .map(|idx| self.owners[idx].weight)
    }
    /// Decodes, verifies, and weight-accounts primitive owner approvals.
    ///
    /// This helper does not validate nested multisig owner approvals because that requires state
    /// access to load each nested account config.
    pub fn verify_owner_signatures(
        &self,
        digest: B256,
        signatures: &[Bytes],
    ) -> Result<u8, &'static str> {
        self.validate().map_err(MultisigConfigError::as_str)?;
        let owners = recover_multisig_owner_addresses(digest, signatures)?;
        verify_recovered_multisig_owners(&owners, self)
    }

    /// Returns a heuristic for the in-memory size of the config.
    pub fn size(&self) -> usize {
        size_of::<Self>() + self.owners.capacity() * size_of::<MultisigOwner>()
    }
}

/// Native multisig transaction signature.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct MultisigSignature {
    /// Native multisig account address.
    account: Address,
    /// Encoded owner approvals over the multisig digest.
    ///
    /// Each approval is either a primitive signature or a nested native multisig signature.
    signatures: Vec<Bytes>,
    /// Initial native multisig config for bootstrapping this account.
    init: Option<InitMultisig>,
    /// Cached multisig digest for the transaction hash this signature approved.
    #[cfg_attr(feature = "serde", serde(skip))]
    cached_digest: OnceLock<(B256, Address, B256)>,
    /// Cached primitive recovered owner addresses for the digest this multisig signature approved.
    #[cfg_attr(feature = "serde", serde(skip))]
    cached_recovered_owners: OnceLock<(B256, Vec<Address>)>,
}

impl MultisigSignature {
    pub fn new(account: Address, signatures: Vec<Bytes>, init: Option<InitMultisig>) -> Self {
        Self {
            account,
            signatures,
            init,
            cached_digest: OnceLock::new(),
            cached_recovered_owners: OnceLock::new(),
        }
    }

    /// Returns the native multisig account address.
    pub fn account(&self) -> Address {
        self.account
    }

    /// Returns encoded owner approvals.
    pub fn signatures(&self) -> &[Bytes] {
        &self.signatures
    }

    /// Returns the number of encoded owner signatures.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Returns the optional bootstrap config.
    pub fn init(&self) -> Option<&InitMultisig> {
        self.init.as_ref()
    }

    /// Performs stateless sender-recovery checks and returns the attempted multisig account.
    pub fn recover_account(&self) -> Result<Address, &'static str> {
        self.validate_shape()?;
        if let Some(init) = &self.init {
            let init_account = init.account().map_err(MultisigConfigError::as_str)?;
            if init_account != self.account {
                return Err("multisig init does not derive account");
            }
        }
        Ok(self.account)
    }

    /// Validates only the stateless signature payload shape.
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.account.is_zero() {
            return Err("multisig account cannot be zero");
        }
        if self.signatures.is_empty() {
            return Err("multisig signatures cannot be empty");
        }
        if self.signatures.len() > MAX_MULTISIG_SIGNATURES {
            return Err("too many multisig signatures");
        }
        if self.signatures.iter().any(|sig| sig.is_empty()) {
            return Err("multisig owner signature cannot be empty");
        }
        if self
            .signatures
            .iter()
            .any(|sig| sig.len() > MAX_MULTISIG_OWNER_SIGNATURE_BYTES)
        {
            return Err("multisig owner signature too large");
        }
        Ok(())
    }

    /// Performs only the registered-account stateless payload checks.
    ///
    /// Registered accounts are already bound to native multisig storage, so the derived-account
    /// check can be skipped on the steady-state path.
    pub fn validate_registered_shape(&self) -> Result<(), &'static str> {
        self.validate_shape()?;
        if self.init.is_some() {
            return Err("multisig_init is only allowed when bootstrapping an account");
        }
        Ok(())
    }

    /// Returns the multisig owner-approval digest for this signature and caches it on first use.
    pub fn digest(&self, inner_digest: B256) -> B256 {
        if let Some((cached_inner, cached_account, cached_digest)) = self.cached_digest.get()
            && *cached_inner == inner_digest
            && *cached_account == self.account
        {
            return *cached_digest;
        }

        let digest = multisig_digest(inner_digest, self.account);
        if self.cached_digest.get().is_none() {
            #[allow(clippy::useless_conversion)]
            let _ = self
                .cached_digest
                .set((inner_digest, self.account, digest).into());
        }
        if let Some((cached_inner, cached_account, cached_digest)) = self.cached_digest.get()
            && *cached_inner == inner_digest
            && *cached_account == self.account
        {
            return *cached_digest;
        }

        digest
    }

    /// Recovers primitive owner addresses for the provided multisig digest and caches them on first
    /// use.
    ///
    /// This is a primitive-only helper. Full protocol validation of nested multisig owner
    /// approvals must be performed by the stateful native multisig verifier.
    pub fn with_recovered_owners<R>(
        &self,
        digest: B256,
        f: impl FnOnce(&[Address]) -> Result<R, &'static str>,
    ) -> Result<R, &'static str> {
        if let Some((cached_digest, owners)) = self.cached_recovered_owners.get()
            && *cached_digest == digest
        {
            return f(owners);
        }

        let owners = recover_multisig_owner_addresses(digest, &self.signatures)?;
        if self.cached_recovered_owners.get().is_none() {
            #[allow(clippy::useless_conversion)]
            let _ = self
                .cached_recovered_owners
                .set((digest, owners.clone()).into());
        }
        if let Some((cached_digest, cached_owners)) = self.cached_recovered_owners.get()
            && *cached_digest == digest
        {
            return f(cached_owners);
        }

        f(&owners)
    }

    /// Verifies primitive owner approvals against a config already validated by trusted storage.
    ///
    /// This helper does not validate nested multisig owner approvals because that requires state
    /// access to load each nested account config.
    pub fn verify_with_trusted_config(
        &self,
        digest: B256,
        config: &InitMultisig,
    ) -> Result<u8, &'static str> {
        self.with_recovered_owners(digest, |owners| {
            verify_recovered_multisig_owners(owners, config)
        })
    }

    /// Returns a heuristic for the in-memory size of the signature.
    pub fn size(&self) -> usize {
        size_of::<Self>()
            + self.signatures.capacity() * size_of::<Bytes>()
            + self.signatures.iter().map(|sig| sig.len()).sum::<usize>()
            + self.init.as_ref().map_or(0, InitMultisig::size)
    }
}

impl PartialEq for MultisigSignature {
    fn eq(&self, other: &Self) -> bool {
        self.account == other.account
            && self.signatures == other.signatures
            && self.init == other.init
    }
}

impl Eq for MultisigSignature {}

impl Hash for MultisigSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.account.hash(state);
        self.signatures.hash(state);
        self.init.hash(state);
    }
}

#[derive(alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[rlp(trailing(canonical))]
struct MultisigSignatureWire {
    account: Address,
    signatures: Vec<Bytes>,
    init: Option<InitMultisig>,
}

impl From<&MultisigSignature> for MultisigSignatureWire {
    fn from(value: &MultisigSignature) -> Self {
        Self {
            account: value.account,
            signatures: value.signatures.clone(),
            init: value.init.clone(),
        }
    }
}

impl TryFrom<MultisigSignatureWire> for MultisigSignature {
    type Error = alloy_rlp::Error;

    fn try_from(value: MultisigSignatureWire) -> alloy_rlp::Result<Self> {
        let signature = Self::new(value.account, value.signatures, value.init);
        signature
            .validate_shape()
            .map_err(alloy_rlp::Error::Custom)?;
        Ok(signature)
    }
}

impl alloy_rlp::Decodable for MultisigSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        MultisigSignatureWire::decode(buf).and_then(TryInto::try_into)
    }
}

impl alloy_rlp::Encodable for MultisigSignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        MultisigSignatureWire::from(self).encode(out);
    }

    fn length(&self) -> usize {
        MultisigSignatureWire::from(self).length()
    }
}

/// Returns whether an address is eligible to be a native multisig account.
pub fn is_valid_multisig_account(account: Address, spec: TempoHardfork) -> bool {
    !account.is_zero() && !account.is_virtual() && !account.is_precompile(spec)
}

/// Computes the digest that native multisig owners approve.
pub fn multisig_digest(inner_digest: B256, account: Address) -> B256 {
    let mut input = [0u8; MULTISIG_SIGNATURE_DOMAIN.len() + 32 + 20];
    let mut offset = 0;
    input[offset..offset + MULTISIG_SIGNATURE_DOMAIN.len()]
        .copy_from_slice(MULTISIG_SIGNATURE_DOMAIN);
    offset += MULTISIG_SIGNATURE_DOMAIN.len();
    input[offset..offset + 32].copy_from_slice(inner_digest.as_slice());
    offset += 32;
    input[offset..].copy_from_slice(account.as_slice());
    keccak256(input)
}

/// Returns the number of leading signatures needed for their weights to meet `threshold`.
pub fn multisig_signature_count_for_threshold(
    weights: impl IntoIterator<Item = u8>,
    threshold: u8,
) -> Result<usize, MultisigQuorumError> {
    let mut signed_weight = 0u16;
    let mut count = 0usize;

    for weight in weights {
        count = count
            .checked_add(1)
            .ok_or(MultisigQuorumError::TooManySignatures)?;
        if count > MAX_MULTISIG_SIGNATURES {
            return Err(MultisigQuorumError::TooManySignatures);
        }
        signed_weight = signed_weight
            .checked_add(u16::from(weight))
            .ok_or(MultisigQuorumError::WeightOverflow)?;
        if signed_weight >= u16::from(threshold) {
            return Ok(count);
        }
    }

    if count == 0 {
        return Err(MultisigQuorumError::EmptySignatures);
    }
    Err(MultisigQuorumError::WeightBelowThreshold)
}

/// Verifies recovered owner order, membership, and accumulated weight for a validated config.
pub fn verify_ordered_owner_weights(
    owners: &[Address],
    config: &InitMultisig,
) -> Result<u8, MultisigQuorumError> {
    let mut accumulator = MultisigWeightAccumulator::new(config.threshold);
    for &owner in owners {
        let weight = config
            .owners
            .binary_search_by_key(&owner, |entry| entry.owner)
            .map(|idx| config.owners[idx].weight)
            .map_err(|_| MultisigQuorumError::SignerNotOwner)?;
        accumulator.record_owner(owner, weight)?;
    }
    accumulator.finish()
}

fn recover_multisig_owner_addresses(
    digest: B256,
    signatures: &[Bytes],
) -> Result<Vec<Address>, &'static str> {
    if signatures.is_empty() {
        return Err("multisig signatures cannot be empty");
    }
    if signatures.len() > MAX_MULTISIG_SIGNATURES {
        return Err("too many multisig signatures");
    }

    let mut owners = Vec::with_capacity(signatures.len());
    for signature_bytes in signatures {
        if signature_bytes.len() > MAX_MULTISIG_OWNER_SIGNATURE_BYTES {
            return Err("multisig owner signature too large");
        }

        let signature = PrimitiveSignature::from_bytes(signature_bytes)
            .map_err(|_| "invalid multisig owner signature")?;
        let owner = signature
            .recover_signer(&digest)
            .map_err(|_| "invalid multisig owner signature")?;
        owners.push(owner);
    }
    Ok(owners)
}

fn verify_recovered_multisig_owners(
    owners: &[Address],
    config: &InitMultisig,
) -> Result<u8, &'static str> {
    verify_ordered_owner_weights(owners, config).map_err(MultisigQuorumError::as_str)
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for MultisigSignature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(1..=MAX_MULTISIG_SIGNATURES)?;
        let mut signatures = Vec::new();
        for _ in 0..len {
            let mut signature = Vec::<u8>::arbitrary(u)?;
            if signature.is_empty() {
                signature.push(0);
            }
            signature.truncate(MAX_MULTISIG_OWNER_SIGNATURE_BYTES);
            signatures.push(Bytes::from(signature));
        }

        let mut account = Address::arbitrary(u)?;
        if account.is_zero() {
            account = Address::repeat_byte(1);
        }

        Ok(Self::new(account, signatures, u.arbitrary()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{
        PrimitiveSignature, TempoSignature, derive_p256_address,
        tt_authorization::tests::{generate_secp256k1_keypair, sign_hash},
        tt_signature::{P256SignatureWithPreHash, normalize_p256_s},
    };
    use alloy_rlp::{Decodable, Encodable};
    use p256::{
        ecdsa::{SigningKey as P256SigningKey, signature::hazmat::PrehashSigner},
        elliptic_curve::rand_core::OsRng,
    };
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};
    use tempo_contracts::precompiles::{
        NATIVE_MULTISIG_ADDRESS, PATH_USD_ADDRESS, SYSTEM_PRECOMPILES,
    };

    fn sorted_secp_config(owners: &[(Address, u8)], threshold: u8) -> InitMultisig {
        let mut owners = owners
            .iter()
            .map(|(owner, weight)| MultisigOwner {
                owner: *owner,
                weight: *weight,
            })
            .collect::<Vec<_>>();
        owners.sort_by_key(|owner| owner.owner);
        InitMultisig {
            salt: B256::ZERO,
            threshold,
            owners,
        }
    }

    fn indexed_owner(index: u16) -> Address {
        let mut bytes = [0u8; 20];
        bytes[18..].copy_from_slice(&index.to_be_bytes());
        Address::from(bytes)
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

    fn encoded_multisig_without_init_slot(account: Address, signatures: Vec<Vec<u8>>) -> Vec<u8> {
        let signatures = signatures.into_iter().map(Bytes::from).collect::<Vec<_>>();
        let payload_length = account.length() + signatures.length();
        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(&mut encoded);
        account.encode(&mut encoded);
        signatures.encode(&mut encoded);
        encoded
    }

    fn encoded_multisig_with_empty_init_placeholder(
        account: Address,
        signatures: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let signatures = signatures.into_iter().map(Bytes::from).collect::<Vec<_>>();
        let payload_length = account.length() + signatures.length() + 1;
        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(&mut encoded);
        account.encode(&mut encoded);
        signatures.encode(&mut encoded);
        encoded.push(alloy_rlp::EMPTY_STRING_CODE);
        encoded
    }

    #[test]
    fn account_derivation_is_stable_and_validates_owner_order() {
        let owner_a = Address::from([0x11; 20]);
        let owner_b = Address::from([0x22; 20]);
        let config = sorted_secp_config(&[(owner_b, 2), (owner_a, 1)], 2);

        config.validate().expect("config is valid");
        assert_eq!(config.account().unwrap(), config.account().unwrap());

        let unsorted = InitMultisig {
            salt: B256::ZERO,
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
            zero_salt.account().unwrap(),
            nonzero_salt.account().unwrap()
        );
        zero_salt.validate().expect("zero salt is valid");
    }

    #[test]
    fn config_accepts_255_owners() {
        let owners = (1..=MAX_MULTISIG_OWNERS as u16)
            .map(|index| (indexed_owner(index), 1))
            .collect::<Vec<_>>();
        let config = sorted_secp_config(&owners, MAX_MULTISIG_THRESHOLD);

        assert_eq!(config.validate(), Ok(u8::MAX));
        assert!(config.account().is_ok());
    }

    #[test]
    fn config_rejects_more_than_255_owners() {
        let owners = (1..=MAX_MULTISIG_OWNERS as u16 + 1)
            .map(|index| (indexed_owner(index), 1))
            .collect::<Vec<_>>();
        let config = sorted_secp_config(&owners, MAX_MULTISIG_THRESHOLD);

        assert_eq!(config.validate(), Err(MultisigConfigError::TooManyOwners));
    }

    #[test]
    fn config_total_weight_is_capped_at_u8_max() {
        let owner_a = Address::from([0x11; 20]);
        let owner_b = Address::from([0x22; 20]);
        let config = sorted_secp_config(&[(owner_a, 128), (owner_b, 128)], MAX_MULTISIG_THRESHOLD);

        assert_eq!(
            config.validate(),
            Err(MultisigConfigError::TotalWeightExceedsMax)
        );
    }

    #[test]
    fn config_rejects_threshold_above_protocol_cap() {
        let owner = Address::from([0x11; 20]);
        let threshold = MAX_MULTISIG_THRESHOLD + 1;
        let config = sorted_secp_config(&[(owner, threshold)], threshold);

        assert_eq!(
            config.validate(),
            Err(MultisigConfigError::ThresholdTooHigh)
        );
    }

    #[test]
    fn shared_quorum_helpers_verify_order_and_threshold() {
        let owner_a = indexed_owner(1);
        let owner_b = indexed_owner(2);
        let owner_c = indexed_owner(3);
        let config = sorted_secp_config(&[(owner_a, 1), (owner_b, 3), (owner_c, 2)], 4);

        assert_eq!(
            verify_ordered_owner_weights(&[owner_a, owner_b], &config),
            Ok(4)
        );
        assert_eq!(
            verify_ordered_owner_weights(&[owner_b], &config),
            Err(MultisigQuorumError::WeightBelowThreshold)
        );
        assert_eq!(
            verify_ordered_owner_weights(&[owner_b, owner_a], &config),
            Err(MultisigQuorumError::SignersNotAscending)
        );
        assert_eq!(
            verify_ordered_owner_weights(&[indexed_owner(4)], &config),
            Err(MultisigQuorumError::SignerNotOwner)
        );

        assert_eq!(
            multisig_signature_count_for_threshold(
                config.owners.iter().map(|owner| owner.weight),
                4
            ),
            Ok(2)
        );
        assert_eq!(
            multisig_signature_count_for_threshold([1, 2], 4),
            Err(MultisigQuorumError::WeightBelowThreshold)
        );
        assert_eq!(
            multisig_signature_count_for_threshold([], 1),
            Err(MultisigQuorumError::EmptySignatures)
        );
    }

    #[test]
    fn multisig_account_eligibility_uses_current_hardfork_precompile_set() {
        assert!(is_valid_multisig_account(
            NATIVE_MULTISIG_ADDRESS,
            TempoHardfork::T7
        ));
        assert!(!is_valid_multisig_account(
            NATIVE_MULTISIG_ADDRESS,
            TempoHardfork::T8
        ));
        assert!(!is_valid_multisig_account(
            PATH_USD_ADDRESS,
            TempoHardfork::Genesis
        ));

        for &(precompile, activated) in SYSTEM_PRECOMPILES {
            if activated <= TempoHardfork::T8 {
                assert!(
                    !is_valid_multisig_account(precompile, TempoHardfork::T8),
                    "{precompile} should not be eligible as a native multisig account"
                );
            }
        }
    }

    #[test]
    fn owner_signature_cannot_replay_across_accounts_with_same_owners() {
        let (signer, owner) = generate_secp256k1_keypair();
        let mut config_a = sorted_secp_config(&[(owner, 1)], 1);
        config_a.salt = B256::repeat_byte(0x11);
        let mut config_b = sorted_secp_config(&[(owner, 1)], 1);
        config_b.salt = B256::repeat_byte(0x22);

        let account_a = config_a.account().unwrap();
        let account_b = config_b.account().unwrap();
        assert_ne!(account_a, account_b);

        let inner_digest = B256::repeat_byte(0x42);
        let digest_a = multisig_digest(inner_digest, account_a);
        let signature = sign_hash(&signer, &digest_a).to_bytes();

        assert!(
            config_a
                .verify_owner_signatures(digest_a, core::slice::from_ref(&signature))
                .is_ok()
        );
        assert!(
            config_b
                .verify_owner_signatures(multisig_digest(inner_digest, account_b), &[signature],)
                .is_err()
        );
    }

    #[test]
    fn verifies_weighted_owner_signatures_in_sorted_order() {
        let (signer_a, owner_a) = generate_secp256k1_keypair();
        let (signer_b, owner_b) = generate_secp256k1_keypair();
        let config = sorted_secp_config(&[(owner_a, 1), (owner_b, 1)], 2);
        let account = config.account().unwrap();
        let digest = multisig_digest(B256::repeat_byte(0x42), account);

        let mut signed = [
            (owner_a, sign_hash(&signer_a, &digest).to_bytes()),
            (owner_b, sign_hash(&signer_b, &digest).to_bytes()),
        ];
        signed.sort_by_key(|(owner, _)| *owner);
        let signatures = signed
            .into_iter()
            .map(|(_, signature)| signature)
            .collect::<Vec<_>>();

        assert_eq!(
            config.verify_owner_signatures(digest, &signatures).unwrap(),
            2
        );

        let one_signature = vec![signatures[0].clone()];
        assert!(
            config
                .verify_owner_signatures(digest, &one_signature)
                .is_err()
        );
    }

    #[test]
    fn rejects_noncanonical_p256_owner_prehash_flag() {
        let (signer, pub_key_x, pub_key_y, owner) = generate_p256_keypair();
        let config = sorted_secp_config(&[(owner, 1)], 1);
        let account = config.account().unwrap();
        let digest = multisig_digest(B256::repeat_byte(0x42), account);

        let canonical_signature =
            sign_p256_owner_approval_with_prehash(&signer, digest, pub_key_x, pub_key_y);
        assert_eq!(
            canonical_signature[canonical_signature.len() - 1],
            1,
            "test setup should use canonical pre_hash=true encoding"
        );
        assert!(
            config
                .verify_owner_signatures(digest, core::slice::from_ref(&canonical_signature))
                .is_ok()
        );

        let mut noncanonical_signature = canonical_signature.to_vec();
        let flag_index = noncanonical_signature.len() - 1;
        noncanonical_signature[flag_index] = 2;
        assert_eq!(
            config.verify_owner_signatures(digest, &[Bytes::from(noncanonical_signature)]),
            Err("invalid multisig owner signature")
        );
    }

    #[test]
    fn multisig_signature_without_init_omits_trailing_slot() {
        let account = Address::repeat_byte(0x11);
        let signatures = vec![Bytes::from(vec![0x03, 0x04])];
        let signature = MultisigSignature::new(account, signatures.clone(), None);

        let mut encoded = Vec::new();
        signature.encode(&mut encoded);
        assert_eq!(
            encoded,
            encoded_multisig_without_init_slot(
                account,
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
    fn multisig_signature_rejects_empty_init_placeholder() {
        let encoded = encoded_multisig_with_empty_init_placeholder(
            Address::repeat_byte(0x11),
            vec![vec![0x03, 0x04]],
        );

        let mut input = encoded.as_slice();
        assert!(MultisigSignature::decode(&mut input).is_err());
    }

    #[test]
    fn multisig_signature_shape_rejects_oversized_owner_signature() {
        let signature = MultisigSignature::new(
            Address::repeat_byte(0x11),
            vec![Bytes::from(vec![
                0xaa;
                MAX_MULTISIG_OWNER_SIGNATURE_BYTES + 1
            ])],
            None,
        );

        assert_eq!(
            signature.validate_shape(),
            Err("multisig owner signature too large")
        );
    }

    #[test]
    fn multisig_signature_decode_rejects_oversized_owner_signature() {
        let signature = MultisigSignature::new(
            Address::repeat_byte(0x11),
            vec![Bytes::from(vec![
                0xaa;
                MAX_MULTISIG_OWNER_SIGNATURE_BYTES + 1
            ])],
            None,
        );
        let mut encoded = Vec::new();
        signature.encode(&mut encoded);
        let mut input = encoded.as_slice();

        assert!(
            MultisigSignature::decode(&mut input).is_err(),
            "RLP decode should reject oversized owner approval bytes"
        );
    }

    #[test]
    fn tempo_signature_decode_rejects_oversized_multisig_owner_signature() {
        let signature = TempoSignature::Multisig(MultisigSignature::new(
            Address::repeat_byte(0x11),
            vec![Bytes::from(vec![
                0xaa;
                MAX_MULTISIG_OWNER_SIGNATURE_BYTES + 1
            ])],
            None,
        ));

        assert!(
            TempoSignature::from_bytes(&signature.to_bytes()).is_err(),
            "TempoSignature decode should reject multisig payloads with oversized owner approvals"
        );
    }

    #[test]
    fn multisig_signature_roundtrips_through_tempo_signature_bytes() {
        let (signer, owner) = generate_secp256k1_keypair();
        let config = sorted_secp_config(&[(owner, 1)], 1);
        let account = config.account().unwrap();
        let signature_hash = B256::ZERO;
        let digest = multisig_digest(signature_hash, account);
        let signature =
            MultisigSignature::new(account, vec![sign_hash(&signer, &digest).to_bytes()], None);
        let tempo_signature = TempoSignature::Multisig(signature.clone());

        let encoded = tempo_signature.to_bytes();
        assert_eq!(encoded[0], SIGNATURE_TYPE_MULTISIG);
        let decoded = TempoSignature::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.as_multisig(), Some(&signature));
        assert_eq!(
            decoded.recover_signer(&signature_hash).unwrap(),
            signature.account
        );
    }

    #[test]
    fn multisig_signature_roundtrips_init_config() {
        let (signer, owner) = generate_secp256k1_keypair();
        let mut config = sorted_secp_config(&[(owner, 1)], 1);
        config.salt = B256::repeat_byte(0x33);
        let account = config.account().unwrap();
        let signature_hash = B256::ZERO;
        let digest = multisig_digest(signature_hash, account);
        let signature = MultisigSignature::new(
            account,
            vec![sign_hash(&signer, &digest).to_bytes()],
            Some(config),
        );
        let tempo_signature = TempoSignature::Multisig(signature.clone());

        let encoded = tempo_signature.to_bytes();
        let decoded = TempoSignature::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.as_multisig(), Some(&signature));
        assert_eq!(
            decoded.recover_signer(&signature_hash).unwrap(),
            signature.account
        );
    }

    proptest! {
        #[test]
        fn proptest_multisig_signature_decode_encode_preserves_accepted_raw_bytes(
            raw in prop_oneof![
                proptest::collection::vec(any::<u8>(), 0..256),
                (
                    any::<Address>(),
                    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..128), 0..=MAX_MULTISIG_SIGNATURES),
                ).prop_map(|(account, signatures)| {
                    encoded_multisig_without_init_slot(account, signatures)
                }),
            ],
        ) {
            let mut input = raw.as_slice();
            if let Ok(decoded) = MultisigSignature::decode(&mut input) {
                prop_assert!(input.is_empty());

                let mut reencoded = Vec::new();
                decoded.encode(&mut reencoded);

                prop_assert_eq!(reencoded, raw);
            }
        }
    }
}
