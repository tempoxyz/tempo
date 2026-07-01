use super::{PrimitiveSignature, tempo_transaction::MAX_WEBAUTHN_SIGNATURE_LENGTH};
use crate::TempoAddressExt;
use alloc::vec::Vec;
use alloy_primitives::{Address, B256, Bytes, keccak256};
use core::hash::{Hash, Hasher};
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, ADDRESS_REGISTRY_ADDRESS, NATIVE_MULTISIG_ADDRESS,
    NONCE_PRECOMPILE_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS, SIGNATURE_VERIFIER_ADDRESS,
    STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS, VALIDATOR_CONFIG_ADDRESS,
    VALIDATOR_CONFIG_V2_ADDRESS,
};

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

/// Maximum number of native multisig signatures in one nested authorization path, including the
/// top-level transaction signature.
pub const MAX_MULTISIG_NESTING_DEPTH: usize = 3;

/// Maximum encoded byte length for one primitive owner approval.
pub const MAX_MULTISIG_OWNER_SIGNATURE_BYTES: usize = 1 + MAX_WEBAUTHN_SIGNATURE_LENGTH;

const MULTISIG_ACCOUNT_DOMAIN: &[u8] = b"tempo:multisig:account";

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
    /// Returns the native multisig account address derived from this initial config.
    pub fn account(&self) -> Result<Address, &'static str> {
        derive_multisig_account(self)
    }

    /// Returns a heuristic for the in-memory size of the config.
    pub fn size(&self) -> usize {
        size_of::<Self>() + self.owners.capacity() * size_of::<MultisigOwner>()
    }
}

/// Native multisig transaction signature.
#[derive(Clone, Debug, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[rlp(trailing(canonical))]
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
    #[rlp(skip, default)]
    cached_digest: OnceLock<(B256, Address, B256)>,
    /// Cached primitive recovered owner addresses for the digest this multisig signature approved.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[rlp(skip, default)]
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
        validate_multisig_signature_shape(self)?;
        if let Some(init) = &self.init {
            if init.account()? != self.account {
                return Err("multisig init does not derive account");
            }
        }
        Ok(self.account)
    }

    /// Performs only the registered-account stateless payload checks.
    ///
    /// Registered accounts are already bound to native multisig storage, so the derived-account
    /// check can be skipped on the steady-state path.
    pub fn validate_registered_shape(&self) -> Result<(), &'static str> {
        validate_multisig_signature_shape(self)?;
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

/// Validates a native multisig config and returns its total owner weight.
pub fn validate_multisig_config(config: &InitMultisig) -> Result<u8, &'static str> {
    if config.owners.is_empty() {
        return Err("multisig owners cannot be empty");
    }
    if config.owners.len() > MAX_MULTISIG_OWNERS {
        return Err("too many multisig owners");
    }
    if config.threshold == 0 {
        return Err("multisig threshold cannot be zero");
    }

    let mut total_weight = 0u16;
    let mut prev_owner = None;
    for owner in &config.owners {
        if owner.owner.is_zero() {
            return Err("multisig owner cannot be zero");
        }
        if owner.weight == 0 {
            return Err("multisig owner weight cannot be zero");
        }
        if prev_owner.is_some_and(|prev| prev >= owner.owner) {
            return Err("multisig owners must be strictly ascending");
        }
        prev_owner = Some(owner.owner);
        total_weight = total_weight
            .checked_add(u16::from(owner.weight))
            .ok_or("multisig owner weight overflow")?;
    }

    if total_weight > u16::from(u8::MAX) {
        return Err("multisig total owner weight exceeds u8::MAX");
    }
    if u16::from(config.threshold) > total_weight {
        return Err("multisig threshold exceeds total owner weight");
    }

    Ok(total_weight as u8)
}

/// Validates only the stateless signature payload shape.
pub fn validate_multisig_signature_shape(
    signature: &MultisigSignature,
) -> Result<(), &'static str> {
    if signature.account.is_zero() {
        return Err("multisig account cannot be zero");
    }
    if signature.signatures.is_empty() {
        return Err("multisig signatures cannot be empty");
    }
    if signature.signatures.len() > MAX_MULTISIG_OWNERS {
        return Err("too many multisig signatures");
    }
    if signature.signatures.iter().any(|sig| sig.is_empty()) {
        return Err("multisig owner signature cannot be empty");
    }
    Ok(())
}

/// Derives the native multisig account address for an initial config.
pub fn derive_multisig_account(config: &InitMultisig) -> Result<Address, &'static str> {
    validate_multisig_config(config)?;

    let owner_count = encode_multisig_owner_count(config.owners.len())?;
    let mut input =
        Vec::with_capacity(MULTISIG_ACCOUNT_DOMAIN.len() + 32 + 2 + config.owners.len() * (20 + 1));
    input.extend_from_slice(MULTISIG_ACCOUNT_DOMAIN);
    input.extend_from_slice(config.salt.as_slice());
    input.push(config.threshold);
    input.push(owner_count);
    for owner in &config.owners {
        input.extend_from_slice(owner.owner.as_slice());
        input.push(owner.weight);
    }

    let account = Address::from_slice(&keccak256(input)[12..]);
    if account.is_zero() {
        return Err("multisig account cannot be zero");
    }
    Ok(account)
}

/// Returns whether an address is eligible to be a derived native multisig account.
pub fn is_valid_multisig_account(account: Address) -> bool {
    !account.is_zero()
        && !account.is_tip20()
        && !account.is_virtual()
        && !is_native_precompile_address(account)
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

fn recover_multisig_owner_addresses(
    digest: B256,
    signatures: &[Bytes],
) -> Result<Vec<Address>, &'static str> {
    if signatures.is_empty() {
        return Err("multisig signatures cannot be empty");
    }
    if signatures.len() > MAX_MULTISIG_OWNERS {
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

/// Decodes, verifies, and weight-accounts primitive owner approvals.
///
/// This helper does not validate nested multisig owner approvals because that requires state access
/// to load each nested account config.
pub fn verify_multisig_owner_signatures(
    digest: B256,
    signatures: &[Bytes],
    config: &InitMultisig,
) -> Result<u8, &'static str> {
    validate_multisig_config(config)?;
    let owners = recover_multisig_owner_addresses(digest, signatures)?;
    verify_recovered_multisig_owners(&owners, config)
}

/// Verifies primitive owner approvals against a config already validated by trusted storage.
///
/// This helper does not validate nested multisig owner approvals because that requires state access
/// to load each nested account config.
pub fn verify_trusted_multisig_owner_signatures(
    digest: B256,
    signature: &MultisigSignature,
    config: &InitMultisig,
) -> Result<u8, &'static str> {
    signature.with_recovered_owners(digest, |owners| {
        verify_recovered_multisig_owners(owners, config)
    })
}

fn verify_recovered_multisig_owners(
    owners: &[Address],
    config: &InitMultisig,
) -> Result<u8, &'static str> {
    if owners.is_empty() {
        return Err("multisig signatures cannot be empty");
    }
    if owners.len() > MAX_MULTISIG_OWNERS {
        return Err("too many multisig signatures");
    }

    if let ([owner], [configured_owner]) = (owners, config.owners.as_slice()) {
        if *owner != configured_owner.owner {
            return Err("multisig signer is not an owner");
        }
        let recovered_weight = u16::from(configured_owner.weight);
        if recovered_weight < u16::from(config.threshold) {
            return Err("multisig signature weight below threshold");
        }

        return Ok(configured_owner.weight);
    }

    let mut recovered_weight = 0u16;
    let mut prev_owner = None;
    for &owner in owners {
        if prev_owner.is_some_and(|prev| prev >= owner) {
            return Err("multisig recovered owners must be strictly ascending");
        }
        prev_owner = Some(owner);

        let configured_owner = config
            .owners
            .binary_search_by_key(&owner, |entry| entry.owner)
            .map(|idx| &config.owners[idx])
            .map_err(|_| "multisig signer is not an owner")?;

        recovered_weight = recovered_weight
            .checked_add(u16::from(configured_owner.weight))
            .ok_or("multisig recovered owner weight overflow")?;
    }

    if recovered_weight < u16::from(config.threshold) {
        return Err("multisig signature weight below threshold");
    }

    u8::try_from(recovered_weight).map_err(|_| "multisig recovered owner weight overflow")
}

fn encode_multisig_owner_count(owner_count: usize) -> Result<u8, &'static str> {
    if owner_count == 0 {
        return Err("multisig owners cannot be empty");
    }
    if owner_count > MAX_MULTISIG_OWNERS {
        return Err("too many multisig owners");
    }
    Ok(owner_count as u8)
}

fn is_native_precompile_address(account: Address) -> bool {
    if account.as_slice()[..19] == [0u8; 19] && (1..=0x11).contains(&account.as_slice()[19]) {
        return true;
    }

    [
        TIP_FEE_MANAGER_ADDRESS,
        TIP20_FACTORY_ADDRESS,
        TIP403_REGISTRY_ADDRESS,
        STABLECOIN_DEX_ADDRESS,
        NONCE_PRECOMPILE_ADDRESS,
        VALIDATOR_CONFIG_ADDRESS,
        ACCOUNT_KEYCHAIN_ADDRESS,
        VALIDATOR_CONFIG_V2_ADDRESS,
        ADDRESS_REGISTRY_ADDRESS,
        SIGNATURE_VERIFIER_ADDRESS,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        RECEIVE_POLICY_GUARD_ADDRESS,
        NATIVE_MULTISIG_ADDRESS,
    ]
    .contains(&account)
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for MultisigSignature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(1..=MAX_MULTISIG_OWNERS)?;
        let mut signatures = Vec::new();
        for _ in 0..len {
            signatures.push(Bytes::from(Vec::<u8>::arbitrary(u)?));
        }
        Ok(Self::new(u.arbitrary()?, signatures, u.arbitrary()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{
        TempoSignature,
        tt_authorization::tests::{generate_secp256k1_keypair, sign_hash},
    };
    use alloy_rlp::{Decodable, Encodable};
    use proptest::prelude::*;

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

        validate_multisig_config(&config).expect("config is valid");
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
        assert!(validate_multisig_config(&unsorted).is_err());
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
        validate_multisig_config(&zero_salt).expect("zero salt is valid");
    }

    #[test]
    fn config_accepts_255_owners() {
        let owners = (1..=MAX_MULTISIG_OWNERS as u16)
            .map(|index| (indexed_owner(index), 1))
            .collect::<Vec<_>>();
        let config = sorted_secp_config(&owners, u8::MAX);

        assert_eq!(validate_multisig_config(&config), Ok(u8::MAX));
        assert!(config.account().is_ok());
    }

    #[test]
    fn config_rejects_more_than_255_owners() {
        let owners = (1..=MAX_MULTISIG_OWNERS as u16 + 1)
            .map(|index| (indexed_owner(index), 1))
            .collect::<Vec<_>>();
        let config = sorted_secp_config(&owners, u8::MAX);

        assert_eq!(
            validate_multisig_config(&config),
            Err("too many multisig owners")
        );
    }

    #[test]
    fn config_total_weight_is_capped_at_u8_max() {
        let owner_a = Address::from([0x11; 20]);
        let owner_b = Address::from([0x22; 20]);
        let config = sorted_secp_config(&[(owner_a, 128), (owner_b, 128)], u8::MAX);

        assert_eq!(
            validate_multisig_config(&config),
            Err("multisig total owner weight exceeds u8::MAX")
        );
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
            verify_multisig_owner_signatures(digest_a, &[signature.clone()], &config_a).is_ok()
        );
        assert!(
            verify_multisig_owner_signatures(
                multisig_digest(inner_digest, account_b),
                &[signature],
                &config_b,
            )
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
            verify_multisig_owner_signatures(digest, &signatures, &config).unwrap(),
            2
        );

        let one_signature = vec![signatures[0].clone()];
        assert!(verify_multisig_owner_signatures(digest, &one_signature, &config).is_err());
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
                    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..128), 0..=MAX_MULTISIG_OWNERS),
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
