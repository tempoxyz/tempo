//! Malachite consensus context implementation.
//!
//! This module provides the context implementation required by Malachite consensus,
//! defining all the associated types and trait implementations needed to run the
//! consensus protocol. It acts as the main bridge between Malachite's generic
//! consensus implementation and our specific blockchain types.
//!
//! # Key Components
//!
//! - [`MalachiteContext`]: The main context type implementing Malachite's `Context` trait
//! - [`BasePeer`], [`BasePeerSet`], [`BasePeerAddress`]: Types for consensus participants
//! - [`BaseProposal`], [`BaseVote`], [`BaseExtension`]: Consensus message types
//! - Wrapper types for Malachite core types to add required trait implementations

use crate::{
    height::Height,
    provider::{Ed25519Provider, PublicKey},
    types::{Address, ProposalPart, Value, ValueId},
};
use malachitebft_core_types::{
    Address as MalachiteAddress, Context, Extension as MalachiteExtension, Height as HeightTrait,
    NilOrVal, Proposal as MalachiteProposal, Round, SignedMessage, Validator as MalachiteValidator,
    ValidatorSet as MalachiteValidatorSet, Vote as MalachiteVote, VoteType,
};
use serde::{Deserialize, Serialize};
use std::{fmt, fmt::Display};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoundWrapper(pub Round);

impl From<Round> for RoundWrapper {
    fn from(r: Round) -> Self {
        Self(r)
    }
}

impl From<RoundWrapper> for Round {
    fn from(r: RoundWrapper) -> Self {
        r.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VoteTypeWrapper(pub VoteType);

impl From<VoteType> for VoteTypeWrapper {
    fn from(vt: VoteType) -> Self {
        Self(vt)
    }
}

impl From<VoteTypeWrapper> for VoteType {
    fn from(vt: VoteTypeWrapper) -> Self {
        vt.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MalachiteContext {
    signing_provider: Ed25519Provider,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BasePeerAddress(pub Address);

impl BasePeerAddress {
    pub fn new(addr: Address) -> Self {
        Self(addr)
    }
}

impl From<Address> for BasePeerAddress {
    fn from(addr: Address) -> Self {
        Self(addr)
    }
}

impl Display for BasePeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl MalachiteAddress for BasePeerAddress {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BaseProposal {
    pub height: Height,
    pub round: RoundWrapper,
    pub value: Value,
    pub proposer: BasePeerAddress,
    pub parts: Vec<ProposalPart>,
    pub pol_round: RoundWrapper,
}

impl MalachiteProposal<MalachiteContext> for BaseProposal {
    fn height(&self) -> Height {
        self.height
    }

    fn round(&self) -> Round {
        self.round.0
    }

    fn value(&self) -> &Value {
        &self.value
    }

    fn take_value(self) -> Value {
        self.value
    }

    fn pol_round(&self) -> Round {
        self.pol_round.0
    }

    fn validator_address(&self) -> &BasePeerAddress {
        &self.proposer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasePeer {
    pub address: BasePeerAddress,
    pub public_key: PublicKey,
    pub voting_power: u64,
}

impl MalachiteValidator<MalachiteContext> for BasePeer {
    fn address(&self) -> &BasePeerAddress {
        &self.address
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn voting_power(&self) -> u64 {
        self.voting_power
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasePeerSet {
    pub peers: Vec<BasePeer>,
    pub total_voting_power: u64,
}

impl MalachiteValidatorSet<MalachiteContext> for BasePeerSet {
    fn count(&self) -> usize {
        self.peers.len()
    }

    fn total_voting_power(&self) -> u64 {
        self.total_voting_power
    }

    fn get_by_address(&self, addr: &BasePeerAddress) -> Option<&BasePeer> {
        self.peers.iter().find(|p| p.address() == addr)
    }

    fn get_by_index(&self, idx: usize) -> Option<&BasePeer> {
        self.peers.get(idx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseVote {
    pub vote_type: VoteTypeWrapper,
    pub height: Height,
    pub round: RoundWrapper,
    pub value_id: NilOrVal<ValueId>,
    pub voter: BasePeerAddress,
    pub extension: Option<SignedMessage<MalachiteContext, BaseExtension>>,
}

impl PartialOrd for BaseVote {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BaseVote {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare all fields except extension
        self.vote_type
            .cmp(&other.vote_type)
            .then_with(|| self.height.cmp(&other.height))
            .then_with(|| self.round.cmp(&other.round))
            .then_with(|| self.value_id.cmp(&other.value_id))
            .then_with(|| self.voter.cmp(&other.voter))
            // For extension, we just compare presence
            .then_with(|| self.extension.is_some().cmp(&other.extension.is_some()))
    }
}

impl MalachiteVote<MalachiteContext> for BaseVote {
    fn vote_type(&self) -> VoteType {
        self.vote_type.0
    }

    fn height(&self) -> Height {
        self.height
    }

    fn round(&self) -> Round {
        self.round.0
    }

    fn value(&self) -> &NilOrVal<ValueId> {
        &self.value_id
    }

    fn take_value(self) -> NilOrVal<ValueId> {
        self.value_id
    }

    fn validator_address(&self) -> &BasePeerAddress {
        &self.voter
    }

    fn extension(&self) -> Option<&SignedMessage<MalachiteContext, BaseExtension>> {
        self.extension.as_ref()
    }

    fn take_extension(&mut self) -> Option<SignedMessage<MalachiteContext, BaseExtension>> {
        self.extension.take()
    }

    fn extend(mut self, ext: SignedMessage<MalachiteContext, BaseExtension>) -> Self {
        self.extension = Some(ext);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BaseExtension {
    pub data: Vec<u8>,
}

impl MalachiteExtension for BaseExtension {
    fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

impl Context for MalachiteContext {
    type Address = BasePeerAddress;
    type Height = Height;
    type ProposalPart = ProposalPart;
    type Proposal = BaseProposal;
    type Validator = BasePeer;
    type ValidatorSet = BasePeerSet;
    type Value = Value;
    type Vote = BaseVote;
    type Extension = BaseExtension;
    type SigningScheme = Ed25519Provider;

    fn select_proposer<'a>(
        &self,
        validators: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        // Implement round-robin proposer selection
        // proposer_index = (height - 1 + round) % validator_count
        let height_offset = height.as_u64().saturating_sub(1) as usize;
        let round_offset = round.as_i64().max(0) as usize;
        let proposer_index = (height_offset + round_offset) % validators.count();

        validators
            .get_by_index(proposer_index)
            .expect("proposer_index is valid")
    }

    fn new_proposal(
        &self,
        height: Self::Height,
        round: Round,
        value: Self::Value,
        pol_round: Round,
        proposer: Self::Address,
    ) -> Self::Proposal {
        BaseProposal {
            height,
            round: RoundWrapper(round),
            value,
            proposer,
            parts: vec![], // TODO: fill with actual parts if needed
            pol_round: RoundWrapper(pol_round),
        }
    }

    fn new_prevote(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId>,
        voter: Self::Address,
    ) -> Self::Vote {
        BaseVote {
            vote_type: VoteTypeWrapper(VoteType::Prevote),
            height,
            round: RoundWrapper(round),
            value_id,
            voter,
            extension: None,
        }
    }

    fn new_precommit(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId>,
        voter: Self::Address,
    ) -> Self::Vote {
        BaseVote {
            vote_type: VoteTypeWrapper(VoteType::Precommit),
            height,
            round: RoundWrapper(round),
            value_id,
            voter,
            extension: None,
        }
    }
}
