use crate::height::Height;
use crate::provider::Ed25519Provider;
use crate::state::Address;
use hex;
use malachitebft_core_types::{
    Address as MalachiteAddress, Context, Extension as MalachiteExtension,
    NilOrVal, Proposal as MalachiteProposal,
    ProposalPart as MalachiteProposalPart, Round, SignedMessage,
    Validator as MalachiteValidator, ValidatorSet as MalachiteValidatorSet,
    Value as MalachiteValue, Vote as MalachiteVote, VoteType,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Display;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoundWrapper(Round);

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VoteTypeWrapper(VoteType);

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalachiteContext {
    signing_provider: Ed25519Provider,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BasePeerAddress(Address);

impl Display for BasePeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl MalachiteAddress for BasePeerAddress {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BaseProposalPart {
    pub height: Height,
    pub round: RoundWrapper,
    pub value: BaseValue,
    pub proposer: BasePeerAddress,
}

impl MalachiteProposalPart<MalachiteContext> for BaseProposalPart {
    fn is_first(&self) -> bool {
        self.round.0 == Round::Nil
    }

    fn is_last(&self) -> bool {
        false // TODO: Implement proper logic
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BaseProposal {
    pub height: Height,
    pub round: RoundWrapper,
    pub value: BaseValue,
    pub proposer: BasePeerAddress,
    pub parts: Vec<BaseProposalPart>,
    pub pol_round: RoundWrapper,
}

impl MalachiteProposal<MalachiteContext> for BaseProposal {
    fn height(&self) -> Height {
        self.height
    }

    fn round(&self) -> Round {
        self.round.0
    }

    fn value(&self) -> &BaseValue {
        &self.value
    }

    fn take_value(self) -> BaseValue {
        self.value
    }

    fn pol_round(&self) -> Round {
        self.pol_round.0
    }

    fn validator_address(&self) -> &BasePeerAddress {
        &self.proposer
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BasePeer {
    pub address: BasePeerAddress,
    pub public_key: Vec<u8>,
    pub voting_power: u64,
}

impl MalachiteValidator<MalachiteContext> for BasePeer {
    fn address(&self) -> &BasePeerAddress {
        &self.address
    }

    fn public_key(&self) -> &Vec<u8> {
        &self.public_key
    }

    fn voting_power(&self) -> u64 {
        self.voting_power
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BaseValue {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ValueIdWrapper(Vec<u8>);

impl ValueIdWrapper {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl MalachiteValue for BaseValue {
    type Id = ValueIdWrapper;

    fn id(&self) -> Self::Id {
        ValueIdWrapper::new(self.data.clone())
    }
}

impl std::fmt::Display for ValueIdWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BaseVote {
    pub vote_type: VoteTypeWrapper,
    pub height: Height,
    pub round: RoundWrapper,
    pub value_id: NilOrVal<ValueIdWrapper>,
    pub voter: BasePeerAddress,
    pub extension: Option<SignedMessage<MalachiteContext, BaseExtension>>,
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

    fn value(&self) -> &NilOrVal<ValueIdWrapper> {
        &self.value_id
    }

    fn take_value(self) -> NilOrVal<ValueIdWrapper> {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    type ProposalPart = BaseProposalPart;
    type Proposal = BaseProposal;
    type Validator = BasePeer;
    type ValidatorSet = BasePeerSet;
    type Value = BaseValue;
    type Vote = BaseVote;
    type Extension = BaseExtension;
    type SigningScheme = Ed25519Provider;

    fn select_proposer<'a>(
        &self,
        validators: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        // For demonstration, always select the first validator
        validators
            .get_by_index(0)
            .expect("ValidatorSet is not empty")
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
        value_id: NilOrVal<ValueIdWrapper>,
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
        value_id: NilOrVal<ValueIdWrapper>,
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

// Implement Default for MalachiteContext
impl Default for MalachiteContext {
    fn default() -> Self {
        Self {
            signing_provider: Ed25519Provider::new(),
        }
    }
}
