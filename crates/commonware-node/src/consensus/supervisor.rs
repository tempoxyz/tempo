//! Interface to manage which participants are active at a time.
//!
//! One-to-one clone of alto's supervisor.
// TODO: Understand this. What does it require to update the participants?
// Can you even do that or is the list of participants always fixed at genesis?
// Will this require some feedback mechanism between execution layer and consensus layer
// (i.e. reth becoming aware of consensus and allowing to update peers)?

use commonware_consensus::types::View;
use commonware_cryptography::ed25519;
use commonware_resolver::p2p;
use std::collections::HashMap;

use tempo_commonware_node_cryptography::{
    BlsScheme, BlsSignature, GroupShare, Identity, PublicKey, PublicPolynomial,
};

/// Manages which participants are active at given time.
///
/// Implementation of `[commonware_consensus::Supervisor]`.
#[derive(Clone)]
pub(crate) struct Supervisor {
    identity: Identity,
    polynomial: Vec<Identity>,
    participants: Vec<ed25519::PublicKey>,
    participants_map: HashMap<ed25519::PublicKey, u32>,

    share: GroupShare,
}

impl Supervisor {
    /// Create a new [Supervisor].
    pub(crate) fn new(
        polynomial: PublicPolynomial,
        mut participants: Vec<ed25519::PublicKey>,
        share: GroupShare,
    ) -> Self {
        use commonware_cryptography::bls12381::dkg::ops::evaluate_all;
        // Setup participants
        participants.sort();
        let mut participants_map = HashMap::new();
        for (index, validator) in participants.iter().enumerate() {
            participants_map.insert(validator.clone(), index as u32);
        }
        let identity = *polynomial.constant();
        let polynomial = evaluate_all::<BlsScheme>(&polynomial, participants.len() as u32);

        // Return supervisor
        Self {
            identity,
            polynomial,
            participants,
            participants_map,
            share,
        }
    }
}

impl p2p::Coordinator for Supervisor {
    type PublicKey = PublicKey;

    fn peers(&self) -> &[Self::PublicKey] {
        &self.participants
    }

    fn peer_set_id(&self) -> u64 {
        0
    }
}

impl commonware_consensus::Supervisor for Supervisor {
    type Index = View;

    type PublicKey = PublicKey;

    fn leader(&self, _: Self::Index) -> Option<Self::PublicKey> {
        unimplemented!("only defined in supertrait")
    }

    fn participants(&self, _: Self::Index) -> Option<&[Self::PublicKey]> {
        Some(&self.participants)
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.participants_map.get(candidate).cloned()
    }
}

impl commonware_consensus::ThresholdSupervisor for Supervisor {
    type Seed = BlsSignature;
    type Identity = Identity;
    type Polynomial = Vec<Identity>;
    type Share = GroupShare;

    fn leader(&self, _: Self::Index, seed: Self::Seed) -> Option<Self::PublicKey> {
        use commonware_codec::Encode;
        let index = leader_index(seed.encode().as_ref(), self.participants.len());
        Some(self.participants[index].clone())
    }

    fn identity(&self) -> &Self::Identity {
        &self.identity
    }

    fn polynomial(&self, _: Self::Index) -> Option<&Self::Polynomial> {
        Some(&self.polynomial)
    }

    fn share(&self, _: Self::Index) -> Option<&Self::Share> {
        Some(&self.share)
    }
}

/// The leader for a given seed is determined by the modulo of the seed with the number of participants.
fn leader_index(seed: &[u8], participants: usize) -> usize {
    commonware_utils::modulo(seed, participants as u64) as usize
}
