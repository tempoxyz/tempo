//! Information about a ceremony that is persisted to disk.

use std::collections::BTreeMap;

use bytes::Buf;
use commonware_codec::{EncodeSize, RangeCfg, Read, Write, varint::UInt};
use commonware_cryptography::{
    bls12381::primitives::{group, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_utils::quorum;

use super::IntermediateOutcome;

/// Information on a ceremony that is persisted to disk.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct State {
    pub(super) num_players: u64,

    /// Tracks the local dealing if we participate as a dealer.
    pub(super) dealing: Option<Dealing>,

    /// Tracks the shares received from other dealers, if we are a player.
    pub(super) received_shares: Vec<(PublicKey, Public<MinSig>, group::Share)>,

    pub(super) dealing_outcome: Option<IntermediateOutcome>,

    pub(super) outcomes: Vec<IntermediateOutcome>,
}

impl Write for State {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        UInt(self.num_players).write(buf);
        self.dealing.write(buf);
        self.received_shares.write(buf);
        self.dealing_outcome.write(buf);
        self.outcomes.write(buf);
    }
}

impl EncodeSize for State {
    fn encode_size(&self) -> usize {
        UInt(self.num_players).encode_size()
            + self.dealing.encode_size()
            + self.received_shares.encode_size()
            + self.dealing_outcome.encode_size()
            + self.outcomes.encode_size()
    }
}

impl Read for State {
    // The consensus quorum
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let num_players = UInt::read_cfg(buf, &())?.into();
        Ok(Self {
            num_players,
            dealing: Option::<Dealing>::read_cfg(buf, &(quorum(num_players as u32) as usize))?,
            received_shares: Vec::<(PublicKey, Public<MinSig>, group::Share)>::read_cfg(
                buf,
                &(
                    RangeCfg::from(0..usize::MAX),
                    ((), quorum(num_players as u32) as usize, ()),
                ),
            )?,
            dealing_outcome: Option::<IntermediateOutcome>::read_cfg(buf, &())?,
            outcomes: Vec::<IntermediateOutcome>::read_cfg(
                buf,
                &(RangeCfg::from(0..usize::MAX), ()),
            )?,
        })
    }
}

/// The local dealing of the current ceremony.
///
/// Here, the dealer tracks its generated commitment and shares, as well
/// as the acknowledgments it received for its shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Dealing {
    pub(super) commitment: Public<MinSig>,
    pub(super) shares: BTreeMap<PublicKey, group::Share>,
    pub(super) acks: BTreeMap<PublicKey, super::Ack>,
}

impl EncodeSize for Dealing {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.shares.encode_size() + self.acks.encode_size()
    }
}

impl Read for Dealing {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let commitment = Public::<MinSig>::read_cfg(buf, cfg)?;
        let shares = BTreeMap::read_cfg(buf, &(RangeCfg::from(0..usize::MAX), ((), ())))?;
        let acks = BTreeMap::read_cfg(buf, &(RangeCfg::from(0..usize::MAX), ((), ())))?;
        Ok(Self {
            commitment,
            shares,
            acks,
        })
    }
}

impl Write for Dealing {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.shares.write(buf);
        self.acks.write(buf);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::dkg::{
        IntermediateOutcome,
        ceremony::{ACK_NAMESPACE, Ack, OUTCOME_NAMESPACE},
    };

    use super::{Dealing, State};
    use commonware_codec::{Decode as _, Encode as _, Read as _};
    use commonware_cryptography::{
        PrivateKeyExt as _, Signer,
        bls12381::{dkg, primitives::variant::MinSig},
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::{quorum, set::Ordered, union};
    use rand::{SeedableRng as _, rngs::StdRng};

    fn four_private_keys() -> Ordered<PrivateKey> {
        vec![
            PrivateKey::from_seed(0),
            PrivateKey::from_seed(1),
            PrivateKey::from_seed(2),
            PrivateKey::from_seed(3),
        ]
        .into()
    }

    fn four_public_keys() -> Ordered<PublicKey> {
        vec![
            PrivateKey::from_seed(0).public_key(),
            PrivateKey::from_seed(1).public_key(),
            PrivateKey::from_seed(2).public_key(),
            PrivateKey::from_seed(3).public_key(),
        ]
        .into()
    }

    fn dealing(dealer_index: usize) -> Dealing {
        let (_, commitment, shares) = dkg::Dealer::<_, MinSig>::new(
            &mut StdRng::from_seed([dealer_index as u8; 32]),
            None,
            four_public_keys(),
        );
        let shares = four_public_keys().iter().cloned().zip(shares).collect();

        let mut acks = BTreeMap::new();
        acks.insert(
            four_public_keys()[0].clone(),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[0].clone(),
                four_public_keys()[0].clone(),
                42,
                &four_public_keys()[dealer_index],
                &commitment,
            ),
        );
        acks.insert(
            four_public_keys()[1].clone(),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[1].clone(),
                four_public_keys()[1].clone(),
                42,
                &four_public_keys()[dealer_index],
                &commitment,
            ),
        );
        acks.insert(
            four_public_keys()[2].clone(),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[2].clone(),
                four_public_keys()[2].clone(),
                42,
                &four_public_keys()[dealer_index],
                &commitment,
            ),
        );
        acks.insert(
            four_public_keys()[3].clone(),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[3].clone(),
                four_public_keys()[3].clone(),
                42,
                &four_public_keys()[dealer_index],
                &commitment,
            ),
        );
        Dealing {
            commitment,
            shares,
            acks,
        }
    }

    fn dealing_outcome(dealer_index: usize) -> IntermediateOutcome {
        let mut dealing = dealing(dealer_index);

        IntermediateOutcome::new(
            4,
            &four_private_keys()[0],
            &union(b"test", OUTCOME_NAMESPACE),
            42,
            dealing.commitment,
            dealing.acks.values().cloned().collect(),
            vec![dealing.shares.pop_last().unwrap().1],
        )
    }

    #[test]
    fn roundtrip_dealing() {
        let bytes = dealing(0).encode();

        assert_eq!(
            Dealing::read_cfg(&mut bytes.as_ref(), &(quorum(4) as usize)).unwrap(),
            dealing(0),
        )
    }

    #[test]
    fn roundtrip_state() {
        let state = State {
            num_players: 4,
            dealing: Some(dealing(0)),
            received_shares: vec![
                (
                    four_public_keys()[1].clone(),
                    dealing(1).commitment,
                    dealing(1).shares[&four_public_keys()[0]].clone(),
                ),
                (
                    four_public_keys()[2].clone(),
                    dealing(2).commitment,
                    dealing(2).shares[&four_public_keys()[0]].clone(),
                ),
            ],
            dealing_outcome: Some(dealing_outcome(0)),
            outcomes: vec![dealing_outcome(1), dealing_outcome(2)],
        };

        let bytes = state.encode().freeze();

        assert_eq!(State::decode_cfg(&mut bytes.as_ref(), &()).unwrap(), state);
    }
}
