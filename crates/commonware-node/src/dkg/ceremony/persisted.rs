//! Information about a ceremony that is persisted to disk.

use std::collections::BTreeMap;

use bytes::Buf;
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::{
    bls12381::primitives::{group, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};

use super::DealingOutcome;

/// Information on a ceremony that is persisted to disk.
#[derive(Clone, Default)]
pub(in crate::dkg) struct State {
    /// Tracks the local dealing if we participate as a dealer.
    pub(super) dealing: Option<Dealing>,

    /// Tracks the shares received from other dealers, if we are a player.
    pub(super) received_shares: Vec<(PublicKey, Public<MinSig>, group::Share)>,

    pub(super) dealing_outcome: Option<DealingOutcome>,

    pub(super) outcomes: Vec<DealingOutcome>,
}

impl Write for State {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealing.write(buf);
        self.received_shares.write(buf);
        self.dealing_outcome.write(buf);
        self.outcomes.write(buf);
    }
}

impl EncodeSize for State {
    fn encode_size(&self) -> usize {
        self.dealing.encode_size()
            + self.received_shares.encode_size()
            + self.dealing_outcome.encode_size()
            + self.outcomes.encode_size()
    }
}

impl Read for State {
    // The consensus quorum
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            dealing: Option::<Dealing>::read_cfg(buf, cfg)?,
            received_shares: Vec::<(PublicKey, Public<MinSig>, group::Share)>::read_cfg(
                buf,
                &(RangeCfg::from(0..usize::MAX), ((), *cfg, ())),
            )?,
            dealing_outcome: Option::<DealingOutcome>::read_cfg(buf, cfg)?,
            outcomes: Vec::<DealingOutcome>::read_cfg(buf, &(RangeCfg::from(0..usize::MAX), *cfg))?,
        })
    }
}

/// The local dealing of the current ceremony.
///
/// Here, the dealer tracks its generated commmitment and shares, as well
/// as the acknowledgments it received for its shares.
#[derive(Clone)]
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
