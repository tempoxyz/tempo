use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt as _, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_utils::{NZU32, ordered, quorum};

use crate::dkg::manager::ValidatorState;

/// All state for an epoch:
///
/// + the DKG outcome containing the public key, the private key share, and the
///   participants for the epoch
/// + the validator state, containing the dealers of the epoch (corresponds to
///   the participants in the DKG outcome), the players of the next ceremony,
///   and the syncing players, who will be players in the ceremony thereafter.
#[derive(Clone, Debug)]
pub(in crate::dkg::manager) struct State {
    pub(super) dkg_outcome: DkgOutcome,
    pub(super) validator_state: ValidatorState,
}

impl State {
    pub(crate) fn epoch(&self) -> Epoch {
        self.dkg_outcome.epoch
    }

    pub(crate) fn participants(&self) -> &ordered::Set<PublicKey> {
        &self.dkg_outcome.participants
    }

    pub(crate) fn public_polynomial(&self) -> &Public<MinSig> {
        &self.dkg_outcome.public
    }

    pub(crate) fn private_share(&self) -> &Option<Share> {
        &self.dkg_outcome.share
    }

    pub(crate) fn dealer_pubkeys(&self) -> ordered::Set<PublicKey> {
        self.validator_state.dealer_pubkeys()
    }

    pub(crate) fn player_pubkeys(&self) -> ordered::Set<PublicKey> {
        self.validator_state.player_pubkeys()
    }
}

impl Write for State {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dkg_outcome.write(buf);
        self.validator_state.write(buf);
    }
}

impl EncodeSize for State {
    fn encode_size(&self) -> usize {
        self.dkg_outcome.encode_size() + self.validator_state.encode_size()
    }
}

impl Read for State {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let dkg_outcome = DkgOutcome::read_cfg(buf, &())?;
        let validator_state = ValidatorState::read_cfg(buf, &())?;
        Ok(Self {
            dkg_outcome,
            validator_state,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct DkgOutcome {
    /// Whether this outcome is due to a successful or a failed DKG ceremony.
    pub(super) dkg_successful: bool,

    /// The epoch that this DKG outcome is for (not during which it was running!).
    pub(super) epoch: Epoch,

    /// The participants in the next epoch as determined by the DKG.
    pub(super) participants: ordered::Set<PublicKey>,

    /// The public polynomial in the next epoch as determined by the DKG.
    pub(super) public: Public<MinSig>,

    /// The share of this node in the next epoch as determined by the DKG.
    pub(super) share: Option<Share>,
}

impl Write for DkgOutcome {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dkg_successful.write(buf);
        self.epoch.write(buf);
        self.participants.write(buf);
        self.public.write(buf);
        self.share.write(buf);
    }
}

impl EncodeSize for DkgOutcome {
    fn encode_size(&self) -> usize {
        self.dkg_successful.encode_size()
            + self.epoch.encode_size()
            + self.participants.encode_size()
            + self.public.encode_size()
            + self.share.encode_size()
    }
}

impl Read for DkgOutcome {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let dkg_successful = bool::read(buf)?;
        let epoch = Epoch::read(buf)?;
        let participants =
            ordered::Set::read_cfg(buf, &(RangeCfg::from(1..=(u16::MAX as usize)), ()))?;
        let quorum = quorum(participants.len() as u32);
        let public =
            Public::<MinSig>::read_cfg(buf, &RangeCfg::from(NZU32!(quorum)..=NZU32!(quorum)))?;
        let share = Option::<Share>::read_cfg(buf, &())?;
        Ok(Self {
            dkg_successful,
            epoch,
            participants,
            public,
            share,
        })
    }
}
