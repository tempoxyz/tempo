use commonware_codec::{EncodeSize, Read, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_utils::set::Ordered;

use crate::dkg::manager::{actor::DkgOutcome, validators::ValidatorState};

/// All state for an epoch:
///
/// + the DKG outcome containing the public key, the private key share, and the
///   participants fo the epoch
/// + the validator state, containing the dealers of the epoch (corresponds to
///   the participants in the DKG outcome), the players of the next ceremony,
///   and the syncing players, who will be players in the ceremony thereafter.
#[derive(Clone, Debug)]
pub(super) struct EpochState {
    pub(super) dkg_outcome: DkgOutcome,
    pub(super) validator_state: ValidatorState,
}

impl EpochState {
    pub(super) fn epoch(&self) -> Epoch {
        self.dkg_outcome.epoch
    }

    pub(super) fn participants(&self) -> &Ordered<PublicKey> {
        &self.dkg_outcome.participants
    }

    pub(super) fn public_polynomial(&self) -> &Public<MinSig> {
        &self.dkg_outcome.public
    }

    pub(super) fn private_share(&self) -> &Option<Share> {
        &self.dkg_outcome.share
    }

    pub(super) fn dealer_pubkeys(&self) -> Ordered<PublicKey> {
        self.validator_state.dealer_pubkeys()
    }

    pub(super) fn player_pubkeys(&self) -> Ordered<PublicKey> {
        self.validator_state.player_pubkeys()
    }
}

impl Write for EpochState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dkg_outcome.write(buf);
        self.validator_state.write(buf);
    }
}

impl EncodeSize for EpochState {
    fn encode_size(&self) -> usize {
        self.dkg_outcome.encode_size() + self.validator_state.encode_size()
    }
}

impl Read for EpochState {
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
