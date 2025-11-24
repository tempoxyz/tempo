pub mod ceremony;
pub use ceremony::{IntermediateOutcome, PublicOutcome, State as CeremonyState};
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt as _, Write, varint::UInt};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_utils::{quorum, set::Ordered};
pub(crate) mod manager;

/// The state with all participants, public and private key share for an epoch.
#[derive(Clone)]
pub struct EpochState {
    epoch: u64,
    participants: Ordered<PublicKey>,
    public: Public<MinSig>,
    share: Option<Share>,
}

impl Write for EpochState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        UInt(self.epoch).write(buf);
        self.participants.write(buf);
        self.public.write(buf);
        self.share.write(buf);
    }
}

impl EncodeSize for EpochState {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size()
            + self.participants.encode_size()
            + self.public.encode_size()
            + self.share.encode_size()
    }
}

impl Read for EpochState {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let epoch = UInt::read(buf)?.into();
        let participants = Ordered::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?;
        let public =
            Public::<MinSig>::read_cfg(buf, &(quorum(participants.len() as u32) as usize))?;
        let share = Option::<Share>::read_cfg(buf, &())?;
        Ok(Self {
            epoch,
            participants,
            public,
            share,
        })
    }
}
