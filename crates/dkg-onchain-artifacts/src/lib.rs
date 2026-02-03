//! Items that are written to chain.

use std::num::NonZeroU32;

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::Output,
        primitives::{sharing::Sharing, variant::MinSig},
    },
    ed25519::PublicKey,
};
use commonware_utils::{NZU32, ordered};

const MAX_VALIDATORS: NonZeroU32 = NZU32!(u16::MAX as u32);

/// The outcome of a DKG ceremony as it is written to the chain.
///
/// This DKG outcome can encode up to [`u16::MAX`] validators. Note that in
/// practice this far exceeds the maximum size permitted header size and so
/// is likely out of reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnchainDkgOutcome {
    /// The epoch for which this outcome is used.
    pub epoch: Epoch,

    /// The output of the DKG ceremony. Contains the shared public polynomial,
    /// and the players in the ceremony (which will be the dealers for the
    /// epoch encoded with this output).
    pub output: Output<MinSig, PublicKey>,

    /// The next players. These will be the players in the DKG ceremony running
    /// during `epoch`.
    pub next_players: ordered::Set<PublicKey>,

    /// Whether the next DKG ceremony should be a full ceremony (new polynomial)
    /// instead of a reshare. Set when `nextFullDkgCeremony == epoch`.
    pub is_next_full_dkg: bool,
}

impl OnchainDkgOutcome {
    pub fn dealers(&self) -> &ordered::Set<PublicKey> {
        self.output.dealers()
    }

    pub fn players(&self) -> &ordered::Set<PublicKey> {
        self.output.players()
    }

    pub fn next_players(&self) -> &ordered::Set<PublicKey> {
        &self.next_players
    }

    pub fn sharing(&self) -> &Sharing<MinSig> {
        self.output.public()
    }
}

impl Write for OnchainDkgOutcome {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.output.write(buf);
        self.next_players.write(buf);
        self.is_next_full_dkg.write(buf);
    }
}

impl Read for OnchainDkgOutcome {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let epoch = ReadExt::read(buf)?;
        let output = Read::read_cfg(buf, &MAX_VALIDATORS)?;
        let next_players = Read::read_cfg(
            buf,
            &(RangeCfg::from(1..=(MAX_VALIDATORS.get() as usize)), ()),
        )?;
        let is_next_full_dkg = ReadExt::read(buf)?;
        Ok(Self {
            epoch,
            output,
            next_players,
            is_next_full_dkg,
        })
    }
}

impl EncodeSize for OnchainDkgOutcome {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.output.encode_size()
            + self.next_players.encode_size()
            + self.is_next_full_dkg.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use std::iter::repeat_with;

    use commonware_codec::{Encode as _, ReadExt as _};
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{Signer as _, bls12381::dkg, ed25519::PrivateKey};
    use commonware_math::algebra::Random as _;
    use commonware_utils::{N3f1, TryFromIterator as _, ordered};
    use rand_08::SeedableRng as _;

    use super::OnchainDkgOutcome;

    #[test]
    fn onchain_dkg_outcome_roundtrip() {
        let mut rng = rand_08::rngs::StdRng::seed_from_u64(42);

        let mut player_keys = repeat_with(|| PrivateKey::random(&mut rng))
            .take(10)
            .collect::<Vec<_>>();
        player_keys.sort_by_key(|key| key.public_key());
        let (output, _shares) = dkg::deal::<_, _, N3f1>(
            &mut rng,
            Default::default(),
            ordered::Set::try_from_iter(player_keys.iter().map(|key| key.public_key())).unwrap(),
        )
        .unwrap();

        let on_chain = OnchainDkgOutcome {
            epoch: Epoch::new(42),
            output,
            next_players: ordered::Set::try_from_iter(
                player_keys.iter().map(|key| key.public_key()),
            )
            .unwrap(),
            is_next_full_dkg: false,
        };
        let bytes = on_chain.encode();
        assert_eq!(
            OnchainDkgOutcome::read(&mut bytes.as_ref()).unwrap(),
            on_chain,
        );
    }
}
