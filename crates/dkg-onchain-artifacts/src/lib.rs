//! Items that are written to chain.

use std::num::NonZeroU32;

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::Output,
        primitives::{poly::Public, variant::MinSig},
    },
    ed25519::PublicKey,
};
use commonware_utils::{NZU32, ordered};

const MAX_VALIDATORS: NonZeroU32 = NZU32!(u16::MAX as u32);

/// The outcome of a DKG ceremony as it is written to the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnchainDkgOutcome {
    pub epoch: Epoch,
    pub output: Output<MinSig, PublicKey>,
    pub next_players: ordered::Set<PublicKey>,
}

impl OnchainDkgOutcome {
    pub fn players(&self) -> &ordered::Set<PublicKey> {
        self.output.players()
    }

    pub fn next_players(&self) -> &ordered::Set<PublicKey> {
        &self.next_players
    }

    pub fn public(&self) -> &Public<MinSig> {
        self.output.public()
    }
}

impl Write for OnchainDkgOutcome {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.output.write(buf);
        self.next_players.write(buf);
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
        Ok(Self {
            epoch,
            output,
            next_players,
        })
    }
}

impl EncodeSize for OnchainDkgOutcome {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.output.encode_size() + self.next_players.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, iter::repeat_with};

    use commonware_codec::{Encode as _, ReadExt as _};
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{
        PrivateKeyExt as _, Signer as _,
        bls12381::{
            dkg::{Dealer, Info, Player},
            primitives::variant::MinSig,
        },
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::{TryFromIterator as _, ordered};
    use rand::SeedableRng as _;

    use super::OnchainDkgOutcome;

    #[test]
    fn onchain_dkg_outcome_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let dealer_key = PrivateKey::from_rng(&mut rng);

        let mut player_keys = repeat_with(|| PrivateKey::from_rng(&mut rng))
            .take(10)
            .collect::<Vec<_>>();
        player_keys.sort_by_key(|key| key.public_key());

        let info = Info::<MinSig, PublicKey>::new(
            b"test",
            42,
            None,
            ordered::Set::try_from_iter(std::iter::once(dealer_key.public_key())).unwrap(),
            ordered::Set::try_from_iter(player_keys.iter().map(|key| key.public_key())).unwrap(),
        )
        .unwrap();

        let (mut dealer, pub_msg, priv_msgs) =
            Dealer::start(rng, info.clone(), dealer_key.clone(), None).unwrap();

        let priv_msgs = priv_msgs.into_iter().collect::<BTreeMap<_, _>>();
        let mut players = player_keys
            .iter()
            .cloned()
            .map(|key| Player::new(info.clone(), key).unwrap())
            .collect::<Vec<_>>();

        for (player, key) in players.iter_mut().zip(&player_keys) {
            let ack = player
                .dealer_message(
                    dealer_key.public_key(),
                    pub_msg.clone(),
                    priv_msgs.get(&key.public_key()).cloned().unwrap(),
                )
                .unwrap();
            dealer.receive_player_ack(key.public_key(), ack).unwrap();
        }
        let signed_log = dealer.finalize();
        let (_, log) = signed_log.check(&info).unwrap();
        let logs = BTreeMap::from([(dealer_key.public_key(), log)]);

        let outputs = players
            .into_iter()
            .map(|player| player.finalize(logs.clone(), 1).unwrap())
            .collect::<Vec<_>>();
        let output = outputs[0].0.clone();
        assert!(outputs.iter().all(|(o, _)| &output == o));

        let on_chain = OnchainDkgOutcome {
            epoch: Epoch::new(42),
            output,
            next_players: ordered::Set::try_from_iter(
                player_keys.iter().map(|key| key.public_key()),
            )
            .unwrap(),
        };
        let bytes = on_chain.encode();
        assert_eq!(
            OnchainDkgOutcome::read(&mut bytes.as_ref()).unwrap(),
            on_chain,
        );
    }
}
