use std::num::NonZeroU32;

use bytes::{Buf, BufMut};
use commonware_codec::{Encode as _, EncodeSize, Read, Write};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{
            sharing::{ModeVersion, Sharing},
            variant::MinSig,
        },
    },
    ed25519::PublicKey,
};
use commonware_utils::ordered;

/// A DKG outcome whose equality ignores the set of revealed players.
#[derive(Clone, Debug)]
pub(super) struct IgnoreRevealed(Output<MinSig, PublicKey>);

impl IgnoreRevealed {
    pub(super) fn public(&self) -> &Sharing<MinSig> {
        self.0.public()
    }

    pub(super) fn players(&self) -> &ordered::Set<PublicKey> {
        self.0.players()
    }

    pub(super) fn into_inner(self) -> Output<MinSig, PublicKey> {
        self.0
    }
}

impl From<Output<MinSig, PublicKey>> for IgnoreRevealed {
    fn from(outcome: Output<MinSig, PublicKey>) -> Self {
        Self(outcome)
    }
}

impl PartialEq for IgnoreRevealed {
    fn eq(&self, other: &Self) -> bool {
        output_without_revealed(&self.0) == output_without_revealed(&other.0)
    }
}

impl Eq for IgnoreRevealed {}

impl Write for IgnoreRevealed {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for IgnoreRevealed {
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Output::read_cfg(buf, cfg).map(Self)
    }
}

impl EncodeSize for IgnoreRevealed {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

fn output_without_revealed(outcome: &Output<MinSig, PublicKey>) -> Vec<u8> {
    // `revealed` is the final field in `Output`'s canonical encoding, so this
    // retains every other field, including the private transcript summary.
    let mut encoded = outcome.encode().to_vec();
    encoded.truncate(encoded.len() - outcome.revealed().encode_size());
    encoded
}

#[cfg(test)]
mod tests {
    use commonware_codec::{Encode as _, EncodeSize as _, Read as _, Write as _};
    use commonware_cryptography::{
        Signer as _,
        bls12381::{
            dkg::feldman_desmedt::{self as dkg, Output},
            primitives::{sharing::ModeVersion, variant::MinSig},
        },
        ed25519::PrivateKey,
    };
    use commonware_math::algebra::Random as _;
    use commonware_utils::{N3f1, NZU32, TryFromIterator as _, ordered};
    use rand::SeedableRng as _;

    use super::IgnoreRevealed;

    #[test]
    fn equality_ignores_revealed_players() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let keys = (0..4)
            .map(|_| PrivateKey::random(&mut rng))
            .collect::<Vec<_>>();
        let players = ordered::Set::try_from_iter(keys.iter().map(|key| key.public_key())).unwrap();
        let (output, _) =
            dkg::deal::<MinSig, _, N3f1>(&mut rng, Default::default(), players).unwrap();

        let mut encoded = output.encode().to_vec();
        encoded.truncate(encoded.len() - output.revealed().encode_size());
        ordered::Set::try_from_iter([keys[0].public_key()])
            .unwrap()
            .write(&mut encoded);
        let output_with_reveal =
            Output::read_cfg(&mut encoded.as_slice(), &(NZU32!(4), ModeVersion::v0())).unwrap();

        assert_eq!(
            IgnoreRevealed::from(output),
            IgnoreRevealed::from(output_with_reveal)
        );
    }
}
