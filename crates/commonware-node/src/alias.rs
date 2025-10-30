//! A collection of aliases for frequently used (primarily commonware) types.

use commonware_consensus::simplex::signing_scheme::bls12381_threshold::Scheme;
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};

pub(crate) mod marshal {
    use super::*;
    use commonware_consensus::marshal;

    use crate::consensus::block::Block;

    pub(crate) type Actor<TContext> =
        marshal::Actor<TContext, Block, crate::epoch::SchemeProvider, ThresholdScheme>;

    pub(crate) type Mailbox = marshal::Mailbox<ThresholdScheme, Block>;
}

pub(crate) type ThresholdScheme = Scheme<PublicKey, MinSig>;
