//! A collection of aliases for frequently used (primarily commonware) types.

pub(crate) mod marshal {
    use commonware_consensus::{marshal, simplex::signing_scheme::bls12381_threshold::Scheme};
    use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};

    use crate::consensus::block::Block;

    pub(crate) type Actor<TContext> =
        marshal::Actor<TContext, Block, crate::epoch::SchemeProvider, Scheme<PublicKey, MinSig>>;

    pub(crate) type Mailbox = marshal::Mailbox<Scheme<PublicKey, MinSig>, Block>;
}
