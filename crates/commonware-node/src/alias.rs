//! A collection of aliases for frequently used (primarily commonware) types.

pub(crate) mod marshal {
    use commonware_consensus::{marshal, simplex::signing_scheme::bls12381_threshold::Scheme};
    use commonware_cryptography::bls12381::primitives::variant::MinSig;

    use crate::consensus::block::Block;

    pub(crate) type Actor<TContext> =
        marshal::Actor<TContext, Block, crate::dkg::manager::Mailbox, Scheme<MinSig>>;

    pub(crate) type Mailbox = marshal::Mailbox<Scheme<MinSig>, Block>;
}
