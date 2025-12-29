//! A collection of aliases for frequently used (primarily commonware) types.

pub(crate) mod marshal {
    use commonware_consensus::{
        marshal,
        simplex::{signing_scheme::bls12381_threshold::Scheme, types::Finalization},
    };
    use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
    use commonware_storage::archive::immutable;
    use commonware_utils::acknowledgement::Exact;

    use crate::consensus::{Digest, block::Block};

    pub(crate) type Actor<TContext> = marshal::Actor<
        TContext,
        Block,
        crate::epoch::SchemeProvider,
        Scheme<PublicKey, MinSig>,
        immutable::Archive<TContext, Digest, Finalization<Scheme<PublicKey, MinSig>, Digest>>,
        immutable::Archive<TContext, Digest, Block>,
        Exact,
    >;

    pub(crate) type Mailbox = marshal::Mailbox<Scheme<PublicKey, MinSig>, Block>;
}
