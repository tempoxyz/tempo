//! Follower finalization driver.
//!
//! Validates finalized blocks received from upstream and reports them to marshal and the consensus
//! feed.

use std::future::Future;

use commonware_consensus::{
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Activity},
    types::{FixedEpocher, Height, Round},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::variant::MinSig,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random as _;
use commonware_runtime::{Clock, Spawner};
use commonware_utils::vec::NonEmptyVec;
use reth_primitives_traits::NodePrimitives;
use reth_provider::{
    BlockIdReader, HeaderProvider,
    providers::{BlockchainProvider, ProviderNodeTypes},
};
use tempo_chainspec::NetworkIdentity;
use tempo_primitives::TempoHeader;

use crate::{
    consensus::{Block, Digest},
    epoch::SchemeProvider,
    feed,
};

mod actor;
mod ingress;

#[cfg(test)]
mod test;

pub(super) use actor::Driver;
pub(super) use ingress::Mailbox;

type ConsensusActivity = Activity<Scheme<PublicKey, MinSig>, Digest>;

pub(super) struct Config<P, M, F> {
    pub(super) execution_provider: P,
    pub(super) scheme_provider: SchemeProvider,
    pub(super) network_identity: NetworkIdentity,

    pub(super) last_finalized_height: Height,

    pub(super) marshal: M,
    pub(super) feed: F,

    pub(super) epoch_strategy: FixedEpocher,
}

pub(super) fn try_init<TContext, P, M, F>(
    context: TContext,
    config: Config<P, M, F>,
) -> eyre::Result<(Driver<TContext, P, M, F>, Mailbox)>
where
    TContext: Clock + Spawner,
    P: ExecutionProvider + 'static,
    M: Marshal + 'static,
    F: Feed + 'static,
{
    actor::try_init(context, config)
}

/// Finalized execution-layer state needed to establish the driver's trusted boundary.
pub(super) trait ExecutionProvider: Send + Sync {
    fn finalized_block_number(&self) -> eyre::Result<u64>;
    fn finalized_header_by_number(&self, number: u64) -> eyre::Result<Option<TempoHeader>>;
}

/// Marshal operations used by the follower driver.
pub(super) trait Marshal: Send + Sync {
    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send;
    fn certified(&self, round: Round, block: Block) -> impl Future<Output = bool> + Send;
    fn report(&self, activity: ConsensusActivity) -> impl Future<Output = ()> + Send;
    fn hint_finalized(&self, height: Height) -> impl Future<Output = ()> + Send;
}

/// Consensus-feed operation used by the follower driver.
pub(super) trait Feed: Send + Sync {
    fn report(&self, activity: ConsensusActivity) -> impl Future<Output = ()> + Send;
}

impl<N> ExecutionProvider for BlockchainProvider<N>
where
    N: ProviderNodeTypes,
    N::Primitives: NodePrimitives<BlockHeader = TempoHeader>,
{
    fn finalized_block_number(&self) -> eyre::Result<u64> {
        Ok(BlockIdReader::finalized_block_num_hash(self)?.map_or(0, |f| f.number))
    }

    fn finalized_header_by_number(&self, number: u64) -> eyre::Result<Option<TempoHeader>> {
        HeaderProvider::header_by_number(self, number).map_err(eyre::Report::new)
    }
}

impl Marshal for crate::alias::marshal::Mailbox {
    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send {
        let mailbox = self.clone();
        async move { mailbox.get_block(height).await }
    }

    fn hint_finalized(&self, height: Height) -> impl Future<Output = ()> + Send {
        let mailbox = self.clone();
        async move {
            // Stub out a random target
            let target = PrivateKey::random(&mut rand_08::thread_rng()).public_key();
            mailbox
                .hint_finalized(height, NonEmptyVec::new(target))
                .await
        }
    }

    fn certified(&self, round: Round, block: Block) -> impl Future<Output = bool> + Send {
        let mailbox = self.clone();
        async move { mailbox.certified(round, block).await }
    }

    fn report(&self, activity: ConsensusActivity) -> impl Future<Output = ()> + Send {
        let mut mailbox = self.clone();
        async move { commonware_consensus::Reporter::report(&mut mailbox, activity).await }
    }
}

impl Feed for feed::Mailbox {
    fn report(&self, activity: ConsensusActivity) -> impl Future<Output = ()> + Send {
        let mut mailbox = self.clone();
        async move { commonware_consensus::Reporter::report(&mut mailbox, activity).await }
    }
}
