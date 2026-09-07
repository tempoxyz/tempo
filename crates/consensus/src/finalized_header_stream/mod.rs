//! RPC-backed stream of authenticated finalized Tempo block headers.
//!
//! Consensus certificates are sparse: a certificate for a block authenticates that block and all
//! of its ancestors. This module expands those certified checkpoints into a contiguous stream of
//! headers after a caller-provided block.

use std::{
    collections::VecDeque,
    num::NonZeroU64,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use alloy_provider::Provider;
use alloy_rpc_types_eth::{BlockNumHash, BlockNumberOrTag};
use alloy_transport::TransportError;
use commonware_codec::ReadExt as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use futures::{Stream, StreamExt as _, TryStreamExt as _, stream};
use rand::rngs::StdRng;
use reth_primitives_traits::SealedHeader;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::NetworkIdentity;
use tempo_node::rpc::consensus::{CertifiedBlock, Query};
use tempo_primitives::TempoHeader;
use tracing::{instrument, warn};

use crate::finalization_verifier::{Error as VerificationError, FinalizationVerifier};

#[cfg(test)]
mod test;

const DEFAULT_FETCH_CONCURRENCY: usize = 32;
const DEFAULT_CHUNK_SIZE: u64 = 1_024;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Configuration for an RPC-backed finalized block stream.
#[derive(Clone, Debug)]
pub struct Config {
    /// Hash of the last block already processed by the consumer. The stream starts at the next block.
    pub start_after: B256,
    /// Authoritative network identity to try before deriving one from `start_after`.
    pub network_identity: Option<NetworkIdentity>,
    /// Fixed consensus epoch length.
    pub epoch_length: NonZeroU64,
    /// Maximum concurrent header requests within a chunk.
    pub fetch_concurrency: usize,
    /// Number of headers authenticated and buffered at a time.
    pub chunk_size: u64,
    /// Delay before polling again when the latest certificate has not advanced.
    pub poll_interval: Duration,
}

impl Config {
    /// Create a stream configuration with conservative fetching defaults.
    pub const fn new(
        start_after: B256,
        network_identity: Option<NetworkIdentity>,
        epoch_length: NonZeroU64,
    ) -> Self {
        Self {
            start_after,
            network_identity,
            epoch_length,
            fetch_concurrency: DEFAULT_FETCH_CONCURRENCY,
            chunk_size: DEFAULT_CHUNK_SIZE,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

/// A never-ending stream of contiguous, certificate-authenticated Tempo headers.
///
/// The stream polls the latest sparse finalization certificate, verifies it, authenticates the
/// complete intervening hash chain, and yields every newly finalized header in ascending order.
pub struct FinalizedHeaderStream {
    inner: Pin<Box<dyn Stream<Item = Result<SealedHeader<TempoHeader>, Error>> + Send>>,
}

impl FinalizedHeaderStream {
    /// Initialize a stream backed by an Alloy Tempo provider over HTTP or WebSocket.
    pub async fn init<P>(provider: P, config: Config) -> Result<Self, Error>
    where
        P: Provider<TempoNetwork> + Send + Sync + 'static,
    {
        let state = State::initialize(provider, config).await?;
        let stream = stream::try_unfold(state, |mut state| async move {
            let header = state.next_header().await?;
            Ok(Some((header, state)))
        });
        Ok(Self {
            inner: Box::pin(stream),
        })
    }
}

impl Stream for FinalizedHeaderStream {
    type Item = Result<SealedHeader<TempoHeader>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(cx)
    }
}

#[derive(Clone, Copy, Debug)]
struct Chunk {
    from: u64,
    to: BlockNumHash,
}

struct State<P> {
    rpc: Rpc<P>,
    verifier: FinalizationVerifier,
    epoch_strategy: FixedEpocher,
    cursor: BlockNumHash,
    chunk_size: u64,
    poll_interval: Duration,
    plan: VecDeque<Chunk>,
    pending: VecDeque<SealedHeader<TempoHeader>>,
    rng: StdRng,
}

impl<P> State<P>
where
    P: Provider<TempoNetwork> + Send + Sync + 'static,
{
    #[instrument(skip_all, err)]
    async fn initialize(provider: P, config: Config) -> Result<Self, Error> {
        let epoch_strategy = FixedEpocher::new(config.epoch_length);
        let fetch_concurrency = config.fetch_concurrency.max(1);
        let chunk_size = config.chunk_size.max(1);
        let rpc = Rpc {
            provider,
            fetch_concurrency,
        };
        let start_after = rpc.header_by_hash(config.start_after).await?.num_hash();
        let mut rng = rand::make_rng();

        let start_block_epoch = epoch_strategy
            .containing(Height::new(start_after.number))
            .expect("failed to get epoch containing start block");

        let verifier = if let Some(identity) = &config.network_identity {
            let mut verifier = FinalizationVerifier::new(identity.clone(), epoch_strategy.clone());

            // If the start block is one or more epoch transitions ahead of the initial identity,
            // check if it could make sense to fetch the identity by reading latest processed boundary block.
            if start_block_epoch.epoch().get() >= identity.from_epoch {
                if start_block_epoch.last().get() == start_after.number {
                    // Always fetch identity from start block if it's the last block in its epoch.
                    verifier = verifier_from_start(&rpc, &epoch_strategy, start_after).await?;
                } else {
                    let latest_finalization = rpc.finalization(Query::Latest).await?;

                    // If the latest finalization we can obtain is older than the start block or it
                    // does not verify against the initial identity, always fetch identity via the start block.
                    if latest_finalization.block.number() < start_after.number
                        || verifier
                            .decode_and_verify(&mut rng, &latest_finalization)
                            .is_err_and(|error| error.is_signature_mismatch())
                    {
                        verifier = verifier_from_start(&rpc, &epoch_strategy, start_after).await?;
                    }
                }
            }

            verifier
        } else {
            // If we don't have an initial identity, our only option is to fetch identity from the start block.
            verifier_from_start(&rpc, &epoch_strategy, start_after).await?
        };

        if let Some(configured) = &config.network_identity {
            let active = verifier.network_identity();
            if active.from_epoch >= configured.from_epoch && active.identity != configured.identity
            {
                warn!(
                    configured_from_epoch = configured.from_epoch,
                    active_from_epoch = active.from_epoch,
                    configured_network_identity = %configured.identity,
                    active_network_identity = %active.identity,
                    "Network identity derived from the trusted start block differs from the configured network identity!!! Update the binary with the latest network identity"
                );
            }
        }

        Ok(Self {
            rpc,
            verifier,
            epoch_strategy,
            cursor: start_after,
            chunk_size,
            poll_interval: config.poll_interval,
            plan: VecDeque::new(),
            pending: VecDeque::new(),
            rng,
        })
    }

    async fn next_header(&mut self) -> Result<SealedHeader<TempoHeader>, Error> {
        loop {
            if let Some(header) = self.pending.pop_front() {
                self.cursor = header.num_hash();
                return Ok(header);
            }

            if self.load_next_chunk().await? {
                continue;
            }

            // If we don't have any more headers, advance by following the latest finalization.
            let certified = self.rpc.finalization(Query::Latest).await?;

            if certified.block.number() <= self.cursor.number {
                tokio::time::sleep(self.poll_interval).await;
                continue;
            }

            match self.verifier.decode_and_verify(&mut self.rng, &certified) {
                Ok(_) => {
                    // If we can verify the latest finalization, trust it as the new chain tip.
                    self.plan = self.plan_to(certified.block.num_hash()).await?;
                }
                Err(error) if error.is_signature_mismatch() => {
                    // If we can't verify the finalization, attempt to sync to the first epoch transition we can verify.
                    let epoch = self
                        .epoch_strategy
                        .containing(Height::new(certified.block.number()))
                        .expect("fixed epoch strategy supports every block height")
                        .epoch();
                    self.plan = self.plan_to_transition(epoch).await?;
                }
                // If the certificate is malformed, treat this as fatal error.
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn load_next_chunk(&mut self) -> Result<bool, Error> {
        let Some(chunk) = self.plan.pop_front() else {
            return Ok(false);
        };

        let headers = self
            .rpc
            .fetch_and_validate_headers(chunk.from, chunk.to)
            .await?;
        self.register_boundaries(&headers)?;
        self.pending = headers.into();
        Ok(true)
    }

    /// Registers boundaries for the provided headers in [`Self::verifier`].
    fn register_boundaries(&self, headers: &[SealedHeader<TempoHeader>]) -> Result<(), Error> {
        for header in headers {
            let info = self
                .epoch_strategy
                .containing(Height::new(header.number()))
                .ok_or(Error::RangeOverflow)?;
            if info.last().get() != header.number() {
                continue;
            }
            let onchain_outcome = self
                .verifier
                .decode_dkg_outcome_and_register_boundary(header.extra_data().as_ref())
                .map_err(|error| Error::MalformedBoundary {
                    height: header.number(),
                    reason: error.to_string(),
                })?;

            let network_identity = self.verifier.network_identity();
            if onchain_outcome.epoch.get() >= network_identity.from_epoch
                && network_identity.identity != *onchain_outcome.network_identity()
            {
                warn!(
                    compiled_from_epoch = network_identity.from_epoch,
                    onchain_epoch = %onchain_outcome.epoch,
                    compiled_network_identity = %network_identity.identity,
                    onchain_network_identity = %onchain_outcome.network_identity(),
                    "Network identity differs from the onchain DKG outcome!!! Update the binary with the latest network identity"
                );
            }
        }
        Ok(())
    }

    /// Fetches headers from the current cursor up to the target block in reverse
    /// while verifying the chain integrity and saves the chunks to `self.plan`.
    async fn plan_to(&self, target: BlockNumHash) -> Result<VecDeque<Chunk>, Error> {
        let first = self
            .cursor
            .number
            .checked_add(1)
            .ok_or(Error::RangeOverflow)?;
        let mut to = target;
        let mut chunks = VecDeque::new();

        while to.number >= first {
            let from = to.number.saturating_sub(self.chunk_size - 1).max(first);
            let headers = self.rpc.fetch_and_validate_headers(from, to).await?;
            let parent_hash = headers
                .first()
                .expect("a non-empty inclusive range always returns a header")
                .parent_hash();
            chunks.push_front(Chunk { from, to });

            if from == first {
                if parent_hash != self.cursor.hash {
                    return Err(Error::ParentHashMismatch {
                        number: from,
                        expected: self.cursor.hash,
                        actual: parent_hash,
                    });
                }
                break;
            }
            to = BlockNumHash::new(from - 1, parent_hash);
        }
        Ok(chunks)
    }

    /// Follows the chain backwards to the first epoch transition we can verify.
    ///
    /// Once it's reached and verified, invokes [`Self::plan_to`] to plan the chunk from the boundary to the current cursor.
    async fn plan_to_transition(
        &mut self,
        mut certificate_epoch: Epoch,
    ) -> Result<VecDeque<Chunk>, Error> {
        loop {
            let previous_epoch = certificate_epoch
                .previous()
                .ok_or(Error::MissingPreviousEpoch(certificate_epoch.get()))?;
            let boundary = self
                .epoch_strategy
                .last(previous_epoch)
                .ok_or(Error::RangeOverflow)?
                .get();
            if boundary <= self.cursor.number {
                return Err(Error::TransitionNotAhead {
                    boundary,
                    checkpoint: self.cursor.number,
                });
            }

            let certified = self
                .rpc
                .finalization(Query::Height(boundary))
                .await
                .map_err(|source| Error::MissingTransitionCertificate {
                    height: boundary,
                    source,
                })?;
            let actual = certified.block.number();
            if actual != boundary {
                return Err(Error::TransitionHeightMismatch {
                    expected: boundary,
                    actual,
                });
            }

            match self.verifier.decode_and_verify(&mut self.rng, &certified) {
                Ok(_) => {
                    return self
                        .plan_to(BlockNumHash::new(boundary, certified.block.hash()))
                        .await;
                }
                Err(error) if error.is_signature_mismatch() => {
                    certificate_epoch = previous_epoch;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

/// Builds a [`FinalizationVerifier`] by finding the latest boundary at
/// or before the provided start block, decoding its DKG outcome and creating a verifier for it.
async fn verifier_from_start<P>(
    rpc: &Rpc<P>,
    strategy: &FixedEpocher,
    start: BlockNumHash,
) -> Result<FinalizationVerifier, Error>
where
    P: Provider<TempoNetwork>,
{
    let boundary = latest_boundary_at_or_before(strategy, start.number)?;
    let headers = rpc.fetch_and_validate_headers(boundary, start).await?;
    let boundary_header = headers
        .first()
        .expect("a non-empty inclusive range always returns a header");
    let outcome = tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(
        &mut boundary_header.extra_data().as_ref(),
    )
    .map_err(|error| Error::MalformedBoundary {
        height: boundary_header.number(),
        reason: error.to_string(),
    })?;

    Ok(FinalizationVerifier::new(
        NetworkIdentity {
            from_epoch: outcome.epoch.get(),
            identity: *outcome.network_identity(),
        },
        strategy.clone(),
    ))
}

fn latest_boundary_at_or_before(strategy: &FixedEpocher, height: u64) -> Result<u64, Error> {
    let info = strategy
        .containing(Height::new(height))
        .ok_or(Error::RangeOverflow)?;
    if info.last().get() == height {
        return Ok(height);
    }
    let Some(previous) = info.epoch().previous() else {
        return Ok(0);
    };
    strategy
        .last(previous)
        .map(Height::get)
        .ok_or(Error::RangeOverflow)
}

struct Rpc<P> {
    provider: P,
    fetch_concurrency: usize,
}

impl<P> Rpc<P>
where
    P: Provider<TempoNetwork>,
{
    async fn finalization(&self, query: Query) -> Result<CertifiedBlock, TransportError> {
        self.provider
            .raw_request("consensus_getFinalization".into(), (query,))
            .await
    }

    async fn header_by_hash(&self, expected: B256) -> Result<SealedHeader<TempoHeader>, Error> {
        let Some(response) = self.provider.get_header_by_hash(expected).await? else {
            return Err(Error::MissingStartHeader(expected));
        };

        let header = SealedHeader::seal_slow(response.inner.inner);
        if header.hash() != expected {
            return Err(Error::StartHashMismatch {
                expected,
                actual: header.hash(),
            });
        }
        Ok(header)
    }

    async fn header_by_number(
        &self,
        number: u64,
    ) -> Result<Option<SealedHeader<TempoHeader>>, Error> {
        let Some(response) = self
            .provider
            .get_header_by_number(BlockNumberOrTag::Number(number))
            .await?
        else {
            return Ok(None);
        };

        let reported_hash = response.inner.hash;
        let header = SealedHeader::seal_slow(response.inner.inner);
        if header.hash() != reported_hash {
            return Err(Error::HeaderHashMismatch {
                number,
                reported: reported_hash,
                actual: header.hash(),
            });
        }
        Ok(Some(header))
    }

    async fn fetch_and_validate_headers(
        &self,
        from: u64,
        to: BlockNumHash,
    ) -> Result<Vec<SealedHeader<TempoHeader>>, Error> {
        if from > to.number {
            return Err(Error::RangeOverflow);
        }

        let headers = stream::iter(from..=to.number)
            .map(|number| async move {
                self.header_by_number(number)
                    .await?
                    .ok_or(Error::MissingHeader(number))
            })
            .buffered(self.fetch_concurrency)
            .try_collect::<Vec<_>>()
            .await?;

        let mut expected_parent = None;
        for (offset, header) in headers.iter().enumerate() {
            let expected = from
                .checked_add(offset as u64)
                .ok_or(Error::RangeOverflow)?;
            if header.number() != expected {
                return Err(Error::HeaderNumberMismatch {
                    expected,
                    actual: header.number(),
                });
            }
            if let Some(parent) = expected_parent
                && header.parent_hash() != parent
            {
                return Err(Error::ParentHashMismatch {
                    number: expected,
                    expected: parent,
                    actual: header.parent_hash(),
                });
            }
            expected_parent = Some(header.hash());
        }

        let actual_tip = headers
            .last()
            .expect("a non-empty inclusive range always returns a header")
            .hash();
        if actual_tip != to.hash {
            return Err(Error::TipHashMismatch {
                expected: to.hash,
                actual: actual_tip,
            });
        }
        Ok(headers)
    }
}

/// Error emitted by [`FinalizedHeaderStream`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An RPC request failed.
    #[error("RPC request failed: {0}")]
    Rpc(#[from] TransportError),
    /// A requested header was unavailable.
    #[error("header `{0}` is unavailable")]
    MissingHeader(u64),
    /// The trusted start header was unavailable.
    #[error("start header `{0}` is unavailable")]
    MissingStartHeader(B256),
    /// The header returned for the trusted start hash did not match it.
    #[error("start header has hash `{actual}`, expected `{expected}`")]
    StartHashMismatch { expected: B256, actual: B256 },
    /// An RPC response returned a header at the wrong height.
    #[error("requested header `{expected}`, received header `{actual}`")]
    HeaderNumberMismatch { expected: u64, actual: u64 },
    /// An RPC response reported a hash that did not match its header.
    #[error("header `{number}` reported hash `{reported}`, computed `{actual}`")]
    HeaderHashMismatch {
        number: u64,
        reported: B256,
        actual: B256,
    },
    /// Two consecutive headers did not form a chain.
    #[error("header `{number}` has parent `{actual}`, expected `{expected}`")]
    ParentHashMismatch {
        number: u64,
        expected: B256,
        actual: B256,
    },
    /// A fetched range did not terminate at the certified or trusted block.
    #[error("range ended at hash `{actual}`, expected `{expected}`")]
    TipHashMismatch { expected: B256, actual: B256 },
    /// A trusted boundary did not contain a valid DKG outcome.
    #[error("boundary block `{height}` did not contain a valid DKG outcome: {reason}")]
    MalformedBoundary { height: u64, reason: String },
    /// Certificate verification failed.
    #[error(transparent)]
    Verification(#[from] VerificationError),
    /// An identity-changing epoch transition could not be retrieved.
    #[error("transition certificate at boundary `{height}` is unavailable: {source}")]
    MissingTransitionCertificate {
        height: u64,
        #[source]
        source: TransportError,
    },
    /// An exact boundary query returned a certificate for another block.
    #[error("requested transition certificate at `{expected}`, received `{actual}`")]
    TransitionHeightMismatch { expected: u64, actual: u64 },
    /// The certificate requires an identity from before epoch zero.
    #[error("cannot find a boundary preceding certificate epoch `{0}`")]
    MissingPreviousEpoch(u64),
    /// The transition needed to verify the tip is not ahead of the consumer's checkpoint.
    #[error("required transition boundary `{boundary}` is not ahead of checkpoint `{checkpoint}`")]
    TransitionNotAhead { boundary: u64, checkpoint: u64 },
    /// The configured range overflowed `u64`.
    #[error("block range overflow")]
    RangeOverflow,
}
