//! Tempo imports carried by Zone blocks: decoding, validation, and proposal selection.
//!
//! Every Zone block opens with exactly one `advanceTempo` (a full import of one finalized Tempo
//! header and its portal work) or `advanceTempoHeaders` (a checkpoint-only range). Simplex nodes
//! consume the finalized deposit queue only when a block finalizes, so proposals and verification
//! select and check imports relative to the parent block, never the queue front.

use alloy_consensus::BlockHeader as _;
use alloy_eips::NumHash;
use alloy_primitives::B256;
use alloy_rlp::Decodable as _;
use alloy_sol_types::SolCall as _;
use reth_primitives_traits::{SealedBlock, SealedHeader};
use tempo_chainspec::{hardfork::TempoHardfork, spec::TempoHardforks as _};
use tempo_precompiles::dispatch::abi_decoder_config_for_spec;
use tempo_primitives::{Block, TempoHeader, TempoTxEnvelope};
use zone_chainspec::ZoneChainSpec;
use zone_l1::{FinalizedTarget, L1BlockDeposits, QueueSnapshot};
use zone_payload::abi::{EnabledToken, IZoneInbox, QueuedDeposit, ZONE_INBOX_ADDRESS};
use zone_primitives::constants::MAX_TEMPO_HEADERS_PER_ZONE_BLOCK;

/// The Tempo import opening a Zone block.
#[derive(Debug)]
pub enum DecodedTempoImport {
    /// `advanceTempo`: one finalized header plus every deposit and token enablement it owes.
    Full {
        /// The imported Tempo header.
        header: Box<SealedHeader<TempoHeader>>,
        /// Deposits processed by the block, in portal order.
        deposits: Vec<QueuedDeposit>,
        /// Token enablements processed by the block, in portal order.
        enabled_tokens: Vec<EnabledToken>,
    },
    /// `advanceTempoHeaders`: a contiguous header range whose portal work is deferred.
    CheckpointOnly {
        /// The imported Tempo headers, oldest first.
        headers: Vec<SealedHeader<TempoHeader>>,
    },
}

impl DecodedTempoImport {
    /// Imported Tempo headers, oldest first.
    pub fn headers(&self) -> &[SealedHeader<TempoHeader>] {
        match self {
            Self::Full { header, .. } => core::slice::from_ref(header),
            Self::CheckpointOnly { headers } => headers,
        }
    }

    /// The last imported header: the block's post-state Tempo checkpoint.
    pub fn anchor(&self) -> Option<NumHash> {
        self.headers().last().map(SealedHeader::num_hash)
    }
}

/// Decode the opening `IZoneInbox.advanceTempo` or `advanceTempoHeaders` system transaction.
pub fn decode_advance_tempo(block: &SealedBlock<Block>) -> eyre::Result<DecodedTempoImport> {
    // Do some basic checks

    // 1. `advanceTempo` is the first tx
    let first_tx = block.body().transactions().next().ok_or_else(|| {
        eyre::eyre!("peer block has no transactions; expected an advanceTempo system tx")
    })?;
    let TempoTxEnvelope::Legacy(signed) = first_tx else {
        eyre::bail!("first transaction in peer block is not a legacy system transaction");
    };
    eyre::ensure!(
        first_tx.is_system_tx(),
        "first transaction in peer block is not a Tempo system transaction"
    );

    // 2. Address is correct
    eyre::ensure!(
        signed.tx().to == ZONE_INBOX_ADDRESS.into(),
        "first Tempo system transaction is not sent to IZoneInbox"
    );
    if signed
        .tx()
        .input
        .starts_with(&IZoneInbox::advanceTempoHeadersCall::SELECTOR)
    {
        eyre::ensure!(
            block.transaction_count() == 1,
            "advanceTempoHeaders must be the only transaction in its block"
        );
        let call = IZoneInbox::advanceTempoHeadersCall::abi_decode(signed.tx().input.as_ref())?;
        eyre::ensure!(
            call.headers.len() <= MAX_TEMPO_HEADERS_PER_ZONE_BLOCK,
            "advanceTempoHeaders has too many headers"
        );
        let mut headers = Vec::with_capacity(call.headers.len());
        for encoded in call.headers {
            let mut input = encoded.as_ref();
            let header = TempoHeader::decode(&mut input)?;
            if !input.is_empty() {
                eyre::bail!("advanceTempoHeaders header has trailing bytes");
            }
            headers.push(SealedHeader::seal_slow(header));
        }
        return Ok(DecodedTempoImport::CheckpointOnly { headers });
    }
    let call = IZoneInbox::advanceTempoCall::abi_decode_with_config(
        signed.tx().input.as_ref(),
        abi_decoder_config_for_spec(TempoHardfork::latest()),
    )
    .map_err(|err| eyre::eyre!("first transaction does not decode as advanceTempo: {err}"))?;

    // 3. the system tx is valid.
    let mut header_rlp = call.header.as_ref();
    let header = TempoHeader::decode(&mut header_rlp)
        .map_err(|err| eyre::eyre!("invalid RLP-encoded L1 header in advanceTempo: {err}"))?;
    eyre::ensure!(
        header_rlp.is_empty(),
        "advanceTempo L1 header has {} trailing bytes",
        header_rlp.len()
    );
    Ok(DecodedTempoImport::Full {
        header: Box::new(SealedHeader::seal_slow(header)),
        deposits: call.deposits,
        enabled_tokens: call.enabledTokens,
    })
}

/// Require a non-empty header range that extends the parent's Tempo checkpoint contiguously.
pub fn validate_l1_checkpoint_range(
    headers: &[SealedHeader<TempoHeader>],
    local_number: u64,
    local_hash: B256,
    zone_block_number: u64,
) -> eyre::Result<()> {
    if headers.is_empty() {
        eyre::bail!("peer block imports no Tempo headers");
    }
    let mut previous_number = local_number;
    let mut previous_hash = local_hash;
    for l1_header in headers {
        if l1_header.number() != previous_number.saturating_add(1) {
            eyre::bail!(
                "peer block {zone_block_number} advances Tempo to L1 block {}, but local checkpoint is {}; expected {}",
                l1_header.number(),
                previous_number,
                previous_number.saturating_add(1)
            );
        }
        if l1_header.parent_hash() != previous_hash {
            eyre::bail!(
                "advanceTempo L1 header {} does not extend the local Tempo checkpoint: embedded parent {}, local hash {}",
                l1_header.number(),
                l1_header.parent_hash(),
                previous_hash
            );
        }
        previous_number = l1_header.number();
        previous_hash = l1_header.hash();
    }
    Ok(())
}

/// Require `deposits` and `enabled_tokens` to process exactly the portal events of `work`, in
/// order.
pub fn validate_portal_inputs(
    work: &[L1BlockDeposits],
    deposits: &[QueuedDeposit],
    enabled_tokens: &[EnabledToken],
) -> eyre::Result<()> {
    let mut deposit_offset = 0usize;
    let mut token_offset = 0usize;
    for block in work {
        let next_deposit_offset = deposit_offset
            .checked_add(block.events.deposits.len())
            .ok_or_else(|| eyre::eyre!("advanceTempo deposit count overflow"))?;
        let next_token_offset = token_offset
            .checked_add(block.events.enabled_tokens.len())
            .ok_or_else(|| eyre::eyre!("advanceTempo token count overflow"))?;
        eyre::ensure!(
            next_deposit_offset <= deposits.len() && next_token_offset <= enabled_tokens.len(),
            "advanceTempo calldata is shorter than the deferred portal event range"
        );
        block.events.validate_advance_tempo_inputs(
            &deposits[deposit_offset..next_deposit_offset],
            &enabled_tokens[token_offset..next_token_offset],
        )?;
        deposit_offset = next_deposit_offset;
        token_offset = next_token_offset;
    }
    eyre::ensure!(
        deposit_offset == deposits.len(),
        "advanceTempo contains {} deposits, but observed portal events contain {deposit_offset}",
        deposits.len()
    );
    eyre::ensure!(
        token_offset == enabled_tokens.len(),
        "advanceTempo contains {} token enables, but observed portal events contain {token_offset}",
        enabled_tokens.len()
    );
    Ok(())
}

/// Portal work a full import at `anchor` owes on top of a parent.
///
/// `last_unfinalized_full_import` is the anchor of the newest full import among the parent's
/// ancestors that the queue has not consumed yet. Without one, the import owes the queue's
/// deferred work plus every pending block through `anchor`; with one, only the pending blocks
/// after it.
pub(crate) fn owed_portal_work(
    snapshot: &QueueSnapshot,
    last_unfinalized_full_import: Option<u64>,
    anchor: NumHash,
) -> eyre::Result<Vec<L1BlockDeposits>> {
    let (mut work, after) = match last_unfinalized_full_import {
        Some(full) => (Vec::new(), full),
        None => (
            snapshot.deferred.iter().cloned().collect::<Vec<_>>(),
            snapshot.consumed_through.number,
        ),
    };
    work.extend(
        snapshot
            .pending
            .iter()
            .filter(|block| (after + 1..=anchor.number).contains(&block.header.number()))
            .cloned(),
    );
    let last = work.last().map(|block| block.header.num_hash());
    eyre::ensure!(
        last == Some(anchor),
        "deposit queue does not hold anchor {anchor:?}; owed work ends at {last:?}"
    );
    Ok(work)
}

/// The import a proposer selects on top of a parent.
#[derive(Debug)]
pub(crate) enum SelectedImport {
    /// Import the next header with its owed portal work.
    Full(NumHash),
    /// Import the next headers as checkpoints.
    CheckpointOnly(Vec<SealedHeader<TempoHeader>>),
}

/// Select the import extending `checkpoint` from a queue snapshot.
///
/// Returns `None` while the next finalized header is not queued yet or the hardfork and
/// finalized-target rules require waiting.
///
/// A parent that was itself checkpoint-only is followed by a full import whenever the hardfork and
/// finalized-target rules allow one. While L1 outpaces consensus the queue always holds more than
/// one header, and reserving only the last one for a full import would checkpoint forever: no
/// deposit would be processed and no withdrawal batch would close.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors tempo_import_decision's inputs"
)]
pub(crate) fn select_import(
    chain_spec: &ZoneChainSpec,
    snapshot: &QueueSnapshot,
    checkpoint: NumHash,
    parent_checkpoint_only: bool,
    finalized_l1_timestamp: Option<u64>,
    finalized_target: Option<FinalizedTarget>,
    parent_timestamp_millis: u64,
    wall_clock_timestamp_millis: u64,
) -> eyre::Result<Option<SelectedImport>> {
    let mut queued_headers: Vec<_> = snapshot
        .pending
        .iter()
        .filter(|block| block.header.number() > checkpoint.number)
        .take(MAX_TEMPO_HEADERS_PER_ZONE_BLOCK + 1)
        .map(|block| block.header.clone())
        .collect();
    let (Some(first), Some(latest)) = (queued_headers.first(), snapshot.latest_header.as_ref())
    else {
        return Ok(None);
    };
    eyre::ensure!(
        first.number() == checkpoint.number + 1 && first.parent_hash() == checkpoint.hash,
        "queued L1 block {:?} does not extend the parent checkpoint {checkpoint:?}",
        first.num_hash()
    );
    let first = first.num_hash();
    let decide = |headers: &[SealedHeader<TempoHeader>], target| {
        tempo_import_decision(
            chain_spec,
            headers,
            latest,
            finalized_l1_timestamp,
            target,
            parent_timestamp_millis,
            wall_clock_timestamp_millis,
        )
    };
    let decision = match decide(&queued_headers, finalized_target) {
        // Reserving the finalized target only batches backfill work; only the hardfork rules
        // can forbid a full import of the next header.
        TempoImportDecision::ImportCheckpoints(_) if parent_checkpoint_only => {
            decide(&queued_headers[..1], None)
        }
        decision => decision,
    };
    Ok(match decision {
        TempoImportDecision::WaitForHardforkMatch | TempoImportDecision::WaitForFinalizedTarget => {
            None
        }
        TempoImportDecision::ImportFull => Some(SelectedImport::Full(first)),
        TempoImportDecision::ImportCheckpoints(count) => {
            queued_headers.truncate(count);
            Some(SelectedImport::CheckpointOnly(queued_headers))
        }
    })
}

/// How the next Zone block imports Tempo headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TempoImportDecision {
    /// Wait until finalized L1 activates the hardfork required by the next Zone block.
    WaitForHardforkMatch,
    /// Wait until the subscriber confirms the queued finalized target did not advance.
    WaitForFinalizedTarget,
    /// Import the full block with `advanceTempo`.
    ImportFull,
    /// Import specified number of checkpoint headers with `advanceTempoHeaders`.
    ImportCheckpoints(usize),
}

/// Decide how the next Zone block imports `queued_headers`, the finalized headers after the
/// parent's checkpoint.
pub fn tempo_import_decision(
    chain_spec: &ZoneChainSpec,
    queued_headers: &[SealedHeader<TempoHeader>],
    latest_l1_header: &SealedHeader<TempoHeader>,
    finalized_l1_timestamp: Option<u64>,
    finalized_target: Option<FinalizedTarget>,
    parent_timestamp_millis: u64,
    wall_clock_timestamp_millis: u64,
) -> TempoImportDecision {
    let Some(first_header) = queued_headers.first() else {
        return TempoImportDecision::ImportFull;
    };
    let first_l1_hardfork = chain_spec.tempo_hardfork_at(first_header.timestamp());
    let next_timestamp_millis = zone_timestamp_millis(
        first_header.timestamp_millis(),
        parent_timestamp_millis,
        wall_clock_timestamp_millis,
    );
    let zone_hardfork = chain_spec.tempo_hardfork_at(next_timestamp_millis / 1000);
    // Also consult finalized L1 observed outside the queue: after a long pause the lookahead can be
    // full of pre-fork headers, and the activation header cannot arrive until some are consumed.
    let l1_tip_hardfork = chain_spec.tempo_hardfork_at(
        latest_l1_header
            .timestamp()
            .max(finalized_l1_timestamp.unwrap_or_default()),
    );

    if !zone_hardfork.is_t13() {
        return TempoImportDecision::ImportFull;
    }
    // Zone execution must not activate a hardfork before L1. Wait whenever the prospective Zone
    // block is ahead of the latest queued L1 header, but allow L1 to be ahead while the Zone
    // imports the remaining pre-fork prefix under its currently active rules.
    if zone_hardfork > l1_tip_hardfork {
        return TempoImportDecision::WaitForHardforkMatch;
    }

    // During backfill, the subscriber announces its finalized target before filling the queue.
    // Until the announced target is visible, every queued header may be checkpointed because a
    // later header is known to exist for the required full block. Once the target is queued,
    // reserve it while the subscriber checks whether finalized advanced again. Only a stable
    // target may become the operational import.
    let target_is_visible = finalized_target.is_some_and(|target| {
        queued_headers
            .last()
            .is_some_and(|header| header.number() >= target.number)
    });
    let reserve_for_full = finalized_target.is_none() || target_is_visible;
    let checkpoint_count = queued_headers
        .len()
        .saturating_sub(usize::from(reserve_for_full))
        .min(MAX_TEMPO_HEADERS_PER_ZONE_BLOCK)
        // Never reserve a queue front from an older hardfork for a full import under newer Zone
        // rules. This also closes the small race where the hardfork successor is appended between
        // the bounded queue snapshot and tip read.
        .max(usize::from(first_l1_hardfork < zone_hardfork));
    if checkpoint_count == 0 {
        if target_is_visible && finalized_target.is_some_and(|target| !target.ready) {
            TempoImportDecision::WaitForFinalizedTarget
        } else {
            TempoImportDecision::ImportFull
        }
    } else {
        TempoImportDecision::ImportCheckpoints(checkpoint_count)
    }
}

/// Select a Zone timestamp that preserves the L1 lower bound without backdating user activity.
pub fn zone_timestamp_millis(
    l1_timestamp_millis: u64,
    parent_timestamp_millis: u64,
    wall_clock_timestamp_millis: u64,
) -> u64 {
    l1_timestamp_millis
        .max(wall_clock_timestamp_millis)
        .max(parent_timestamp_millis)
}
