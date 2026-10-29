//! Zone-side protocol invariants judged on every canonical Zone block.
//!
//! The fuzz harness executes Tempo blocks only, so the checks in [`tempo_invariants::zones::zone`]
//! run here, over the exact state each Zone block leaves: view calls run in the node's own Zone
//! EVM against historical state, answering as any caller for the privacy getters. Their Tempo
//! reads never wait out an L1 outage (see [`ViewEvm`]).

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    convert::Infallible,
    num::NonZeroU32,
    time::Duration,
};

use alloy_consensus::{BlockHeader as _, Transaction as _, TxReceipt as _};
use alloy_contract::CallBuilder;
use alloy_eips::{BlockId, BlockNumHash};
use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_provider::{DynProvider, Provider as _};
use alloy_rlp::Decodable as _;
use alloy_rpc_types_eth::Filter;
use alloy_sol_types::{SolCall as _, SolEvent as _};
use evm2::evm::SystemTx;
use futures::future;
use reth_evm::{ConfigureEvm, Database, database::StateProviderDatabase};
use reth_primitives_traits::RecoveredBlock;
use reth_storage_api::{EvmStateProviderAdapter, HeaderProvider, StateProviderFactory};
use tempo_alloy::TempoNetwork;
use tempo_contracts::zones::{ZONE_TOKEN_ADDRESS, ZonePortal};
use tempo_evm::{TempoEvm, TempoEvmError};
use tempo_invariants::{
    Observe, Report, Step, Views,
    tip20::{ITIP20, transfer},
    zones::zone::{
        ACCOUNT_KEYCHAIN_ADDRESS, ANCHOR_CHECKS, BATCH_CHECKS, Bridged, CHECKS, Getter,
        HISTORY_CHECKS, History, IZoneInbox, NONCE_PRECOMPILE_ADDRESS, Outcome, PRIVACY_CHECKS,
        Pair, PortalAnchor, Privacy, PrivacyAt, STEP_CHECKS, Submission, THIRD_PARTY,
        TempoHeader as ImportedHeader, ZONE_INBOX_ADDRESS, Zone, ZoneBlock, ZoneTx, inbox_mint,
    },
};
use tempo_primitives::{Block, TempoHeader, TempoPrimitives, TempoReceipt, is_tip20_prefix};
use zone_evm::ZoneEvmConfig;

use crate::telemetry::CheckerMetrics;

/// Most account-scoped getters asked as a third party per block, bounding the view calls a
/// block with many transfers costs.
const MAX_PRIVACY_READS: usize = 64;

/// How long a view call's Tempo read waits for L1 on a cache miss before it answers nothing.
const L1_READ_DEADLINE: Duration = Duration::from_secs(1);

/// A node EVM configuration the checker can make view calls with.
pub trait ViewEvm: ConfigureEvm<Primitives = TempoPrimitives> {
    /// The EVM over `db` with `header`'s environment, for the invariant view calls. Its
    /// Tempo reads must give up rather than wait for L1, since the checker's ExEx loop waits on
    /// every view call.
    fn view_evm<'a>(
        &self,
        db: impl Database + 'a,
        header: &TempoHeader,
    ) -> Result<TempoEvm<'a>, Self::Error>;
}

/// Tempo reads go through the node's L1 cache with one RPC attempt per miss, given up after
/// [`L1_READ_DEADLINE`], where the node's own execution retries a miss forever: a failed or
/// unanswered read makes its view answer nothing, so an L1 outage leaves the checks reading it
/// (such as refunds asked as a third party, which read the portal's roles) unjudged instead of
/// stalling the checker.
impl ViewEvm for ZoneEvmConfig {
    fn view_evm<'a>(
        &self,
        db: impl Database + 'a,
        header: &TempoHeader,
    ) -> Result<TempoEvm<'a>, TempoEvmError> {
        self.with_l1_reader(
            self.l1_reader()
                .with_sync_limits(NonZeroU32::MIN, L1_READ_DEADLINE),
        )
        .evm_for_block(db, header)
    }
}

/// The zone-side checks and the bridge history they fold across blocks.
///
/// The history starts at the first block checked, from the supplies before it, and lives in
/// memory: a restarted checker folds again from where it resumes, and a block that does not
/// extend the last one checked starts it over.
#[derive(Debug, Default)]
pub struct ZoneInvariants {
    history: History<Bridged>,
    /// Zone tokens seen so far, whose supplies every later block reads.
    tokens: BTreeSet<Address>,
    last: Option<BlockNumHash>,
    totals: Report,
}

/// What checking one Zone block found.
#[derive(Debug)]
struct BlockChecks {
    report: Report,
    /// The block's step, for checks paired with Tempo state.
    step: Step<Zone, ZoneBlock>,
}

impl ZoneInvariants {
    /// The last block checked.
    pub const fn last_checked(&self) -> Option<BlockNumHash> {
        self.last
    }

    /// Every verdict count since the first block checked, by check. It keeps no violations:
    /// each block's report carries its own.
    pub const fn totals(&self) -> &Report {
        &self.totals
    }

    /// Judges every zone-side check on canonical `block`: [`CHECKS`], [`STEP_CHECKS`],
    /// [`HISTORY_CHECKS`] and [`PRIVACY_CHECKS`] over local state, and with `l1` (a Tempo
    /// provider and the zone's portal) [`ANCHOR_CHECKS`] against the portal at the Tempo block
    /// it imported and [`BATCH_CHECKS`] on every batch the portal accepted in the Tempo blocks it
    /// imported. Fails when local state cannot be opened or an answer is malformed; a view the EVM
    /// cannot run, a Tempo read that fails, or a batch whose state cannot be read leaves its
    /// checks unjudged.
    pub async fn check<P, E>(
        &mut self,
        provider: &P,
        evm_config: &E,
        l1: Option<(&DynProvider<TempoNetwork>, Address)>,
        block: &RecoveredBlock<Block>,
        receipts: &[TempoReceipt],
    ) -> eyre::Result<Report>
    where
        P: StateProviderFactory + HeaderProvider<Header = TempoHeader> + Sync,
        E: ViewEvm + Sync,
    {
        if self
            .last
            .is_some_and(|last| last.hash != block.parent_hash())
        {
            self.history = History::default();
        }
        self.learn_tokens(receipts);
        let tokens: Vec<Address> = self.tokens.iter().copied().collect();
        let BlockChecks { mut report, step } =
            self.check_block(provider, evm_config, block, receipts, &tokens)?;
        if let Some((l1, portal)) = l1 {
            check_anchor(&mut report, &step, l1, portal).await;
            match submissions(l1, portal, &step).await {
                Ok(submissions) => {
                    for submission in submissions {
                        let next_block_hash = submission.next_block_hash;
                        match self.check_batch(provider, evm_config, submission) {
                            Ok(Some(batch)) => report.merge(batch),
                            Ok(None) => {}
                            Err(error) => tracing::warn!(
                                target: "zone::checker",
                                error = %format_args!("{error:#}"),
                                zone_block = block.number(),
                                %next_block_hash,
                                "cannot check a submitted batch; its batch invariants unjudged"
                            ),
                        }
                    }
                }
                Err(error) => tracing::warn!(
                    target: "zone::checker",
                    %error,
                    zone_block = block.number(),
                    "cannot read submitted batches; batch invariants unjudged"
                ),
            }
        }
        self.last = Some(block.num_hash());
        self.totals.merge(Report {
            counts: report.counts.clone(),
            violations: Vec::new(),
        });
        Ok(report)
    }

    /// Adds the zone token, every token the inbox enabled or minted, and every TIP-20 that
    /// logged in `receipts`.
    fn learn_tokens(&mut self, receipts: &[TempoReceipt]) {
        self.tokens.insert(ZONE_TOKEN_ADDRESS);
        for log in receipts.iter().flat_map(|receipt| receipt.logs()) {
            if is_tip20_prefix(log.address) {
                self.tokens.insert(log.address);
            }
            if log.address != ZONE_INBOX_ADDRESS {
                continue;
            }
            if let Ok(e) = IZoneInbox::TokenEnabled::decode_log_data(&log.data) {
                self.tokens.insert(e.token);
            } else if let Some((token, _)) = inbox_mint(&log.data) {
                self.tokens.insert(token);
            }
        }
    }

    /// Judges [`CHECKS`] on the state `block` leaves, [`STEP_CHECKS`] on its step,
    /// [`HISTORY_CHECKS`] on its state beside every block checked so far, and
    /// [`PRIVACY_CHECKS`] on getters for the accounts it touched. `tokens` are the Zone tokens
    /// whose supply to read. Fails when a state cannot be opened or an answer is malformed.
    fn check_block<P, E>(
        &mut self,
        provider: &P,
        evm_config: &E,
        block: &RecoveredBlock<Block>,
        receipts: &[TempoReceipt],
        tokens: &[Address],
    ) -> eyre::Result<BlockChecks>
    where
        P: StateProviderFactory + HeaderProvider<Header = TempoHeader>,
        E: ViewEvm,
    {
        let parent = provider
            .header(block.parent_hash())?
            .ok_or_else(|| eyre::eyre!("Zone block {} has no parent header", block.number()))?;
        let mut pre_views = StateViews::open(provider, evm_config, block.parent_hash(), &parent)?;
        let pre = Zone::observe(&mut pre_views, tokens)?;
        drop(pre_views);
        let mut post_views = StateViews::open(provider, evm_config, block.hash(), block.header())?;
        let post = Zone::observe(&mut post_views, tokens)?;

        let mut logs = Vec::new();
        let mut txs = Vec::with_capacity(receipts.len());
        for ((sender, tx), receipt) in block.transactions_with_sender().zip(receipts) {
            let start = logs.len();
            logs.extend(receipt.logs().iter().cloned());
            txs.push(ZoneTx {
                sender: *sender,
                to: tx.kind().to().copied(),
                input: tx.input().clone(),
                success: receipt.status(),
                logs: start..logs.len(),
            });
        }
        let imported = txs.first().map(imported_headers).unwrap_or_default();
        let step = Step {
            pre,
            post,
            changes: Vec::new(),
            logs,
            calls: Vec::new(),
            tx: ZoneBlock {
                number: block.number(),
                timestamp: block.timestamp(),
                parent_number: parent.number(),
                parent_timestamp: parent.timestamp(),
                txs,
                imported,
            },
        };

        let mut report = Report::default();
        report.run(CHECKS, &step.post);
        report.run(STEP_CHECKS, &step);
        self.history.push(&step);
        report.run(HISTORY_CHECKS, &self.history.at(step.post.clone()));
        let getters = privacy_getters(&step, tokens);
        let privacy = Privacy::observe(
            &mut post_views,
            PrivacyAt {
                asker: THIRD_PARTY,
                getters: &getters,
            },
        )?;
        report.run(PRIVACY_CHECKS, &privacy);
        Ok(BlockChecks { report, step })
    }

    /// Judges [`BATCH_CHECKS`] on a batch the portal accepted, against the Zone block it proves.
    /// Returns `None` when that block is not in local history.
    fn check_batch<P, E>(
        &self,
        provider: &P,
        evm_config: &E,
        submission: Submission,
    ) -> eyre::Result<Option<Report>>
    where
        P: StateProviderFactory + HeaderProvider<Header = TempoHeader>,
        E: ViewEvm,
    {
        let Some(header) = provider.header(submission.next_block_hash)? else {
            return Ok(None);
        };
        let mut views =
            StateViews::open(provider, evm_config, submission.next_block_hash, &header)?;
        let zone = Zone::observe(&mut views, &[])?;
        let mut report = Report::default();
        report.run(
            BATCH_CHECKS,
            &Pair {
                left: zone,
                right: submission,
            },
        );
        Ok(Some(report))
    }
}

/// Judges [`ANCHOR_CHECKS`] on a block that imported Tempo, reading the portal at the Tempo block
/// it imported over `l1`. A portal view that fails or reverts reads as unanswered.
async fn check_anchor(
    report: &mut Report,
    step: &Step<Zone, ZoneBlock>,
    l1: &DynProvider<TempoNetwork>,
    portal: Address,
) {
    let Some(tempo) = step.post.tempo.filter(|_| step.tx.imports_tempo()) else {
        return;
    };
    let portal = observe_l1::<PortalAnchor, Address>(l1, tempo.hash, portal).await;
    report.run(
        ANCHOR_CHECKS,
        &Pair {
            left: step.clone(),
            right: portal,
        },
    );
}

/// The batches `portal` accepted in the Tempo blocks `step` imported, oldest first.
async fn submissions(
    l1: &DynProvider<TempoNetwork>,
    portal: Address,
    step: &Step<Zone, ZoneBlock>,
) -> eyre::Result<Vec<Submission>> {
    let (Some(pre), Some(post)) = (step.pre.tempo, step.post.tempo) else {
        return Ok(Vec::new());
    };
    if post.number <= pre.number {
        return Ok(Vec::new());
    }
    let filter = Filter::new()
        .address(portal)
        .event_signature(vec![
            ZonePortal::BatchSubmitted_0::SIGNATURE_HASH,
            ZonePortal::BatchSubmitted_1::SIGNATURE_HASH,
        ])
        .from_block(pre.number + 1)
        .to_block(post.number);
    Ok(l1
        .get_logs(&filter)
        .await?
        .iter()
        .filter_map(|log| Submission::from_log(&log.inner))
        .collect())
}

/// Judges the zone-side invariants on every block of a committed chain after the last one
/// checked, logging each violation as the checker logs a divergence. Observe-only: a block whose
/// checks cannot run is logged and skipped, and nothing here stops verification.
pub(crate) async fn observe_committed<P, E>(
    invariants: &mut ZoneInvariants,
    provider: &P,
    evm_config: &E,
    l1: (&DynProvider<TempoNetwork>, Address),
    blocks: Vec<(&RecoveredBlock<Block>, &[TempoReceipt])>,
    metrics: &CheckerMetrics,
) where
    P: StateProviderFactory + HeaderProvider<Header = TempoHeader> + Sync,
    E: ViewEvm + Sync,
{
    for (block, receipts) in blocks {
        if invariants
            .last_checked()
            .is_some_and(|last| block.number() <= last.number)
        {
            continue;
        }
        match invariants
            .check(provider, evm_config, Some(l1), block, receipts)
            .await
        {
            Ok(report) => {
                metrics.invariant_blocks_checked_total.increment(1);
                metrics
                    .invariant_violations_total
                    .increment(report.violations.len() as u64);
                for violation in &report.violations {
                    tracing::error!(
                        target: "zone::checker",
                        invariant = violation.id,
                        subject = %violation.subject,
                        detail = %violation.detail,
                        zone_block = block.number(),
                        zone_hash = %block.hash(),
                        "zone invariant violated"
                    );
                }
            }
            Err(error) => {
                metrics.invariant_errors_total.increment(1);
                tracing::warn!(
                    target: "zone::checker",
                    error = %format_args!("{error:#}"),
                    zone_block = block.number(),
                    zone_hash = %block.hash(),
                    "zone invariants could not run on block"
                );
            }
        }
    }
}

/// `M` read from Tempo at block `block`: the calls `M` makes, sent as `eth_call`s, then answered.
async fn observe_l1<M, A: Copy>(l1: &DynProvider<TempoNetwork>, block: B256, at: A) -> M
where
    M: for<'a> Observe<At<'a> = A> + Unobserved,
{
    let mut asked = Vec::new();
    let recording = M::observe(
        &mut |calls: &[(Address, Bytes)]| {
            asked.extend_from_slice(calls);
            Ok::<_, Infallible>(vec![None; calls.len()])
        },
        at,
    );
    if recording.is_err() {
        return M::unobserved(at);
    }
    let answers: Vec<Option<Bytes>> =
        future::join_all(asked.iter().map(|(to, input)| async move {
            CallBuilder::new_raw(l1, input.clone())
                .to(*to)
                .block(BlockId::hash_canonical(block))
                .call()
                .await
                .ok()
        }))
        .await;
    M::observe(
        &mut |calls: &[(Address, Bytes)]| {
            Ok::<_, Infallible>(
                calls
                    .iter()
                    .map(|call| {
                        asked
                            .iter()
                            .position(|asked| asked == call)
                            .and_then(|index| answers[index].clone())
                    })
                    .collect(),
            )
        },
        at,
    )
    .unwrap_or_else(|_| M::unobserved(at))
}

/// A Tempo-side model that may read as wholly unanswered.
trait Unobserved: Observe {
    fn unobserved(at: Self::At<'_>) -> Self;
}

impl Unobserved for PortalAnchor {
    fn unobserved(portal: Address) -> Self {
        Self {
            portal,
            token_enablement_hash: None,
            deposit_count: None,
            current_deposit_queue_hash: None,
        }
    }
}

/// View calls against one Zone block's exact post-state, through the node's Zone EVM.
struct StateViews<'a> {
    evm: TempoEvm<'a>,
}

impl StateViews<'static> {
    /// Opens the state `hash` left, with `header`'s environment.
    fn open<P: StateProviderFactory, E: ViewEvm>(
        provider: &P,
        evm_config: &E,
        hash: B256,
        header: &TempoHeader,
    ) -> eyre::Result<Self> {
        let state = provider.state_by_block_hash(hash)?;
        let db = StateProviderDatabase::new(EvmStateProviderAdapter(state));
        let evm = evm_config
            .view_evm(db, header)
            .map_err(|error| eyre::eyre!("failed to configure the view EVM at {hash}: {error}"))?;
        Ok(Self { evm })
    }
}

impl StateViews<'_> {
    /// Runs `input` on `to` as `from`, discarding any state it writes. `None` when the EVM
    /// cannot run it, such as when a Tempo read it makes is unavailable: the view then answers
    /// nothing, so only the checks reading it go unjudged.
    fn run(&mut self, from: Address, to: Address, input: &Bytes) -> Option<Outcome> {
        let executed = match self
            .evm
            .system_call(SystemTx::new(to, input.clone()).with_caller(from))
        {
            Ok(executed) => executed,
            Err(error) => {
                tracing::debug!(
                    target: "zone::checker",
                    %to,
                    %from,
                    %error,
                    "invariant view call could not run; it answers nothing"
                );
                return None;
            }
        };
        let result = executed.result();
        Some(if result.is_success() {
            Outcome::Return(result.output.clone())
        } else {
            Outcome::Revert(result.output.clone())
        })
    }
}

impl Views for StateViews<'_> {
    type Error = Infallible;

    /// A call that reverts, returns nothing (no code at `to`) or cannot run answers nothing.
    fn call(&mut self, calls: &[(Address, Bytes)]) -> Result<Vec<Option<Bytes>>, Infallible> {
        Ok(calls
            .iter()
            .map(|(to, input)| match self.run(Address::ZERO, *to, input)? {
                Outcome::Return(output) if !output.is_empty() => Some(output),
                _ => None,
            })
            .collect())
    }

    /// An empty return (no code at `to`), or a call that cannot run, answers nothing.
    fn call_from(
        &mut self,
        from: Address,
        calls: &[(Address, Bytes)],
    ) -> Result<Vec<Option<Outcome>>, Infallible> {
        Ok(calls
            .iter()
            .map(|(to, input)| match self.run(from, *to, input)? {
                Outcome::Return(output) if output.is_empty() => None,
                outcome => Some(outcome),
            })
            .collect())
    }
}

/// The Tempo headers a block's first transaction imports, when it is a successful
/// `advanceTempo` or `advanceTempoHeaders` and every header decodes; empty otherwise.
fn imported_headers(tx: &ZoneTx) -> Vec<ImportedHeader> {
    if !tx.success || tx.to != Some(ZONE_INBOX_ADDRESS) {
        return Vec::new();
    }
    let headers = if let Ok(call) = IZoneInbox::advanceTempoCall::abi_decode(&tx.input) {
        vec![call.header]
    } else if let Ok(call) = IZoneInbox::advanceTempoHeadersCall::abi_decode(&tx.input) {
        call.headers
    } else {
        return Vec::new();
    };
    headers
        .iter()
        .map(|rlp| {
            let header = TempoHeader::decode(&mut rlp.as_ref()).ok()?;
            Some(ImportedHeader {
                number: header.number(),
                hash: keccak256(rlp),
                parent_hash: header.parent_hash(),
            })
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default()
}

/// The account-scoped getters to ask about the accounts a block touched: balances of
/// `Transfer` parties, allowances of `Approval` pairs, refunds of both, and the nonce and keys
/// of each sender. At most [`MAX_PRIVACY_READS`].
fn privacy_getters(step: &Step<Zone, ZoneBlock>, tokens: &[Address]) -> Vec<(Address, Getter)> {
    let mut getters = BTreeSet::new();
    for log in step.logs.iter().filter(|log| tokens.contains(&log.address)) {
        let token = log.address;
        if let Some(t) = transfer(&log.data) {
            for account in [t.from, t.to].into_iter().filter(|a| !a.is_zero()) {
                getters.insert((token, Getter::Balance { account }));
                getters.insert((
                    ZONE_INBOX_ADDRESS,
                    Getter::Refund {
                        token,
                        owner: account,
                    },
                ));
            }
        } else if let Ok(a) = ITIP20::Approval::decode_log_data(&log.data) {
            getters.insert((
                token,
                Getter::Allowance {
                    owner: a.owner,
                    spender: a.spender,
                },
            ));
        }
    }
    for tx in step.tx.txs.iter().filter(|tx| !tx.sender.is_zero()) {
        getters.insert((
            NONCE_PRECOMPILE_ADDRESS,
            Getter::Nonce { account: tx.sender },
        ));
        getters.insert((ACCOUNT_KEYCHAIN_ADDRESS, Getter::Key { account: tx.sender }));
    }
    within_budget(getters, MAX_PRIVACY_READS)
}

/// At most `max` of `getters`, taken round-robin across their targets, so a busy block's many
/// reads of one contract (refunds on the inbox, say) cannot crowd out every read of another.
fn within_budget(getters: BTreeSet<(Address, Getter)>, max: usize) -> Vec<(Address, Getter)> {
    let mut by_target: BTreeMap<Address, VecDeque<Getter>> = BTreeMap::new();
    for (target, getter) in getters {
        by_target.entry(target).or_default().push_back(getter);
    }
    let mut picked = Vec::new();
    while picked.len() < max && !by_target.is_empty() {
        by_target.retain(|&target, queue| {
            if picked.len() < max
                && let Some(getter) = queue.pop_front()
            {
                picked.push((target, getter));
            }
            !queue.is_empty()
        });
    }
    picked
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    /// Many refund reads on the inbox leave room for the nonce and key reads of other targets.
    #[test]
    fn the_read_budget_reaches_every_target() {
        let mut getters = BTreeSet::new();
        for byte in 1..=100u8 {
            let owner = Address::with_last_byte(byte);
            getters.insert((
                ZONE_INBOX_ADDRESS,
                Getter::Refund {
                    token: Address::ZERO,
                    owner,
                },
            ));
        }
        let sender = Address::with_last_byte(0xee);
        getters.insert((NONCE_PRECOMPILE_ADDRESS, Getter::Nonce { account: sender }));
        getters.insert((ACCOUNT_KEYCHAIN_ADDRESS, Getter::Key { account: sender }));
        let picked = within_budget(getters, MAX_PRIVACY_READS);
        assert_eq!(picked.len(), MAX_PRIVACY_READS);
        assert!(
            picked
                .iter()
                .any(|(target, _)| *target == NONCE_PRECOMPILE_ADDRESS)
        );
        assert!(
            picked
                .iter()
                .any(|(target, _)| *target == ACCOUNT_KEYCHAIN_ADDRESS)
        );
    }
}
