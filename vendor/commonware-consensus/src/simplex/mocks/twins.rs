//! Twins framework scenario generator and executor helpers.
//!
//! This module follows the testing architecture from
//! [Twins: BFT Systems Made Robust](https://arxiv.org/pdf/2004.10617):
//! 1. Generate primary/secondary recipient-set scenarios.
//! 2. Combine those sets with leader choices per round.
//! 3. Arrange those round choices into full multi-round scenarios.
//! 4. Execute each scenario across compromised-node assignments.
//!
//! The original paper models disjoint network partitions over nodes and their
//! twins. This harness deliberately uses a stronger Simplex-specific
//! recipient-set model: the primary and secondary halves are represented as
//! independent recipient masks, so a participant may be visible to both halves,
//! one half, or neither half in a scripted round. After the scripted prefix,
//! traffic returns to all-to-all synchrony and leader election resumes through
//! the caller's fallback elector.
//!
//! Campaigns are intended to cover small representative Twins schedules rather
//! than production-sized validator sets. Participant sets are capped at 64 so
//! recipient sets and residual cell boundaries can be stored as plain `u64`
//! masks.
//!
//! Scenarios are generated in a canonical unlabeled form instead of by
//! enumerating every participant relabeling. The generator tracks participant
//! symmetry classes as `cells`, where each cell is a group of participants that
//! have been indistinguishable across all attack rounds generated so far.
//! Advancing one round refines those cells by splitting each group according to
//! the role its members take in the new round.
//!
//! ## Algorithm
//!
//! In each round, every non-leader participant belongs to one of four ordered
//! role buckets: outside both halves, visible to both halves, visible only to
//! the secondary half, or visible only to the primary half. The generated
//! leader is a singleton at the end of its cell and must be visible to at least
//! one half. Total leader isolation is outside this scenario space.
//!
//! A residual cell is a group of participants with identical role history in
//! the scripted prefix. When a participant leads, it becomes a permanent
//! singleton because future rounds can distinguish it from the other members of
//! its old cell. A transition records only the next residual cell boundaries.
//! For a fixed set of part sizes, multiple role-bucket choices can produce the
//! same next boundaries, so the transition stores their count as
//! `multiplicity`. Scenario counts are computed over this compressed transition
//! DAG, and `round_from_edge` reconstructs sampled rounds by decoding the
//! chosen edge's rank as mixed-radix digits in cell order.
//!
//! For example, with one cell of three participants and leader `2`, a round can
//! split the two non-leaders as `[both = 1, primary-only = 1]` and place the
//! leader in the secondary half. The canonical representative sets primary to
//! `{0, 1}` and secondary to `{0, 2}`, producing residual cells `[1, 1, 1]`.
//! The same part sizes with `both` and `secondary-only` roles instead produce
//! the same residual cells but different masks, so they share the transition
//! target and contribute to its multiplicity.
//!
//! Scenario generation guarantees that every case within a campaign is
//! structurally distinct -- no duplicate (scenario, compromised-assignment)
//! pairs are ever emitted. The scenario space is counted with an exact
//! compressed transition DAG: each edge stores a residual symmetry-cell
//! transition and the exact number of concrete round scenarios represented by
//! that transition. Counts are computed bottom-up over the reachable residual
//! states. When the scenario space exceeds the configured budget, sampled
//! campaigns choose canonical scenarios uniformly without replacement. For each
//! selected scenario, `cases()` computes the residual symmetry cells and
//! generates only the unique compromised-node assignments: two assignments that
//! differ only in which members of a cell are chosen are equivalent and
//! collapsed to a single representative.
//!
//! These recipient sets are not required to be disjoint. A participant may
//! appear in both masks for a round, meaning both twin halves can exchange
//! messages with that participant identity in that view.

use crate::{
    simplex::elector::{Config as ElectorConfig, Elector as Elected},
    types::{Participant, Round, View},
};
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::simulated::SplitTarget;
use commonware_utils::ordered::Set;
use rand::{seq::SliceRandom, Rng, RngExt as _};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

/// Maximum participant count supported by the scenario generator.
const MAX_PARTICIPANTS: usize = u64::BITS as usize;

/// Sizes of the residual symmetry cells in canonical participant order.
///
/// For example, `[2, 1]` represents cells `{0, 1}` and `{2}`.
type Cells = Vec<usize>;

/// Sizes of contiguous role parts within one residual cell.
type Parts = Vec<usize>;

/// Participant index in canonical scenario order.
type ParticipantIndex = usize;

/// Canonical compromised participant indices for one generated case.
type Compromised = Vec<ParticipantIndex>;

/// Per-round adversarial setting from the Twins framework.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoundScenario {
    // Participant index chosen to lead this round.
    leader: ParticipantIndex,
    // Bitmasks selecting which participant identities each twin half can
    // exchange messages with. The masks may overlap.
    primary_mask: u64,
    secondary_mask: u64,
}

impl RoundScenario {
    /// Returns the designated leader index for this round scenario.
    pub const fn leader(&self) -> usize {
        self.leader
    }

    /// Returns recipient sets for this round's twin halves.
    fn partitions<P: Clone>(&self, participants: &[P]) -> (Vec<P>, Vec<P>) {
        let primary = partition_for_mask(self.primary_mask, participants);
        let secondary = partition_for_mask(self.secondary_mask, participants);
        (primary, secondary)
    }

    /// Routes a sender according to this round's recipient masks.
    fn route<P: PartialEq>(&self, sender: &P, participants: &[P]) -> SplitTarget {
        let sender_idx = participants
            .iter()
            .position(|participant| participant == sender)
            .expect("sender missing from runtime participant list");
        let in_primary = mask_contains(self.primary_mask, sender_idx);
        let in_secondary = mask_contains(self.secondary_mask, sender_idx);
        match (in_primary, in_secondary) {
            (true, true) => SplitTarget::Both,
            (true, false) => SplitTarget::Primary,
            (false, true) => SplitTarget::Secondary,
            (false, false) => SplitTarget::None,
        }
    }
}

/// Multi-round scenario from the Twins framework.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Scenario {
    rounds: Vec<RoundScenario>,
}

impl Scenario {
    /// Returns the round scenarios in this scenario.
    pub fn rounds(&self) -> &[RoundScenario] {
        &self.rounds
    }

    /// Returns recipient sets for each twin half at a given view.
    ///
    /// These sets are not required to be disjoint: if the same participant
    /// appears in both, both twin halves may exchange messages with that
    /// participant in the given view.
    ///
    /// Views after the configured adversarial rounds use full synchrony
    /// (`all -> all`) to model eventual synchrony for liveness checks.
    pub fn partitions<P: Clone>(&self, view: View, participants: &[P]) -> (Vec<P>, Vec<P>) {
        let idx = view.get().saturating_sub(1) as usize;
        if let Some(round) = self.rounds.get(idx) {
            return round.partitions(participants);
        }
        (participants.to_vec(), participants.to_vec())
    }

    /// Routes a message from sender to the correct twin half at a given view.
    ///
    /// For scripted rounds, inbound twin traffic is routed by checking the
    /// sender against the primary and secondary bitmasks. When a sender appears
    /// in both masks, this returns [`SplitTarget::Both`].
    ///
    /// # Panics
    ///
    /// Panics if `sender` is not present in `participants` for a scripted
    /// round.
    pub fn route<P: PartialEq>(&self, view: View, sender: &P, participants: &[P]) -> SplitTarget {
        let idx = view.get().saturating_sub(1) as usize;
        if let Some(round) = self.rounds.get(idx) {
            return round.route(sender, participants);
        }
        // After attack rounds, both halves see everyone.
        SplitTarget::Both
    }
}

/// Routes a sender according to explicit primary and secondary recipient sets.
fn route_with_groups<P: PartialEq>(sender: &P, primary: &[P], secondary: &[P]) -> SplitTarget {
    let in_primary = primary.contains(sender);
    let in_secondary = secondary.contains(sender);
    match (in_primary, in_secondary) {
        (true, true) => SplitTarget::Both,
        (true, false) => SplitTarget::Primary,
        (false, true) => SplitTarget::Secondary,
        (false, false) => panic!("sender not in any partition"),
    }
}

/// Returns the strict disjoint split at index `view % n`.
///
/// # Panics
///
/// Panics if `participants` is empty.
pub fn view_partitions<P: Clone>(view: View, participants: &[P]) -> (Vec<P>, Vec<P>) {
    let split = (view.get() as usize) % participants.len();
    let (primary, secondary) = participants.split_at(split);
    (primary.to_vec(), secondary.to_vec())
}

/// Routes a sender according to [`view_partitions`].
///
/// # Panics
///
/// Panics if `participants` is empty or `sender` is not present in
/// `participants`.
pub fn view_route<P: Clone + PartialEq>(view: View, sender: &P, participants: &[P]) -> SplitTarget {
    let (primary, secondary) = view_partitions(view, participants);
    route_with_groups(sender, &primary, &secondary)
}

/// Twins leader-election config that follows scripted scenario leaders before
/// delegating to a fallback elector.
#[derive(Clone, Debug)]
pub struct Elector<C> {
    fallback: C,
    round_leaders: Arc<[Participant]>,
}

impl<C: Default> Default for Elector<C> {
    fn default() -> Self {
        Self {
            fallback: C::default(),
            round_leaders: Arc::from(Vec::new()),
        }
    }
}

impl<C> Elector<C> {
    /// Create a twins elector from a scenario and fallback elector.
    ///
    /// # Panics
    ///
    /// Panics if any scenario leader is outside `0..participants`.
    pub fn new(fallback: C, scenario: &Scenario, participants: usize) -> Self {
        let round_leaders: Vec<_> = scenario
            .rounds()
            .iter()
            .map(|round| {
                assert!(
                    round.leader() < participants,
                    "scenario leader out of bounds"
                );
                Participant::from_usize(round.leader())
            })
            .collect();
        Self {
            fallback,
            round_leaders: Arc::from(round_leaders),
        }
    }
}

/// Initialized twins leader elector built from [`Elector`].
#[derive(Clone, Debug)]
pub struct ElectorState<E> {
    fallback: E,
    round_leaders: Arc<[Participant]>,
}

impl<S, C> ElectorConfig<S> for Elector<C>
where
    S: Scheme,
    C: ElectorConfig<S>,
{
    type Elector = ElectorState<C::Elector>;

    fn build(self, participants: &Set<S::PublicKey>) -> Self::Elector {
        ElectorState {
            fallback: self.fallback.build(participants),
            round_leaders: self.round_leaders,
        }
    }
}

impl<S, E> Elected<S> for ElectorState<E>
where
    S: Scheme,
    E: Elected<S>,
{
    fn elect(&self, round: Round, certificate: Option<&S::Certificate>) -> Participant {
        let idx = round.view().get().saturating_sub(1) as usize;
        if let Some(&leader) = self.round_leaders.get(idx) {
            return leader;
        }

        // After the scripted attack prefix, intentionally resume the caller's
        // fallback elector rather than forcing an honest-only suffix. Twins
        // campaigns should not prevent the protocol from timing out in
        // later views (if a twin is elected).
        self.fallback.elect(round, certificate)
    }
}

/// Controls how multi-round scenarios are constructed.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// Each round gets independently chosen primary and secondary recipient
    /// sets and a leader.
    Sampled,
    /// A single 1-round recipient-set pattern is repeated across all rounds,
    /// modeling a persistent adversarial split.
    Sustained,
}

/// Framework configuration for generating Twins cases.
///
/// The generator uses `u64` masks for recipient sets and residual cell
/// boundaries, so campaigns support at most 64 participants.
///
/// Each canonical scenario tracks residual symmetry cells -- participants that
/// were treated identically across all rounds. Two compromised-node assignments
/// that differ only in which members of a symmetry cell are compromised are
/// equivalent under relabeling for the adversarial prefix, so the framework
/// generates only one representative per equivalence class. This keeps the case
/// budget focused on structurally distinct attack configurations. The
/// synchronous suffix may elect different concrete participant indices after
/// such a relabeling, but under full synchrony the pass/fail verdict is
/// invariant to that relabeling.
///
/// The generator selects canonical scenarios first: all scenarios when the
/// scenario count fits within [`Framework::max_cases`], or uniformly sampled
/// scenario ranks when it does not. It then expands the selected scenarios
/// across their symmetry-unique compromised assignments, shuffles the cases,
/// and truncates to [`Framework::max_cases`]. Scenario counts must fit in
/// `u128`, overflowing configurations panic.
#[derive(Clone, Copy, Debug)]
pub struct Framework {
    /// Number of participants in the network. Must be at most 64.
    pub participants: usize,
    /// Number of compromised participants.
    pub faults: usize,
    /// Number of adversarial rounds before synchronous suffix.
    pub rounds: usize,
    /// How multi-round scenarios are constructed.
    pub mode: Mode,
    /// Upper bound on emitted cases. This also caps the number of canonical
    /// scenarios selected before compromised assignments are expanded.
    pub max_cases: usize,
}

/// Executable case from the Twins framework.
#[derive(Clone, Debug)]
pub struct Case {
    /// Compromised participant indices for this case.
    pub compromised: Compromised,
    /// Multi-round scenario for this case.
    pub scenario: Scenario,
}

/// Generate executable Twins cases from framework parameters.
///
/// The generator computes exact scenario counts from compressed transition
/// multiplicities. It emits every scenario when the count fits within
/// [`Framework::max_cases`] and samples scenario ranks uniformly without
/// replacement when it does not. For each canonical scenario, the generator
/// computes the residual symmetry cells and emits only the structurally unique
/// compromised-node assignments.
///
/// # Panics
///
/// Panics if `framework` has fewer than 2 participants, zero faults, faults
/// greater than or equal to participants, more than 64 participants, zero
/// rounds, or zero max cases. Panics if the canonical scenario count overflows
/// `u128`.
pub fn cases(rng: &mut impl Rng, framework: Framework) -> Vec<Case> {
    assert!(framework.participants > 1, "participants must be > 1");
    assert!(
        framework.participants <= MAX_PARTICIPANTS,
        "participants must be <= {MAX_PARTICIPANTS}"
    );
    assert!(framework.faults > 0, "faults must be > 0");
    assert!(
        framework.faults < framework.participants,
        "faults must be less than participants"
    );
    assert!(framework.rounds > 0, "rounds must be > 0");
    assert!(framework.max_cases > 0, "max_cases must be > 0");

    let mut generator = ScenarioGenerator::new(framework.participants);
    let scenarios = match framework.mode {
        Mode::Sampled => generator.generate(rng, framework.rounds, framework.max_cases),
        Mode::Sustained => {
            // Generate 1-round scenarios and repeat across all rounds.
            // The 1-round residual cells are valid here because applying
            // the same recipient-set pattern repeatedly never distinguishes
            // participants that were indistinguishable after the first round.
            let single_round = generator.generate(rng, 1, framework.max_cases);
            single_round
                .into_iter()
                .map(|(s, cells)| {
                    let scenario = Scenario {
                        rounds: vec![s.rounds[0]; framework.rounds],
                    };
                    (scenario, cells)
                })
                .collect()
        }
    };

    let mut result: Vec<Case> = scenarios
        .iter()
        .flat_map(|(scenario, residual_cells)| {
            compromised_sets_for_cells(residual_cells, framework.faults)
                .into_iter()
                .map(move |compromised| Case {
                    compromised,
                    scenario: scenario.clone(),
                })
        })
        .collect();
    result.shuffle(rng);
    result.truncate(framework.max_cases);
    result
}

/// Materializes the participants selected by a bitmask.
fn partition_for_mask<P: Clone>(mask: u64, participants: &[P]) -> Vec<P> {
    let mut group = Vec::new();
    for (idx, participant) in participants.iter().enumerate() {
        if mask_contains(mask, idx) {
            group.push(participant.clone());
        }
    }
    group
}

/// Sets bit `idx` in `mask`.
#[inline]
const fn set_mask_bit(mask: &mut u64, idx: usize) {
    *mask |= 1u64 << idx;
}

/// Sets every bit in the contiguous range `[start, start + len)`.
#[inline]
const fn set_mask_range(mask: &mut u64, start: usize, len: usize) {
    if len == 0 {
        return;
    }
    let range = if len == u64::BITS as usize {
        u64::MAX
    } else {
        ((1u64 << len) - 1) << start
    };
    *mask |= range;
}

/// Returns whether bit `idx` is set in `mask`.
#[inline]
const fn mask_contains(mask: u64, idx: usize) -> bool {
    idx < MAX_PARTICIPANTS && (mask & (1u64 << idx)) != 0
}

/// Converts cell sizes into contiguous index ranges.
fn cells_to_ranges(cells: &[usize]) -> Vec<(usize, usize)> {
    let mut start = 0usize;
    cells
        .iter()
        .copied()
        .map(|size| {
            let range = (start, size);
            start += size;
            range
        })
        .collect()
}

/// Compact representation of a canonical cell partition.
///
/// Bit `i` is set when there is a cell boundary after participant `i`. The
/// unset gaps between boundaries belong to the same residual symmetry cell.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CellState {
    boundaries: u64,
}

impl CellState {
    /// Returns the state with a single symmetry cell covering all participants.
    fn initial(n: usize) -> Self {
        assert!(
            n <= MAX_PARTICIPANTS,
            "participants must be <= {MAX_PARTICIPANTS}"
        );
        Self { boundaries: 0 }
    }

    /// Converts explicit cell sizes into a boundary mask.
    #[cfg(test)]
    fn from_cells(cells: &[usize]) -> Self {
        let n = cells.iter().sum();
        let mut state = Self::initial(n);
        let mut end = 0usize;
        for size in cells.iter().take(cells.len().saturating_sub(1)) {
            end += size;
            set_mask_bit(&mut state.boundaries, end - 1);
        }
        state
    }

    /// Returns whether this state has a boundary after `idx`.
    const fn boundary_after(&self, idx: usize) -> bool {
        mask_contains(self.boundaries, idx)
    }

    /// Converts the state back into cell sizes.
    fn to_cells(self, n: usize) -> Cells {
        self.ranges(n).into_iter().map(|(_, len)| len).collect()
    }

    /// Converts the state into contiguous `(start, len)` cell ranges.
    fn ranges(&self, n: usize) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        let mut start = 0usize;
        for idx in 0..n.saturating_sub(1) {
            if self.boundary_after(idx) {
                ranges.push((start, idx + 1 - start));
                start = idx + 1;
            }
        }
        ranges.push((start, n - start));
        ranges
    }

    /// Returns the positive parts of the cell `[start, start + size)`.
    fn parts_in_cell(&self, start: usize, size: usize) -> Parts {
        let end = start + size;
        let mut parts = Vec::new();
        let mut part_start = start;
        for idx in start..end {
            if idx + 1 == end || self.boundary_after(idx) {
                parts.push(idx + 1 - part_start);
                part_start = idx + 1;
            }
        }
        parts
    }

    /// Adds boundaries for `parts` starting at `start`.
    fn add_local_boundaries(&mut self, start: usize, n: usize, parts: &[usize]) {
        let mut offset = 0usize;
        for part in parts {
            offset += part;
            let end = start + offset;
            if end < n {
                set_mask_bit(&mut self.boundaries, end - 1);
            }
        }
    }
}

/// One local cell refinement used while building compressed transition edges.
///
/// A non-leader cell can split into at most the four non-empty role buckets
/// `outside`, `both`, `secondary-only`, and `primary-only`. The leader cell
/// uses the same buckets for its non-leader prefix and then appends the leader
/// singleton as the final part. `parts` stores the resulting non-empty bucket
/// sizes, `multiplicity` counts how many ordered role-bucket choices produce
/// those same sizes.
#[derive(Clone, Copy, Debug)]
struct LocalRefinement {
    parts: [usize; 5],
    len: usize,
    multiplicity: u128,
}

impl LocalRefinement {
    /// Creates a refinement from `parts`, copying them into fixed storage.
    fn new(parts: &[usize], multiplicity: u128) -> Self {
        let mut stored = [0usize; 5];
        stored[..parts.len()].copy_from_slice(parts);
        Self {
            parts: stored,
            len: parts.len(),
            multiplicity,
        }
    }

    /// Returns the non-zero contiguous parts that form this refinement.
    fn parts(&self) -> &[usize] {
        &self.parts[..self.len]
    }
}

/// Compressed transition to a residual cell state.
///
/// `multiplicity` is the exact number of `RoundScenario`s that produce `next`
/// when `leader_cell` supplies the canonical leader. During suffix counting,
/// this edge contributes `multiplicity * suffix_count(next)`. This value must
/// match the product of the per-cell local spaces decoded by `round_from_edge`.
#[derive(Clone, Copy, Debug)]
struct TransitionEdge {
    next: CellState,
    leader_cell: usize,
    multiplicity: u128,
}

/// Compressed outgoing transitions for one residual cell state.
///
/// `overflowed` is set when at least one transition multiplicity cannot be
/// represented as a `u128`, scenario counting treats that as count overflow.
#[derive(Clone, Debug, Default)]
struct TransitionSet {
    edges: Vec<TransitionEdge>,
    overflowed: bool,
}

/// Recursively combines precomputed local cell refinements into compressed edges.
fn build_transitions(
    ranges: &[(usize, usize)],
    refinements_by_cell: &[Vec<LocalRefinement>],
    leader_cell: usize,
    cell_idx: usize,
    next_state: CellState,
    multiplicity: u128,
    transitions: &mut TransitionSet,
) {
    if cell_idx == ranges.len() {
        // Every current cell has chosen one local refinement. The accumulated
        // boundary mask identifies the residual state reached by this round,
        // and multiplicity is the product of the local role spaces that map to
        // that same residual state.
        transitions.edges.push(TransitionEdge {
            next: next_state,
            leader_cell,
            multiplicity,
        });
        return;
    }

    let (start, _) = ranges[cell_idx];
    let n = ranges
        .last()
        .map(|(start, len)| start + len)
        .expect("transition ranges must be non-empty");
    for refinement in refinements_by_cell[cell_idx].iter().copied() {
        // Choose one refinement for this cell and carry its contribution into
        // the DFS prefix. Different refinements may produce the same
        // `next_state`, keeping them as separate edges is intentional because
        // unranking uses each edge's multiplicity to reconstruct a concrete
        // round.
        let Some(multiplicity) = multiplicity.checked_mul(refinement.multiplicity) else {
            transitions.overflowed = true;
            continue;
        };
        let mut next_state = next_state;
        next_state.add_local_boundaries(start, n, refinement.parts());
        build_transitions(
            ranges,
            refinements_by_cell,
            leader_cell,
            cell_idx + 1,
            next_state,
            multiplicity,
            transitions,
        );
    }
}

/// Role of a non-leader contiguous part in a round refinement.
///
/// The declaration order is the canonical role order used when reconstructing
/// a concrete transition from its rank.
#[derive(Clone, Copy, Debug)]
enum Role {
    Outside,
    Both,
    Secondary,
    Primary,
}

/// Scenario generator for a fixed participant count.
///
/// The generator lazily memoizes the compressed transition DAG keyed by
/// residual symmetry state. Each transition set describes the canonical
/// one-round refinements reachable from a state, with edge multiplicities
/// carrying the number of concrete role choices represented by that edge.
/// Generation first builds exact suffix counts over this DAG, then enumerates
/// or samples scenario ranks and unpacks each selected rank into concrete
/// [`RoundScenario`] masks.
struct ScenarioGenerator {
    /// Number of participants in the generated scenarios.
    n: usize,
    /// Memoized outgoing transitions for each residual symmetry state.
    transition_memo: HashMap<CellState, TransitionSet>,
    /// Memoized cell-local refinements keyed by cell size and whether the cell
    /// contains the round leader.
    local_memo: HashMap<(usize, bool), Vec<LocalRefinement>>,
}

impl ScenarioGenerator {
    /// Creates a generator for `n` participants.
    fn new(n: usize) -> Self {
        Self {
            n,
            transition_memo: HashMap::new(),
            local_memo: HashMap::new(),
        }
    }

    /// Enumerates canonical scenarios with their residual symmetry cells.
    ///
    /// Returns all scenarios when the space fits within `max_scenarios`,
    /// otherwise samples `max_scenarios` without replacement.
    ///
    /// # Panics
    ///
    /// Panics if the scenario space overflows `u128`.
    fn generate(
        &mut self,
        rng: &mut impl Rng,
        rounds: usize,
        max_scenarios: usize,
    ) -> Vec<(Scenario, Cells)> {
        let initial = CellState::initial(self.n);

        // Count the complete canonical scenario space before choosing which
        // ranks to materialize. The same count table is reused by unranking so
        // each selected rank can skip whole compressed subtrees.
        let counts = self
            .counts(&initial, rounds)
            .expect("scenario space overflows u128; reduce rounds or participants");
        let total = counts[rounds][&initial];

        // If the requested budget covers the whole space, enumerate ranks in
        // canonical order. Otherwise sample distinct ranks uniformly and
        // materialize only those scenarios.
        if total <= max_scenarios as u128 {
            return (0..total)
                .map(|idx| self.scenario_from_rank(&initial, rounds, idx, &counts))
                .collect();
        }
        sample_unique_indices(rng, total, max_scenarios)
            .into_iter()
            .map(|idx| self.scenario_from_rank(&initial, rounds, idx, &counts))
            .collect()
    }

    /// Builds bottom-up scenario counts for paths starting at `initial`.
    ///
    /// `counts[r][state]` is the exact number of canonical scenario suffixes
    /// of length `r` reachable from `state`. `None` indicates arithmetic
    /// overflow while building transitions or summing suffix counts.
    fn counts(
        &mut self,
        initial: &CellState,
        rounds: usize,
    ) -> Option<Vec<HashMap<CellState, u128>>> {
        // First discover which residual states can appear at each depth from
        // the initial state. Later DP layers only need to account for these
        // reachable states.
        let mut layers = Vec::with_capacity(rounds + 1);
        layers.push(HashSet::from([*initial]));

        for depth in 0..rounds {
            let mut next_layer = HashSet::new();
            for state in layers[depth].iter() {
                self.ensure_transitions(state);
                let transitions = self.transitions(state);
                if transitions.overflowed {
                    return None;
                }
                for edge in &transitions.edges {
                    next_layer.insert(edge.next);
                }
            }
            layers.push(next_layer);
        }

        // A zero-round suffix has exactly one continuation: emit no more
        // rounds. Seed that base case for every state reachable after the full
        // scripted prefix.
        let mut counts = vec![HashMap::new(); rounds + 1];
        for state in layers[rounds].iter() {
            counts[0].insert(*state, 1);
        }

        // Fold suffix counts back toward the initial state. Each outgoing edge
        // contributes its round multiplicity times the number of suffixes from
        // the edge's next residual state.
        for remaining in 1..=rounds {
            let depth = rounds - remaining;
            for state in layers[depth].iter() {
                self.ensure_transitions(state);
                let transitions = self.transitions(state);
                if transitions.overflowed {
                    return None;
                }

                let mut total = 0u128;
                for edge in &transitions.edges {
                    let suffix = counts[remaining - 1]
                        .get(&edge.next)
                        .copied()
                        .expect("next state missing from count layer");
                    let edge_count = edge.multiplicity.checked_mul(suffix)?;
                    total = total.checked_add(edge_count)?;
                }
                counts[remaining].insert(*state, total);
            }
        }

        Some(counts)
    }

    /// Reconstructs the scenario at `rank` under the compressed ordering.
    fn scenario_from_rank(
        &mut self,
        initial: &CellState,
        rounds: usize,
        mut rank: u128,
        counts: &[HashMap<CellState, u128>],
    ) -> (Scenario, Cells) {
        let mut scenario = Vec::with_capacity(rounds);
        let mut state = *initial;

        // Walk the scenario prefix from left to right. At each residual state,
        // each edge owns a contiguous rank interval equal to its concrete
        // round multiplicity times the number of suffixes behind its next
        // state.
        for remaining in (1..=rounds).rev() {
            self.ensure_transitions(&state);
            let transitions = self.transitions(&state);
            assert!(
                !transitions.overflowed,
                "transition multiplicity should fit in u128"
            );

            let mut selected = false;
            for edge in &transitions.edges {
                let suffix = counts[remaining - 1]
                    .get(&edge.next)
                    .copied()
                    .expect("next state missing from count layer");
                let subtree_count = edge
                    .multiplicity
                    .checked_mul(suffix)
                    .expect("canonical scenario count should fit in u128");

                if rank < subtree_count {
                    // The high digit selects which concrete round within this
                    // edge to decode, the remainder is the suffix rank used at
                    // the next residual state.
                    let transition_rank = rank / suffix;
                    scenario.push(self.round_from_edge(&state, edge, transition_rank));
                    state = edge.next;
                    rank %= suffix;
                    selected = true;
                    break;
                }
                rank -= subtree_count;
            }
            assert!(selected, "canonical scenario rank out of bounds");
        }

        (Scenario { rounds: scenario }, state.to_cells(self.n))
    }

    /// Ensures compressed transition edges for `state` are memoized.
    fn ensure_transitions(&mut self, state: &CellState) {
        if self.transition_memo.contains_key(state) {
            return;
        }
        let ranges = state.ranges(self.n);
        let mut transitions = TransitionSet::default();

        // Try each residual cell as the canonical source of this round's
        // leader. The leader cell's local refinements reserve its final
        // participant as a singleton leader part.
        for leader_cell in 0..ranges.len() {
            let refinements: Vec<_> = ranges
                .iter()
                .enumerate()
                .map(|(cell_idx, (_, size))| {
                    self.local_refinements(*size, cell_idx == leader_cell)
                        .to_vec()
                })
                .collect();

            // Combine one local refinement per cell into complete outgoing
            // edges for this leader choice.
            build_transitions(
                &ranges,
                &refinements,
                leader_cell,
                0,
                CellState::initial(self.n),
                1,
                &mut transitions,
            );
        }
        self.transition_memo.insert(*state, transitions);
    }

    /// Returns memoized compressed transition edges for `state`.
    fn transitions(&self, state: &CellState) -> &TransitionSet {
        self.transition_memo
            .get(state)
            .expect("transition set should be memoized")
    }

    /// Returns all local refinements for a cell of `size`.
    fn local_refinements(&mut self, size: usize, is_leader: bool) -> &[LocalRefinement] {
        self.local_memo
            .entry((size, is_leader))
            .or_insert_with(|| build_local_refinements(size, is_leader))
            .as_slice()
    }

    /// Reconstructs one concrete round represented by `edge`.
    fn round_from_edge(
        &self,
        state: &CellState,
        edge: &TransitionEdge,
        mut rank: u128,
    ) -> RoundScenario {
        let mut primary_mask = 0u64;
        let mut secondary_mask = 0u64;
        let mut leader = None;

        // The edge fixes only the next residual cell boundaries. Decode the
        // edge-local rank in cell order: each low digit selects this cell's
        // role subset, and the leader cell has an extra digit for which half
        // sees the leader.
        for (cell_idx, (start, size)) in state.ranges(self.n).into_iter().enumerate() {
            // Recover this current cell's part sizes by slicing it with the
            // next state's residual boundaries.
            let parts = edge.next.parts_in_cell(start, size);
            if cell_idx == edge.leader_cell {
                let non_leader_len = parts.len() - 1;
                let role_count = role_subset_count(non_leader_len);
                let local_space = role_count * 3;
                let local_rank = rank % local_space;
                rank /= local_space;

                // The leader cell first consumes a role-subset digit for its
                // non-leader prefix, then one of three leader placements:
                // primary-only, secondary-only, or both halves.
                let roles = roles_from_rank(non_leader_len, local_rank / 3);
                apply_roles(
                    start,
                    &parts[..non_leader_len],
                    &roles[..non_leader_len],
                    &mut primary_mask,
                    &mut secondary_mask,
                );

                let leader_idx = start + size - 1;
                match local_rank % 3 {
                    0 => set_mask_bit(&mut primary_mask, leader_idx),
                    1 => set_mask_bit(&mut secondary_mask, leader_idx),
                    2 => {
                        set_mask_bit(&mut primary_mask, leader_idx);
                        set_mask_bit(&mut secondary_mask, leader_idx);
                    }
                    _ => unreachable!("leader placement rank out of bounds"),
                }
                leader = Some(leader_idx);
            } else {
                let role_count = role_subset_count(parts.len());
                let local_rank = rank % role_count;
                rank /= role_count;

                // Non-leader cells only consume a role-subset digit.
                let roles = roles_from_rank(parts.len(), local_rank);
                apply_roles(
                    start,
                    &parts,
                    &roles[..parts.len()],
                    &mut primary_mask,
                    &mut secondary_mask,
                );
            }
        }

        assert_eq!(rank, 0, "transition rank should be fully consumed");
        RoundScenario {
            leader: leader.expect("leader cell should assign a leader"),
            primary_mask,
            secondary_mask,
        }
    }
}

/// Number of ways to choose `len` non-empty role buckets from four ordered
/// non-leader roles.
const fn role_subset_count(len: usize) -> u128 {
    match len {
        0 => 1,
        1 => 4,
        2 => 6,
        3 => 4,
        4 => 1,
        _ => panic!("role bucket count exceeds role space"),
    }
}

/// Builds all local refinements for a cell.
///
/// A local refinement is the shape this cell can have after one round. The
/// shape only stores contiguous part sizes, `multiplicity` records how many
/// assignments of those parts to the ordered non-leader roles produce the same
/// shape.
fn build_local_refinements(size: usize, is_leader: bool) -> Vec<LocalRefinement> {
    let mut refinements = Vec::new();
    let available = if is_leader { size - 1 } else { size };
    let mut prefix = Vec::new();
    for_each_composition(available, 4, &mut prefix, &mut |parts| {
        // `parts` partitions the non-leader portion into the non-empty role
        // buckets that will remain distinguishable after this round.
        let role_choices = role_subset_count(parts.len());
        let mut local = Vec::with_capacity(parts.len() + usize::from(is_leader));
        local.extend_from_slice(parts);
        let multiplicity = if is_leader {
            // The leader is always the final participant in its current cell
            // and becomes a singleton residual cell. It can be visible to the
            // primary half, the secondary half, or both halves.
            local.push(1);
            role_choices * 3
        } else {
            role_choices
        };
        refinements.push(LocalRefinement::new(&local, multiplicity));
    });
    refinements
}

/// Enumerates positive compositions of `total` into at most `max_parts` parts.
///
/// The empty composition is emitted for `total == 0`, which is needed for a
/// singleton leader cell with no non-leader prefix.
fn for_each_composition<F: FnMut(&[usize])>(
    total: usize,
    max_parts: usize,
    current: &mut Parts,
    f: &mut F,
) {
    if total == 0 {
        f(current);
        return;
    }
    for parts in 1..=total.min(max_parts) {
        for_each_composition_with_len(total, parts, current, f);
    }
}

/// Enumerates positive compositions of `remaining` with exactly `parts_left`
/// parts.
fn for_each_composition_with_len<F: FnMut(&[usize])>(
    remaining: usize,
    parts_left: usize,
    current: &mut Parts,
    f: &mut F,
) {
    if parts_left == 0 {
        if remaining == 0 {
            f(current);
        }
        return;
    }
    if parts_left == 1 {
        current.push(remaining);
        f(current);
        current.pop();
        return;
    }

    let max_first = remaining - (parts_left - 1);
    for first in 1..=max_first {
        current.push(first);
        for_each_composition_with_len(remaining - first, parts_left - 1, current, f);
        current.pop();
    }
}

/// Returns the ranked subset of `len` roles from the four ordered non-leader
/// roles. The selected roles are returned in canonical role order.
///
/// A local refinement with `len` parts does not store which role bucket each
/// part came from. Its rank selects one of the `C(4, len)` non-empty subsets of
/// the ordered role list: outside, both, secondary-only, primary-only.
fn roles_from_rank(len: usize, rank: u128) -> [Role; 4] {
    let mut seen = 0u128;
    for mask in 0u8..16 {
        if mask.count_ones() as usize != len {
            continue;
        }
        if seen == rank {
            let mut roles = [Role::Outside; 4];
            let mut next = 0usize;
            // Scan masks in numeric order while assigning selected bits in the
            // canonical role order. This is the inverse of the
            // `role_subset_count(len)` space used by local refinements.
            for (bit, role) in [Role::Outside, Role::Both, Role::Secondary, Role::Primary]
                .into_iter()
                .enumerate()
            {
                if (mask & (1u8 << bit)) != 0 {
                    roles[next] = role;
                    next += 1;
                }
            }
            return roles;
        }
        seen += 1;
    }
    unreachable!("role subset rank out of bounds")
}

/// Applies `roles` to contiguous `parts` starting at `start`.
fn apply_roles(
    start: usize,
    parts: &[usize],
    roles: &[Role],
    primary_mask: &mut u64,
    secondary_mask: &mut u64,
) {
    let mut offset = 0usize;
    for (part, role) in parts.iter().zip(roles) {
        let range_start = start + offset;
        match role {
            Role::Outside => {}
            Role::Both => {
                set_mask_range(primary_mask, range_start, *part);
                set_mask_range(secondary_mask, range_start, *part);
            }
            Role::Secondary => set_mask_range(secondary_mask, range_start, *part),
            Role::Primary => set_mask_range(primary_mask, range_start, *part),
        }
        offset += part;
    }
}

/// Generates compromised-node assignments that are unique modulo residual
/// symmetry cells.
///
/// Two assignments are equivalent if one can be obtained from the other by
/// permuting participants within the same cell. This function emits exactly
/// one canonical representative per equivalence class by always picking the
/// first indices from each cell.
fn compromised_sets_for_cells(cells: &[usize], faults: usize) -> Vec<Compromised> {
    let ranges = cells_to_ranges(cells);
    let mut result = Vec::new();
    let mut current = Vec::new();
    allocate_faults(&ranges, 0, faults, &mut current, &mut result);
    result
}

/// Recursively allocates `remaining` faults across cells starting at
/// `cell_idx`, picking the first `take` indices from each cell as the
/// canonical representative.
fn allocate_faults(
    ranges: &[(usize, usize)],
    cell_idx: usize,
    remaining: usize,
    current: &mut Compromised,
    result: &mut Vec<Compromised>,
) {
    if remaining == 0 {
        result.push(current.clone());
        return;
    }
    if cell_idx >= ranges.len() {
        return;
    }
    let (start, size) = ranges[cell_idx];
    let remaining_capacity: usize = ranges[cell_idx..].iter().map(|(_, s)| *s).sum();
    if remaining > remaining_capacity {
        return;
    }
    let max_from_this = remaining.min(size);
    for take in 0..=max_from_this {
        for i in 0..take {
            current.push(start + i);
        }
        allocate_faults(ranges, cell_idx + 1, remaining - take, current, result);
        for _ in 0..take {
            current.pop();
        }
    }
}

/// Samples unique indices without replacement from `[0, total)`.
fn sample_unique_indices(rng: &mut impl Rng, total: u128, samples: usize) -> Vec<u128> {
    assert!(
        (samples as u128) <= total,
        "cannot sample more unique indices than total domain size"
    );
    if samples == 0 {
        return Vec::new();
    }

    // Floyd's algorithm: O(samples) time, no retry loop.
    let mut sampled = Vec::with_capacity(samples);
    let mut seen = HashSet::with_capacity(samples);
    for idx in (total - samples as u128)..total {
        let candidate = rng.random_range(0..=idx);
        if seen.insert(candidate) {
            sampled.push(candidate);
        } else {
            assert!(
                seen.insert(idx),
                "tail index should be unique in Floyd sampling"
            );
            sampled.push(idx);
        }
    }
    sampled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            elector::{Config as ElectorConfig, RoundRobin},
            scheme::ed25519,
        },
        types::Epoch,
    };
    use commonware_cryptography::{ed25519::PrivateKey, Sha256, Signer};
    use commonware_utils::{ordered::Set, test_rng, TestRng};
    use std::collections::HashSet;

    fn round(_: usize, leader: usize, primary_mask: u64, secondary_mask: u64) -> RoundScenario {
        RoundScenario {
            leader,
            primary_mask,
            secondary_mask,
        }
    }

    fn range_mask(start: usize, len: usize) -> u64 {
        if len == 0 {
            return 0;
        }
        (((1u128 << len) - 1) << start) as u64
    }

    // Independent reference enumerator for small test cases. The production
    // generator uses compressed transition edges, while this helper expands
    // next-round refinements directly so tests can compare the DAG counter and
    // unranker against a simpler implementation.
    fn reference_next_round_transitions(cells: &[usize]) -> Vec<(RoundScenario, Cells)> {
        let n = cells.iter().sum();

        #[derive(Clone, Copy)]
        struct PrimaryState {
            primary_mask: u64,
            leader: Option<usize>,
        }

        #[derive(Clone, Copy)]
        struct SecondaryState {
            primary_mask: u64,
            secondary_mask: u64,
            leader: Option<usize>,
        }

        const LEADER_PLACEMENTS: &[(bool, bool)] = &[(true, false), (false, true), (true, true)];

        fn push_nonzero_cells(next_cells: &mut Cells, sizes: [usize; 4]) {
            for size in sizes {
                if size > 0 {
                    next_cells.push(size);
                }
            }
        }

        fn no_secondary(
            n: usize,
            ranges: &[(usize, usize)],
            leader_cell: usize,
            cell_idx: usize,
            state: PrimaryState,
            next_cells: &mut Cells,
            out: &mut Vec<(RoundScenario, Cells)>,
        ) {
            if cell_idx == ranges.len() {
                out.push((
                    round(
                        n,
                        state.leader.expect("leader cell should assign a leader"),
                        state.primary_mask,
                        state.primary_mask,
                    ),
                    next_cells.clone(),
                ));
                return;
            }

            let (start, size) = ranges[cell_idx];
            let max_outside = if cell_idx == leader_cell {
                size - 1
            } else {
                size
            };
            for outside in 0..=max_outside {
                let both = if cell_idx == leader_cell {
                    size - outside - 1
                } else {
                    size - outside
                };

                if outside > 0 {
                    next_cells.push(outside);
                }
                if both > 0 {
                    next_cells.push(both);
                }

                let mut next_primary = state.primary_mask | range_mask(start + outside, both);
                let mut next_leader = state.leader;
                if cell_idx == leader_cell {
                    let leader_idx = start + outside + both;
                    next_primary |= 1u64 << leader_idx;
                    next_cells.push(1);
                    next_leader = Some(leader_idx);
                }

                no_secondary(
                    n,
                    ranges,
                    leader_cell,
                    cell_idx + 1,
                    PrimaryState {
                        primary_mask: next_primary,
                        leader: next_leader,
                    },
                    next_cells,
                    out,
                );

                if cell_idx == leader_cell {
                    next_cells.pop();
                }
                if both > 0 {
                    next_cells.pop();
                }
                if outside > 0 {
                    next_cells.pop();
                }
            }
        }

        fn with_secondary(
            n: usize,
            ranges: &[(usize, usize)],
            leader_cell: usize,
            cell_idx: usize,
            state: SecondaryState,
            next_cells: &mut Cells,
            out: &mut Vec<(RoundScenario, Cells)>,
        ) {
            if cell_idx == ranges.len() {
                if state.primary_mask == state.secondary_mask {
                    return;
                }
                out.push((
                    round(
                        n,
                        state.leader.expect("leader cell should assign a leader"),
                        state.primary_mask,
                        state.secondary_mask,
                    ),
                    next_cells.clone(),
                ));
                return;
            }

            let (start, size) = ranges[cell_idx];
            let has_leader = cell_idx == leader_cell;
            let available = if has_leader { size - 1 } else { size };

            for outside in 0..=available {
                let remaining_after_outside = available - outside;
                for both in 0..=remaining_after_outside {
                    let remaining = remaining_after_outside - both;
                    for secondary in 0..=remaining {
                        let primary = remaining - secondary;
                        let checkpoint = next_cells.len();
                        push_nonzero_cells(next_cells, [outside, both, secondary, primary]);

                        let shared_mask = range_mask(start + outside, both);
                        let next_secondary = state.secondary_mask
                            | shared_mask
                            | range_mask(start + outside + both, secondary);
                        let next_primary = state.primary_mask
                            | shared_mask
                            | range_mask(start + outside + both + secondary, primary);
                        if has_leader {
                            let leader_idx = start + outside + both + secondary + primary;
                            next_cells.push(1);
                            for &(leader_in_primary, leader_in_secondary) in LEADER_PLACEMENTS {
                                let leader_bit = 1u64 << leader_idx;
                                with_secondary(
                                    n,
                                    ranges,
                                    leader_cell,
                                    cell_idx + 1,
                                    SecondaryState {
                                        primary_mask: if leader_in_primary {
                                            next_primary | leader_bit
                                        } else {
                                            next_primary
                                        },
                                        secondary_mask: if leader_in_secondary {
                                            next_secondary | leader_bit
                                        } else {
                                            next_secondary
                                        },
                                        leader: Some(leader_idx),
                                    },
                                    next_cells,
                                    out,
                                );
                            }
                        } else {
                            with_secondary(
                                n,
                                ranges,
                                leader_cell,
                                cell_idx + 1,
                                SecondaryState {
                                    primary_mask: next_primary,
                                    secondary_mask: next_secondary,
                                    leader: state.leader,
                                },
                                next_cells,
                                out,
                            );
                        }
                        next_cells.truncate(checkpoint);
                    }
                }
            }
        }

        let ranges = cells_to_ranges(cells);
        let mut out = Vec::new();
        for leader_cell in 0..cells.len() {
            let mut next_cells = Vec::new();
            no_secondary(
                n,
                &ranges,
                leader_cell,
                0,
                PrimaryState {
                    primary_mask: 0,
                    leader: None,
                },
                &mut next_cells,
                &mut out,
            );
            let mut next_cells = Vec::new();
            with_secondary(
                n,
                &ranges,
                leader_cell,
                0,
                SecondaryState {
                    primary_mask: 0,
                    secondary_mask: 0,
                    leader: None,
                },
                &mut next_cells,
                &mut out,
            );
        }
        out
    }

    fn reference_scenario_count(
        cells: &[usize],
        rounds: usize,
        memo: &mut HashMap<(Cells, usize), Option<u128>>,
    ) -> Option<u128> {
        if rounds == 0 {
            return Some(1);
        }
        let key = (cells.to_vec(), rounds);
        if let Some(cached) = memo.get(&key) {
            return *cached;
        }

        let result = (|| {
            let mut total = 0u128;
            for (_, next_cells) in reference_next_round_transitions(cells) {
                let suffix = reference_scenario_count(&next_cells, rounds - 1, memo)?;
                total = total.checked_add(suffix)?;
            }
            Some(total)
        })();
        memo.insert(key, result);
        result
    }

    fn reference_scenarios(cells: &[usize], rounds: usize) -> HashSet<(Scenario, Cells)> {
        if rounds == 0 {
            return HashSet::from([(Scenario { rounds: Vec::new() }, cells.to_vec())]);
        }

        let mut out = HashSet::new();
        for (round, next_cells) in reference_next_round_transitions(cells) {
            for (mut scenario, residual) in reference_scenarios(&next_cells, rounds - 1) {
                scenario.rounds.insert(0, round);
                out.insert((scenario, residual));
            }
        }
        out
    }

    fn expected_single_round_transitions(n: usize) -> HashSet<(RoundScenario, Cells)> {
        let mut out = HashSet::new();

        for outside in 0..n {
            let both = n - outside - 1;
            let leader = outside + both;
            let leader_bit = 1u64 << leader;
            let mask = range_mask(outside, both) | leader_bit;

            let mut cells = Vec::new();
            if outside > 0 {
                cells.push(outside);
            }
            if both > 0 {
                cells.push(both);
            }
            cells.push(1);

            out.insert((round(n, leader, mask, mask), cells));
        }

        for outside in 0..n {
            let remaining_after_outside = n - outside - 1;
            for both in 0..=remaining_after_outside {
                let remaining = remaining_after_outside - both;
                for secondary in 0..=remaining {
                    let primary = remaining - secondary;
                    let leader = outside + both + secondary + primary;
                    let leader_bit = 1u64 << leader;
                    let shared_mask = range_mask(outside, both);
                    let secondary_mask = shared_mask | range_mask(outside + both, secondary);
                    let primary_mask =
                        shared_mask | range_mask(outside + both + secondary, primary);

                    let mut cells = Vec::new();
                    if outside > 0 {
                        cells.push(outside);
                    }
                    if both > 0 {
                        cells.push(both);
                    }
                    if secondary > 0 {
                        cells.push(secondary);
                    }
                    if primary > 0 {
                        cells.push(primary);
                    }
                    cells.push(1);

                    out.insert((
                        round(n, leader, primary_mask | leader_bit, secondary_mask),
                        cells.clone(),
                    ));
                    out.insert((
                        round(n, leader, primary_mask, secondary_mask | leader_bit),
                        cells.clone(),
                    ));
                    out.insert((
                        round(
                            n,
                            leader,
                            primary_mask | leader_bit,
                            secondary_mask | leader_bit,
                        ),
                        cells,
                    ));
                }
            }
        }

        out
    }

    #[test]
    fn generated_cases_are_deterministic() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            mode: Mode::Sampled,
            max_cases: 50,
        };
        let first = cases(&mut test_rng(), framework);
        let second = cases(&mut test_rng(), framework);
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.compromised, b.compromised);
            assert_eq!(a.scenario, b.scenario);
        }
    }

    #[test]
    fn sampled_cases_are_unique() {
        let framework = Framework {
            participants: 7,
            faults: 2,
            rounds: 3,
            mode: Mode::Sampled,
            max_cases: 64,
        };
        let generated = cases(&mut test_rng(), framework);
        assert_eq!(generated.len(), framework.max_cases);

        let mut seen = HashSet::new();
        for case in generated {
            assert!(
                seen.insert((case.scenario, case.compromised)),
                "duplicate generated case"
            );
        }
    }

    #[test]
    fn generated_single_round_scenarios_match_expected_canonical_space() {
        for n in 3..=5 {
            let mut generator = ScenarioGenerator::new(n);
            let generated: HashSet<_> = generator
                .generate(&mut test_rng(), 1, usize::MAX)
                .into_iter()
                .map(|(scenario, cells)| (scenario.rounds[0], cells))
                .collect();
            assert_eq!(generated, expected_single_round_transitions(n));
        }
    }

    #[test]
    fn cell_state_roundtrips_cell_partitions() {
        for cells in [
            vec![5],
            vec![1, 4],
            vec![2, 1, 2],
            vec![1, 1, 1, 1],
            vec![3, 2, 1],
        ] {
            let n = cells.iter().sum();
            let state = CellState::from_cells(&cells);
            let ranges = cells_to_ranges(&cells);

            assert_eq!(state.to_cells(n), cells);
            assert_eq!(state.ranges(n), ranges);
        }
    }

    #[test]
    fn compressed_counts_match_reference_enumeration() {
        for n in 2..=4 {
            for rounds in 1..=3 {
                let initial_cells = vec![n];
                let mut reference_memo = HashMap::new();
                let reference =
                    reference_scenario_count(&initial_cells, rounds, &mut reference_memo);

                let initial = CellState::from_cells(&initial_cells);
                let mut generator = ScenarioGenerator::new(n);
                let counts = generator.counts(&initial, rounds);
                let compressed = counts.as_ref().map(|counts| counts[rounds][&initial]);
                assert_eq!(
                    compressed, reference,
                    "count mismatch for n={n} rounds={rounds}"
                );
            }
        }
    }

    #[test]
    fn compressed_unranking_matches_reference_space() {
        for (n, rounds) in [(2usize, 3usize), (3, 2)] {
            let mut generator = ScenarioGenerator::new(n);
            let generated: HashSet<_> = generator
                .generate(&mut test_rng(), rounds, usize::MAX)
                .into_iter()
                .collect();
            assert_eq!(
                generated,
                reference_scenarios(&[n], rounds),
                "mismatch for n={n} rounds={rounds}"
            );
        }
    }

    #[test]
    fn scripted_partitions_preserve_participant_order_and_overlap() {
        let scenario = Scenario {
            rounds: vec![round(4, 3, 0b1011, 0b0110)],
        };
        let participants: Vec<u32> = (0..4).collect();
        let (primary, secondary) = scenario.partitions(View::new(1), &participants);

        assert_eq!(primary, vec![0, 1, 3]);
        assert_eq!(secondary, vec![1, 2]);
    }

    #[test]
    fn route_with_groups_covers_reachable_split_targets() {
        let primary = vec![1u32, 2];
        let secondary = vec![2u32, 3];

        assert_eq!(
            route_with_groups(&2, &primary, &secondary),
            SplitTarget::Both
        );
        assert_eq!(
            route_with_groups(&1, &primary, &secondary),
            SplitTarget::Primary
        );
        assert_eq!(
            route_with_groups(&3, &primary, &secondary),
            SplitTarget::Secondary
        );
    }

    #[test]
    #[should_panic(expected = "sender not in any partition")]
    fn route_with_groups_panics_when_sender_is_missing() {
        let primary = vec![1u32, 2];
        let secondary = vec![2u32, 3];

        let _ = route_with_groups(&0, &primary, &secondary);
    }

    #[test]
    fn view_helpers_follow_modulo_split() {
        let participants: Vec<u32> = (0..4).collect();

        assert_eq!(
            view_partitions(View::new(1), &participants),
            (vec![0], vec![1, 2, 3])
        );
        assert_eq!(
            view_partitions(View::new(4), &participants),
            (Vec::<u32>::new(), participants.clone())
        );
        assert_eq!(
            view_route(View::new(1), &0, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            view_route(View::new(1), &3, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            view_route(View::new(4), &0, &participants),
            SplitTarget::Secondary
        );
    }

    #[test]
    fn route_supports_shared_non_leaders_in_split_rounds() {
        let scenario = Scenario {
            rounds: vec![round(5, 4, 0b11010, 0b00110)],
        };
        let participants: Vec<u32> = (0..5).collect();
        assert_eq!(
            scenario.route(View::new(1), &0, &participants),
            SplitTarget::None
        );
        assert_eq!(
            scenario.route(View::new(1), &1, &participants),
            SplitTarget::Both
        );
        assert_eq!(
            scenario.route(View::new(1), &2, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            scenario.route(View::new(1), &3, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            scenario.route(View::new(1), &4, &participants),
            SplitTarget::Primary
        );
    }

    #[test]
    fn leader_visible_to_both_halves_preserves_partitions_and_route() {
        let scenario = Scenario {
            rounds: vec![round(4, 3, 0b1010, 0b1100)],
        };
        let participants: Vec<u32> = (0..4).collect();
        let (primary, secondary) = scenario.partitions(View::new(1), &participants);

        assert_eq!(primary, vec![1, 3]);
        assert_eq!(secondary, vec![2, 3]);
        assert_eq!(
            scenario.route(View::new(1), &3, &participants),
            SplitTarget::Both
        );
    }

    #[test]
    fn generated_split_round_leaders_belong_to_at_least_one_half() {
        let mut generator = ScenarioGenerator::new(4);
        let scenarios = generator.generate(&mut test_rng(), 2, usize::MAX);
        for (scenario, _) in scenarios {
            for round in scenario.rounds {
                if round.primary_mask == round.secondary_mask {
                    continue;
                }
                let leader_in_primary = mask_contains(round.primary_mask, round.leader);
                let leader_in_secondary = mask_contains(round.secondary_mask, round.leader);
                assert!(leader_in_primary || leader_in_secondary);
            }
        }
    }

    #[test]
    fn route_selects_correct_half() {
        let scenario = Scenario {
            rounds: vec![round(4, 0, 0b0011, 0b1100)],
        };
        let participants: Vec<u32> = (0..4).collect();
        assert_eq!(
            scenario.route(View::new(1), &0, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            scenario.route(View::new(1), &1, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            scenario.route(View::new(1), &2, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            scenario.route(View::new(1), &3, &participants),
            SplitTarget::Secondary
        );
    }

    #[test]
    fn route_returns_both_after_scripted_rounds() {
        let scenario = Scenario {
            rounds: vec![round(4, 0, 0b0011, 0b1100)],
        };
        let participants: Vec<u32> = (0..4).collect();

        for participant in &participants {
            assert_eq!(
                scenario.route(View::new(2), participant, &participants),
                SplitTarget::Both
            );
        }
    }

    #[test]
    fn scenarios_fall_back_to_synchrony_after_attack_rounds() {
        let scenario = Scenario {
            rounds: vec![round(4, 0, 0b0011, 0b1100)],
        };
        let participants: Vec<u32> = (0..4).collect();
        let (primary, secondary) = scenario.partitions(View::new(2), &participants);
        assert_eq!(primary, participants);
        assert_eq!(secondary, participants);
    }

    #[test]
    fn canonical_scenario_count_reports_overflow() {
        let initial = CellState::from_cells(&[4]);
        let mut generator = ScenarioGenerator::new(4);
        assert_eq!(generator.counts(&initial, 40), None);
    }

    #[test]
    fn unique_index_sampling_handles_near_full_ranges() {
        let total = 100_000u128;
        let samples = 99_999usize;
        let mut rng = TestRng::new(9);
        let sampled = sample_unique_indices(&mut rng, total, samples);
        assert_eq!(sampled.len(), samples);
        assert_eq!(
            sampled.iter().copied().collect::<HashSet<_>>().len(),
            samples
        );
        assert!(sampled.into_iter().all(|idx| idx < total));
    }

    #[test]
    fn sustained_cases_repeat_single_round() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            mode: Mode::Sustained,
            max_cases: 50,
        };
        let all = cases(&mut test_rng(), framework);
        assert!(!all.is_empty());
        for case in &all {
            let rounds = case.scenario.rounds();
            assert_eq!(rounds.len(), 3);
            assert_eq!(rounds[0], rounds[1]);
            assert_eq!(rounds[1], rounds[2]);
        }
    }

    #[test]
    #[should_panic(expected = "scenario space overflows u128")]
    fn cases_panic_on_scenario_overflow() {
        let _ = cases(
            &mut test_rng(),
            Framework {
                participants: 4,
                faults: 1,
                rounds: 40,
                mode: Mode::Sampled,
                max_cases: 1,
            },
        );
    }

    #[test]
    fn pruned_scenarios_vary_across_round_positions() {
        let mut generator = ScenarioGenerator::new(5);
        let scenarios = generator.generate(&mut test_rng(), 3, 32);
        for round in 0..3 {
            let unique: HashSet<_> = scenarios
                .iter()
                .map(|(scenario, _)| scenario.rounds[round])
                .collect();
            assert!(
                unique.len() > 1,
                "round index {round} should vary under deterministic pruning"
            );
        }
    }

    #[test]
    fn compromised_sets_collapse_symmetry_cells() {
        // All 3 participants in one cell: only 1 unique compromised set for f=1
        assert_eq!(compromised_sets_for_cells(&[3], 1).len(), 1);
        assert_eq!(compromised_sets_for_cells(&[3], 1), vec![vec![0]]);

        // Cells [2, 1]: two unique compromised sets for f=1
        let sets = compromised_sets_for_cells(&[2, 1], 1);
        assert_eq!(sets, vec![vec![2], vec![0]]);

        // All singletons [1, 1, 1]: 3 unique compromised sets for f=1
        let sets = compromised_sets_for_cells(&[1, 1, 1], 1);
        assert_eq!(sets, vec![vec![2], vec![1], vec![0]]);
    }

    #[test]
    fn compromised_sets_multi_fault() {
        // Cells [3, 2], f=2: allocate across cells
        let sets = compromised_sets_for_cells(&[3, 2], 2);
        // take=0 from cell0, take=2 from cell1 -> [3, 4]
        // take=1 from cell0, take=1 from cell1 -> [0, 3]
        // take=2 from cell0, take=0 from cell1 -> [0, 1]
        assert_eq!(sets, vec![vec![3, 4], vec![0, 3], vec![0, 1]]);
    }

    #[test]
    fn cases_fewer_than_naive_cross_product() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 1,
            mode: Mode::Sampled,
            max_cases: usize::MAX,
        };
        let all_cases = cases(&mut test_rng(), framework);
        let mut generator = ScenarioGenerator::new(5);
        let scenarios = generator.generate(&mut test_rng(), 1, usize::MAX);
        // Naive cross-product would be scenarios * C(5,1) = scenarios * 5.
        // Symmetry-aware should produce fewer.
        let naive = scenarios.len() * 5;
        assert!(
            all_cases.len() < naive,
            "got {} cases but naive would be {naive}",
            all_cases.len()
        );
    }

    #[test]
    fn cases_reject_more_than_64_participants() {
        let result = std::panic::catch_unwind(|| {
            cases(
                &mut test_rng(),
                Framework {
                    participants: MAX_PARTICIPANTS + 1,
                    faults: 1,
                    rounds: 1,
                    mode: Mode::Sampled,
                    max_cases: 1,
                },
            )
        });
        assert!(result.is_err());
    }

    #[test]
    fn mask_helpers_set_boundary_ranges() {
        let mut mask = 0u64;
        set_mask_bit(&mut mask, 63);
        assert!(!mask_contains(mask, 62));
        assert!(mask_contains(mask, 63));

        let mut mask = 0u64;
        set_mask_range(&mut mask, 60, 4);
        for idx in 60..=63 {
            assert!(mask_contains(mask, idx), "bit {idx} should be set");
        }
        assert!(!mask_contains(mask, 59));
    }

    #[test]
    fn scenario_masks_route_within_one_word() {
        let mut primary_mask = 0u64;
        set_mask_range(&mut primary_mask, 60, 4);
        let mut secondary_mask = 0u64;
        set_mask_bit(&mut secondary_mask, 61);
        set_mask_bit(&mut secondary_mask, 63);
        let scenario = Scenario {
            rounds: vec![RoundScenario {
                leader: 63,
                primary_mask,
                secondary_mask,
            }],
        };
        let participants: Vec<_> = (0..64).collect();

        let (primary, secondary) = scenario.partitions(View::new(1), &participants);
        assert_eq!(primary, vec![60, 61, 62, 63]);
        assert_eq!(secondary, vec![61, 63]);
        assert_eq!(
            scenario.route(View::new(1), &60, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            scenario.route(View::new(1), &61, &participants),
            SplitTarget::Both
        );
        assert_eq!(
            scenario.route(View::new(1), &63, &participants),
            SplitTarget::Both
        );
        assert_eq!(
            scenario.route(View::new(1), &0, &participants),
            SplitTarget::None
        );
    }

    #[test]
    fn cases_support_64_participants() {
        let generated = cases(
            &mut test_rng(),
            Framework {
                participants: MAX_PARTICIPANTS,
                faults: 1,
                rounds: 1,
                mode: Mode::Sampled,
                max_cases: 1,
            },
        );
        assert_eq!(generated.len(), 1);
    }

    #[test]
    fn route_returns_none_for_participants_outside_selected_partitions() {
        let scenario = Scenario {
            rounds: vec![round(4, 0, 0b0001, 0b0010)],
        };
        let participants: Vec<u32> = (0..4).collect();
        assert_eq!(
            scenario.route(View::new(1), &2, &participants),
            SplitTarget::None
        );
    }

    #[test]
    #[should_panic(expected = "sender missing from runtime participant list")]
    fn route_panics_when_sender_is_missing_from_participants() {
        let scenario = Scenario {
            rounds: vec![round(4, 0, 0b0001, 0b0010)],
        };
        let participants: Vec<u32> = (0..4).collect();
        let _ = scenario.route(View::new(1), &99, &participants);
    }

    #[test]
    fn twins_elector_uses_scenario_leaders_then_fallback_suffix() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            mode: Mode::Sampled,
            max_cases: 1,
        };
        let case = cases(&mut test_rng(), framework)
            .into_iter()
            .next()
            .expect("expected at least one generated twins case");
        let participants: Vec<_> = (0..framework.participants as u64)
            .map(|seed| PrivateKey::from_seed(seed).public_key())
            .collect();
        let participants = Set::try_from(participants).expect("participants should be unique");
        let twins = <Elector<RoundRobin<Sha256>> as ElectorConfig<ed25519::Scheme>>::build(
            Elector::new(
                RoundRobin::<Sha256>::default(),
                &case.scenario,
                framework.participants,
            ),
            &participants,
        );
        let fallback = <RoundRobin<Sha256> as ElectorConfig<ed25519::Scheme>>::build(
            RoundRobin::<Sha256>::default(),
            &participants,
        );

        for (round_idx, round_scenario) in case.scenario.rounds().iter().enumerate() {
            let round = Round::new(Epoch::new(0), View::new((round_idx as u64) + 1));
            assert_eq!(
                twins.elect(round, None),
                Participant::from_usize(round_scenario.leader()),
                "unexpected leader in scripted attack round"
            );
        }

        for view in (framework.rounds as u64 + 1)..=20 {
            let round = Round::new(Epoch::new(333), View::new(view));
            assert_eq!(twins.elect(round, None), fallback.elect(round, None));
        }
    }
}
