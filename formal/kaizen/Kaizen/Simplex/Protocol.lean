import Kaizen.Simplex.Block

/-!
Kaizen.Simplex.Protocol: the Simplex voting protocol as a state-transition system.

The global state is the set of signed votes cast so far. Honest validators cast votes
only when Commonware's voter rules allow it (preconditions read on the global state,
an over-approximation of what any single voter has seen, since every certificate a
voter has seen exists globally). Byzantine validators may cast arbitrary votes.
-/

namespace Kaizen.Simplex

open Block

/-- Static parameters: 'n' validators, at most 'f' Byzantine ones ('byz'), quorum 'q'
such that any two quorums intersect in more than 'f' validators. -/
structure Config where
  /-- Number of validators, identified as 'Fin n'. -/
  n : ℕ
  /-- Fault bound. -/
  f : ℕ
  /-- Quorum size (Commonware: 2f+1 with n = 3f+1, i.e. n - f). -/
  q : ℕ
  /-- The (unknown) Byzantine validators. -/
  byz : Finset (Fin n)
  /-- At most 'f' validators are Byzantine. -/
  byz_card : byz.card ≤ f
  /-- Quorum intersection: two quorums share more than 'f' validators. -/
  quorum_inter : n + f < 2 * q

/-- The standard quorum 'n - f' satisfies the intersection requirement when 'n ≥ 3f + 1'. -/
theorem quorum_n_sub_f {n f : ℕ} (h : 3 * f + 1 ≤ n) : n + f < 2 * (n - f) := by omega

/-- Build a configuration with quorum 'n - f' from 'n ≥ 3f + 1'. -/
def Config.ofN3f1 (n f : ℕ) (byz : Finset (Fin n)) (hbyz : byz.card ≤ f)
    (h : 3 * f + 1 ≤ n) : Config :=
  ⟨n, f, n - f, byz, hbyz, quorum_n_sub_f h⟩

/-- Votes. The view of 'notarize b' and 'finalize b' is 'b.view'. -/
inductive Vote (P : Type) where
  | notarize (b : Block P)
  | nullify (v : ℕ)
  | finalize (b : Block P)

/-- Global state: the set of (validator, vote) pairs cast so far. -/
structure State (n : ℕ) (P : Type) where
  votes : Set (Fin n × Vote P)

variable {P : Type}

namespace State

variable {n : ℕ}

/-- Initial state: no votes. -/
def init : State n P := ⟨∅⟩

/-- Add one vote. -/
def cast (s : State n P) (i : Fin n) (m : Vote P) : State n P :=
  ⟨insert (i, m) s.votes⟩

/-- A certificate for vote 'm' exists: at least 'q' distinct validators cast 'm'. -/
def Cert (q : ℕ) (s : State n P) (m : Vote P) : Prop :=
  ∃ Q : Finset (Fin n), q ≤ Q.card ∧ ∀ i ∈ Q, (i, m) ∈ s.votes

end State

section
variable (C : Config)

/-- Notarization certificate for 'b' (at view 'b.view'). -/
def notarized (s : State C.n P) (b : Block P) : Prop := s.Cert C.q (.notarize b)
/-- Nullification certificate for view 'v'. -/
def nullified (s : State C.n P) (v : ℕ) : Prop := s.Cert C.q (.nullify v)
/-- Finalization certificate for 'b' (at view 'b.view'). -/
def finalized (s : State C.n P) (b : Block P) : Prop := s.Cert C.q (.finalize b)

/-- One protocol step. -/
inductive Step : State C.n P → State C.n P → Prop where
  /-- A Byzantine validator casts any vote. -/
  | byzantine {s : State C.n P} (i : Fin C.n) (hi : i ∈ C.byz) (m : Vote P) :
      Step s (s.cast i m)
  /-- An honest validator notarizes proposal 'mk v x p' (Commonware: on the leader's
  proposal, if the parent is finalized or notarized(+certified) and every skipped view
  between the parent's view and 'v' is nullified; at most one proposal per view, and
  never a different one from a proposal it already finalized at 'v'). -/
  | notarize {s : State C.n P} (i : Fin C.n) (hi : i ∉ C.byz) (v : ℕ) (x : P) (p : Block P)
      (hview : p.view < v)
      (hparent : p = .genesis ∨ notarized C s p ∨ finalized C s p)
      (hskip : ∀ w, p.view < w → w < v → nullified C s w)
      (honce : ∀ b', (i, .notarize b') ∈ s.votes → b'.view = v → b' = .mk v x p)
      (hfin : ∀ b', (i, .finalize b') ∈ s.votes → b'.view = v → b' = .mk v x p) :
      Step s (s.cast i (.notarize (.mk v x p)))
  /-- An honest validator nullifies view 'v' (on a timeout or a treated-as-timeout event),
  unless it already finalized 'v'. -/
  | nullify {s : State C.n P} (i : Fin C.n) (hi : i ∉ C.byz) (v : ℕ)
      (hnf : ∀ b, (i, .finalize b) ∈ s.votes → b.view ≠ v) :
      Step s (s.cast i (.nullify v))
  /-- An honest validator finalizes 'b' once 'b' is notarized (and certified), unless it
  nullified 'b.view' or notarized a different proposal at that view (equivocation). -/
  | finalize {s : State C.n P} (i : Fin C.n) (hi : i ∉ C.byz) (b : Block P)
      (hcert : notarized C s b)
      (hnn : (i, .nullify b.view) ∉ s.votes)
      (hno : ∀ b', (i, .notarize b') ∈ s.votes → b'.view = b.view → b' = b) :
      Step s (s.cast i (.finalize b))

/-- States reachable from the initial state. -/
inductive Reachable : State C.n P → Prop where
  | init : Reachable State.init
  | step {s s' : State C.n P} : Reachable s → Step C s s' → Reachable s'

end

end Kaizen.Simplex
